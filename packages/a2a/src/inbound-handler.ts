/**
 * Inbound A2A JSON-RPC handler (§A.7, §A.8, §A.13, §A.16, §A.17).
 *
 * Exposes `tasks/send`, `tasks/get`, `tasks/cancel`, `message/stream` (SSE),
 * and an AgentCard publisher. A2A credentials terminate here; mesh credentials
 * never cross the dialect boundary. Remote A2A principals are second-class.
 */
import http from "node:http";
import { uuidv7 } from "@latticeag/polymesh-broker";

import {
  A2AAuthBoundary,
  MESH_CREDENTIAL_HEADERS,
  type MeshTrustScope,
} from "./auth-boundary.js";
import {
  capabilityNameFromSkill,
  isPublishableSkill,
  mapCapabilitiesToSkills,
  mapCardToA2a,
} from "./card-mapper.js";
import type { A2AAdapterConfig, A2AAuthConfig } from "./config.js";
import { A2ADialectError, jsonRpcCodeFor } from "./errors.js";
import { AdapterEventLog } from "./event-log.js";
import { IdempotencyStore } from "./idempotency.js";
import { buildJsonRpcError, buildJsonRpcResult, JSONRPC_VERSION } from "./jsonrpc.js";
import { HierarchicalRateLimiter } from "./rate-limit.js";
import { polymeshStateToA2a } from "./task-translator.js";
import type {
  A2AMessage,
  A2ATask,
  PolyMeshCapability,
  PolyMeshTaskState,
} from "./types.js";

export const CAPABILITIES_LIST = "org.polymesh.capabilities.list";
export const DEFAULT_SSE_CLIENT_TIMEOUT_MS = 45_000;
export const MAX_REQUEST_BYTES = 1_048_576;

const A2A_METHODS = new Set(["tasks/send", "tasks/get", "tasks/cancel", "message/stream"]);
const ROOM_PREFIXES = [
  "org.polymesh.room.",
  "org.polymesh.mesh.join",
  "org.polymesh.mesh.leave",
  "org.polymesh.rooms.",
];

export interface InboundTaskRecord {
  task_id: string;
  principal_id: string;
  capability_id: string;
  state: PolyMeshTaskState;
  result?: unknown;
  error?: { code?: string; message?: string; data?: unknown };
  fingerprint?: string;
  session_id?: string;
  payload?: unknown;
  progress?: number;
}

export interface InboundSubmitEnvelope {
  task_id: string;
  capability: string;
  payload: unknown;
  principal_id: string;
  idempotency_key: string;
  headers: Record<string, string>;
  dialect: "a2a";
  rooms: [];
}

export interface InboundHandlerOptions {
  inbound_enabled?: boolean;
  auth?: A2AAuthConfig;
  allow_public_unauthenticated?: boolean;
  capabilities?: readonly PolyMeshCapability[];
  agent_card?: Record<string, unknown>;
  event_log?: AdapterEventLog;
  idempotency?: IdempotencyStore;
  rate_limit?: HierarchicalRateLimiter | false;
  auth_boundary?: A2AAuthBoundary;
  onSubmit?: (
    input: InboundSubmitEnvelope,
  ) =>
    | void
    | { state?: PolyMeshTaskState; result?: unknown; error?: InboundTaskRecord["error"] }
    | Promise<void | { state?: PolyMeshTaskState; result?: unknown; error?: InboundTaskRecord["error"] }>;
  onCancel?: (taskId: string) => void | Promise<void>;
  now?: () => number;
  listen_host?: string;
  listen_port?: number;
  public_card_path?: string;
  jsonrpc_path?: string;
  sse_enabled?: boolean;
  sse_client_timeout_ms?: number;
  config?: Partial<A2AAdapterConfig>;
}

export function projectMeshToA2aTask(input: {
  task_id: string;
  state: PolyMeshTaskState | string;
  capability_id?: string;
  result?: unknown;
  error?: { code?: string; message?: string; data?: unknown };
  event_seq?: number;
  progress?: number;
  session_id?: string;
}): A2ATask {
  const state = input.state as PolyMeshTaskState;
  const a2aState = polymeshStateToA2a(state);
  const status: A2ATask["status"] = { state: a2aState };
  if (input.progress !== undefined && a2aState === "working") {
    status.progress = input.progress;
  }
  if (a2aState === "failed" && input.error) {
    status.error = {
      code: String(input.error.code ?? "EXECUTION_FAILED"),
      message: String(input.error.message ?? "Execution failed"),
      data: input.error.data,
    };
  }
  const task: A2ATask = { id: input.task_id, status };
  if (input.session_id) task.sessionId = input.session_id;
  const metadata: Record<string, unknown> = { polymesh_state: state };
  if (input.capability_id) metadata.polymesh_capability_id = input.capability_id;
  if (input.event_seq !== undefined) metadata.polymesh_last_event_seq = input.event_seq;
  task.metadata = metadata;
  if (a2aState === "completed" && input.result !== undefined) {
    task.artifacts = [
      {
        name: "result",
        parts: [{ type: "data", data: input.result, mimeType: "application/json" }],
      },
    ];
  }
  return task;
}

export class A2AInboundHandler {
  readonly enabled: boolean;
  readonly auth: A2AAuthBoundary;
  readonly eventLog: AdapterEventLog;
  readonly idempotency: IdempotencyStore;
  readonly rateLimit: HierarchicalRateLimiter;
  readonly public_card_path: string;
  readonly jsonrpc_path: string;
  readonly sse_enabled: boolean;
  listen_host: string;
  listen_port: number;

  private readonly authCfg: A2AAuthConfig;
  private readonly allowPublic: boolean;
  private readonly capabilities: PolyMeshCapability[];
  private readonly agentCard: Record<string, unknown>;
  private readonly onSubmit?: InboundHandlerOptions["onSubmit"];
  private readonly onCancel?: InboundHandlerOptions["onCancel"];
  private readonly sseClientTimeoutMs: number;
  private readonly tasks = new Map<string, InboundTaskRecord>();
  private server: http.Server | null = null;
  private lastMeshSubmit: InboundSubmitEnvelope | null = null;
  private rateLimitEnabled: boolean;

  constructor(options: InboundHandlerOptions = {}) {
    const cfg = options.config ?? {};
    this.enabled = options.inbound_enabled ?? (cfg.inbound_enabled as boolean | undefined) ?? true;
    this.authCfg = options.auth ?? (cfg.auth as A2AAuthConfig | undefined) ?? { mode: "none" };
    this.allowPublic =
      options.allow_public_unauthenticated ??
      Boolean(cfg.allow_public_unauthenticated) ??
      false;
    this.capabilities = [...(options.capabilities ?? [])];
    this.agentCard = { ...(options.agent_card ?? {}) };
    if (this.capabilities.length > 0 && !this.agentCard.capabilities) {
      this.agentCard.capabilities = this.capabilities;
    }
    this.auth =
      options.auth_boundary ??
      new A2AAuthBoundary({ trustedEndpoints: [], defaultAuth: this.authCfg });
    this.eventLog = options.event_log ?? new AdapterEventLog();
    this.idempotency = options.idempotency ?? new IdempotencyStore();
    this.rateLimitEnabled = options.rate_limit !== false;
    this.rateLimit =
      options.rate_limit instanceof HierarchicalRateLimiter
        ? options.rate_limit
        : new HierarchicalRateLimiter({ enabled: this.rateLimitEnabled, now: options.now });
    this.onSubmit = options.onSubmit;
    this.onCancel = options.onCancel;
    this.sseClientTimeoutMs = options.sse_client_timeout_ms ?? DEFAULT_SSE_CLIENT_TIMEOUT_MS;
    this.listen_host = options.listen_host ?? "127.0.0.1";
    this.listen_port = options.listen_port ?? 0;
    this.public_card_path = options.public_card_path ?? "/.well-known/agent.json";
    this.jsonrpc_path = options.jsonrpc_path ?? "/a2a";
    this.sse_enabled = options.sse_enabled ?? true;
  }

  get publishedCapabilities(): PolyMeshCapability[] {
    return this.capabilities.filter((c) => isPublishableSkill(c));
  }

  get publishedCapabilityIds(): Set<string> {
    return new Set(this.publishedCapabilities.map((c) => c.name));
  }

  publishedSkills() {
    return mapCapabilitiesToSkills(this.publishedCapabilities, { enforcePublishGate: true });
  }

  handleCardRequest(): Record<string, unknown> {
    const card = {
      ...this.agentCard,
      agent_id: this.agentCard.agent_id ?? "polymesh-agent",
      capabilities: this.publishedCapabilities,
      sse_enabled: this.sse_enabled,
    };
    return mapCardToA2a(card, { enforcePublishGate: true });
  }

  /** Alias retained for tests that call the inbound-gated publisher explicitly. */
  handleCardRequestInbound(): Record<string, unknown> {
    return this.handleCardRequest();
  }

  trustScopeFor(headers: Record<string, string | string[] | undefined> = {}): MeshTrustScope {
    return this.auth.terminateInboundAuth(headers, {
      auth: this.authCfg,
      allowPublicUnauthenticated: this.allowPublic || this.authCfg.mode === "none",
    });
  }

  async handleTasksSend(
    params: Record<string, unknown>,
    ctx: { headers?: Record<string, string | string[] | undefined>; clientIp?: string } = {},
  ): Promise<A2ATask> {
    const response = await this.handle(
      { jsonrpc: JSONRPC_VERSION, id: "1", method: "tasks/send", params },
      ctx,
    );
    if (response.error) {
      throw dialectFromRpc(response.error);
    }
    return response.result as A2ATask;
  }

  async handleTasksGet(
    params: Record<string, unknown>,
    ctx: { headers?: Record<string, string | string[] | undefined>; clientIp?: string } = {},
  ): Promise<A2ATask> {
    const response = await this.handle(
      { jsonrpc: JSONRPC_VERSION, id: "1", method: "tasks/get", params },
      ctx,
    );
    if (response.error) throw dialectFromRpc(response.error);
    return response.result as A2ATask;
  }

  async handleTasksCancel(
    params: Record<string, unknown>,
    ctx: { headers?: Record<string, string | string[] | undefined>; clientIp?: string } = {},
  ): Promise<A2ATask> {
    const response = await this.handle(
      { jsonrpc: JSONRPC_VERSION, id: "1", method: "tasks/cancel", params },
      ctx,
    );
    if (response.error) throw dialectFromRpc(response.error);
    return response.result as A2ATask;
  }

  async handle(
    request: {
      jsonrpc?: string;
      id?: string | number | null;
      method?: string;
      params?: unknown;
    } | null,
    ctx: { headers?: Record<string, string | string[] | undefined>; clientIp?: string } = {},
  ): Promise<{ jsonrpc: string; id: string | number | null; result?: unknown; error?: unknown }> {
    const requestId = (request?.id ?? null) as string | number | null;
    try {
      if (!this.enabled) {
        throw new A2ADialectError("UNSUPPORTED_METHOD", "inbound A2A serving is disabled");
      }
      if (!request || typeof request !== "object") {
        throw new A2ADialectError("MALFORMED", "Invalid request");
      }
      if (request.jsonrpc !== JSONRPC_VERSION) {
        throw new A2ADialectError("MALFORMED", "Invalid request");
      }
      const method = request.method;
      if (typeof method !== "string" || !A2A_METHODS.has(method)) {
        throw new A2ADialectError(
          method && typeof method === "string" ? "UNSUPPORTED_METHOD" : "MALFORMED",
          method && typeof method === "string" ? "Method not found" : "Invalid request",
        );
      }

      const headers = ctx.headers ?? {};
      const safeHeaders = this.auth.stripMeshCredentialsFromHeaders(headers);
      const trust = this.auth.terminateInboundAuth(headers, {
        auth: this.authCfg,
        allowPublicUnauthenticated: this.allowPublic || this.authCfg.mode === "none",
      });
      const principalId = trust.principal_id;
      const params =
        request.params === undefined || request.params === null
          ? {}
          : (request.params as Record<string, unknown>);
      if (typeof params !== "object" || Array.isArray(params)) {
        throw new A2ADialectError("MALFORMED", "Invalid request");
      }

      const capabilityHint = method === "tasks/send" ? this.peekCapability(params) : undefined;
      if (
        this.rateLimitEnabled &&
        !this.rateLimit.allow({
          ip: ctx.clientIp ?? "127.0.0.1",
          principal: principalId,
          capability: capabilityHint ?? undefined,
        })
      ) {
        throw new A2ADialectError("RATE_LIMITED", "Rate limited", {
          data: { retry_after_ms: 1000 },
        });
      }

      let result: unknown;
      if (method === "tasks/send") {
        result = await this.tasksSend(params, principalId, safeHeaders);
      } else if (method === "tasks/get") {
        result = this.tasksGet(params, principalId);
      } else if (method === "tasks/cancel") {
        result = await this.tasksCancel(params, principalId);
      } else {
        result = this.messageStream(params, principalId);
      }
      return buildJsonRpcResult(requestId, result);
    } catch (err) {
      const dialect =
        err instanceof A2ADialectError
          ? err
          : new A2ADialectError("INTERNAL", err instanceof Error ? err.message : "Internal error");
      return buildJsonRpcError(requestId, dialect.jsonRpcCode, dialect.message, {
        polymesh_code: dialect.code,
        retryable: dialect.retryable,
        ...(typeof dialect.data === "object" && dialect.data ? (dialect.data as object) : {}),
      });
    }
  }

  private peekCapability(params: Record<string, unknown>): string | null {
    try {
      return this.resolveSkill(params);
    } catch {
      return null;
    }
  }

  private resolveSkill(params: Record<string, unknown>): string {
    const metadata = params.metadata;
    if (metadata && typeof metadata === "object" && !Array.isArray(metadata)) {
      const meta = metadata as Record<string, unknown>;
      if (typeof meta.capability_id === "string" && meta.capability_id.trim()) {
        return meta.capability_id.trim();
      }
      if (typeof meta.skill === "string" && meta.skill.trim()) {
        return capabilityNameFromSkill({ name: meta.skill.trim() }).name;
      }
    }
    const message = params.message;
    if (message && typeof message === "object") {
      const parts = (message as A2AMessage).parts;
      if (Array.isArray(parts)) {
        for (const part of parts) {
          if (part?.type === "data" && part.data && typeof part.data === "object") {
            const data = part.data as Record<string, unknown>;
            for (const key of ["capability_id", "capability", "skill"] as const) {
              const value = data[key];
              if (typeof value === "string" && value.trim()) {
                return key === "skill"
                  ? capabilityNameFromSkill({ name: value.trim() }).name
                  : value.trim();
              }
            }
          }
        }
      }
    }
    throw new A2ADialectError("UNSUPPORTED_CAPABILITY", "Skill unsupported");
  }

  private validateMessage(message: unknown): A2AMessage {
    if (!message || typeof message !== "object" || Array.isArray(message)) {
      throw new A2ADialectError("MALFORMED", "Invalid request");
    }
    const msg = message as Record<string, unknown>;
    const allowed = new Set(["messageId", "role", "parts"]);
    for (const key of Object.keys(msg)) {
      if (!allowed.has(key)) throw new A2ADialectError("MALFORMED", "Invalid request");
    }
    if (msg.role !== "user" && msg.role !== "agent") {
      throw new A2ADialectError("MALFORMED", "Invalid request");
    }
    if (!Array.isArray(msg.parts) || msg.parts.length < 1 || msg.parts.length > 32) {
      throw new A2ADialectError("MALFORMED", "Invalid request");
    }
    return msg as unknown as A2AMessage;
  }

  private validateSendParams(params: Record<string, unknown>): void {
    const allowed = new Set(["id", "sessionId", "message", "metadata"]);
    for (const key of Object.keys(params)) {
      if (!allowed.has(key)) throw new A2ADialectError("MALFORMED", "Invalid request");
    }
    if (!("message" in params)) throw new A2ADialectError("MALFORMED", "Invalid request");
    this.validateMessage(params.message);
    if (params.id !== undefined && typeof params.id !== "string") {
      throw new A2ADialectError("MALFORMED", "Invalid request");
    }
    if (typeof params.id === "string" && (params.id.length < 1 || params.id.length > 128)) {
      throw new A2ADialectError("MALFORMED", "Invalid request");
    }
    if (
      params.metadata !== undefined &&
      (typeof params.metadata !== "object" || Array.isArray(params.metadata))
    ) {
      throw new A2ADialectError("MALFORMED", "Invalid request");
    }
  }

  private extractInput(message: A2AMessage): unknown {
    for (const part of message.parts) {
      if (part.type === "file") throw new A2ADialectError("MALFORMED", "Invalid request");
      if (part.type === "data" && part.data !== undefined) {
        if (part.data && typeof part.data === "object" && !Array.isArray(part.data)) {
          const data = { ...(part.data as Record<string, unknown>) };
          delete data.skill;
          delete data.capability;
          delete data.capability_id;
          return data;
        }
        if (Array.isArray(part.data)) return part.data;
        throw new A2ADialectError("MALFORMED", "Invalid request");
      }
    }
    if (message.parts.length === 1 && message.parts[0]?.type === "text") {
      const text = message.parts[0].text;
      if (typeof text !== "string") throw new A2ADialectError("MALFORMED", "Invalid request");
      try {
        const parsed = JSON.parse(text) as unknown;
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
          throw new A2ADialectError("MALFORMED", "Invalid request");
        }
        return parsed;
      } catch (err) {
        if (err instanceof A2ADialectError) throw err;
        throw new A2ADialectError("MALFORMED", "Invalid request");
      }
    }
    throw new A2ADialectError("MALFORMED", "Invalid request");
  }

  private isRoomCapability(capabilityId: string): boolean {
    return ROOM_PREFIXES.some((p) => capabilityId.startsWith(p));
  }

  private async tasksSend(
    params: Record<string, unknown>,
    principalId: string,
    safeHeaders: Record<string, string>,
  ): Promise<A2ATask> {
    this.validateSendParams(params);
    const capabilityId = this.resolveSkill(params);
    if (this.isRoomCapability(capabilityId)) {
      throw new A2ADialectError("AUTHORIZATION_DENIED", "Authorization denied");
    }
    if (!this.publishedCapabilityIds.has(capabilityId)) {
      throw new A2ADialectError("UNSUPPORTED_CAPABILITY", "Skill unsupported");
    }

    const message = this.validateMessage(params.message);
    const payload = this.extractInput(message);

    if (capabilityId === CAPABILITIES_LIST) {
      return this.completeBuiltinList(params, principalId, payload);
    }

    const metadata =
      params.metadata && typeof params.metadata === "object"
        ? (params.metadata as Record<string, unknown>)
        : {};
    const idemKey = typeof metadata.idempotency_key === "string" ? metadata.idempotency_key : undefined;
    const suppliedId = typeof params.id === "string" ? params.id : undefined;
    const taskId = suppliedId ?? uuidv7();

    const { hit, meta } = this.idempotency.checkOrThrow({
      capability_id: capabilityId,
      payload,
      task_id: taskId,
      principal_id: principalId,
      idempotency_key: idemKey,
    });
    if (hit) return this.projectTask(hit.task_id);

    const prior = this.tasks.get(taskId);
    if (prior && prior.principal_id !== principalId) {
      throw new A2ADialectError("IDEMPOTENCY_CONFLICT", "Idempotency conflict");
    }
    if (prior && prior.fingerprint && prior.fingerprint !== meta.fingerprint) {
      throw new A2ADialectError("IDEMPOTENCY_CONFLICT", "Idempotency conflict");
    }

    const submitEnvelope: InboundSubmitEnvelope = {
      task_id: taskId,
      capability: capabilityId,
      payload,
      principal_id: principalId,
      idempotency_key: meta.dedup_key,
      headers: { ...safeHeaders },
      dialect: "a2a",
      rooms: [],
    };
    for (const name of Object.keys(submitEnvelope.headers)) {
      if (MESH_CREDENTIAL_HEADERS.includes(name.toLowerCase())) {
        throw new A2ADialectError(
          "AUTHORIZATION_DENIED",
          "mesh credential must not cross boundary",
        );
      }
    }
    this.lastMeshSubmit = submitEnvelope;

    let state: PolyMeshTaskState = "SUBMITTED";
    let result: unknown;
    let error: InboundTaskRecord["error"];
    if (this.onSubmit) {
      const meshResult = await this.onSubmit(submitEnvelope);
      if (meshResult && typeof meshResult === "object") {
        if (meshResult.state) state = meshResult.state;
        if (meshResult.result !== undefined) result = meshResult.result;
        if (meshResult.error) error = meshResult.error;
      }
    }

    this.idempotency.store(meta, taskId);
    this.eventLog.ensure(taskId);
    this.eventLog.append(taskId, "submitted", { state: "SUBMITTED" });
    if (state !== "SUBMITTED") {
      const terminal = ["SUCCEEDED", "FAILED", "CANCELLED", "REJECTED"].includes(state);
      this.eventLog.append(taskId, terminal ? "terminal" : "status", {
        state,
        terminal,
        result,
        ...(error ? { error } : {}),
      });
    }

    this.tasks.set(taskId, {
      task_id: taskId,
      principal_id: principalId,
      capability_id: capabilityId,
      state,
      result,
      error,
      fingerprint: meta.fingerprint,
      session_id: typeof params.sessionId === "string" ? params.sessionId : undefined,
      payload,
    });
    return this.projectTask(taskId);
  }

  private completeBuiltinList(
    params: Record<string, unknown>,
    principalId: string,
    payload: unknown,
  ): A2ATask {
    const taskId = typeof params.id === "string" ? params.id : uuidv7();
    const skills = this.publishedSkills();
    const result = { skills, capabilities: skills.map((s) => s.name) };
    this.eventLog.ensure(taskId);
    this.eventLog.append(taskId, "submitted", { state: "SUBMITTED" });
    this.eventLog.append(taskId, "completed", {
      state: "SUCCEEDED",
      terminal: true,
      result,
    });
    this.tasks.set(taskId, {
      task_id: taskId,
      principal_id: principalId,
      capability_id: CAPABILITIES_LIST,
      state: "SUCCEEDED",
      result,
      session_id: typeof params.sessionId === "string" ? params.sessionId : undefined,
      payload,
    });
    return this.projectTask(taskId);
  }

  private requireOwnedTask(taskId: string, principalId: string): InboundTaskRecord {
    const task = this.tasks.get(taskId);
    if (!task || task.principal_id !== principalId) {
      throw new A2ADialectError("TASK_NOT_FOUND", "Task not found");
    }
    return task;
  }

  private tasksGet(params: Record<string, unknown>, principalId: string): A2ATask {
    for (const key of Object.keys(params)) {
      if (key !== "id" && key !== "historyLength") {
        throw new A2ADialectError("MALFORMED", "Invalid request");
      }
    }
    if (typeof params.id !== "string" || !params.id) {
      throw new A2ADialectError("MALFORMED", "Invalid request");
    }
    this.requireOwnedTask(params.id, principalId);
    return this.projectTask(params.id);
  }

  private async tasksCancel(
    params: Record<string, unknown>,
    principalId: string,
  ): Promise<A2ATask> {
    for (const key of Object.keys(params)) {
      if (key !== "id" && key !== "reason") {
        throw new A2ADialectError("MALFORMED", "Invalid request");
      }
    }
    if (typeof params.id !== "string" || !params.id) {
      throw new A2ADialectError("MALFORMED", "Invalid request");
    }
    const task = this.requireOwnedTask(params.id, principalId);
    if (["SUCCEEDED", "FAILED", "REJECTED"].includes(task.state)) {
      return this.projectTask(params.id);
    }
    if (task.state !== "CANCELLED") {
      await this.onCancel?.(params.id);
      task.state = "CANCELLED";
      this.eventLog.append(params.id, "canceled", { state: "CANCELLED", terminal: true });
    }
    return this.projectTask(params.id);
  }

  private messageStream(
    params: Record<string, unknown>,
    principalId: string,
  ): { events: ReturnType<A2AInboundHandler["streamEvents"]>; task: A2ATask } {
    for (const key of Object.keys(params)) {
      if (key !== "id" && key !== "from_event_seq") {
        throw new A2ADialectError("MALFORMED", "Invalid request");
      }
    }
    if (typeof params.id !== "string" || !params.id) {
      throw new A2ADialectError("MALFORMED", "Invalid request");
    }
    this.requireOwnedTask(params.id, principalId);
    const fromSeq =
      params.from_event_seq === undefined ? undefined : Number(params.from_event_seq);
    if (fromSeq !== undefined && (!Number.isInteger(fromSeq) || fromSeq < 1)) {
      throw new A2ADialectError("MALFORMED", "Invalid request");
    }
    const events = this.streamEvents(params.id, {
      from_event_seq: fromSeq,
      principal_id: principalId,
    });
    return { events, task: this.projectTask(params.id) };
  }

  streamEvents(
    taskId: string,
    options: {
      from_event_seq?: number;
      principal_id?: string;
      client_timeout_ms?: number;
    } = {},
  ): Array<{ event: string; task: A2ATask; adapter_seq: number }> {
    if (options.principal_id) {
      this.requireOwnedTask(taskId, options.principal_id);
    } else if (!this.eventLog.contains(taskId)) {
      throw new A2ADialectError("TASK_NOT_FOUND", "Task not found");
    }

    const timeoutMs =
      options.client_timeout_ms === undefined
        ? this.sseClientTimeoutMs
        : options.client_timeout_ms;
    if (timeoutMs <= 0) return [];

    let retained = this.eventLog.get(taskId);
    if (options.from_event_seq !== undefined) {
      const minRetained = retained.reduce(
        (min, e) => Math.min(min, e.event_seq),
        Number.POSITIVE_INFINITY,
      );
      if (
        Number.isFinite(minRetained) &&
        options.from_event_seq < minRetained &&
        retained.length > 0
      ) {
        throw new A2ADialectError("TASK_NOT_FOUND", "Task not found");
      }
      retained = retained.filter((e) => e.event_seq >= options.from_event_seq!);
    }

    return retained.map((event) => {
      const state = (event.state ?? "RUNNING") as PolyMeshTaskState;
      const payload =
        event.payload && typeof event.payload === "object"
          ? (event.payload as Record<string, unknown>)
          : {};
      const task = projectMeshToA2aTask({
        task_id: taskId,
        state,
        capability_id: this.tasks.get(taskId)?.capability_id,
        result: payload.result ?? event.result,
        error: payload.error as InboundTaskRecord["error"],
        event_seq: event.event_seq,
      });
      return {
        event: event.terminal ? "task.terminal" : "task.status",
        task,
        adapter_seq: event.event_seq,
      };
    });
  }

  applyMeshEvent(
    taskId: string,
    input: {
      state: PolyMeshTaskState;
      result?: unknown;
      error?: InboundTaskRecord["error"];
      progress?: number;
    },
  ): A2ATask {
    const task = this.tasks.get(taskId);
    if (!task) throw new A2ADialectError("TASK_NOT_FOUND", "Task not found");
    task.state = input.state;
    if (input.result !== undefined) task.result = input.result;
    if (input.error) task.error = input.error;
    if (input.progress !== undefined) task.progress = input.progress;
    const terminal = ["SUCCEEDED", "FAILED", "CANCELLED", "REJECTED"].includes(input.state);
    this.eventLog.append(taskId, terminal ? "terminal" : "status", {
      state: input.state,
      terminal,
      result: input.result,
      ...(input.error ? { error: input.error } : {}),
      progress: input.progress,
    });
    return this.projectTask(taskId);
  }

  projectTask(taskId: string): A2ATask {
    const task = this.tasks.get(taskId);
    if (!task) throw new A2ADialectError("TASK_NOT_FOUND", "Task not found");
    return projectMeshToA2aTask({
      task_id: taskId,
      state: task.state,
      capability_id: task.capability_id,
      result: task.result,
      error: task.error,
      event_seq: this.eventLog.lastSeq(taskId),
      progress: task.progress,
      session_id: task.session_id,
    });
  }

  joinRoom(): never {
    throw new A2ADialectError("AUTHORIZATION_DENIED", "Authorization denied");
  }

  listMeshMembers(): never {
    throw new A2ADialectError("AUTHORIZATION_DENIED", "Authorization denied");
  }

  getLastMeshSubmit(): InboundSubmitEnvelope | null {
    return this.lastMeshSubmit ? { ...this.lastMeshSubmit, headers: { ...this.lastMeshSubmit.headers } } : null;
  }

  async start(): Promise<A2AInboundHandler> {
    if (this.server) return this;
    await new Promise<void>((resolve, reject) => {
      const server = http.createServer((req, res) => {
        void this.dispatchHttp(req, res);
      });
      server.once("error", reject);
      server.listen(this.listen_port, this.listen_host, () => {
        const addr = server.address();
        if (addr && typeof addr === "object") {
          this.listen_host = addr.address;
          this.listen_port = addr.port;
        }
        this.server = server;
        resolve();
      });
    });
    return this;
  }

  async stop(): Promise<void> {
    if (!this.server) return;
    const server = this.server;
    this.server = null;
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  }

  get url(): string {
    return `http://${this.listen_host}:${this.listen_port}${this.jsonrpc_path}`;
  }

  get cardUrl(): string {
    return `http://${this.listen_host}:${this.listen_port}${this.public_card_path}`;
  }

  private async dispatchHttp(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "127.0.0.1"}`);
    const path = url.pathname;

    if (req.method === "GET" && path === this.public_card_path) {
      const body = JSON.stringify(this.handleCardRequest());
      res.writeHead(200, { "content-type": "application/json" });
      res.end(body);
      return;
    }

    if (req.method !== "POST" || path !== this.jsonrpc_path) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not found" }));
      return;
    }

    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    const raw = Buffer.concat(chunks);
    if (raw.byteLength > MAX_REQUEST_BYTES) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify(
          buildJsonRpcError(null, -32600, "Invalid request", {
            polymesh_code: "MALFORMED",
            retryable: false,
          }),
        ),
      );
      return;
    }

    let body: unknown;
    try {
      body = raw.length ? JSON.parse(raw.toString("utf8")) : null;
    } catch {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify(
          buildJsonRpcError(null, -32700, "Parse error", {
            polymesh_code: "MALFORMED_JSON",
            retryable: false,
          }),
        ),
      );
      return;
    }

    const headers = req.headers as Record<string, string | string[] | undefined>;
    const clientIp = req.socket.remoteAddress ?? "127.0.0.1";
    const rpc = body as {
      id?: string | number | null;
      method?: string;
      params?: Record<string, unknown>;
    };

    if (rpc?.method === "message/stream" && this.sse_enabled) {
      const prelude = await this.handle(rpc, { headers, clientIp });
      if (prelude.error) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(prelude));
        return;
      }
      const trust = this.trustScopeFor(headers);
      const fromSeq =
        typeof rpc.params?.from_event_seq === "number" ? rpc.params.from_event_seq : undefined;
      let events: ReturnType<A2AInboundHandler["streamEvents"]>;
      try {
        events = this.streamEvents(String(rpc.params?.id), {
          from_event_seq: fromSeq,
          principal_id: trust.principal_id,
        });
      } catch (err) {
        const dialect =
          err instanceof A2ADialectError
            ? err
            : new A2ADialectError("INTERNAL", "Internal error");
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify(
            buildJsonRpcError(rpc.id ?? null, dialect.jsonRpcCode, dialect.message, {
              polymesh_code: dialect.code,
              retryable: dialect.retryable,
            }),
          ),
        );
        return;
      }
      res.writeHead(200, {
        "content-type": "text/event-stream",
        "cache-control": "no-cache",
        connection: "close",
      });
      for (const event of events) {
        const data = JSON.stringify({
          event: event.event,
          task: event.task,
          adapter_seq: event.adapter_seq,
        });
        res.write(`event: task\ndata: ${data}\n\n`);
      }
      res.end();
      return;
    }

    const response = await this.handle(
      body && typeof body === "object" ? (body as never) : null,
      { headers, clientIp },
    );
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(response));
  }
}

function dialectFromRpc(error: unknown): A2ADialectError {
  const err = error as { code?: number; message?: string; data?: { polymesh_code?: string } };
  const code = err.data?.polymesh_code ?? "INTERNAL";
  return new A2ADialectError(code, err.message, {
    jsonRpcCode: err.code ?? jsonRpcCodeFor(code),
    data: err.data,
  });
}

/** Barrel-facing name for the M3 ingress handler (§E.1.2). */
export { A2AInboundHandler as InboundHandler };

export function createInboundHandler(options?: InboundHandlerOptions): A2AInboundHandler {
  return new A2AInboundHandler(options);
}

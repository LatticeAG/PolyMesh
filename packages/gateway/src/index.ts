/**
 * PolyMesh v2 REST/SSE gateway.
 *
 * The gateway deliberately has a small adapter boundary.  HTTP credentials
 * are verified here and reduced to a closed authorization context before a
 * broker sees a request; raw bearer tokens never enter an envelope, task
 * input, event, or broker adapter call.  This is a loopback-only local
 * gateway adapter: it deliberately does not claim to be a remote relay.
 */

import { createHash, randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { URL } from "node:url";
import {
  V2_PROTOCOL_VERSION,
  canonicalize,
  isJsonValue,
  parseStrictJson,
  uuidv7,
  type JsonObject,
  type JsonValue,
} from "@latticeag/polymesh-broker";

export const GATEWAY_MAX_REQUEST_BYTES = 256 * 1024;
export const GATEWAY_MAX_INPUT_BYTES = 256 * 1024;
export const GATEWAY_MAX_IDEMPOTENCY_KEY_BYTES = 200;
/** The only profile exposed by the v0.4 loopback gateway. */
export const GATEWAY_PROFILE = V2_PROTOCOL_VERSION;
export const GATEWAY_SCOPE = "loopback-only" as const;

export const GATEWAY_TASK_REQUEST_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://polymesh.dev/schemas/v2/gateway-task-request.json",
  type: "object",
  additionalProperties: false,
  required: ["target", "capability", "input", "deadline"],
  properties: {
    profile: { const: GATEWAY_PROFILE },
    target: {
      type: "object",
      additionalProperties: false,
      required: ["mesh_id", "agent_id"],
      properties: {
        // Earlier v2 adapters use msh_ IDs; the native v0.4 profile uses a
        // UUIDv7 broker mesh identity.  The loopback gateway accepts either
        // while profile selection remains explicit at the HTTP boundary.
        mesh_id: {
          type: "string",
          anyOf: [
            { pattern: "^msh_[A-Za-z0-9_-]{8,120}$", maxLength: 124 },
            { pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", maxLength: 36 },
          ],
        },
        agent_id: { type: "string", pattern: "^[a-z][a-z0-9]*(\\.[a-z][a-z0-9_-]*)+$", maxLength: 255 },
        instance_id: { type: "string", pattern: "^[A-Za-z0-9_-]{16,128}$", maxLength: 128 },
      },
    },
    capability: { type: "string", pattern: "^[a-z][a-z0-9]*(\\.[a-z][a-z0-9_-]*)+$", maxLength: 255 },
    capability_version: { type: "string", pattern: "^[0-9]+\\.[0-9]+\\.[0-9]+$", maxLength: 32 },
    input: { type: ["object", "array", "string", "number", "integer", "boolean", "null"] },
    deadline: { type: "string", format: "date-time", maxLength: 40 },
  },
} as const;

export const GATEWAY_EVENT_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://polymesh.dev/schemas/v2/gateway-event.json",
  type: "object",
  additionalProperties: false,
  required: ["event_id", "task_id", "event_seq", "type", "occurred_at", "data"],
  properties: {
    event_id: { type: "string", pattern: "^evt_[A-Za-z0-9_-]{20,120}$", maxLength: 124 },
    task_id: { type: "string", pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" },
    event_seq: { type: "integer", minimum: 1, maximum: Number.MAX_SAFE_INTEGER },
    type: { type: "string", enum: ["task.accepted", "task.rejected", "task.progress", "task.completed", "error", "delivery.error"] },
    occurred_at: { type: "string", format: "date-time", maxLength: 40 },
    data: { type: ["object", "array", "string", "number", "integer", "boolean", "null"] },
  },
} as const;

const UUID_V7_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MESH_ID_RE = /^msh_[A-Za-z0-9_-]{8,120}$/;
const AGENT_OR_CAPABILITY_RE = /^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9_-]*)+$/;
const INSTANCE_ID_RE = /^[A-Za-z0-9_-]{16,128}$/;
const SEMVER_RE = /^[0-9]+\.[0-9]+\.[0-9]+$/;
const IDEMPOTENCY_KEY_RE = /^[A-Za-z0-9._~:-]+$/;
const EVENT_ID_RE = /^evt_[A-Za-z0-9_-]{20,120}$/;
const EVENT_TYPES = new Set<GatewayEventType>([
  "task.accepted",
  "task.rejected",
  "task.progress",
  "task.completed",
  "error",
  "delivery.error",
]);

/** A bearer credential is reduced to these non-secret, verified fields. */
export interface GatewayPrincipal {
  principal_id: string;
  mesh_id: string;
  /** Stable identity of an attenuated grant, when one was used. */
  delegation_id?: string;
}

/** The gateway's enrolled PolyMesh identity, not a caller supplied identity. */
export interface GatewayIdentity {
  agent_id: string;
  instance_id: string;
}

export interface GatewayTarget {
  mesh_id: string;
  agent_id: string;
  instance_id?: string;
}

export interface GatewayTaskRequest {
  /** Selected explicitly by the native /v2/tasks endpoint. */
  profile?: typeof GATEWAY_PROFILE;
  target: GatewayTarget;
  capability: string;
  capability_version?: string;
  input: JsonValue;
  /** Normalized to RFC 3339 UTC milliseconds before it enters the envelope. */
  deadline: string;
}

export interface GatewayCapabilityContract {
  capability_version: string;
  capability_contract_digest: string;
}

export interface GatewayTaskEnvelope {
  protocol: typeof V2_PROTOCOL_VERSION;
  type: "task.submit";
  message_id: string;
  timestamp: string;
  source: GatewayTarget & { instance_id: string };
  target: GatewayTarget;
  delivery: {
    delivery_id: string;
    mode: "at_least_once";
    idempotency_key: string;
    deadline: string;
  };
  params: JsonObject & {
    task_id: string;
    capability: string;
    capability_version: string;
    capability_contract_digest: string;
    input: JsonValue;
    deadline: string;
  };
}

/** This context is out-of-band transport metadata and is never serialized. */
export interface GatewayAuthorizationContext {
  principal_id: string;
  mesh_id: string;
  delegation_id?: string;
}

export interface GatewayTaskAdmission {
  /** The durable task identity. It must agree with the gateway envelope. */
  task_id?: string;
  state?: "submitted";
  receipt?: "stored";
}

export type GatewayEventType =
  | "task.accepted"
  | "task.rejected"
  | "task.progress"
  | "task.completed"
  | "error"
  | "delivery.error";

/** The closed event payload which is sent verbatim as SSE JSON data. */
export interface GatewayEvent {
  event_id: string;
  task_id: string;
  event_seq: number;
  type: GatewayEventType;
  occurred_at: string;
  data: JsonValue;
}

export interface GatewayEventQuery {
  authorization: GatewayAuthorizationContext;
  profile?: typeof GATEWAY_PROFILE;
  task_id?: string;
  /** Last-Event-ID wins over the `cursor` / legacy `after` query field. */
  after?: string;
}

export interface GatewayEventPage {
  events: readonly GatewayEvent[];
  /** The requested durable cursor no longer maps to this authorized view. */
  cursor_expired?: boolean;
}

export interface GatewayTaskResolution {
  authorization: GatewayAuthorizationContext;
  request: GatewayTaskRequest;
}

export interface GatewayTaskSubmission {
  authorization: GatewayAuthorizationContext;
  envelope: GatewayTaskEnvelope;
  /** Opaque durable idempotency comparison value; it contains no token. */
  idempotency_fingerprint: string;
}

/**
 * Durable broker/gateway boundary.  In production `admitTask` is expected to
 * commit ingress, idempotency, route, outbox, and audit state atomically.
 * The gateway intentionally cannot turn an HTTP write into such a receipt.
 */
export interface GatewayBroker {
  resolveTask(input: GatewayTaskResolution): Promise<GatewayCapabilityContract> | GatewayCapabilityContract;
  admitTask?(input: GatewayTaskSubmission): Promise<GatewayTaskAdmission> | GatewayTaskAdmission;
  /** `submitTask` is accepted as a friendly adapter alias. */
  submitTask?(input: GatewayTaskSubmission): Promise<GatewayTaskAdmission> | GatewayTaskAdmission;
  readEvents?(query: GatewayEventQuery): Promise<GatewayEventPage> | GatewayEventPage;
  subscribeEvents?(
    query: Omit<GatewayEventQuery, "after">,
    listener: (event: GatewayEvent) => void,
  ): (() => void) | void;
}

export type GatewayAuthenticator = (
  bearerToken: string,
  request: IncomingMessage,
) => Promise<GatewayPrincipal | undefined> | GatewayPrincipal | undefined;

export interface GatewayOptions {
  authenticate: GatewayAuthenticator;
  broker: GatewayBroker;
  identity?: GatewayIdentity;
  maxRequestBytes?: number;
  maxInputBytes?: number;
  /** Bound only keepalive comments; comments never advance an event cursor. */
  sseKeepaliveMs?: number;
  /** Native v0.4 is intentionally a single-profile local gateway. */
  supportedProfiles?: readonly [typeof GATEWAY_PROFILE];
  now?: () => number;
}

export interface GatewayTaskResponse {
  profile?: typeof GATEWAY_PROFILE;
  task_id: string;
  state: "submitted";
  receipt: "stored";
  status_url: string;
  events_url: string;
}

interface IdempotencyRecord {
  fingerprint: string;
  response: Promise<GatewayTaskResponse>;
}

interface SseConnection {
  response: ServerResponse;
  close: () => void;
}

/** Stable HTTP error with a public, bounded PolyMesh problem body. */
export class GatewayHttpError extends Error {
  readonly status: number;
  readonly code: string;
  readonly retryable: boolean;
  readonly retryAfterSeconds?: number;

  constructor(
    status: number,
    code: string,
    message: string,
    options: { retryable?: boolean; retryAfterSeconds?: number } = {},
  ) {
    super(message);
    this.name = "GatewayHttpError";
    this.status = status;
    this.code = code;
    this.retryable = options.retryable ?? false;
    this.retryAfterSeconds = options.retryAfterSeconds;
  }
}

/** Adapter sources may use this to produce the required 410 cursor response. */
export class GatewayCursorExpiredError extends GatewayHttpError {
  constructor() {
    super(410, "PMX.GATEWAY.CURSOR_EXPIRED", "The requested event cursor is no longer retained.");
    this.name = "GatewayCursorExpiredError";
  }
}

/**
 * Node HTTP implementation of the v2 gateway. It binds numeric loopback
 * only; deploy a separate authenticated relay for remote access.
 */
export class PolyMeshGateway {
  readonly server: Server;
  readonly options: Readonly<GatewayOptions>;
  private readonly identity: GatewayIdentity;
  private readonly now: () => number;
  private readonly maxRequestBytes: number;
  private readonly maxInputBytes: number;
  private readonly sseKeepaliveMs: number;
  private readonly idempotency = new Map<string, IdempotencyRecord>();
  private readonly sseConnections = new Set<SseConnection>();

  constructor(options: GatewayOptions) {
    if (!options || typeof options.authenticate !== "function" || !options.broker || typeof options.broker.resolveTask !== "function") {
      throw new TypeError("Gateway requires an authenticator and a broker resolveTask adapter");
    }
    if (typeof options.broker.admitTask !== "function" && typeof options.broker.submitTask !== "function") {
      throw new TypeError("Gateway broker must provide admitTask or submitTask");
    }
    this.options = Object.freeze({ ...options });
    this.identity = normalizeGatewayIdentity(options.identity);
    this.now = options.now ?? Date.now;
    this.maxRequestBytes = boundedPositiveInteger(options.maxRequestBytes, GATEWAY_MAX_REQUEST_BYTES, GATEWAY_MAX_REQUEST_BYTES);
    this.maxInputBytes = boundedPositiveInteger(options.maxInputBytes, GATEWAY_MAX_INPUT_BYTES, GATEWAY_MAX_INPUT_BYTES);
    this.sseKeepaliveMs = boundedPositiveInteger(options.sseKeepaliveMs, 15_000, 60_000);
    if (options.supportedProfiles !== undefined &&
      (options.supportedProfiles.length !== 1 || options.supportedProfiles[0] !== GATEWAY_PROFILE)) {
      throw new TypeError(`Gateway supports only ${GATEWAY_PROFILE}`);
    }
    this.server = createServer((request, response) => {
      void this.handle(request, response).catch(() => {
        if (!response.headersSent) this.writeProblem(response, new GatewayHttpError(500, "PMX.GATEWAY.INTERNAL", "Gateway request failed.", { retryable: true }));
        else response.end();
      });
    });
  }

  address() {
    return this.server.address();
  }

  async listen(port = 0, host = "127.0.0.1"): Promise<this> {
    if (this.server.listening) return this;
    if (!isLoopbackHost(host)) {
      throw new GatewayHttpError(400, "PMX.GATEWAY.LOOPBACK_ONLY", "The v2 gateway may bind only a loopback address.");
    }
    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error) => {
        this.server.off("listening", onListening);
        reject(error);
      };
      const onListening = () => {
        this.server.off("error", onError);
        resolve();
      };
      this.server.once("error", onError);
      this.server.once("listening", onListening);
      this.server.listen(port, host);
    });
    return this;
  }

  async close(): Promise<void> {
    for (const connection of [...this.sseConnections]) connection.close();
    if (!this.server.listening) return;
    await new Promise<void>((resolve, reject) => this.server.close((error) => error ? reject(error) : resolve()));
  }

  async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const url = new URL(request.url ?? "/", "http://polymesh.invalid");
    if (request.method === "POST" && url.pathname === "/v2/gateway/tasks") {
      await this.handleSubmit(request, response, false);
      return;
    }
    if (request.method === "POST" && url.pathname === "/v2/tasks") {
      await this.handleSubmit(request, response, true);
      return;
    }
    if (request.method === "GET" && url.pathname === "/v2/gateway/events") {
      await this.handleEvents(request, response, url, false);
      return;
    }
    if (request.method === "GET" && url.pathname === "/v2/events") {
      await this.handleEvents(request, response, url, true);
      return;
    }
    // The task-scoped endpoint is a strict alias of the general event stream.
    const eventAlias = /^\/v2\/gateway\/tasks\/([^/]+)\/events$/.exec(url.pathname);
    if (request.method === "GET" && eventAlias) {
      if (url.searchParams.has("task_id")) {
        this.writeProblem(response, new GatewayHttpError(400, "PMX.GATEWAY.INVALID_REQUEST", "task_id is supplied by the task event route."));
        return;
      }
      url.searchParams.set("task_id", decodeURIComponent(eventAlias[1]!));
      await this.handleEvents(request, response, url, false);
      return;
    }
    this.writeProblem(response, new GatewayHttpError(404, "PMX.GATEWAY.NOT_FOUND", "Gateway route was not found."));
  }

  private async handleSubmit(request: IncomingMessage, response: ServerResponse, nativePath: boolean): Promise<void> {
    try {
      const principal = await this.authenticate(request);
      const idempotencyKey = readIdempotencyKey(request);
      const parsed = await this.readTaskRequest(request, nativePath);
      if (parsed.target.mesh_id !== principal.mesh_id) {
        throw new GatewayHttpError(403, "PMX.AUTHORIZATION_DENIED", "Caller is not authorized for the requested mesh.");
      }
      const deadlineAt = Date.parse(parsed.deadline);
      if (!Number.isFinite(deadlineAt) || deadlineAt <= this.now()) {
        throw new GatewayHttpError(422, "PMX.TASK.DEADLINE_EXCEEDED", "The task deadline has elapsed.");
      }
      const authorization = authorizationContext(principal);
      const fingerprint = gatewayIdempotencyFingerprint(authorization, parsed, idempotencyKey);
      const scope = `${authorization.mesh_id}\0${authorization.principal_id}\0${idempotencyKey}`;
      const previous = this.idempotency.get(scope);
      if (previous) {
        if (previous.fingerprint !== fingerprint) {
          throw new GatewayHttpError(409, "PMX.GATEWAY.IDEMPOTENCY_CONFLICT", "Idempotency-Key was reused for a different request.");
        }
        this.writeJson(response, 202, await previous.response);
        return;
      }

      const admission = this.createAdmission(authorization, parsed, idempotencyKey, fingerprint, nativePath);
      const record: IdempotencyRecord = { fingerprint, response: admission };
      this.idempotency.set(scope, record);
      try {
        this.writeJson(response, 202, await admission);
      } catch (error) {
        // An adapter that throws before it durably admits the task must not
        // leave an in-memory key which would hide a legitimate retry.
        if (this.idempotency.get(scope) === record) this.idempotency.delete(scope);
        throw error;
      }
    } catch (error) {
      this.writeProblem(response, asGatewayError(error));
    }
  }

  private async createAdmission(
    authorization: GatewayAuthorizationContext,
    request: GatewayTaskRequest,
    idempotencyKey: string,
    fingerprint: string,
    nativePath = false,
  ): Promise<GatewayTaskResponse> {
    const contract = await this.options.broker.resolveTask({ authorization, request });
    if (!isCapabilityContract(contract) || (request.capability_version !== undefined && request.capability_version !== contract.capability_version)) {
      throw new GatewayHttpError(403, "PMX.AUTHORIZATION_DENIED", "Capability contract is not available to this caller.");
    }
    const now = this.now();
    const taskId = uuidv7(now);
    const envelope: GatewayTaskEnvelope = {
      protocol: V2_PROTOCOL_VERSION,
      type: "task.submit",
      message_id: uuidv7(now),
      timestamp: new Date(now).toISOString(),
      source: {
        mesh_id: authorization.mesh_id,
        agent_id: this.identity.agent_id,
        instance_id: this.identity.instance_id,
      },
      target: { ...request.target },
      delivery: {
        delivery_id: uuidv7(now),
        mode: "at_least_once",
        idempotency_key: idempotencyKey,
        deadline: request.deadline,
      },
      params: {
        task_id: taskId,
        capability: request.capability,
        capability_version: contract.capability_version,
        capability_contract_digest: contract.capability_contract_digest,
        input: request.input,
        deadline: request.deadline,
      },
    };
    const submission: GatewayTaskSubmission = {
      authorization,
      envelope,
      idempotency_fingerprint: fingerprint,
    };
    const admitted = this.options.broker.admitTask
      ? await this.options.broker.admitTask(submission)
      : await this.options.broker.submitTask!(submission);
    if (admitted.task_id !== undefined && admitted.task_id !== taskId) {
      throw new GatewayHttpError(500, "PMX.GATEWAY.INTERNAL", "Broker returned an inconsistent task identifier.");
    }
    if (admitted.state !== undefined && admitted.state !== "submitted") {
      throw new GatewayHttpError(500, "PMX.GATEWAY.INTERNAL", "Broker did not return a submitted task state.");
    }
    if (admitted.receipt !== undefined && admitted.receipt !== "stored") {
      throw new GatewayHttpError(503, "PMX.GATEWAY.ADMISSION_UNAVAILABLE", "Broker admission was not durably stored.", { retryable: true, retryAfterSeconds: 1 });
    }
    return taskResponse(taskId, nativePath);
  }

  private async handleEvents(request: IncomingMessage, response: ServerResponse, url: URL, nativePath: boolean): Promise<void> {
    try {
      const principal = await this.authenticate(request);
      const query = parseEventQuery(request, url, authorizationContext(principal), nativePath);
      const page = this.options.broker.readEvents
        ? await this.options.broker.readEvents(query)
        : { events: [] };
      if (page.cursor_expired) throw new GatewayCursorExpiredError();
      if (!page || !Array.isArray(page.events)) {
        throw new GatewayHttpError(500, "PMX.GATEWAY.INTERNAL", "Broker returned an invalid event page.");
      }
      for (const event of page.events) assertGatewayEvent(event);

      response.writeHead(200, {
        "content-type": "text/event-stream; charset=utf-8",
        "cache-control": "no-store",
        "x-polymesh-profile": GATEWAY_PROFILE,
        "x-polymesh-gateway-scope": GATEWAY_SCOPE,
        connection: "keep-alive",
        "x-accel-buffering": "no",
      });
      response.flushHeaders?.();
      for (const event of page.events) writeSseEvent(response, event);

      const unsubscribe = this.options.broker.subscribeEvents?.(
        { authorization: query.authorization, ...(query.task_id === undefined ? {} : { task_id: query.task_id }) },
        (event) => {
          try {
            assertGatewayEvent(event);
            if (query.task_id === undefined || event.task_id === query.task_id) writeSseEvent(response, event);
          } catch {
            // A malformed adapter event is never reflected to the caller.
            // Close so the client can resume from its last durable cursor.
            response.end();
          }
        },
      );
      const keepalive = setInterval(() => {
        if (!response.writableEnded) response.write(": keepalive\n\n");
      }, this.sseKeepaliveMs);
      keepalive.unref?.();
      const connection: SseConnection = {
        response,
        close: () => {
          clearInterval(keepalive);
          try { unsubscribe?.(); } catch { /* adapter cleanup is best effort */ }
          if (!response.writableEnded) response.end();
          this.sseConnections.delete(connection);
        },
      };
      this.sseConnections.add(connection);
      request.once("close", connection.close);
      response.once("close", connection.close);
    } catch (error) {
      this.writeProblem(response, asGatewayError(error));
    }
  }

  private async authenticate(request: IncomingMessage): Promise<GatewayPrincipal> {
    const header = request.headers.authorization;
    if (typeof header !== "string") throw authenticationError();
    const match = /^Bearer ([^\s]+)$/.exec(header);
    if (!match) throw authenticationError();
    let principal: GatewayPrincipal | undefined;
    try {
      // The raw bearer token is intentionally scoped to this call only.
      principal = await this.options.authenticate(match[1]!, request);
    } catch {
      throw authenticationError();
    }
    if (!isGatewayPrincipal(principal)) throw authenticationError();
    return principal;
  }

  private async readTaskRequest(request: IncomingMessage, requireProfile = false): Promise<GatewayTaskRequest> {
    const contentLength = request.headers["content-length"];
    if (typeof contentLength === "string") {
      const declared = Number(contentLength);
      if (!Number.isSafeInteger(declared) || declared < 0 || declared > this.maxRequestBytes) {
        throw new GatewayHttpError(413, "PMX.GATEWAY.REQUEST_TOO_LARGE", "Gateway request body exceeds its limit.");
      }
    }
    const body = await readBody(request, this.maxRequestBytes);
    const parsed = parseStrictJson(body, { maxBytes: this.maxRequestBytes });
    if (!parsed.ok || !isObject(parsed.value)) {
      throw new GatewayHttpError(400, "PMX.GATEWAY.INVALID_REQUEST", "Request body must be valid JSON.");
    }
    return decodeGatewayTaskRequest(parsed.value, this.maxInputBytes, requireProfile);
  }

  private writeJson(response: ServerResponse, status: number, body: unknown): void {
    if (response.writableEnded) return;
    const encoded = JSON.stringify(body);
    response.writeHead(status, {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-polymesh-profile": GATEWAY_PROFILE,
      "x-polymesh-gateway-scope": GATEWAY_SCOPE,
      "content-length": Buffer.byteLength(encoded),
    });
    response.end(encoded);
  }

  private writeProblem(response: ServerResponse, error: GatewayHttpError): void {
    if (response.writableEnded || response.headersSent) return;
    const body = {
      code: error.code,
      message: boundedMessage(error.message),
      retryable: error.retryable,
    };
    const encoded = JSON.stringify(body);
    response.writeHead(error.status, {
      "content-type": "application/problem+json; charset=utf-8",
      "cache-control": "no-store",
      "x-polymesh-profile": GATEWAY_PROFILE,
      "x-polymesh-gateway-scope": GATEWAY_SCOPE,
      "content-length": Buffer.byteLength(encoded),
      ...(error.retryAfterSeconds === undefined ? {} : { "retry-after": String(error.retryAfterSeconds) }),
    });
    response.end(encoded);
  }
}

/** Preferred factory for application integrations. */
export function createGatewayServer(options: GatewayOptions): PolyMeshGateway {
  return new PolyMeshGateway(options);
}

/** A concise alias for code which calls the gateway a server. */
export { PolyMeshGateway as GatewayServer };
export { PolyMeshGateway as Gateway };

/** Compute the stable non-secret admission fingerprint required by §7.1. */
export function gatewayIdempotencyFingerprint(
  authorization: GatewayAuthorizationContext,
  request: GatewayTaskRequest,
  idempotencyKey: string,
): string {
  const canonical = canonicalize({
    principal_id: authorization.principal_id,
    mesh_id: authorization.mesh_id,
    delegation_id: authorization.delegation_id ?? null,
    idempotency_key: idempotencyKey,
    request: {
      target: request.target,
      capability: request.capability,
      ...(request.capability_version === undefined ? {} : { capability_version: request.capability_version }),
      input: request.input,
      deadline: request.deadline,
    },
  } as unknown as JsonObject);
  return createHash("sha256")
    .update("PMX-GATEWAY-IDEMPOTENCY/0.2\0", "utf8")
    .update(canonical, "utf8")
    .digest("base64url");
}

/** A small reference adapter useful for local tests and examples. */
export class InMemoryGatewayBroker implements GatewayBroker {
  readonly submissions: GatewayTaskSubmission[] = [];
  private readonly contracts = new Map<string, GatewayCapabilityContract>();
  private readonly events: Array<GatewayEvent & { owner_principal_id: string }> = [];
  private readonly listeners = new Set<{ query: Omit<GatewayEventQuery, "after">; listener: (event: GatewayEvent) => void }>();
  private readonly admitted = new Map<string, GatewayTaskAdmission>();

  setContract(targetAgentId: string, capability: string, contract: GatewayCapabilityContract): void {
    if (!isCapabilityContract(contract)) throw new TypeError("Invalid capability contract");
    this.contracts.set(`${targetAgentId}\0${capability}`, { ...contract });
  }

  resolveTask(input: GatewayTaskResolution): GatewayCapabilityContract {
    const contract = this.contracts.get(`${input.request.target.agent_id}\0${input.request.capability}`);
    if (!contract) {
      throw new GatewayHttpError(403, "PMX.AUTHORIZATION_DENIED", "Capability is not available to this caller.");
    }
    return { ...contract };
  }

  admitTask(input: GatewayTaskSubmission): GatewayTaskAdmission {
    const existing = this.admitted.get(input.idempotency_fingerprint);
    if (existing) return existing;
    const result: GatewayTaskAdmission = {
      task_id: input.envelope.params.task_id,
      state: "submitted",
      receipt: "stored",
    };
    this.admitted.set(input.idempotency_fingerprint, result);
    this.submissions.push(input);
    return result;
  }

  readEvents(query: GatewayEventQuery): GatewayEventPage {
    let visible = this.events.filter((event) => event.owner_principal_id === query.authorization.principal_id);
    if (query.task_id !== undefined) visible = visible.filter((event) => event.task_id === query.task_id);
    if (query.after !== undefined) {
      const index = visible.findIndex((event) => event.event_id === query.after);
      if (index < 0) return { events: [], cursor_expired: true };
      // SSE is at-least-once: replaying the cursor event itself is permitted.
      visible = visible.slice(index);
    }
    return { events: visible.map(publicEvent) };
  }

  subscribeEvents(query: Omit<GatewayEventQuery, "after">, listener: (event: GatewayEvent) => void): () => void {
    const registration = { query, listener };
    this.listeners.add(registration);
    return () => this.listeners.delete(registration);
  }

  /** Append one already-authorized durable lifecycle event for test/local use. */
  appendEvent(ownerPrincipalId: string, event: GatewayEvent): void {
    assertGatewayEvent(event);
    const stored = { ...event, owner_principal_id: ownerPrincipalId };
    this.events.push(stored);
    for (const { query, listener } of this.listeners) {
      if (query.authorization.principal_id !== ownerPrincipalId) continue;
      if (query.task_id !== undefined && query.task_id !== event.task_id) continue;
      listener(publicEvent(stored));
    }
  }
}

function decodeGatewayTaskRequest(
  value: Record<string, JsonValue>,
  maxInputBytes: number,
  requireProfile = false,
): GatewayTaskRequest {
  if (!hasOnlyKeys(value, ["profile", "target", "capability", "capability_version", "input", "deadline"]) ||
    !hasKeys(value, ["target", "capability", "input", "deadline"]) ||
    (requireProfile && !Object.hasOwn(value, "profile"))) {
    throw invalidRequest("Request body does not match the gateway task schema.");
  }
  if (value.profile !== undefined && value.profile !== GATEWAY_PROFILE) {
    throw new GatewayHttpError(409, "PMX.SESSION.PROFILE", `Gateway does not support profile ${String(value.profile)}.`);
  }
  if (!isObject(value.target) || !hasOnlyKeys(value.target, ["mesh_id", "agent_id", "instance_id"]) || !hasKeys(value.target, ["mesh_id", "agent_id"])) {
    throw invalidRequest("target does not match the gateway task schema.");
  }
  const target = value.target;
  if (typeof target.mesh_id !== "string" || !isGatewayMeshId(target.mesh_id) ||
    typeof target.agent_id !== "string" || !AGENT_OR_CAPABILITY_RE.test(target.agent_id) ||
    (target.instance_id !== undefined && (typeof target.instance_id !== "string" || !INSTANCE_ID_RE.test(target.instance_id)))) {
    throw invalidRequest("target does not contain a valid mesh and agent identity.");
  }
  if (typeof value.capability !== "string" || !AGENT_OR_CAPABILITY_RE.test(value.capability) || value.capability.length > 255) {
    throw invalidRequest("capability is invalid.");
  }
  if (value.capability_version !== undefined && (typeof value.capability_version !== "string" || !SEMVER_RE.test(value.capability_version) || value.capability_version.length > 32)) {
    throw invalidRequest("capability_version is invalid.");
  }
  if (!isJsonValue(value.input) || hasUnsafeInteger(value.input)) {
    throw invalidRequest("input contains an unsafe JSON integer.");
  }
  let inputBytes: number;
  try {
    inputBytes = Buffer.byteLength(canonicalize(value.input), "utf8");
  } catch {
    throw invalidRequest("input is not a supported JSON value.");
  }
  if (inputBytes > maxInputBytes) {
    throw new GatewayHttpError(413, "PMX.GATEWAY.INPUT_TOO_LARGE", "Task input exceeds the gateway byte limit.");
  }
  if (typeof value.deadline !== "string" || value.deadline.length > 40) throw invalidRequest("deadline is invalid.");
  const parsedDeadline = Date.parse(value.deadline);
  if (!Number.isFinite(parsedDeadline)) throw invalidRequest("deadline is invalid.");
  const deadline = new Date(parsedDeadline).toISOString();
  return {
    ...(value.profile === undefined ? {} : { profile: GATEWAY_PROFILE }),
    target: {
      mesh_id: target.mesh_id,
      agent_id: target.agent_id,
      ...(target.instance_id === undefined ? {} : { instance_id: target.instance_id }),
    },
    capability: value.capability,
    ...(value.capability_version === undefined ? {} : { capability_version: value.capability_version }),
    input: value.input,
    deadline,
  };
}

function parseEventQuery(
  request: IncomingMessage,
  url: URL,
  authorization: GatewayAuthorizationContext,
  nativePath = false,
): GatewayEventQuery {
  const permitted = new Set(["task_id", "after", "cursor", "profile"]);
  for (const key of url.searchParams.keys()) {
    if (!permitted.has(key) || url.searchParams.getAll(key).length !== 1) {
      throw new GatewayHttpError(400, "PMX.GATEWAY.INVALID_REQUEST", "Event query contains an unsupported parameter.");
    }
  }
  const taskId = url.searchParams.get("task_id") ?? undefined;
  if (taskId !== undefined && !UUID_V7_RE.test(taskId)) {
    throw new GatewayHttpError(400, "PMX.GATEWAY.INVALID_REQUEST", "task_id must be a UUIDv7.");
  }
  const headerCursor = request.headers["last-event-id"];
  const after = typeof headerCursor === "string" && headerCursor.length > 0
    ? headerCursor
    : url.searchParams.get("cursor") ?? url.searchParams.get("after") ?? undefined;
  const profile = url.searchParams.get("profile") ?? undefined;
  if (profile !== undefined && profile !== GATEWAY_PROFILE) {
    throw new GatewayHttpError(409, "PMX.SESSION.PROFILE", `Gateway does not support profile ${profile}.`);
  }
  if (nativePath && profile === undefined) {
    // The local gateway still uses the one native profile by default.  This
    // keeps EventSource usable while exposing an explicit profile parameter
    // for clients that negotiate/select it themselves.
    // No error is emitted for omission because it is not a protocol downgrade.
  }
  if (after !== undefined && !EVENT_ID_RE.test(after)) {
    throw new GatewayCursorExpiredError();
  }
  return {
    authorization,
    ...(profile === undefined ? {} : { profile: GATEWAY_PROFILE }),
    ...(taskId === undefined ? {} : { task_id: taskId }),
    ...(after === undefined ? {} : { after }),
  };
}

function readIdempotencyKey(request: IncomingMessage): string {
  const header = request.headers["idempotency-key"];
  if (typeof header !== "string" || header.length === 0 || Buffer.byteLength(header, "utf8") > GATEWAY_MAX_IDEMPOTENCY_KEY_BYTES || !IDEMPOTENCY_KEY_RE.test(header)) {
    throw new GatewayHttpError(400, "PMX.GATEWAY.INVALID_REQUEST", "A valid Idempotency-Key is required.");
  }
  return header;
}

function authorizationContext(principal: GatewayPrincipal): GatewayAuthorizationContext {
  return {
    principal_id: principal.principal_id,
    mesh_id: principal.mesh_id,
    ...(principal.delegation_id === undefined ? {} : { delegation_id: principal.delegation_id }),
  };
}

function taskResponse(taskId: string, nativePath = false): GatewayTaskResponse {
  return {
    ...(nativePath ? { profile: GATEWAY_PROFILE } : {}),
    task_id: taskId,
    state: "submitted",
    receipt: "stored",
    status_url: nativePath ? `/v2/tasks/${taskId}` : `/v2/gateway/tasks/${taskId}`,
    events_url: nativePath
      ? `/v2/events?task_id=${taskId}&profile=${encodeURIComponent(GATEWAY_PROFILE)}`
      : `/v2/gateway/events?task_id=${taskId}`,
  };
}

function writeSseEvent(response: ServerResponse, event: GatewayEvent): void {
  if (response.writableEnded) return;
  response.write(`id: ${event.event_id}\nevent: ${event.type}\ndata: ${JSON.stringify(publicEvent(event))}\n\n`);
}

function publicEvent(event: GatewayEvent): GatewayEvent {
  return {
    event_id: event.event_id,
    task_id: event.task_id,
    event_seq: event.event_seq,
    type: event.type,
    occurred_at: event.occurred_at,
    data: event.data,
  };
}

function assertGatewayEvent(value: unknown): asserts value is GatewayEvent {
  if (!isObject(value) || typeof value.event_id !== "string" || !EVENT_ID_RE.test(value.event_id) ||
    typeof value.task_id !== "string" || !UUID_V7_RE.test(value.task_id) ||
    typeof value.event_seq !== "number" || !Number.isSafeInteger(value.event_seq) || value.event_seq < 1 ||
    typeof value.type !== "string" || !EVENT_TYPES.has(value.type as GatewayEventType) ||
    typeof value.occurred_at !== "string" || value.occurred_at.length > 40 || !Number.isFinite(Date.parse(value.occurred_at)) ||
    !isJsonValue(value.data) || hasUnsafeInteger(value.data)) {
    throw new TypeError("Gateway event does not match the closed event schema");
  }
}

function normalizeGatewayIdentity(identity?: GatewayIdentity): GatewayIdentity {
  const result = identity ?? {
    agent_id: "org.polymesh.gateway",
    instance_id: randomBytes(16).toString("base64url"),
  };
  if (typeof result.agent_id !== "string" || !AGENT_OR_CAPABILITY_RE.test(result.agent_id) ||
    typeof result.instance_id !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(result.instance_id)) {
    throw new TypeError("Gateway identity must contain a valid agent_id and 16-byte instance_id");
  }
  return { ...result };
}

function isGatewayPrincipal(value: unknown): value is GatewayPrincipal {
  return isObject(value) && typeof value.principal_id === "string" && value.principal_id.length > 0 && value.principal_id.length <= 192 &&
    typeof value.mesh_id === "string" && isGatewayMeshId(value.mesh_id) &&
    (value.delegation_id === undefined || (typeof value.delegation_id === "string" && value.delegation_id.length > 0 && value.delegation_id.length <= 192));
}

function isGatewayMeshId(value: string): boolean {
  return MESH_ID_RE.test(value) || UUID_V7_RE.test(value);
}

function isLoopbackHost(host: string): boolean {
  const normalized = host.replace(/^\[|\]$/g, "").toLowerCase();
  return normalized === "::1" || normalized === "localhost" || /^127(?:\.\d{1,3}){3}$/.test(normalized);
}

function isCapabilityContract(value: unknown): value is GatewayCapabilityContract {
  return isObject(value) && typeof value.capability_version === "string" && SEMVER_RE.test(value.capability_version) &&
    typeof value.capability_contract_digest === "string" && /^[A-Za-z0-9_-]{43}$/.test(value.capability_contract_digest);
}

function isObject(value: unknown): value is Record<string, JsonValue> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).every((key) => keys.includes(key));
}

function hasKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return keys.every((key) => Object.hasOwn(value, key));
}

function hasUnsafeInteger(value: JsonValue): boolean {
  if (typeof value === "number") return Number.isInteger(value) && !Number.isSafeInteger(value);
  if (Array.isArray(value)) return value.some((entry) => hasUnsafeInteger(entry));
  if (value !== null && typeof value === "object") return Object.values(value).some((entry) => hasUnsafeInteger(entry));
  return false;
}

async function readBody(request: IncomingMessage, maximum: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const part of request) {
    const chunk = Buffer.isBuffer(part) ? part : Buffer.from(part);
    size += chunk.byteLength;
    if (size > maximum) {
      request.resume();
      throw new GatewayHttpError(413, "PMX.GATEWAY.REQUEST_TOO_LARGE", "Gateway request body exceeds its limit.");
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, size);
}

function boundedPositiveInteger(value: number | undefined, fallback: number, maximum: number): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) throw new RangeError("Gateway limit is invalid");
  return value;
}

function invalidRequest(message: string): GatewayHttpError {
  return new GatewayHttpError(422, "PMX.GATEWAY.INVALID_REQUEST", message);
}

function authenticationError(): GatewayHttpError {
  return new GatewayHttpError(401, "AUTHENTICATION_FAILED", "Authentication failed.");
}

function asGatewayError(error: unknown): GatewayHttpError {
  if (error instanceof GatewayHttpError) return error;
  return new GatewayHttpError(500, "PMX.GATEWAY.INTERNAL", "Gateway request failed.", { retryable: true });
}

function boundedMessage(value: string): string {
  return value.length <= 1024 ? value : value.slice(0, 1024);
}

export default PolyMeshGateway;

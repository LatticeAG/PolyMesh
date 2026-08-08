/**
 * Gateway transport for PolyMesh v5 — connects agents to a PolyMesh Gateway
 * relay over the internet (API-key auth → JWT → WSS envelope routing).
 *
 * Implements PM-V5-SPEC.md §2 (and §5–§8 as they apply to the transport).
 * Additive to the existing broker loopback / WSS modes.
 */
import { EventEmitter } from "node:events";
import WebSocket from "ws";

import {
  PROTOCOL_VERSION,
  createEnvelope,
  isEnvelope,
  parseStrictJson,
  uuidv7,
  type Envelope,
  type JsonObject,
  type JsonValue,
  type MessageType,
} from "@latticeag/polymesh-broker";

/** Named transport mode accepted by PolyMeshClient. */
export type GatewayTransportMode = "gateway";

export interface GatewayCapability {
  name: string;
  schema?: JsonObject;
  scope?: string;
  security?: string;
  /** v6 dialect tag; default `"native"` when omitted (§B.12). */
  dialect?: "native" | "a2a";
  /** Required when `dialect` is `"a2a"` (§B.11.2). */
  a2a_url?: string;
  [key: string]: JsonValue | undefined;
}

export interface GatewayAgentInfo {
  id: string;
  display_name: string;
  capabilities: GatewayCapability[] | JsonValue[];
  last_seen?: string | null;
  metadata?: JsonObject;
  /** v6 health enum (§B.5.1); discovery MAY omit (router treats absent as healthy when merging). */
  health?: "healthy" | "degraded" | "unhealthy" | "offline" | "unknown";
  /** v6 locality tier (§B.11.4); gateway-only peers default to `relay` at merge time. */
  locality?: "same_host" | "lan" | "relay" | "unknown";
  /** False for A2A-only leaf registrations (§B.11.1). */
  mesh_member?: boolean;
  /** Present when known from mesh handshake; used in exclusion keys (§B.7.2.5.1). */
  instance_id?: string;
  /** Caller-side permission hint (§B.6.1 / §C.8). */
  perm_hint?: "allow" | "deny" | "absent";
}

export interface GatewayTokenResponse {
  token: string;
  expires_at: string;
}

export interface GatewayJoinMeshOptions {
  /** Preferred camelCase form. */
  inviteCode?: string;
  /** Snake_case alias accepted for Python/JSON parity. */
  invite_code?: string;
  capabilities?: GatewayCapability[];
  displayName?: string;
  display_name?: string;
}

/**
 * Discovery filter. All fields are AND-combined.
 * Capability matching rules are defined in PM-V5-SPEC §7.2.
 */
export interface GatewayDiscoverQuery {
  /** Exact capability name or glob (`calendar.*`, `*.check`). */
  capability?: string;
  /** Glob over agent display_name (e.g. `alice*`). */
  name?: string;
  /** Exact agent id. */
  agentId?: string;
  agent_id?: string;
  /**
   * Metadata equality filters.
   * Keys are metadata field names; values are exact match strings / numbers / booleans.
   */
  metadata?: Record<string, string | number | boolean>;
  /** 1-based page index. Default 1. */
  page?: number;
  /** Page size 1..100. Default 50. */
  limit?: number;
}

export interface GatewayDiscoverResult {
  agents: GatewayAgentInfo[];
  page: number;
  limit: number;
  total: number;
  has_more: boolean;
}

export interface GatewayMeshJoined {
  mesh_id: string;
  members: GatewayAgentInfo[];
  agent_id?: string;
}

export interface GatewayWsSocket {
  readyState?: number;
  on?(event: string, listener: (...args: any[]) => void): unknown;
  once?(event: string, listener: (...args: any[]) => void): unknown;
  off?(event: string, listener: (...args: any[]) => void): unknown;
  removeListener?(event: string, listener: (...args: any[]) => void): unknown;
  send(data: string, callback?: (error?: Error) => void): unknown;
  close?(code?: number, reason?: string): unknown;
  terminate?(): unknown;
}

export type GatewayFetch = (
  input: string,
  init?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    signal?: AbortSignal;
  },
) => Promise<{
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
  text(): Promise<string>;
}>;

export interface GatewayReconnectOptions {
  /** Master switch. Default true. */
  enabled?: boolean;
  /** Initial delay before first retry. Default 500ms. */
  initialDelayMs?: number;
  /** Cap on exponential backoff. Default 30_000ms. */
  maxDelayMs?: number;
  /** Multiplier per attempt. Default 2. */
  multiplier?: number;
  /** Full-jitter fraction in [0,1]. Default 0.2. */
  jitter?: number;
  /** Maximum reconnect attempts before giving up. Default 10. 0 = unlimited until leaveMesh/close. */
  maxAttempts?: number;
}

export interface GatewayTransportOptions {
  apiKey?: string;
  gatewayUrl?: string;
  agentId?: string;
  meshId?: string;
  /** Optional EventEmitter that mirrors gateway events (client bridge). */
  eventTarget?: EventEmitter;
  fetch?: GatewayFetch;
  createWebSocket?: (url: string) => GatewayWsSocket;
  /** Timeout for REST calls and pending WS request/response pairs. Default 15_000. */
  requestTimeoutMs?: number;
  /** Refresh JWT this many ms before expires_at. Default 300_000 (5 min). */
  tokenRefreshSkewMs?: number;
  reconnect?: GatewayReconnectOptions;
}

export type GatewayWireMessage = {
  type: string;
  [key: string]: JsonValue | undefined;
};

const OPEN = 1;

const DEFAULT_RECONNECT: Required<GatewayReconnectOptions> = {
  enabled: true,
  initialDelayMs: 500,
  maxDelayMs: 30_000,
  multiplier: 2,
  jitter: 0.2,
  maxAttempts: 10,
};

const INVITE_CODE_RE = /^[A-Z0-9][A-Z0-9-]{2,63}$/;

const KNOWN_WS_TYPES = new Set([
  "mesh.joined",
  "mesh.leave",
  "discovery.response",
  "card.registered",
  "card.announce",
  "token.expiring",
  "task.submit",
  "task.accepted",
  "task.progress",
  "task.completed",
  "task.failed",
  "task.fail",
  "task.accept",
  "task.complete",
  "error",
]);

export class GatewayTransportError extends Error {
  readonly code: string;
  readonly retryable: boolean;
  readonly status?: number;
  override readonly cause?: unknown;

  constructor(
    code: string,
    message = code,
    retryable = false,
    options?: { status?: number; cause?: unknown },
  ) {
    super(message);
    this.name = "GatewayTransportError";
    this.code = code;
    this.retryable = retryable;
    if (options?.status !== undefined) this.status = options.status;
    if (options?.cause !== undefined) {
      Object.defineProperty(this, "cause", { value: options.cause, enumerable: false, writable: true, configurable: true });
    }
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function mergeReconnectOptions(input?: GatewayReconnectOptions): Required<GatewayReconnectOptions> {
  return {
    enabled: input?.enabled ?? DEFAULT_RECONNECT.enabled,
    initialDelayMs: input?.initialDelayMs ?? DEFAULT_RECONNECT.initialDelayMs,
    maxDelayMs: input?.maxDelayMs ?? DEFAULT_RECONNECT.maxDelayMs,
    multiplier: input?.multiplier ?? DEFAULT_RECONNECT.multiplier,
    jitter: input?.jitter ?? DEFAULT_RECONNECT.jitter,
    maxAttempts: input?.maxAttempts ?? DEFAULT_RECONNECT.maxAttempts,
  };
}

/** Convert a gateway WSS/HTTPS URL into the REST HTTPS origin. */
export function gatewayHttpBase(gatewayUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(gatewayUrl);
  } catch (cause) {
    throw new GatewayTransportError("INVALID_GATEWAY_URL", "gatewayUrl must be a valid URL", false, { cause });
  }
  if (parsed.protocol === "wss:") parsed.protocol = "https:";
  else if (parsed.protocol === "ws:") parsed.protocol = "http:";
  else if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new GatewayTransportError("INVALID_GATEWAY_URL", "gatewayUrl must use ws(s) or http(s)");
  }
  // Strip WS path if the caller passed a full /api/v1/ws URL.
  if (parsed.pathname === "/api/v1/ws" || parsed.pathname.endsWith("/api/v1/ws")) {
    parsed.pathname = parsed.pathname.replace(/\/?api\/v1\/ws$/, "") || "/";
  }
  parsed.search = "";
  parsed.hash = "";
  return parsed.origin + (parsed.pathname === "/" ? "" : parsed.pathname.replace(/\/$/, ""));
}

/** Build the authenticated WebSocket endpoint. */
export function gatewayWsUrl(gatewayUrl: string, token: string, meshId?: string): string {
  let parsed: URL;
  try {
    parsed = new URL(gatewayUrl);
  } catch (cause) {
    throw new GatewayTransportError("INVALID_GATEWAY_URL", "gatewayUrl must be a valid URL", false, { cause });
  }
  if (parsed.protocol === "https:") parsed.protocol = "wss:";
  else if (parsed.protocol === "http:") parsed.protocol = "ws:";
  else if (parsed.protocol !== "wss:" && parsed.protocol !== "ws:") {
    throw new GatewayTransportError("INVALID_GATEWAY_URL", "gatewayUrl must use ws(s) or http(s)");
  }
  if (!parsed.pathname || parsed.pathname === "/") {
    parsed.pathname = "/api/v1/ws";
  } else if (!parsed.pathname.endsWith("/api/v1/ws")) {
    parsed.pathname = `${parsed.pathname.replace(/\/$/, "")}/api/v1/ws`;
  }
  parsed.search = "";
  parsed.hash = "";
  parsed.searchParams.set("token", token);
  if (meshId) parsed.searchParams.set("mesh", meshId);
  return parsed.toString();
}

function textFromMessage(data: unknown): string {
  if (typeof data === "string") return data;
  if (Buffer.isBuffer(data)) return data.toString("utf8");
  if (data instanceof ArrayBuffer) return Buffer.from(data).toString("utf8");
  if (Array.isArray(data)) {
    return Buffer.concat(data.map((part) => Buffer.isBuffer(part) ? part : Buffer.from(part))).toString("utf8");
  }
  if (isRecord(data) && typeof (data as { data?: unknown }).data === "string") {
    return (data as { data: string }).data;
  }
  if (isRecord(data) && Buffer.isBuffer((data as { data?: unknown }).data)) {
    return ((data as { data: Buffer }).data).toString("utf8");
  }
  throw new GatewayTransportError("MALFORMED_FRAME", "Gateway WebSocket frame is not text");
}

function normalizeInviteCode(raw: string): string {
  return raw.trim().toUpperCase();
}

function assertValidInviteCode(raw: string): string {
  const invite = normalizeInviteCode(raw);
  if (!INVITE_CODE_RE.test(invite)) {
    throw new GatewayTransportError("INVITE_INVALID", `Invite code format is invalid: ${raw}`);
  }
  return invite;
}

function computeBackoffDelay(
  attempt: number,
  opts: Required<GatewayReconnectOptions>,
): number {
  const base = Math.min(
    opts.initialDelayMs * (opts.multiplier ** Math.max(0, attempt - 1)),
    opts.maxDelayMs,
  );
  const jitter = Math.min(1, Math.max(0, opts.jitter));
  return base * (1 - jitter + 2 * jitter * Math.random());
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizeDiscoverResult(
  raw: unknown,
  query: GatewayDiscoverQuery = {},
): GatewayDiscoverResult {
  if (!isRecord(raw) || !Array.isArray(raw.agents)) {
    throw new GatewayTransportError("DISCOVERY_FAILED", "Discovery response is missing agents[]");
  }
  const agents = raw.agents as GatewayAgentInfo[];
  const hasPagination =
    typeof raw.page === "number" ||
    typeof raw.limit === "number" ||
    typeof raw.total === "number" ||
    typeof raw.has_more === "boolean";

  if (!hasPagination) {
    return {
      agents,
      page: 1,
      limit: agents.length,
      total: agents.length,
      has_more: false,
    };
  }

  const page = typeof raw.page === "number" && Number.isFinite(raw.page) && raw.page >= 1
    ? Math.floor(raw.page)
    : (query.page ?? 1);
  const limit = typeof raw.limit === "number" && Number.isFinite(raw.limit) && raw.limit >= 1
    ? Math.floor(raw.limit)
    : (query.limit ?? Math.max(agents.length, 1));
  const total = typeof raw.total === "number" && Number.isFinite(raw.total) && raw.total >= 0
    ? Math.floor(raw.total)
    : agents.length;
  const has_more = typeof raw.has_more === "boolean"
    ? raw.has_more
    : page * limit < total;

  return { agents, page, limit, total, has_more };
}

/**
 * Standalone gateway relay transport. Emits message-type events
 * (`task.completed`, `mesh.joined`, `error`, …) plus `message` / `close`.
 */
export class GatewayTransport extends EventEmitter {
  private apiKey?: string;
  private gatewayUrl?: string;
  private agentId?: string;
  private token?: string;
  private tokenExpiresAtIso?: string;
  private meshId?: string;
  private socket?: GatewayWsSocket;
  private readonly eventTarget?: EventEmitter;
  private readonly fetchImpl: GatewayFetch;
  private readonly createWebSocket: (url: string) => GatewayWsSocket;
  private readonly requestTimeoutMs: number;
  private readonly tokenRefreshSkewMs: number;
  private readonly reconnectOpts: Required<GatewayReconnectOptions>;
  private pendingJoin?: {
    meshId: string;
    resolve: (value: GatewayMeshJoined) => void;
    reject: (error: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  };
  private pendingDiscovery?: {
    resolve: (result: GatewayDiscoverResult) => void;
    reject: (error: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  };
  private bound = false;
  private closed = false;
  private refreshTimer?: ReturnType<typeof setTimeout>;
  private reconnectTimer?: ReturnType<typeof setTimeout>;
  private reconnectAttempt = 0;
  private reconnectInFlight = false;
  private socketGeneration = 0;
  private cachedCapabilities?: GatewayCapability[];
  private cachedDisplayName?: string;
  private socketCleanup?: () => void;

  constructor(options: GatewayTransportOptions = {}) {
    super();
    this.apiKey = options.apiKey;
    this.gatewayUrl = options.gatewayUrl;
    this.agentId = options.agentId;
    this.meshId = options.meshId;
    this.eventTarget = options.eventTarget;
    this.fetchImpl = options.fetch ?? ((input, init) => fetch(input, init as RequestInit));
    this.createWebSocket = options.createWebSocket ?? ((url) => new WebSocket(url) as unknown as GatewayWsSocket);
    this.requestTimeoutMs = options.requestTimeoutMs ?? 15_000;
    if (!Number.isFinite(this.requestTimeoutMs) || this.requestTimeoutMs <= 0) {
      throw new RangeError("requestTimeoutMs must be a positive finite number");
    }
    this.tokenRefreshSkewMs = options.tokenRefreshSkewMs ?? 300_000;
    if (!Number.isFinite(this.tokenRefreshSkewMs) || this.tokenRefreshSkewMs < 0) {
      throw new RangeError("tokenRefreshSkewMs must be a non-negative finite number");
    }
    this.reconnectOpts = mergeReconnectOptions(options.reconnect);
  }

  get connected(): boolean {
    return this.socket?.readyState === OPEN || (this.socket !== undefined && this.bound && !this.closed);
  }

  get currentMeshId(): string | undefined {
    return this.meshId;
  }

  get currentToken(): string | undefined {
    return this.token;
  }

  get currentAgentId(): string | undefined {
    return this.agentId;
  }

  get currentGatewayUrl(): string | undefined {
    return this.gatewayUrl;
  }

  get tokenExpiresAt(): string | undefined {
    return this.tokenExpiresAtIso;
  }

  /** Exchange an API key for a JWT and open the gateway WebSocket. */
  async connectGateway(apiKey?: string, gatewayUrl?: string): Promise<this> {
    const key = apiKey ?? this.apiKey;
    const url = gatewayUrl ?? this.gatewayUrl;
    if (!key) throw new GatewayTransportError("API_KEY_REQUIRED", "An API key is required to connect to the gateway");
    if (!url) throw new GatewayTransportError("GATEWAY_URL_REQUIRED", "A gatewayUrl is required");

    this.apiKey = key;
    this.gatewayUrl = url;
    this.closed = false;
    this.stopReconnectLoop();
    this.reconnectAttempt = 0;

    let lastError: unknown;
    const maxAttempts = this.reconnectOpts.maxAttempts;
    let attempt = 0;

    for (;;) {
      attempt += 1;
      try {
        const auth = await this.exchangeToken(key, url);
        this.token = auth.token;
        this.tokenExpiresAtIso = auth.expires_at;
        const sub = decodeJwtSub(auth.token);
        if (sub) this.agentId = sub;
        this.scheduleTokenRefresh();

        await this.openSocket(gatewayWsUrl(url, auth.token, this.meshId));
        this.maybeAnnounceCard();
        this.reconnectAttempt = 0;
        this.emitBridge("connected", {
          token: this.token,
          expires_at: this.tokenExpiresAtIso,
          agent_id: this.agentId,
        });
        return this;
      } catch (error) {
        lastError = error;
        const retryable = isRetryableConnectError(error);
        const unlimited = maxAttempts === 0;
        const exhausted = !unlimited && attempt >= maxAttempts;
        if (!retryable || exhausted || this.closed) {
          if (retryable && exhausted) {
            const exhaustedErr = new GatewayTransportError(
              "RECONNECT_EXHAUSTED",
              `connectGateway failed after ${attempt} attempts`,
              false,
              { cause: error },
            );
            this.emitBridge("error", exhaustedErr);
            throw exhaustedErr;
          }
          throw error instanceof Error ? error : new GatewayTransportError("AUTH_FAILED", String(error));
        }
        const delayMs = computeBackoffDelay(attempt, this.reconnectOpts);
        this.emitBridge("reconnecting", { attempt, delayMs });
        await sleep(delayMs);
        if (this.closed) {
          throw error instanceof Error ? error : new GatewayTransportError("TRANSPORT_CLOSED", "Closed during connect", true);
        }
      }
    }

    throw lastError instanceof Error ? lastError : new GatewayTransportError("AUTH_FAILED", String(lastError));
  }

  /** Join a mesh over the open WebSocket (optionally after a REST invite join). */
  async joinMesh(meshId: string, opts: GatewayJoinMeshOptions = {}): Promise<GatewayMeshJoined> {
    if (!meshId || typeof meshId !== "string") {
      throw new GatewayTransportError("MESH_ID_REQUIRED", "meshId is required");
    }

    const inviteRaw = opts.inviteCode ?? opts.invite_code;
    const invite = inviteRaw === undefined ? undefined : assertValidInviteCode(inviteRaw);
    const capabilities = opts.capabilities;
    const displayName = opts.displayName ?? opts.display_name;

    if (capabilities !== undefined) this.cachedCapabilities = capabilities;
    if (displayName !== undefined) this.cachedDisplayName = displayName;

    let lastError: unknown;
    for (let attempt = 0; attempt < 4; attempt += 1) {
      try {
        return await this.joinMeshOnce(meshId, { invite, capabilities, displayName });
      } catch (error) {
        lastError = error;
        const canRetry =
          error instanceof GatewayTransportError &&
          (error.code === "JOIN_TIMEOUT" || (error.code === "JOIN_FAILED" && error.retryable));
        if (!canRetry || attempt >= 3) throw error;
        const delayMs = Math.min(1000 * (2 ** attempt), this.reconnectOpts.maxDelayMs);
        await sleep(delayMs);
        if (this.closed) throw error;
      }
    }
    throw lastError instanceof Error ? lastError : new GatewayTransportError("JOIN_FAILED", String(lastError), true);
  }

  private async joinMeshOnce(
    meshId: string,
    opts: { invite?: string; capabilities?: GatewayCapability[]; displayName?: string },
  ): Promise<GatewayMeshJoined> {
    await this.waitUntilOpen();
    if (!this.socket) {
      throw new GatewayTransportError("NOT_CONNECTED", "connectGateway() must be called before joinMesh()");
    }

    if (opts.invite && this.gatewayUrl && this.agentId) {
      await this.restJoinMesh(meshId, opts.invite);
    }

    return await new Promise<GatewayMeshJoined>((resolve, reject) => {
      if (this.pendingJoin) {
        clearTimeout(this.pendingJoin.timer);
        this.pendingJoin.reject(new GatewayTransportError("JOIN_SUPERSEDED", "A newer joinMesh() replaced the pending join"));
      }
      const timer = setTimeout(() => {
        if (this.pendingJoin?.meshId === meshId) {
          this.pendingJoin = undefined;
          reject(new GatewayTransportError("JOIN_TIMEOUT", "Timed out waiting for mesh.joined", true));
        }
      }, this.requestTimeoutMs);
      this.pendingJoin = { meshId, resolve, reject, timer };
      this.meshId = meshId;
      try {
        this.sendWire({
          type: "mesh.join",
          mesh_id: meshId,
          ...(opts.invite === undefined ? {} : { invite_code: opts.invite }),
          ...(opts.capabilities === undefined ? {} : { capabilities: opts.capabilities as unknown as JsonValue }),
          ...(opts.displayName === undefined ? {} : { display_name: opts.displayName }),
          ...(this.agentId === undefined ? {} : { agent_id: this.agentId }),
        });
      } catch (error) {
        clearTimeout(timer);
        this.pendingJoin = undefined;
        reject(error instanceof Error ? error : new GatewayTransportError("SEND_FAILED", String(error), true));
      }
    });
  }

  /** Request agents in the current mesh, optionally filtered. */
  async discoverAgents(query: GatewayDiscoverQuery = {}): Promise<GatewayDiscoverResult> {
    await this.waitUntilOpen().catch(() => {
      throw new GatewayTransportError("NOT_CONNECTED", "connectGateway() must be called before discoverAgents()");
    });
    if (!this.socket) {
      throw new GatewayTransportError("NOT_CONNECTED", "connectGateway() must be called before discoverAgents()");
    }
    if (!this.meshId) {
      throw new GatewayTransportError("NOT_IN_MESH", "joinMesh() must be called before discoverAgents()");
    }

    const meshId = this.meshId;
    const normalizedQuery = normalizeDiscoverQuery(query);

    return await new Promise<GatewayDiscoverResult>((resolve, reject) => {
      if (this.pendingDiscovery) {
        clearTimeout(this.pendingDiscovery.timer);
        this.pendingDiscovery.reject(
          new GatewayTransportError("DISCOVERY_SUPERSEDED", "A newer discoverAgents() replaced the pending request"),
        );
      }

      let settled = false;
      const settle = (fn: () => void) => {
        if (settled) return;
        settled = true;
        fn();
      };

      const softWaitMs = Math.min(1_500, this.requestTimeoutMs);
      const timer = setTimeout(() => {
        void this.restDiscoverAgents(meshId, normalizedQuery)
          .then((result) => {
            settle(() => {
              this.pendingDiscovery = undefined;
              resolve(result);
            });
          })
          .catch((error) => {
            settle(() => {
              this.pendingDiscovery = undefined;
              reject(
                error instanceof GatewayTransportError
                  ? error
                  : new GatewayTransportError("DISCOVERY_FAILED", String(error), true, { cause: error }),
              );
            });
          });
      }, softWaitMs);

      this.pendingDiscovery = {
        resolve: (result) => settle(() => {
          clearTimeout(timer);
          this.pendingDiscovery = undefined;
          resolve(result);
        }),
        reject: (error) => settle(() => {
          clearTimeout(timer);
          this.pendingDiscovery = undefined;
          reject(error);
        }),
        timer,
      };

      try {
        this.sendWire({
          type: "discovery.request",
          mesh_id: meshId,
          ...(normalizedQuery.capability === undefined ? {} : { capability: normalizedQuery.capability }),
          ...(normalizedQuery.name === undefined ? {} : { name: normalizedQuery.name }),
          ...(normalizedQuery.agent_id === undefined ? {} : { agent_id: normalizedQuery.agent_id }),
          ...(normalizedQuery.metadata === undefined ? {} : { metadata: normalizedQuery.metadata as JsonObject }),
          ...(normalizedQuery.page === undefined ? {} : { page: normalizedQuery.page }),
          ...(normalizedQuery.limit === undefined ? {} : { limit: normalizedQuery.limit }),
        });
      } catch {
        // REST fallback is scheduled on the soft timer.
      }
    });
  }

  /** Leave the current mesh and close the WebSocket. */
  async leaveMesh(): Promise<void> {
    this.closed = true;
    this.stopReconnectLoop();
    this.cancelTokenRefresh();

    if (this.socket && (this.connected || this.bound)) {
      try {
        this.sendWire({ type: "mesh.leave", ...(this.meshId === undefined ? {} : { mesh_id: this.meshId }) });
      } catch {
        // Best-effort leave; still close the socket.
      }
    }
    this.meshId = undefined;
    await this.teardownSocket(1000, "mesh.leave");
  }

  /** Submit a task to another agent through the gateway relay. */
  async submitTask(
    target: string,
    capability: string,
    payload: JsonValue,
    options: { taskId?: string; task_id?: string } = {},
  ): Promise<string> {
    if (!this.connected) {
      throw new GatewayTransportError("NOT_CONNECTED", "connectGateway() must be called before submitTask()");
    }
    if (!this.meshId) {
      throw new GatewayTransportError("NOT_IN_MESH", "joinMesh() must be called before submitTask()");
    }
    if (!target || !capability) {
      throw new GatewayTransportError("INVALID_TASK", "target and capability are required");
    }
    const taskId = options.taskId ?? options.task_id ?? uuidv7();
    const wire: GatewayWireMessage = {
      type: "task.submit",
      target,
      capability,
      payload: payload as JsonValue,
      task_id: taskId,
    };

    if (this.agentId) {
      try {
        const envelope = createEnvelope({
          type: "task.submit",
          source: { agent_id: sanitizeAgentId(this.agentId), instance_id: "gateway" },
          target: { agent_id: sanitizeAgentId(target) },
          params: {
            task_id: taskId,
            method: capability.includes(".") ? capability : `org.gateway.${capability.replace(/[^a-z0-9]+/gi, ".").toLowerCase()}`,
            capability_version: "1.0.0",
            capability_contract_digest: "0".repeat(64),
            params: isRecord(payload) ? payload as JsonObject : { value: payload as JsonValue },
            deadline: new Date(Date.now() + 60_000).toISOString(),
          },
        });
        this.emitBridge("envelope", envelope);
      } catch {
        // Gateway wire uses simplified ids; envelope emission is best-effort.
      }
    }

    this.sendWire(wire);
    return taskId;
  }

  /** Route one inbound WebSocket text frame into the event system. */
  handleMessage(raw: string | Buffer | ArrayBuffer | unknown): void {
    let text: string;
    try {
      text = typeof raw === "string" || Buffer.isBuffer(raw) || raw instanceof ArrayBuffer || Array.isArray(raw)
        ? textFromMessage(raw)
        : textFromMessage(raw);
    } catch (error) {
      this.emitBridge("error", error);
      return;
    }

    const parsed = parseStrictJson(text);
    if (!parsed.ok) {
      this.emitBridge("error", new GatewayTransportError("MALFORMED_FRAME", parsed.error ?? "Invalid JSON frame"));
      return;
    }
    const value = parsed.value;
    if (!isRecord(value) || typeof value.type !== "string") {
      this.emitBridge("error", new GatewayTransportError("MALFORMED_FRAME", "Gateway message requires a type field"));
      return;
    }

    const message = value as GatewayWireMessage;
    this.emitBridge("message", message);
    this.emitBridge(message.type, message);

    switch (message.type) {
      case "mesh.joined": {
        const meshId = typeof message.mesh_id === "string" ? message.mesh_id : this.meshId;
        const members = Array.isArray(message.members) ? message.members as unknown as GatewayAgentInfo[] : [];
        if (typeof message.agent_id === "string") this.agentId = message.agent_id;
        if (meshId) this.meshId = meshId;
        if (this.pendingJoin) {
          clearTimeout(this.pendingJoin.timer);
          const pending = this.pendingJoin;
          this.pendingJoin = undefined;
          pending.resolve({
            mesh_id: meshId ?? pending.meshId,
            members,
            ...(this.agentId === undefined ? {} : { agent_id: this.agentId }),
          });
        }
        break;
      }
      case "discovery.response": {
        if (this.pendingDiscovery) {
          clearTimeout(this.pendingDiscovery.timer);
          const pending = this.pendingDiscovery;
          this.pendingDiscovery = undefined;
          try {
            pending.resolve(normalizeDiscoverResult(message));
          } catch (error) {
            pending.reject(error instanceof Error ? error : new GatewayTransportError("DISCOVERY_FAILED", String(error), true));
          }
        }
        break;
      }
      case "card.registered": {
        if (typeof message.agent_id === "string") this.agentId = message.agent_id;
        break;
      }
      case "token.expiring": {
        void this.refreshToken().catch((error) => this.emitBridge("error", error));
        break;
      }
      case "task.submit":
      case "task.accepted":
      case "task.progress":
      case "task.completed":
      case "task.failed":
      case "task.fail": {
        const envelope = gatewayMessageToEnvelope(message, this.agentId);
        if (envelope) this.emitBridge("envelope", envelope);
        break;
      }
      case "error": {
        const code = typeof message.code === "string" ? message.code : undefined;
        if (code === "DUPLICATE_TASK_ID" || code === "INVALID_CAPABILITY") {
          this.emitBridge(
            "error",
            new GatewayTransportError(
              code,
              typeof message.message === "string" ? message.message : code,
              false,
            ),
          );
        }
        const envelope = gatewayMessageToEnvelope(message, this.agentId);
        if (envelope) this.emitBridge("envelope", envelope);
        break;
      }
      default: {
        if (!KNOWN_WS_TYPES.has(message.type)) {
          this.emitBridge(
            "error",
            new GatewayTransportError(
              "PROTOCOL_UNKNOWN_TYPE",
              `Unknown gateway message type: ${message.type}`,
              false,
            ),
          );
        }
        break;
      }
    }
  }

  /** Refresh the JWT using the stored API key. */
  async refreshToken(): Promise<GatewayTokenResponse> {
    if (!this.apiKey || !this.gatewayUrl) {
      throw new GatewayTransportError("NOT_CONNECTED", "Cannot refresh token before connectGateway()");
    }
    try {
      const auth = await this.exchangeToken(this.apiKey, this.gatewayUrl);
      this.token = auth.token;
      this.tokenExpiresAtIso = auth.expires_at;
      const sub = decodeJwtSub(auth.token);
      if (sub) this.agentId = sub;
      this.scheduleTokenRefresh();
      this.emitBridge("token.refreshed", auth);
      return auth;
    } catch (error) {
      if (
        error instanceof GatewayTransportError &&
        (error.code === "AUTH_INVALID_KEY" || error.code === "AUTH_REVOKED")
      ) {
        this.stopReconnectLoop();
        this.cancelTokenRefresh();
      }
      if (error instanceof GatewayTransportError && error.code === "AUTH_FAILED") {
        throw new GatewayTransportError(
          "TOKEN_REFRESH_FAILED",
          error.message,
          error.retryable,
          { status: error.status, cause: error },
        );
      }
      if (error instanceof GatewayTransportError) throw error;
      throw new GatewayTransportError("TOKEN_REFRESH_FAILED", String(error), true, { cause: error });
    }
  }

  /** Explicitly close the transport and disable reconnect. */
  async close(code = 1000, reason = "close"): Promise<void> {
    this.closed = true;
    this.stopReconnectLoop();
    this.cancelTokenRefresh();
    this.meshId = undefined;
    await this.teardownSocket(code, reason);
  }

  private async exchangeToken(apiKey: string, gatewayUrl: string): Promise<GatewayTokenResponse> {
    const base = gatewayHttpBase(gatewayUrl);
    let response: Awaited<ReturnType<GatewayFetch>>;
    try {
      response = await this.fetchWithTimeout(`${base}/api/v1/auth/token`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ api_key: apiKey }),
      });
    } catch (error) {
      throw mapNetworkError(error);
    }
    if (!response.ok) {
      const body = await response.text().catch(() => "");
      if (response.status === 401) {
        throw new GatewayTransportError(
          "AUTH_INVALID_KEY",
          `Gateway rejected API key (401)${body ? `: ${body.slice(0, 200)}` : ""}`,
          false,
          { status: 401 },
        );
      }
      if (response.status === 403) {
        throw new GatewayTransportError(
          "AUTH_REVOKED",
          `Gateway access revoked (403)${body ? `: ${body.slice(0, 200)}` : ""}`,
          false,
          { status: 403 },
        );
      }
      throw new GatewayTransportError(
        "AUTH_FAILED",
        `Gateway token exchange failed (${response.status})${body ? `: ${body.slice(0, 200)}` : ""}`,
        response.status >= 500,
        { status: response.status },
      );
    }
    const json = await response.json();
    if (!isRecord(json) || typeof json.token !== "string" || typeof json.expires_at !== "string") {
      throw new GatewayTransportError("AUTH_FAILED", "Gateway token response is missing token/expires_at");
    }
    return { token: json.token, expires_at: json.expires_at };
  }

  private async restJoinMesh(meshId: string, inviteCode: string): Promise<void> {
    if (!this.gatewayUrl || !this.agentId) return;
    const base = gatewayHttpBase(this.gatewayUrl);
    let response: Awaited<ReturnType<GatewayFetch>>;
    try {
      response = await this.fetchWithTimeout(`${base}/api/v1/meshes/${encodeURIComponent(meshId)}/join`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json",
          ...(this.token ? { authorization: `Bearer ${this.token}` } : {}),
        },
        body: JSON.stringify({ agent_id: this.agentId, invite_code: inviteCode }),
      });
    } catch (error) {
      throw mapNetworkError(error);
    }
    if (response.ok || response.status === 409) return;

    const bodyText = await response.text().catch(() => "");
    let bodyCode: string | undefined;
    try {
      const parsed = JSON.parse(bodyText) as unknown;
      if (isRecord(parsed) && typeof parsed.code === "string") bodyCode = parsed.code;
    } catch {
      // ignore non-JSON bodies
    }

    if (response.status === 404) {
      throw new GatewayTransportError(
        "MESH_NOT_FOUND",
        `Mesh not found (${meshId})${bodyText ? `: ${bodyText.slice(0, 200)}` : ""}`,
        false,
        { status: 404 },
      );
    }
    if (response.status === 401) {
      throw new GatewayTransportError(
        "AUTH_EXPIRED",
        `Authentication expired during join${bodyText ? `: ${bodyText.slice(0, 200)}` : ""}`,
        true,
        { status: 401 },
      );
    }
    if (response.status === 403) {
      const revoked = bodyCode === "AUTH_REVOKED" || bodyCode === "FORBIDDEN" || bodyCode === "REVOKED";
      throw new GatewayTransportError(
        revoked ? "AUTH_REVOKED" : "INVITE_INVALID",
        `REST mesh join forbidden (403)${bodyText ? `: ${bodyText.slice(0, 200)}` : ""}`,
        false,
        { status: 403 },
      );
    }
    throw new GatewayTransportError(
      "JOIN_FAILED",
      `REST mesh join failed (${response.status})${bodyText ? `: ${bodyText.slice(0, 200)}` : ""}`,
      response.status >= 500,
      { status: response.status },
    );
  }

  private async restDiscoverAgents(meshId: string, query: NormalizedDiscoverQuery): Promise<GatewayDiscoverResult> {
    if (!this.gatewayUrl) {
      throw new GatewayTransportError("GATEWAY_URL_REQUIRED", "gatewayUrl is required for discovery");
    }
    const base = gatewayHttpBase(this.gatewayUrl);
    const url = new URL(`${base}/api/v1/meshes/${encodeURIComponent(meshId)}/agents`);
    if (query.capability !== undefined) url.searchParams.set("capability", query.capability);
    if (query.name !== undefined) url.searchParams.set("name", query.name);
    if (query.agent_id !== undefined) url.searchParams.set("agent_id", query.agent_id);
    if (query.metadata) {
      for (const [key, value] of Object.entries(query.metadata)) {
        url.searchParams.set(`meta.${key}`, String(value));
      }
    }
    if (query.page !== undefined) url.searchParams.set("page", String(query.page));
    if (query.limit !== undefined) url.searchParams.set("limit", String(query.limit));

    let response: Awaited<ReturnType<GatewayFetch>>;
    try {
      response = await this.fetchWithTimeout(url.toString(), {
        method: "GET",
        headers: {
          accept: "application/json",
          ...(this.token ? { authorization: `Bearer ${this.token}` } : {}),
        },
      });
    } catch (error) {
      throw mapNetworkError(error);
    }
    if (!response.ok) {
      const body = await response.text().catch(() => "");
      throw new GatewayTransportError(
        "DISCOVERY_FAILED",
        `REST discovery failed (${response.status})${body ? `: ${body.slice(0, 200)}` : ""}`,
        response.status >= 500,
        { status: response.status },
      );
    }
    const json = await response.json();
    return normalizeDiscoverResult(json, query);
  }

  private async fetchWithTimeout(
    input: string,
    init: NonNullable<Parameters<GatewayFetch>[1]>,
  ): Promise<Awaited<ReturnType<GatewayFetch>>> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.requestTimeoutMs);
    try {
      return await this.fetchImpl(input, { ...init, signal: controller.signal });
    } catch (error) {
      if (controller.signal.aborted) {
        throw new GatewayTransportError("NETWORK_TIMEOUT", `Request timed out after ${this.requestTimeoutMs}ms`, true, { cause: error });
      }
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  private async openSocket(url: string): Promise<void> {
    await this.teardownSocket(1000, "reconnect", { quiet: true });
    if (this.closed) {
      throw new GatewayTransportError("TRANSPORT_CLOSED", "Transport closed before WebSocket open", true);
    }
    const generation = ++this.socketGeneration;
    const socket = this.createWebSocket(url);
    this.socket = socket;
    await new Promise<void>((resolve, reject) => {
      const onOpen = () => {
        cleanup();
        if (generation !== this.socketGeneration || this.closed) {
          reject(new GatewayTransportError("TRANSPORT_CLOSED", "Transport closed during WebSocket open", true));
          return;
        }
        this.bindSocket(socket, generation);
        resolve();
      };
      const onError = (error: unknown) => {
        cleanup();
        reject(error instanceof Error ? error : new GatewayTransportError("WS_CONNECT_FAILED", String(error), true, { cause: error }));
      };
      const onClose = () => {
        cleanup();
        reject(new GatewayTransportError("WS_CONNECT_FAILED", "WebSocket closed before open", true));
      };
      const timer = setTimeout(() => {
        cleanup();
        reject(new GatewayTransportError("WS_CONNECT_TIMEOUT", "Timed out opening gateway WebSocket", true));
      }, this.requestTimeoutMs);
      const cleanup = () => {
        clearTimeout(timer);
        socket.off?.("open", onOpen);
        socket.off?.("error", onError);
        socket.off?.("close", onClose);
        socket.removeListener?.("open", onOpen);
        socket.removeListener?.("error", onError);
        socket.removeListener?.("close", onClose);
      };
      if (socket.readyState === OPEN) {
        clearTimeout(timer);
        this.bindSocket(socket, generation);
        resolve();
        return;
      }
      socket.once?.("open", onOpen) ?? socket.on?.("open", onOpen);
      socket.once?.("error", onError) ?? socket.on?.("error", onError);
      socket.once?.("close", onClose) ?? socket.on?.("close", onClose);
    });
  }

  private bindSocket(socket: GatewayWsSocket, generation: number): void {
    if (this.bound && this.socket === socket) return;
    this.socketCleanup?.();
    this.bound = true;
    const onMessage = (data: unknown) => {
      if (generation !== this.socketGeneration) return;
      try {
        this.handleMessage(data);
      } catch (error) {
        this.emitBridge("error", error);
      }
    };
    const onClose = (code?: number, reason?: Buffer | string) => {
      if (generation !== this.socketGeneration) return;
      this.bound = false;
      if (this.socket === socket) this.socket = undefined;
      this.socketCleanup = undefined;
      this.rejectPending(new GatewayTransportError("TRANSPORT_CLOSED", `Gateway WebSocket closed (${code ?? 0})`, true));
      this.emitBridge("close", { code: code ?? 0, reason: reason?.toString() ?? "" });
      if (!this.closed && this.reconnectOpts.enabled) {
        void this.beginReconnect();
      }
    };
    const onError = (error: unknown) => {
      if (generation !== this.socketGeneration) return;
      this.emitBridge("error", error instanceof Error ? error : new GatewayTransportError("WS_ERROR", String(error), true, { cause: error }));
    };
    socket.on?.("message", onMessage);
    socket.on?.("close", onClose);
    socket.on?.("error", onError);
    this.socketCleanup = () => {
      socket.off?.("message", onMessage);
      socket.off?.("close", onClose);
      socket.off?.("error", onError);
      socket.removeListener?.("message", onMessage);
      socket.removeListener?.("close", onClose);
      socket.removeListener?.("error", onError);
    };
  }

  private async beginReconnect(): Promise<void> {
    if (this.closed || this.reconnectInFlight || !this.reconnectOpts.enabled) return;
    this.reconnectInFlight = true;

    try {
      while (!this.closed && this.reconnectOpts.enabled) {
        this.reconnectAttempt += 1;
        const maxAttempts = this.reconnectOpts.maxAttempts;
        if (maxAttempts > 0 && this.reconnectAttempt > maxAttempts) {
          const exhausted = new GatewayTransportError(
            "RECONNECT_EXHAUSTED",
            `WebSocket reconnect failed after ${maxAttempts} attempts`,
            false,
          );
          this.emitBridge("error", exhausted);
          this.closed = true;
          this.emitBridge("close", { code: 1006, reason: "reconnect exhausted" });
          return;
        }

        const delayMs = computeBackoffDelay(this.reconnectAttempt, this.reconnectOpts);
        this.emitBridge("reconnecting", { attempt: this.reconnectAttempt, delayMs });
        await sleep(delayMs);
        if (this.closed) return;

        try {
          if (this.tokenNeedsRefresh()) {
            await this.refreshToken();
          }
          if (!this.token || !this.gatewayUrl) {
            throw new GatewayTransportError("NOT_CONNECTED", "Missing credentials for reconnect");
          }
          await this.openSocket(gatewayWsUrl(this.gatewayUrl, this.token, this.meshId));
          this.maybeAnnounceCard();

          if (this.meshId) {
            const meshId = this.meshId;
            await new Promise<GatewayMeshJoined>((resolve, reject) => {
              if (this.pendingJoin) {
                clearTimeout(this.pendingJoin.timer);
                this.pendingJoin.reject(new GatewayTransportError("JOIN_SUPERSEDED", "Reconnect join replaced pending join"));
              }
              const timer = setTimeout(() => {
                if (this.pendingJoin?.meshId === meshId) {
                  this.pendingJoin = undefined;
                  reject(new GatewayTransportError("JOIN_TIMEOUT", "Timed out waiting for mesh.joined during reconnect", true));
                }
              }, this.requestTimeoutMs);
              this.pendingJoin = { meshId, resolve, reject, timer };
              try {
                this.sendWire({
                  type: "mesh.join",
                  mesh_id: meshId,
                  ...(this.cachedCapabilities === undefined
                    ? {}
                    : { capabilities: this.cachedCapabilities as unknown as JsonValue }),
                  ...(this.cachedDisplayName === undefined ? {} : { display_name: this.cachedDisplayName }),
                  ...(this.agentId === undefined ? {} : { agent_id: this.agentId }),
                });
              } catch (error) {
                clearTimeout(timer);
                this.pendingJoin = undefined;
                reject(error instanceof Error ? error : new GatewayTransportError("SEND_FAILED", String(error), true));
              }
            });
          }

          this.reconnectAttempt = 0;
          this.emitBridge("reconnected", {
            ...(this.meshId === undefined ? {} : { mesh_id: this.meshId }),
            ...(this.agentId === undefined ? {} : { agent_id: this.agentId }),
          });
          return;
        } catch (error) {
          if (
            error instanceof GatewayTransportError &&
            (error.code === "AUTH_INVALID_KEY" || error.code === "AUTH_REVOKED")
          ) {
            this.closed = true;
            this.emitBridge("error", error);
            this.emitBridge("close", { code: 1008, reason: error.code });
            return;
          }
          this.emitBridge("error", error instanceof Error ? error : new GatewayTransportError("WS_CONNECT_FAILED", String(error), true));
          // continue backoff loop
        }
      }
    } finally {
      this.reconnectInFlight = false;
    }
  }

  private maybeAnnounceCard(): void {
    if (!this.cachedCapabilities || this.cachedCapabilities.length === 0) return;
    try {
      this.sendWire({
        type: "card.announce",
        capabilities: this.cachedCapabilities as unknown as JsonValue,
        ...(this.cachedDisplayName === undefined ? {} : { display_name: this.cachedDisplayName }),
      });
    } catch {
      // Best-effort announce after open.
    }
  }

  private tokenNeedsRefresh(): boolean {
    if (!this.tokenExpiresAtIso) return true;
    const expires = Date.parse(this.tokenExpiresAtIso);
    if (!Number.isFinite(expires)) return true;
    return expires - Date.now() <= this.tokenRefreshSkewMs;
  }

  private scheduleTokenRefresh(): void {
    this.cancelTokenRefresh();
    if (!this.tokenExpiresAtIso || this.closed) return;
    const expires = Date.parse(this.tokenExpiresAtIso);
    if (!Number.isFinite(expires)) return;
    const delay = Math.max(1_000, expires - Date.now() - this.tokenRefreshSkewMs);
    this.refreshTimer = setTimeout(() => {
      this.refreshTimer = undefined;
      if (this.closed) return;
      void this.refreshToken().catch((error) => this.emitBridge("error", error));
    }, delay);
  }

  private cancelTokenRefresh(): void {
    if (this.refreshTimer !== undefined) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = undefined;
    }
  }

  private stopReconnectLoop(): void {
    if (this.reconnectTimer !== undefined) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = undefined;
    }
    this.reconnectAttempt = 0;
  }

  private async waitUntilOpen(): Promise<void> {
    const socket = this.socket;
    if (!socket) throw new GatewayTransportError("NOT_CONNECTED", "connectGateway() must be called first");
    if (socket.readyState === OPEN || socket.readyState === undefined) return;
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new GatewayTransportError("WS_CONNECT_TIMEOUT", "Timed out waiting for WebSocket open", true)),
        this.requestTimeoutMs,
      );
      const onOpen = () => {
        clearTimeout(timer);
        resolve();
      };
      const onClose = () => {
        clearTimeout(timer);
        reject(new GatewayTransportError("TRANSPORT_CLOSED", "WebSocket closed while waiting to open", true));
      };
      socket.once?.("open", onOpen) ?? socket.on?.("open", onOpen);
      socket.once?.("close", onClose) ?? socket.on?.("close", onClose);
    });
  }

  private sendWire(message: GatewayWireMessage): void {
    const socket = this.socket;
    if (!socket) throw new GatewayTransportError("NOT_CONNECTED", "No active gateway WebSocket");
    if (socket.readyState !== undefined && socket.readyState !== OPEN) {
      throw new GatewayTransportError("NOT_CONNECTED", "Gateway WebSocket is not open");
    }
    const payload = JSON.stringify(message);
    try {
      socket.send(payload);
    } catch (error) {
      throw new GatewayTransportError("SEND_FAILED", "Failed to send gateway frame", true, { cause: error });
    }
  }

  private async teardownSocket(
    code = 1000,
    reason = "close",
    options: { quiet?: boolean } = {},
  ): Promise<void> {
    const socket = this.socket;
    this.socketCleanup?.();
    this.socketCleanup = undefined;
    this.socket = undefined;
    this.bound = false;
    this.socketGeneration += 1;
    if (!options.quiet) {
      this.rejectPending(new GatewayTransportError("TRANSPORT_CLOSED", reason, true));
    }
    if (!socket) {
      if (!options.quiet) this.emitBridge("close", { code, reason });
      return;
    }
    await new Promise<void>((resolve) => {
      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        resolve();
      };
      try {
        socket.once?.("close", finish);
        socket.close?.(code, reason);
        if (socket.readyState === undefined || socket.readyState > OPEN) finish();
        else setTimeout(finish, 25);
      } catch {
        try {
          socket.terminate?.();
        } catch {
          // ignore
        }
        finish();
      }
    });
    if (!options.quiet) this.emitBridge("close", { code, reason });
  }

  private rejectPending(error: Error): void {
    if (this.pendingJoin) {
      clearTimeout(this.pendingJoin.timer);
      this.pendingJoin.reject(error);
      this.pendingJoin = undefined;
    }
    if (this.pendingDiscovery) {
      clearTimeout(this.pendingDiscovery.timer);
      this.pendingDiscovery.reject(error);
      this.pendingDiscovery = undefined;
    }
  }

  private emitBridge(event: string, payload?: unknown): void {
    this.emit(event, payload);
    this.eventTarget?.emit(event, payload);
  }
}

interface NormalizedDiscoverQuery {
  capability?: string;
  name?: string;
  agent_id?: string;
  metadata?: Record<string, string | number | boolean>;
  page?: number;
  limit?: number;
}

function normalizeDiscoverQuery(query: GatewayDiscoverQuery): NormalizedDiscoverQuery {
  const page = query.page === undefined ? 1 : query.page;
  const limit = query.limit === undefined ? 50 : query.limit;
  if (!Number.isInteger(page) || page < 1) {
    throw new GatewayTransportError("DISCOVERY_FAILED", "page must be an integer >= 1");
  }
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
    throw new GatewayTransportError("DISCOVERY_FAILED", "limit must be an integer in 1..100");
  }
  const agentId = query.agentId ?? query.agent_id;
  return {
    ...(query.capability === undefined ? {} : { capability: query.capability }),
    ...(query.name === undefined ? {} : { name: query.name }),
    ...(agentId === undefined ? {} : { agent_id: agentId }),
    ...(query.metadata === undefined ? {} : { metadata: query.metadata }),
    page,
    limit,
  };
}

function isRetryableConnectError(error: unknown): boolean {
  if (!(error instanceof GatewayTransportError)) return true;
  if (error.code === "AUTH_INVALID_KEY" || error.code === "AUTH_REVOKED") return false;
  if (error.code === "AUTH_FAILED" && !error.retryable) return false;
  if (error.code === "API_KEY_REQUIRED" || error.code === "GATEWAY_URL_REQUIRED" || error.code === "INVALID_GATEWAY_URL") {
    return false;
  }
  return error.retryable || error.code === "WS_CONNECT_FAILED" || error.code === "WS_CONNECT_TIMEOUT"
    || error.code === "NETWORK_TIMEOUT" || error.code === "DNS_FAILURE" || error.code === "CONNECTION_REFUSED"
    || error.code === "TRANSPORT_CLOSED";
}

function mapNetworkError(error: unknown): GatewayTransportError {
  if (error instanceof GatewayTransportError) return error;
  const err = error as NodeJS.ErrnoException & { cause?: unknown; code?: string; name?: string };
  const code = err?.code ?? (err?.cause as NodeJS.ErrnoException | undefined)?.code;
  if (code === "ENOTFOUND" || code === "EAI_AGAIN") {
    return new GatewayTransportError("DNS_FAILURE", "Hostname resolution failed", true, { cause: error });
  }
  if (code === "ECONNREFUSED" || code === "EHOSTUNREACH" || code === "ENETUNREACH") {
    return new GatewayTransportError("CONNECTION_REFUSED", "Connection refused or unreachable", true, { cause: error });
  }
  if (code === "ETIMEDOUT" || code === "ABORT_ERR" || err?.name === "AbortError" || err?.name === "TimeoutError") {
    return new GatewayTransportError("NETWORK_TIMEOUT", "Network request timed out", true, { cause: error });
  }
  return new GatewayTransportError("AUTH_FAILED", String(error), true, { cause: error });
}

function decodeJwtSub(token: string): string | undefined {
  const parts = token.split(".");
  if (parts.length < 2) return undefined;
  try {
    const json = Buffer.from(parts[1]!.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    const payload = JSON.parse(json) as { sub?: unknown };
    return typeof payload.sub === "string" ? payload.sub : undefined;
  } catch {
    return undefined;
  }
}

/** Agent ids on the gateway may use email-like forms; coerce for envelope helpers. */
function sanitizeAgentId(value: string): string {
  if (/^[a-zA-Z][a-zA-Z0-9._-]*$/.test(value)) return value;
  return `agent.${value.replace(/[^a-zA-Z0-9._-]+/g, ".").replace(/^\.+|\.+$/g, "") || "unknown"}`;
}

function gatewayMessageToEnvelope(message: GatewayWireMessage, localAgentId?: string): Envelope | undefined {
  const type = message.type;
  const taskId = typeof message.task_id === "string" ? message.task_id : undefined;
  if (!taskId && type !== "error") return undefined;

  const sourceId = typeof message.from === "string"
    ? message.from
    : (localAgentId ?? "gateway");
  const targetId = typeof message.target === "string"
    ? message.target
    : (localAgentId ?? "local");

  const mappedType: MessageType | undefined =
    type === "task.submit" ? "task.submit"
      : type === "task.accepted" ? "task.accepted"
        : type === "task.progress" ? "task.progress"
          : type === "task.completed" ? "task.completed"
            : type === "task.failed" || type === "task.fail" ? "task.rejected"
              : type === "error" ? "error"
                : undefined;
  if (!mappedType) return undefined;

  try {
    if (mappedType === "task.submit") {
      const capability = typeof message.capability === "string" ? message.capability : "org.gateway.task";
      const method = capability.includes(".") ? capability : `org.gateway.${capability}`;
      const deadline = new Date(Date.now() + 60_000).toISOString();
      const params: JsonObject = {
        task_id: taskId!,
        method,
        capability_version: "1.0.0",
        capability_contract_digest: "0".repeat(64),
        params: isRecord(message.payload) ? message.payload as JsonObject : { value: (message.payload ?? null) as JsonValue },
        deadline,
      };
      const envelope = createEnvelope({
        type: "task.submit",
        source: { agent_id: sanitizeAgentId(sourceId), instance_id: "gateway" },
        target: { agent_id: sanitizeAgentId(targetId) },
        params,
        deadline,
      });
      return isEnvelope(envelope) ? envelope : undefined;
    }

    if (mappedType === "task.accepted") {
      return createEnvelope({
        type: "task.accepted",
        source: { agent_id: sanitizeAgentId(sourceId), instance_id: "gateway" },
        target: { agent_id: sanitizeAgentId(targetId) },
        params: {
          task_id: taskId!,
          event_seq: 1,
          accepted_at: new Date().toISOString(),
          capability_id: "org.gateway.task",
          capability_version: "1.0.0",
          capability_contract_digest: "0".repeat(64),
        },
      });
    }

    if (mappedType === "task.progress") {
      const progress = typeof message.progress === "number"
        ? { fraction: message.progress, ...(typeof message.message === "string" ? { status: message.message } : {}) }
        : (isRecord(message.progress) ? message.progress as JsonObject : { status: "progress" });
      return createEnvelope({
        type: "task.progress",
        source: { agent_id: sanitizeAgentId(sourceId), instance_id: "gateway" },
        target: { agent_id: sanitizeAgentId(targetId) },
        params: { task_id: taskId!, event_seq: 2, progress },
      });
    }

    if (mappedType === "task.completed") {
      const result = isRecord(message.result)
        ? message.result as JsonObject
        : { value: (message.result ?? null) as JsonValue };
      return createEnvelope({
        type: "task.completed",
        source: { agent_id: sanitizeAgentId(sourceId), instance_id: "gateway" },
        target: { agent_id: sanitizeAgentId(targetId) },
        params: {
          task_id: taskId!,
          event_seq: 2,
          terminal: {
            outcome: "succeeded",
            completed_at: new Date().toISOString(),
            result,
          },
          capability_id: "org.gateway.task",
          capability_version: "1.0.0",
          capability_contract_digest: "0".repeat(64),
        },
      });
    }

    if (mappedType === "task.rejected") {
      return createEnvelope({
        type: "task.rejected",
        source: { agent_id: sanitizeAgentId(sourceId), instance_id: "gateway" },
        target: { agent_id: sanitizeAgentId(targetId) },
        params: {
          task_id: taskId!,
          event_seq: 1,
          code: "GATEWAY_TASK_FAILED",
          message: typeof message.error === "string" ? message.error : "task failed",
        },
      });
    }

    if (mappedType === "error") {
      return createEnvelope({
        type: "error",
        source: { agent_id: sanitizeAgentId(sourceId), instance_id: "gateway" },
        target: { agent_id: sanitizeAgentId(targetId) },
        params: {
          code: typeof message.code === "string" ? message.code : "GATEWAY_ERROR",
          message: typeof message.message === "string" ? message.message : "gateway error",
          category: "protocol",
          retryable: false,
        },
        in_reply_to: uuidv7(),
      });
    }
  } catch {
    return undefined;
  }
  return undefined;
}

// Retain a protocol reference so tree-shaking keeps the version marker visible.
void PROTOCOL_VERSION;

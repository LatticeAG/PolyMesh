/**
 * Small, stateful PolyMesh client.  It speaks the broker handshake and turns
 * task envelopes into a simple `call()` / handler API without hiding the wire
 * protocol from callers that need to inspect it.
 */
import { EventEmitter } from "node:events";
import WebSocket from "ws";

import {
  MAX_FRAME_BYTES,
  PROTOCOL_VERSION,
  canonicalize,
  cardDigest,
  createEnvelope,
  deriveSessionId,
  isAgentCard,
  isEnvelope,
  isInstanceId,
  isJsonValue,
  isNonce,
  randomNonce,
  uuidv7,
  type AgentCard,
  type AgentIdentity,
  type AgentRef,
  type Envelope,
  type ErrorCategory,
  type JsonObject,
  type JsonValue,
  type WireTransport,
} from "@polymesh/broker";

export type ClientPhase = "idle" | "await_hello" | "await_card" | "await_ready" | "active" | "closed";

export interface ClientTransport {
  send(data: string, callback?: (error?: Error) => void): unknown;
  close?(code?: number, reason?: string): unknown;
  terminate?(): unknown;
  on?(event: "open" | "message" | "close" | "error", listener: (...args: any[]) => void): unknown;
  once?(event: "open" | "message" | "close" | "error", listener: (...args: any[]) => void): unknown;
  readyState?: number;
}

export interface TaskProgress {
  current?: number;
  total?: number;
  status?: string;
  state?: string;
  [key: string]: JsonValue | undefined;
}

export interface TaskContext {
  taskId: string;
  source: AgentIdentity;
  deadline: string;
  resultSchema?: JsonObject;
  signal: AbortSignal;
  progress(progress: TaskProgress): void;
}

export type TaskHandler = (input: JsonObject, context: TaskContext) => JsonValue | Promise<JsonValue>;

export interface CallOptions {
  taskId?: string;
  targetInstanceId?: string;
  /** Absolute RFC 3339 deadline. If omitted, timeoutMs determines it. */
  deadline?: string;
  timeoutMs?: number;
  idempotencyKey?: string;
  onProgress?: (progress: TaskProgress, envelope: Envelope<"task.progress">) => void;
}

export interface ClientOptions {
  card: AgentCard;
  url?: string;
  token?: string;
  transport?: ClientTransport | WireTransport;
  handlers?: Record<string, TaskHandler>;
  defaultTimeoutMs?: number;
  now?: () => number;
  handshakeTimeoutMs?: number;
  /** Capability authorization. Defaults to deny for all non-standard methods. */
  authorize?: (request: AuthorizationRequest) => boolean | Promise<boolean>;
  /** Retention for inbound idempotency fingerprints (minimum protocol value is 24h). */
  idempotencyRetentionMs?: number;
  heartbeatIntervalMs?: number;
  pongTimeoutMs?: number;
  inboundTimeoutMs?: number;
  /** Lets tests or non-Node embedders provide their own WebSocket constructor. */
  createWebSocket?: (url: string, protocols: string | string[]) => ClientTransport;
}

export interface AuthorizationRequest {
  source: AgentIdentity;
  capability: string;
  input: JsonObject;
  envelope: Envelope<"task.submit">;
}

export interface TaskFailureDetails {
  task_id?: string;
  [key: string]: JsonValue | undefined;
}

export class PolyMeshError extends Error {
  readonly code: string;
  readonly category: ErrorCategory | "transport" | "timeout";
  readonly retryable: boolean;
  readonly details?: TaskFailureDetails;

  constructor(
    code: string,
    message = code,
    category: ErrorCategory | "transport" | "timeout" = "protocol",
    retryable = false,
    details?: TaskFailureDetails,
  ) {
    super(message);
    this.name = "PolyMeshError";
    this.code = code;
    this.category = category;
    this.retryable = retryable;
    this.details = details;
  }
}

interface Deferred<T> {
  promise: Promise<T>;
  resolve(value: T): void;
  reject(reason: unknown): void;
  settled: boolean;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const result: Deferred<T> = {
    promise: new Promise<T>((resolvePromise, rejectPromise) => {
      resolve = resolvePromise;
      reject = rejectPromise;
    }),
    resolve(value) {
      if (!result.settled) {
        result.settled = true;
        resolve(value);
      }
    },
    reject(reason) {
      if (!result.settled) {
        result.settled = true;
        reject(reason);
      }
    },
    settled: false,
  };
  return result;
}

interface PendingCall {
  taskId: string;
  submitMessageId: string;
  target: AgentRef;
  resolve(value: JsonValue): void;
  reject(error: unknown): void;
  timer?: ReturnType<typeof setTimeout>;
  accepted: boolean;
  terminal: boolean;
  lastEventSeq: number;
  onProgress?: CallOptions["onProgress"];
}

interface LocalTask {
  taskId: string;
  fingerprint: string;
  source: AgentIdentity;
  target: AgentRef;
  deadline: string;
  resultSchema?: JsonObject;
  submitMessageId: string;
  events: Envelope[];
  nextEventSeq: number;
  terminal: boolean;
  controller: AbortController;
}

interface InboundDeduplication {
  fingerprint: string;
  taskId: string;
  events: Envelope[];
  expiresAt: number;
}

interface HelloFrame {
  type: "hello";
  v: "0.1";
  role: "responder";
  agent_id: string;
  instance_id: string;
  nonce: string;
  echo: string;
  sid: string;
}

interface CardFrame {
  type: "card";
  sid: string;
  for_nonce: string;
  digest: string;
  card: AgentCard;
}

interface ReadyFrame {
  type: "ready";
  sid: string;
  self_card: string;
  peer_card: string;
}

const OPEN = 1;
const IDEMPOTENCY_RETENTION_MS = 24 * 60 * 60 * 1_000;
export const PING_INTERVAL_MS = 30_000;
export const PONG_TIMEOUT_MS = 5_000;
export const INBOUND_TIMEOUT_MS = 90_000;
const STANDARD_METHODS = new Set([
  "org.polymesh.agent.ping",
  "org.polymesh.agent.info",
  "org.polymesh.capabilities.list",
]);

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function textFromWire(data: unknown): string | undefined {
  if (typeof data === "string") return data;
  if (Buffer.isBuffer(data)) return data.toString("utf8");
  if (data instanceof ArrayBuffer) return Buffer.from(data).toString("utf8");
  if (ArrayBuffer.isView(data)) return Buffer.from(data.buffer, data.byteOffset, data.byteLength).toString("utf8");
  return undefined;
}

function asError(error: unknown, fallbackCode = "TRANSPORT_ERROR"): PolyMeshError {
  if (error instanceof PolyMeshError) return error;
  if (error instanceof Error) return new PolyMeshError(fallbackCode, error.message, "transport", true);
  return new PolyMeshError(fallbackCode, String(error), "transport", true);
}

function taskIdFrom(envelope: Envelope): string | undefined {
  const taskId = (envelope.params as Record<string, unknown>).task_id;
  return typeof taskId === "string" ? taskId : undefined;
}

function eventSeqFrom(envelope: Envelope): number | undefined {
  const sequence = (envelope.params as Record<string, unknown>).event_seq;
  return typeof sequence === "number" && Number.isSafeInteger(sequence) ? sequence : undefined;
}

function safeDeadline(now: () => number, timeoutMs: number): string {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new RangeError("timeoutMs must be a positive finite number");
  return new Date(now() + timeoutMs).toISOString();
}

/** Small JSON Schema subset for capability I/O validation in the reference implementation. */
function matchesSchema(schema: JsonObject | undefined, value: unknown): boolean {
  if (!schema || Object.keys(schema).length === 0) return true;
  if ("const" in schema && !Object.is(schema.const, value)) return false;
  if (Array.isArray(schema.enum) && !schema.enum.some((candidate) => canonicalize(candidate as JsonValue) === canonicalize(value as JsonValue))) return false;
  if (Array.isArray(schema.anyOf) && !schema.anyOf.some((candidate) => isObject(candidate) && matchesSchema(candidate as JsonObject, value))) return false;
  if (Array.isArray(schema.oneOf) && schema.oneOf.filter((candidate) => isObject(candidate) && matchesSchema(candidate as JsonObject, value)).length !== 1) return false;
  const acceptedTypes = Array.isArray(schema.type) ? schema.type : schema.type === undefined ? [] : [schema.type];
  const typeMatches = (type: unknown): boolean => {
    switch (type) {
      case "object": return isObject(value);
      case "array": return Array.isArray(value);
      case "string": return typeof value === "string";
      case "number": return typeof value === "number" && Number.isFinite(value);
      case "integer": return typeof value === "number" && Number.isSafeInteger(value);
      case "boolean": return typeof value === "boolean";
      case "null": return value === null;
      default: return false;
    }
  };
  if (acceptedTypes.length > 0 && !acceptedTypes.some(typeMatches)) return false;
  if (typeof value === "string") {
    if (typeof schema.minLength === "number" && value.length < schema.minLength) return false;
    if (typeof schema.maxLength === "number" && value.length > schema.maxLength) return false;
    if (typeof schema.pattern === "string" && !new RegExp(schema.pattern).test(value)) return false;
  }
  if (typeof value === "number") {
    if (typeof schema.minimum === "number" && value < schema.minimum) return false;
    if (typeof schema.maximum === "number" && value > schema.maximum) return false;
  }
  if (Array.isArray(value)) {
    if (typeof schema.minItems === "number" && value.length < schema.minItems) return false;
    if (typeof schema.maxItems === "number" && value.length > schema.maxItems) return false;
    if (isObject(schema.items) && !value.every((item) => matchesSchema(schema.items as JsonObject, item))) return false;
  }
  if (isObject(value)) {
    const required = Array.isArray(schema.required) ? schema.required : [];
    if (required.some((key) => typeof key !== "string" || !(key in value))) return false;
    const properties = isObject(schema.properties) ? schema.properties : {};
    for (const [key, childSchema] of Object.entries(properties)) {
      if (key in value && isObject(childSchema) && !matchesSchema(childSchema as JsonObject, value[key])) return false;
    }
    if (schema.additionalProperties === false && Object.keys(value).some((key) => !(key in properties))) return false;
  }
  return true;
}

/**
 * Client for a single broker session.  It is an EventEmitter and emits
 * `ready`, `envelope`, `progress`, `protocolError`, and `close`.
 */
export class PolyMeshClient extends EventEmitter {
  readonly card: AgentCard;
  readonly cardDigest: string;
  readonly handlers = new Map<string, TaskHandler>();
  readonly defaultTimeoutMs: number;

  private readonly now: () => number;
  private readonly handshakeTimeoutMs: number;
  private readonly authorize: NonNullable<ClientOptions["authorize"]>;
  private readonly idempotencyRetentionMs: number;
  private readonly heartbeatIntervalMs: number;
  private readonly pongTimeoutMs: number;
  private readonly inboundTimeoutMs: number;
  private readonly token?: string;
  private readonly createWebSocket: (url: string, protocols: string | string[]) => ClientTransport;
  private configuredUrl?: string;
  private configuredTransport?: ClientTransport;
  private transport?: ClientTransport;
  private readyDeferred?: Deferred<this>;
  private handshakeTimer?: ReturnType<typeof setTimeout>;
  private nonce?: string;
  private peerNonce?: string;
  private sessionId?: string;
  private peerCard?: AgentCard;
  private peerCardDigest?: string;
  private peerIdentity?: AgentIdentity;
  private pendingByTask = new Map<string, Set<PendingCall>>();
  private pendingByMessage = new Map<string, PendingCall>();
  private localTasks = new Map<string, LocalTask>();
  private readonly inboundDedupe = new Map<string, InboundDeduplication>();
  private cancellationTombstones = new Map<string, Envelope<"task.cancel">>();
  private heartbeatTimer?: ReturnType<typeof setTimeout>;
  private lastValidInboundAt = 0;
  private nextPingAt = 0;
  private nextPingN = 0;
  private outstandingPing?: { n: number; deadline: number };

  phase: ClientPhase = "idle";

  constructor(options: ClientOptions) {
    super();
    if (!isAgentCard(options.card)) throw new TypeError("Client card is not a valid AgentCard");
    this.card = options.card;
    this.cardDigest = cardDigest(options.card);
    this.configuredUrl = options.url;
    this.configuredTransport = options.transport as ClientTransport | undefined;
    this.token = options.token;
    this.defaultTimeoutMs = options.defaultTimeoutMs ?? 60_000;
    this.now = options.now ?? Date.now;
    this.handshakeTimeoutMs = options.handshakeTimeoutMs ?? 5_000;
    this.authorize = options.authorize ?? ((request) => STANDARD_METHODS.has(request.capability));
    this.idempotencyRetentionMs = Math.max(IDEMPOTENCY_RETENTION_MS, options.idempotencyRetentionMs ?? IDEMPOTENCY_RETENTION_MS);
    this.heartbeatIntervalMs = options.heartbeatIntervalMs ?? PING_INTERVAL_MS;
    this.pongTimeoutMs = options.pongTimeoutMs ?? PONG_TIMEOUT_MS;
    this.inboundTimeoutMs = options.inboundTimeoutMs ?? INBOUND_TIMEOUT_MS;
    if (!Number.isFinite(this.defaultTimeoutMs) || this.defaultTimeoutMs <= 0) {
      throw new RangeError("defaultTimeoutMs must be a positive finite number");
    }
    if (!Number.isFinite(this.handshakeTimeoutMs) || this.handshakeTimeoutMs <= 0) {
      throw new RangeError("handshakeTimeoutMs must be a positive finite number");
    }
    if (!Number.isFinite(this.idempotencyRetentionMs)) throw new RangeError("idempotencyRetentionMs must be finite");
    if (![this.heartbeatIntervalMs, this.pongTimeoutMs, this.inboundTimeoutMs].every((value) => Number.isFinite(value) && value > 0)) {
      throw new RangeError("heartbeat durations must be positive finite numbers");
    }
    this.createWebSocket = options.createWebSocket ?? ((url, protocols) => new WebSocket(url, protocols));
    for (const [method, handler] of Object.entries(options.handlers ?? {})) this.setHandler(method, handler);
  }

  get connected(): boolean {
    return this.phase === "active";
  }

  get url(): string | undefined {
    return this.configuredUrl;
  }

  get brokerCard(): AgentCard | undefined {
    return this.peerCard;
  }

  get brokerIdentity(): AgentIdentity | undefined {
    return this.peerIdentity;
  }

  setHandler(method: string, handler: TaskHandler): this {
    if (!method) throw new TypeError("Capability method is required");
    if (typeof handler !== "function") throw new TypeError("Task handler must be a function");
    this.handlers.set(method, handler);
    return this;
  }

  removeHandler(method: string): boolean {
    return this.handlers.delete(method);
  }

  /** Connect using a configured transport or URL and resolve after READY. */
  async connect(url = this.configuredUrl): Promise<this> {
    if (this.phase === "active") return this;
    if (this.readyDeferred && !this.readyDeferred.settled) return this.readyDeferred.promise;
    if (this.configuredTransport) return this.connectTransport(this.configuredTransport);
    if (!url) throw new PolyMeshError("URL_REQUIRED", "A broker URL or transport is required", "transport");

    const endpoint = new URL(url);
    if (this.token && !endpoint.searchParams.has("token")) endpoint.searchParams.set("token", this.token);
    this.configuredUrl = endpoint.toString();
    return this.connectTransport(this.createWebSocket(this.configuredUrl, PROTOCOL_VERSION));
  }

  /** Connect an already-open WebSocket-shaped transport (ideal for unit tests). */
  connectTransport(transport: ClientTransport | WireTransport): Promise<this> {
    if (this.phase === "active") return Promise.resolve(this);
    if (this.readyDeferred && !this.readyDeferred.settled) return this.readyDeferred.promise;
    this.transport = transport as ClientTransport;
    this.configuredTransport = transport as ClientTransport;
    this.phase = "idle";
    const ready = deferred<this>();
    this.readyDeferred = ready;
    this.bindTransport(this.transport);

    const start = () => {
      if (this.phase === "idle") this.beginHandshake();
    };
    if (this.transport.readyState === undefined || this.transport.readyState === OPEN) queueMicrotask(start);
    else if (typeof this.transport.once === "function") this.transport.once("open", start);
    else if (typeof this.transport.on === "function") this.transport.on("open", start);
    else ready.reject(new PolyMeshError("TRANSPORT_NOT_OPEN", "Transport does not expose an open event", "transport", true));
    return ready.promise;
  }

  /** Resolve once handshake has completed; starts the configured connection if needed. */
  ready(): Promise<this> {
    if (this.phase === "active") return Promise.resolve(this);
    return this.connect();
  }

  /** Submit a task and resolve only when its terminal result arrives. */
  async call(targetAgentId: string, capability: string, input: JsonObject, options: CallOptions = {}): Promise<JsonValue> {
    await this.ready();
    if (this.phase !== "active") throw new PolyMeshError("SESSION_NOT_READY", "Session is not active", "transport", true);
    if (!targetAgentId || !capability || !isObject(input)) throw new TypeError("targetAgentId, capability, and object input are required");

    const timeoutMs = options.timeoutMs ?? this.defaultTimeoutMs;
    const deadline = options.deadline ?? safeDeadline(this.now, timeoutMs);
    if (!Number.isFinite(Date.parse(deadline))) throw new TypeError("deadline must be an RFC 3339 timestamp");
    if (Date.parse(deadline) <= this.now()) throw new PolyMeshError("PMX.TASK.DEADLINE_EXCEEDED", "Task deadline has already elapsed", "task");
    const taskId = options.taskId ?? uuidv7(this.now());
    const target: AgentRef = options.targetInstanceId === undefined
      ? { agent_id: targetAgentId }
      : { agent_id: targetAgentId, instance_id: options.targetInstanceId };
    const envelope = createEnvelope({
      type: "task.submit",
      source: this.identity(),
      target,
      delivery: {
        mode: "at_least_once",
        idempotency_key: options.idempotencyKey ?? `submit:${taskId}`,
        deadline,
      },
      params: { task_id: taskId, method: capability, params: input, deadline },
    });

    return new Promise<JsonValue>((resolve, reject) => {
      const pending: PendingCall = {
        taskId,
        submitMessageId: envelope.message_id,
        target,
        resolve,
        reject,
        accepted: false,
        terminal: false,
        lastEventSeq: 0,
        onProgress: options.onProgress,
      };
      const delay = Math.max(1, Date.parse(deadline) - this.now());
      pending.timer = setTimeout(() => {
        this.finishPending(pending, new PolyMeshError("TIMEOUT", `Task ${taskId} timed out`, "timeout", true, { task_id: taskId }));
      }, delay);
      const attempts = this.pendingByTask.get(taskId) ?? new Set<PendingCall>();
      attempts.add(pending);
      this.pendingByTask.set(taskId, attempts);
      this.pendingByMessage.set(envelope.message_id, pending);
      try {
        this.sendEnvelope(envelope);
      } catch (error) {
        this.finishPending(pending, asError(error));
      }
    });
  }

  /** Request idempotent cancellation of a task submitted by this client. */
  cancel(taskId: string, reason?: string): void {
    const pending = this.pendingByTask.get(taskId)?.values().next().value as PendingCall | undefined;
    if (!pending) throw new PolyMeshError("PMX.TASK.NOT_FOUND", `No pending task ${taskId}`, "task");
    const target = pending.target;
    this.sendEnvelope(createEnvelope({
      type: "task.cancel",
      source: this.identity(),
      target,
      delivery: { mode: "at_least_once", idempotency_key: `cancel:${taskId}` },
      params: reason === undefined ? { task_id: taskId } : { task_id: taskId, reason },
    }));
  }

  close(code = 1000, reason = "client closed"): void {
    this.clearHandshakeTimer();
    this.stopHeartbeat();
    const transport = this.transport;
    this.transport = undefined;
    if (this.phase !== "closed") this.phase = "closed";
    if (transport) {
      try {
        transport.close?.(code, reason);
      } catch {
        transport.terminate?.();
      }
    }
    this.rejectOpenAndPending(new PolyMeshError("TRANSPORT_CLOSED", reason, "transport", true));
  }

  private identity(): AgentIdentity {
    return { agent_id: this.card.agent_id, instance_id: this.card.instance_id };
  }

  private bindTransport(transport: ClientTransport): void {
    const onMessage = (data: unknown, isBinary?: boolean) => {
      if (isBinary) {
        this.failSession(new PolyMeshError("MALFORMED_FRAME", "Binary WebSocket frames are not supported", "parse"));
        return;
      }
      const text = textFromWire(data);
      if (text === undefined || Buffer.byteLength(text, "utf8") > MAX_FRAME_BYTES) {
        this.failSession(new PolyMeshError("MALFORMED_FRAME", "Frame is not a valid PolyMesh text frame", "parse"));
        return;
      }
      this.receive(text);
    };
    const onClose = (code?: number, reason?: Buffer | string) => {
      const rendered = Buffer.isBuffer(reason) ? reason.toString("utf8") : reason ?? "transport closed";
      this.onTransportClosed(code ?? 1000, rendered);
    };
    const onError = (error: Error) => {
      if (this.phase !== "closed") this.emit("protocolError", asError(error));
    };
    transport.on?.("message", onMessage);
    transport.on?.("close", onClose);
    transport.on?.("error", onError);
  }

  private beginHandshake(): void {
    if (!this.transport || this.phase !== "idle") return;
    this.nonce = randomNonce();
    this.phase = "await_hello";
    this.handshakeTimer = setTimeout(() => {
      this.failSession(new PolyMeshError("HANDSHAKE_TIMEOUT", "Handshake did not complete in time", "protocol", true));
    }, this.handshakeTimeoutMs);
    this.sendRaw({
      type: "hello",
      v: "0.1",
      role: "initiator",
      agent_id: this.card.agent_id,
      instance_id: this.card.instance_id,
      nonce: this.nonce,
    });
  }

  private receive(text: string): void {
    let frame: unknown;
    try {
      frame = JSON.parse(text) as unknown;
    } catch {
      this.failSession(new PolyMeshError("MALFORMED_JSON", "Peer sent invalid JSON", "parse"));
      return;
    }
    if (this.phase !== "active" && isObject(frame) && frame.type === "error") {
      const params = isObject(frame.params) ? frame.params : {};
      this.failSession(new PolyMeshError(
        typeof params.code === "string" ? params.code : "HANDSHAKE_FAILED",
        typeof params.message === "string" ? params.message : "Broker rejected handshake",
        typeof params.category === "string" ? params.category as ErrorCategory : "protocol",
        params.retryable === true,
      ));
      return;
    }
    if (this.phase === "await_hello") return this.receiveHello(frame);
    if (this.phase === "await_card") return this.receiveCard(frame);
    if (this.phase === "await_ready") return this.receiveReady(frame);
    if (this.phase === "active") this.receiveEnvelope(frame);
  }

  private receiveHello(frame: unknown): void {
    if (!isObject(frame) || frame.type !== "hello" || frame.v !== "0.1" || frame.role !== "responder" ||
      typeof frame.agent_id !== "string" || !isInstanceId(frame.instance_id) || !isNonce(frame.nonce) ||
      frame.echo !== this.nonce || typeof frame.sid !== "string") {
      this.failSession(new PolyMeshError("MALFORMED_FRAME", "Invalid responder hello", "protocol"));
      return;
    }
    const hello = frame as unknown as HelloFrame;
    const sid = deriveSessionId(this.nonce!, hello.nonce);
    if (hello.sid !== sid) {
      this.failSession(new PolyMeshError("SESSION_ID_MISMATCH", "Responder session id is invalid", "identity"));
      return;
    }
    if (hello.agent_id === this.card.agent_id && hello.instance_id === this.card.instance_id) {
      this.failSession(new PolyMeshError("SELF_CONNECTION", "An agent cannot connect to itself", "identity"));
      return;
    }
    this.peerNonce = hello.nonce;
    this.sessionId = sid;
    this.peerIdentity = { agent_id: hello.agent_id, instance_id: hello.instance_id };
    this.phase = "await_card";
    this.sendRaw({
      type: "card",
      sid,
      for_nonce: hello.nonce,
      digest: this.cardDigest,
      card: this.card,
    });
  }

  private receiveCard(frame: unknown): void {
    if (!isObject(frame) || frame.type !== "card" || frame.sid !== this.sessionId || frame.for_nonce !== this.nonce ||
      typeof frame.digest !== "string" || !isAgentCard(frame.card)) {
      this.failSession(new PolyMeshError("MALFORMED_FRAME", "Invalid broker card", "protocol"));
      return;
    }
    const cardFrame = frame as unknown as CardFrame;
    if (!this.peerIdentity || cardFrame.card.agent_id !== this.peerIdentity.agent_id || cardFrame.card.instance_id !== this.peerIdentity.instance_id) {
      this.failSession(new PolyMeshError("SOURCE_IDENTITY_MISMATCH", "Broker card does not match hello", "identity"));
      return;
    }
    if (Date.parse(cardFrame.card.expires_at) <= this.now() || cardDigest(cardFrame.card) !== cardFrame.digest) {
      this.failSession(new PolyMeshError("CARD_DIGEST_MISMATCH", "Broker card is expired or has an invalid digest", "protocol"));
      return;
    }
    this.peerCard = cardFrame.card;
    this.peerCardDigest = cardFrame.digest;
    this.phase = "await_ready";
    this.sendRaw({
      type: "ready",
      sid: this.sessionId,
      self_card: this.cardDigest,
      peer_card: this.peerCardDigest,
    });
  }

  private receiveReady(frame: unknown): void {
    if (!isObject(frame) || frame.type !== "ready" || frame.sid !== this.sessionId ||
      frame.self_card !== this.peerCardDigest || frame.peer_card !== this.cardDigest) {
      this.failSession(new PolyMeshError("MALFORMED_FRAME", "Ready transcript does not match", "protocol"));
      return;
    }
    const ready = frame as unknown as ReadyFrame;
    void ready; // Retains the named frame shape in the public source documentation.
    this.clearHandshakeTimer();
    this.phase = "active";
    this.startHeartbeat();
    this.readyDeferred?.resolve(this);
    this.emit("ready", this);
  }

  private receiveEnvelope(frame: unknown): void {
    if (!isEnvelope(frame)) {
      this.emit("protocolError", new PolyMeshError("MALFORMED_FRAME", "Peer sent an invalid protocol envelope", "parse"));
      return;
    }
    const envelope = frame as Envelope;
    if (envelope.target.agent_id !== this.card.agent_id ||
      (envelope.target.instance_id !== undefined && envelope.target.instance_id !== this.card.instance_id)) {
      this.emit("protocolError", new PolyMeshError("SOURCE_IDENTITY_MISMATCH", "Envelope was not addressed to this client", "identity"));
      return;
    }
    this.lastValidInboundAt = this.now();
    if (
      envelope.type === "pong" &&
      this.outstandingPing &&
      this.peerIdentity &&
      envelope.source.agent_id === this.peerIdentity.agent_id &&
      envelope.source.instance_id === this.peerIdentity.instance_id &&
      (envelope.params as Record<string, unknown>).n === this.outstandingPing.n
    ) {
      this.outstandingPing = undefined;
    }
    this.emit("envelope", envelope);
    switch (envelope.type) {
      case "ping":
        this.replyPong(envelope as Envelope<"ping">);
        break;
      case "task.submit":
        void this.handleSubmit(envelope as Envelope<"task.submit">);
        break;
      case "task.cancel":
        this.handleCancel(envelope as Envelope<"task.cancel">);
        break;
      case "task.accepted":
      case "task.rejected":
      case "task.progress":
      case "task.completed":
        this.handleLifecycle(envelope);
        break;
      case "error":
        this.handleErrorEnvelope(envelope as Envelope<"error">);
        break;
      default:
        break;
    }
  }

  private replyPong(ping: Envelope<"ping">): void {
    const n = (ping.params as Record<string, JsonValue>).n;
    if (typeof n !== "number" || !Number.isSafeInteger(n) || n < 0) return;
    this.sendEnvelope(createEnvelope({
      type: "pong",
      source: this.identity(),
      target: ping.source,
      delivery: { mode: "at_least_once", idempotency_key: `pong:${n}` },
      in_reply_to: ping.message_id,
      params: { n },
    }));
  }

  private handleLifecycle(envelope: Envelope): void {
    const taskId = taskIdFrom(envelope);
    const eventSeq = eventSeqFrom(envelope);
    if (!taskId || eventSeq === undefined) return;
    const attempts = [...(this.pendingByTask.get(taskId) ?? [])].filter((attempt) => !attempt.terminal);
    if (attempts.length === 0) return;
    if (envelope.type === "task.accepted" || envelope.type === "task.rejected") {
      const pending = envelope.in_reply_to ? this.pendingByMessage.get(envelope.in_reply_to) : undefined;
      if (!pending || pending.taskId !== taskId || pending.terminal) return;
      if (eventSeq <= pending.lastEventSeq) return;
      pending.lastEventSeq = eventSeq;
      if (envelope.type === "task.accepted") {
        pending.accepted = true;
        return;
      }
      const params = envelope.params as Record<string, unknown>;
      this.finishPending(pending, new PolyMeshError(
        typeof params.code === "string" ? params.code : "TASK_REJECTED",
        typeof params.message === "string" ? params.message : "Task rejected",
        "task",
        false,
        { task_id: taskId },
      ));
      return;
    }
    if (envelope.type === "task.progress") {
      const progress = (envelope.params as Record<string, unknown>).progress;
      for (const pending of attempts) {
        if (eventSeq <= pending.lastEventSeq) continue;
        pending.lastEventSeq = eventSeq;
        if (isObject(progress)) pending.onProgress?.(progress as TaskProgress, envelope as Envelope<"task.progress">);
      }
      if (isObject(progress)) this.emit("progress", progress, envelope);
      return;
    }
    if (envelope.type === "task.completed") {
      const terminal = (envelope.params as Record<string, unknown>).terminal;
      if (!isObject(terminal)) {
        for (const pending of attempts) this.finishPending(pending, new PolyMeshError("MALFORMED_FRAME", "Task completion has no terminal record", "parse"));
        return;
      }
      for (const pending of attempts) {
        if (eventSeq <= pending.lastEventSeq) continue;
        pending.lastEventSeq = eventSeq;
        if (terminal.outcome === "succeeded" && "result" in terminal) {
          this.finishPending(pending, undefined, terminal.result as JsonValue);
        } else if (terminal.outcome === "cancelled") {
          this.finishPending(pending, new PolyMeshError("TASK_CANCELLED", "Task was cancelled", "task", false, { task_id: taskId }));
        } else {
          const error = isObject(terminal.error) ? terminal.error : {};
          this.finishPending(pending, new PolyMeshError(
            typeof error.code === "string" ? error.code : "EXECUTION_FAILED",
            typeof error.message === "string" ? error.message : "Task failed",
            "execution",
            false,
            { task_id: taskId },
          ));
        }
      }
    }
  }

  private handleErrorEnvelope(envelope: Envelope<"error">): void {
    const params = envelope.params as Record<string, unknown>;
    const pending = envelope.in_reply_to ? this.pendingByMessage.get(envelope.in_reply_to) : undefined;
    const taskId = typeof (params.details as Record<string, unknown> | undefined)?.task_id === "string"
      ? (params.details as Record<string, string>).task_id
      : undefined;
    const target = pending ?? (taskId ? this.pendingByTask.get(taskId)?.values().next().value as PendingCall | undefined : undefined);
    const category = typeof params.category === "string" ? params.category as ErrorCategory : "protocol";
    const error = new PolyMeshError(
      typeof params.code === "string" ? params.code : "PROTOCOL_ERROR",
      typeof params.message === "string" ? params.message : "Broker returned an error",
      category,
      params.retryable === true,
      taskId ? { task_id: taskId } : undefined,
    );
    if (target) this.finishPending(target, error);
    else this.emit("protocolError", error);
  }

  private async handleSubmit(envelope: Envelope<"task.submit">): Promise<void> {
    const params = envelope.params as Record<string, unknown>;
    const taskId = typeof params.task_id === "string" ? params.task_id : undefined;
    const method = typeof params.method === "string" ? params.method : undefined;
    const input = isObject(params.params) ? params.params as JsonObject : undefined;
    const deadline = typeof params.deadline === "string" ? params.deadline : undefined;
    if (!taskId || !method || !input || !deadline) return;
    this.pruneInboundDedupe();
    const fingerprint = canonicalize({ method, params: input, deadline });
    const dedupeKey = this.inboundDedupeKey(envelope);
    const deliveryFingerprint = this.inboundFingerprint(envelope);
    const priorDelivery = this.inboundDedupe.get(dedupeKey);
    if (priorDelivery) {
      if (priorDelivery.fingerprint !== deliveryFingerprint) {
        this.sendTaskError(envelope, "PMX.DELIVERY.IDEMPOTENCY_CONFLICT", "Idempotency key was reused with different message semantics");
      } else {
        this.replayEvents(priorDelivery.events, envelope.message_id);
      }
      return;
    }
    const existing = this.localTasks.get(taskId);
    if (existing) {
      if (existing.fingerprint !== fingerprint || existing.source.agent_id !== envelope.source.agent_id || existing.source.instance_id !== envelope.source.instance_id) {
        this.sendTaskError(envelope, "PMX.TASK.ID_CONFLICT", "Task id was reused with different immutable input");
      } else {
        this.rememberInboundDedupe(dedupeKey, deliveryFingerprint, taskId, existing.events);
        this.replayEvents(existing.events, envelope.message_id);
      }
      return;
    }
    const capability = this.card.capabilities.find((candidate) => candidate.id === method);
    const handler = this.handlers.get(method) ?? this.standardHandler(method);
    if (!handler || !capability) {
      const rejection = this.sendRejected(envelope, "UNSUPPORTED_CAPABILITY", `Agent does not implement ${method}`);
      this.rememberInboundDedupe(dedupeKey, deliveryFingerprint, taskId, [rejection]);
      return;
    }
    if (Date.parse(deadline) <= this.now()) {
      const rejection = this.sendRejected(envelope, "PMX.TASK.DEADLINE_EXCEEDED", "Task deadline has already elapsed");
      this.rememberInboundDedupe(dedupeKey, deliveryFingerprint, taskId, [rejection]);
      return;
    }
    if (!matchesSchema(capability.input_schema, input)) {
      const rejection = this.sendRejected(envelope, "INVALID_INPUT", "Task input does not satisfy the capability input schema");
      this.rememberInboundDedupe(dedupeKey, deliveryFingerprint, taskId, [rejection]);
      return;
    }
    let allowed = false;
    try {
      allowed = await this.authorize({ source: envelope.source, capability: method, input, envelope });
    } catch {
      allowed = false;
    }
    if (!allowed) {
      const rejection = this.sendRejected(envelope, "AUTHORIZATION_DENIED", `Caller is not authorized for ${method}`);
      this.rememberInboundDedupe(dedupeKey, deliveryFingerprint, taskId, [rejection]);
      return;
    }
    const task: LocalTask = {
      taskId,
      fingerprint,
      source: envelope.source,
      target: envelope.target,
      deadline,
      resultSchema: capability.result_schema,
      submitMessageId: envelope.message_id,
      events: [],
      nextEventSeq: 1,
      terminal: false,
      controller: new AbortController(),
    };
    this.localTasks.set(taskId, task);
    this.rememberInboundDedupe(dedupeKey, deliveryFingerprint, taskId, task.events);
    this.emitTaskEvent(task, "task.accepted", {
      task_id: taskId,
      event_seq: task.nextEventSeq++,
      accepted_at: new Date(this.now()).toISOString(),
    }, envelope.message_id);

    if (this.cancellationTombstones.has(taskId)) {
      this.cancellationTombstones.delete(taskId);
      this.finishLocalTask(task, "cancelled", { code: "CANCELLED_BEFORE_SUBMIT" });
      return;
    }
    const context: TaskContext = {
      taskId,
      source: envelope.source,
      deadline,
      signal: task.controller.signal,
      progress: (progress) => {
        if (task.terminal) return;
        this.emitTaskEvent(task, "task.progress", {
          task_id: taskId,
          event_seq: task.nextEventSeq++,
          progress: progress as unknown as JsonObject,
        });
      },
    };
    try {
      const result = await handler(input, context);
      if (!task.terminal) this.finishLocalTask(task, "succeeded", result);
    } catch (error) {
      if (!task.terminal) this.finishLocalTask(task, "failed", error);
    }
  }

  private handleCancel(envelope: Envelope<"task.cancel">): void {
    const taskId = taskIdFrom(envelope);
    if (!taskId) return;
    const task = this.localTasks.get(taskId);
    if (!task) {
      this.cancellationTombstones.set(taskId, envelope);
      return;
    }
    if (!task.terminal) {
      task.controller.abort();
      this.finishLocalTask(task, "cancelled", { code: "CANCELLED" });
    }
  }

  private standardHandler(method: string): TaskHandler | undefined {
    if (method === "org.polymesh.agent.ping") return () => ({});
    if (method === "org.polymesh.agent.info") return () => this.card as unknown as JsonValue;
    if (method === "org.polymesh.capabilities.list") {
      return () => this.card.capabilities.map(({ id, version }) => ({ id, version })) as unknown as JsonValue;
    }
    return undefined;
  }

  private inboundDedupeKey(envelope: Envelope<"task.submit">): string {
    return [
      envelope.source.instance_id,
      this.card.instance_id,
      envelope.protocol,
      envelope.type,
      envelope.delivery.idempotency_key,
    ].join("\0");
  }

  private inboundFingerprint(envelope: Envelope<"task.submit">): string {
    return canonicalize({
      protocol: envelope.protocol,
      type: envelope.type,
      source: { agent_id: envelope.source.agent_id, instance_id: envelope.source.instance_id },
      target: envelope.target.instance_id === undefined
        ? { agent_id: envelope.target.agent_id }
        : { agent_id: envelope.target.agent_id, instance_id: envelope.target.instance_id },
      delivery: { mode: envelope.delivery.mode, deadline: envelope.delivery.deadline },
      params: envelope.params,
    } as unknown as JsonValue);
  }

  private rememberInboundDedupe(key: string, fingerprint: string, taskId: string, events: Envelope[]): void {
    this.inboundDedupe.set(key, {
      fingerprint,
      taskId,
      events,
      expiresAt: this.now() + this.idempotencyRetentionMs,
    });
  }

  private pruneInboundDedupe(): void {
    const now = this.now();
    for (const [key, record] of this.inboundDedupe) {
      if (record.expiresAt <= now) this.inboundDedupe.delete(key);
    }
  }

  /** Replay lifecycle records while correlating a replayed admission to this submission. */
  private replayEvents(events: Envelope[], submitMessageId: string): void {
    for (const event of events) {
      const inReplyTo = event.type === "task.accepted" || event.type === "task.rejected"
        ? submitMessageId
        : event.in_reply_to;
      const replay: Envelope = {
        ...event,
        message_id: uuidv7(this.now()),
        timestamp: new Date(this.now()).toISOString(),
        ...(inReplyTo === undefined ? {} : { in_reply_to: inReplyTo }),
      };
      this.sendEnvelope(replay);
    }
  }

  private sendRejected(submit: Envelope<"task.submit">, code: string, message: string): Envelope<"task.rejected"> {
    const taskId = taskIdFrom(submit)!;
    const envelope = createEnvelope({
      type: "task.rejected",
      source: this.identity(),
      target: submit.source,
      delivery: { mode: "at_least_once", idempotency_key: `rejected:${taskId}`, deadline: submit.delivery.deadline },
      in_reply_to: submit.message_id,
      params: { task_id: taskId, event_seq: 1, code, message },
    });
    this.sendEnvelope(envelope);
    return envelope;
  }

  private sendTaskError(submit: Envelope<"task.submit">, code: string, message: string): void {
    this.sendEnvelope(createEnvelope({
      type: "error",
      source: this.identity(),
      target: submit.source,
      delivery: { mode: "at_least_once", idempotency_key: `error:${submit.message_id}` },
      in_reply_to: submit.message_id,
      params: { category: "task", code, message, retryable: false, retry_after_ms: null },
    }));
  }

  private finishLocalTask(task: LocalTask, outcome: "succeeded" | "failed" | "cancelled", value: unknown): void {
    if (task.terminal) return;
    let finalOutcome = outcome;
    const terminal: Record<string, JsonValue> = {
      completed_at: new Date(this.now()).toISOString(),
    };
    if (outcome === "succeeded") {
      let normalized: JsonValue | undefined;
      let failure: { code: string; message: string } | undefined;
      try {
        const serialized = JSON.stringify(value);
        if (typeof serialized !== "string") failure = { code: "RESULT_SCHEMA_INVALID", message: "Handler result is not JSON-serializable" };
        else if (Buffer.byteLength(serialized, "utf8") > MAX_FRAME_BYTES) failure = { code: "RESULT_TOO_LARGE", message: "Handler result exceeds the 1 MiB protocol limit" };
        else normalized = JSON.parse(serialized) as JsonValue;
      } catch {
        failure = { code: "RESULT_SCHEMA_INVALID", message: "Handler result is not JSON-serializable" };
      }
      if (!failure && (!isJsonValue(normalized) || !matchesSchema(task.resultSchema, normalized))) {
        failure = { code: "RESULT_SCHEMA_INVALID", message: "Handler result does not satisfy the capability result schema" };
      }
      if (failure) {
        finalOutcome = "failed";
        terminal.error = failure;
      } else {
        terminal.result = normalized!;
      }
    } else if (outcome === "cancelled") terminal.cancellation = isObject(value) ? value as JsonObject : { code: "CANCELLED" };
    else {
      const error = value instanceof Error ? value : new Error(String(value));
      terminal.error = { code: "EXECUTION_FAILED", message: error.message };
    }
    terminal.outcome = finalOutcome;
    task.terminal = true;
    this.emitTaskEvent(task, "task.completed", {
      task_id: task.taskId,
      event_seq: task.nextEventSeq++,
      terminal,
    });
  }

  private emitTaskEvent(task: LocalTask, type: "task.accepted" | "task.progress" | "task.completed", params: JsonObject, inReplyTo?: string): void {
    const envelope = createEnvelope({
      type,
      source: this.identity(),
      target: task.source,
      delivery: { mode: "at_least_once", idempotency_key: `${type}:${task.taskId}:${params.event_seq}`, deadline: task.deadline },
      ...(inReplyTo === undefined ? {} : { in_reply_to: inReplyTo }),
      params,
    });
    task.events.push(envelope);
    this.sendEnvelope(envelope);
  }

  private finishPending(pending: PendingCall, error?: unknown, value?: JsonValue): void {
    if (pending.terminal) return;
    pending.terminal = true;
    if (pending.timer) clearTimeout(pending.timer);
    const attempts = this.pendingByTask.get(pending.taskId);
    attempts?.delete(pending);
    if (attempts?.size === 0) this.pendingByTask.delete(pending.taskId);
    this.pendingByMessage.delete(pending.submitMessageId);
    if (error !== undefined) pending.reject(error);
    else pending.resolve(value as JsonValue);
  }

  private sendEnvelope(envelope: Envelope): void {
    if (this.phase !== "active") throw new PolyMeshError("SESSION_NOT_READY", "Application messages require an active session", "transport", true);
    this.sendRaw(envelope);
  }

  private sendRaw(frame: unknown): void {
    if (!this.transport || (this.transport.readyState !== undefined && this.transport.readyState !== OPEN)) {
      throw new PolyMeshError("TRANSPORT_CLOSED", "Cannot send on a closed transport", "transport", true);
    }
    const serialized = JSON.stringify(frame);
    if (Buffer.byteLength(serialized, "utf8") > MAX_FRAME_BYTES) {
      throw new PolyMeshError("FRAME_TOO_LARGE", "Frame exceeds the protocol size limit", "resource");
    }
    this.transport.send(serialized);
  }

  private onTransportClosed(code: number, reason: string): void {
    if (this.phase === "closed") return;
    this.phase = "closed";
    this.transport = undefined;
    this.clearHandshakeTimer();
    this.stopHeartbeat();
    const error = new PolyMeshError("TRANSPORT_CLOSED", reason || `Transport closed (${code})`, "transport", true);
    this.rejectOpenAndPending(error);
    this.emit("close", code, reason);
  }

  private failSession(error: PolyMeshError): void {
    if (this.phase === "closed") return;
    this.emit("protocolError", error);
    const transport = this.transport;
    this.phase = "closed";
    this.transport = undefined;
    this.clearHandshakeTimer();
    this.stopHeartbeat();
    this.rejectOpenAndPending(error);
    try {
      transport?.close?.(1002, error.code);
    } catch {
      transport?.terminate?.();
    }
  }

  private rejectOpenAndPending(error: PolyMeshError): void {
    this.readyDeferred?.reject(error);
    for (const attempts of [...this.pendingByTask.values()]) {
      for (const pending of [...attempts]) this.finishPending(pending, error);
    }
  }

  private startHeartbeat(): void {
    this.stopHeartbeat();
    const now = this.now();
    this.lastValidInboundAt = now;
    this.nextPingAt = now + this.heartbeatIntervalMs;
    this.nextPingN = 0;
    this.outstandingPing = undefined;
    this.armHeartbeat();
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer) clearTimeout(this.heartbeatTimer);
    this.heartbeatTimer = undefined;
    this.outstandingPing = undefined;
  }

  private armHeartbeat(): void {
    if (this.phase !== "active") return;
    const now = this.now();
    let due = Math.min(this.nextPingAt, this.lastValidInboundAt + this.inboundTimeoutMs);
    if (this.outstandingPing) due = Math.min(due, this.outstandingPing.deadline);
    this.heartbeatTimer = setTimeout(() => this.heartbeatTick(), Math.max(1, due - now));
    this.heartbeatTimer.unref?.();
  }

  private heartbeatTick(): void {
    if (this.phase !== "active") return;
    const now = this.now();
    if (this.outstandingPing && now >= this.outstandingPing.deadline) {
      this.failSession(new PolyMeshError("HEARTBEAT_TIMEOUT", "Broker did not answer the heartbeat ping", "transport", true));
      return;
    }
    if (now - this.lastValidInboundAt >= this.inboundTimeoutMs) {
      this.failSession(new PolyMeshError("HEARTBEAT_TIMEOUT", "No valid inbound records arrived before timeout", "transport", true));
      return;
    }
    if (!this.outstandingPing && now >= this.nextPingAt && this.peerIdentity) {
      const n = this.nextPingN++;
      try {
        this.sendEnvelope(createEnvelope({
          type: "ping",
          source: this.identity(),
          target: this.peerIdentity,
          delivery: { mode: "at_least_once", idempotency_key: `heartbeat:${n}` },
          params: { n },
        }));
        this.outstandingPing = { n, deadline: now + this.pongTimeoutMs };
        this.nextPingAt = now + this.heartbeatIntervalMs;
      } catch (error) {
        this.failSession(asError(error));
        return;
      }
    }
    this.armHeartbeat();
  }

  private clearHandshakeTimer(): void {
    if (this.handshakeTimer) clearTimeout(this.handshakeTimer);
    this.handshakeTimer = undefined;
  }
}

/** Short alias for consumers that prefer `new Client(...)`. */
export const Client = PolyMeshClient;
export default PolyMeshClient;

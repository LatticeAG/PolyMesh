/**
 * Small, stateful PolyMesh client.  It speaks the broker handshake and turns
 * task envelopes into a simple `call()` / handler API without hiding the wire
 * protocol from callers that need to inspect it.
 */
import { EventEmitter } from "node:events";
import { isIP } from "node:net";
import type { ConnectionOptions as TlsConnectionOptions } from "node:tls";
import WebSocket, { type ClientOptions as WebSocketClientOptions } from "ws";

import {
  MAX_FRAME_BYTES,
  PROTOCOL_VERSION,
  SECURE_IDENTITY_PROFILE,
  V2_PROFILE,
  V2_PROTOCOL_VERSION,
  V2_SUBPROTOCOL,
  EnrollmentStore,
  authTranscript,
  capabilityContractTuple,
  canonicalize,
  cardDigest,
  createAuthProof,
  createCardIdentityFromPrivateKey,
  createEnvelope,
  V2ZstdStateMachine,
  decodeRuntimeToken,
  deriveSessionId,
  isAgentId,
  isAgentCard,
  isCapabilityContractTuple,
  isEnvelope,
  isInstanceId,
  isJsonValue,
  isTimestamp,
  isUuidV7,
  isValidWebSocketCloseCode,
  normalizePeerClose,
  parseStrictJson,
  randomNonce,
  sanitizeCloseReason,
  signAgentCard,
  tlsChannelBinding,
  validateHandshakeFrame,
  validateRestrictedSchema,
  verifyAuthProof,
  verifyEnrolledCard,
  verifyRoutedProvenance,
  uuidv7,
  type AgentCard,
  type AgentIdentity,
  type AgentRef,
  type AuthFrame,
  type Capability,
  type CapabilityContractTuple,
  type CardIdentity,
  type Ed25519PrivateKey,
  type Enrollment,
  type Envelope,
  type ErrorCategory,
  type HelloFrame as ProtocolHelloFrame,
  type JsonObject,
  type JsonValue,
  type ReceiptParams,
  type VerifiedPrincipal as EnrolledPrincipal,
  type V2AckFrame,
  type V2CompressionAlgorithm,
  type V2ErrorFrame,
  type V2InitFrame,
  type V2NativeEnvelope,
  type WireTransport,
} from "@latticeag/polymesh-broker";
import {
  PolicyEngine,
  isPolicyAuthorizationDecision,
  isVerifiedPrincipal,
  type PolicyAllowDecision,
  type PolicyAuthorizationRequest,
  type VerifiedPrincipal,
} from "./policy.js";
import {
  isReplayPrincipal,
  replayPrincipalFromVerified,
  type ReplayLedger,
  type ReplayLedgerRecord,
  type ReplayPrincipal,
} from "./replay-ledger.js";

export type ClientPhase = "idle" | "await_hello" | "await_card" | "await_auth" | "await_ready" | "active" | "closed";

/** The selected profile is immutable for the lifetime of a client session. */
export type ClientProfile = typeof PROTOCOL_VERSION | typeof V2_PROTOCOL_VERSION;
export const CLIENT_PROFILES = [PROTOCOL_VERSION, V2_PROTOCOL_VERSION] as const;

export interface ClientTransport {
  send(data: string | Uint8Array, callback?: (error?: Error) => void): unknown;
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
  /**
   * Exact capability entry copied from a verified target Agent Card. This is
   * the preferred way to pin both the input/result schemas and the security
   * semantics covered by the contract digest.
   */
  capabilityContract?: Capability;
  /**
   * A precomputed contract tuple for compatibility adapters that cannot pass
   * a full card entry. Both fields are required together. The enrolled
   * profile requires `capabilityContract` (or an authenticated direct peer
   * card) so it can validate the pinned input/result schemas as well.
   */
  capabilityVersion?: string;
  capabilityContractDigest?: string;
  /**
   * The result contract pinned by the task owner.  Callers that discover a
   * peer's card out of band should always supply this rather than trusting an
   * unvalidated terminal result.
   */
  resultSchema?: JsonObject;
  onProgress?: (progress: TaskProgress, envelope: Envelope<"task.progress">) => void;
}

/** A syntactically valid allow decision is the only decision that permits work. */
export type AuthorizationDecision =
  | { effect: "allow"; ruleId: string; policyGeneration: number; leaseId: string; [key: string]: unknown }
  | { effect: "deny"; code: string; [key: string]: unknown };

export interface ClientWebSocketOptions {
  headers?: Record<string, string>;
  perMessageDeflate: false;
  followRedirects: false;
  /** Set by the enrolled-key profile and intentionally not caller-relaxable. */
  minVersion?: "TLSv1.3";
  /** Set by the enrolled-key profile and intentionally not caller-relaxable. */
  rejectUnauthorized?: true;
  ca?: TlsConnectionOptions["ca"];
  cert?: TlsConnectionOptions["cert"];
  key?: TlsConnectionOptions["key"];
  servername?: TlsConnectionOptions["servername"];
}

/** Configuration required to enable the enrolled Ed25519 secure profile. */
export interface SecureIdentityOptions {
  privateKey: Ed25519PrivateKey;
  /** Local, pre-approved agent-to-key bindings. Peer cards never populate this. */
  enrollments: EnrollmentStore | readonly Enrollment[];
}

export interface ClientOptions {
  card: AgentCard;
  /** Select native `polymesh.0.2`; v0.1 remains the default. */
  profile?: ClientProfile;
  /** Optional native-v2 broker mesh hint. The v2.ack selection is authoritative. */
  meshId?: string;
  /** Ordered native-v2 compression preferences; `none` is retained automatically. */
  compression?: readonly V2CompressionAlgorithm[];
  url?: string;
  token?: string;
  /**
   * Permit `ws://` only for an explicitly selected numeric-loopback local
   * development endpoint. Production and LAN endpoints must use WSS.
   */
  allowInsecureLoopbackDevelopment?: boolean;
  /**
   * Enables a fail-closed WSS + enrolled-Ed25519 handshake. A `wss:`
   * endpoint without this configuration is rejected rather than treated as
   * authenticated merely because its certificate chain validates.
   */
  identity?: SecureIdentityOptions;
  /** mTLS trust material used only with the enrolled-key WSS profile. */
  tls?: Pick<TlsConnectionOptions, "ca" | "cert" | "key" | "servername">;
  transport?: ClientTransport | WireTransport;
  handlers?: Record<string, TaskHandler>;
  defaultTimeoutMs?: number;
  /** Absolute client-side ceiling for submitted and accepted tasks. */
  maxTaskTimeoutMs?: number;
  /** Maximum application input accepted before handler admission. */
  maxTaskInputBytes?: number;
  /** Maximum serialized handler result (the envelope has its own frame limit). */
  maxResultBytes?: number;
  /** Hard bounds for untrusted task and replay state. */
  maxPendingCalls?: number;
  maxLocalTasks?: number;
  maxInboundDedupeEntries?: number;
  maxProgressEventsPerTask?: number;
  now?: () => number;
  handshakeTimeoutMs?: number;
  /** Capability authorization. Only a validated `{ effect: "allow" }` permits work. */
  authorize?: (request: AuthorizationRequest) => AuthorizationDecision | Promise<AuthorizationDecision>;
  /**
   * Mandatory policy engine for the verified-principal authorization path.
   * It must be paired with `resolveVerifiedPrincipal` and
   * `policyTargetPrincipal`; supplying only part of this configuration is an
   * error rather than an invitation to fall back to the legacy callback.
   */
  policyEngine?: PolicyEngine;
  /**
   * Trusted bridge from routed provenance to an authenticated policy
   * principal. It MUST NOT manufacture a principal from `source.agent_id`;
   * callers must verify that binding in the transport/router layer first.
   */
  resolveVerifiedPrincipal?: (
    request: VerifiedPrincipalResolutionRequest,
  ) => VerifiedPrincipal | Promise<VerifiedPrincipal>;
  /** Stable local policy principal that owns this client's capabilities. */
  policyTargetPrincipal?: string;
  /**
   * Transactional replay/idempotency store. Secure side-effecting work
   * requires an adapter that advertises durable storage; an in-process map is
   * deliberately insufficient after restart.
   */
  replayLedger?: ReplayLedger;
  /**
   * Trusted source-provenance bridge for replay protection. This callback
   * must resolve an authenticated stable principal/key, never derive one from
   * `source.agent_id` or `source.instance_id` alone.
   */
  resolveReplayPrincipal?: (
    request: VerifiedPrincipalResolutionRequest,
  ) => ReplayPrincipal | Promise<ReplayPrincipal>;
  /** Retention for inbound idempotency fingerprints (minimum protocol value is 24h). */
  idempotencyRetentionMs?: number;
  heartbeatIntervalMs?: number;
  pongTimeoutMs?: number;
  inboundTimeoutMs?: number;
  /** Lets tests or non-Node embedders provide their own WebSocket constructor. */
  createWebSocket?: (
    url: string,
    protocols: string | string[],
    options: ClientWebSocketOptions,
  ) => ClientTransport;
}

export interface AuthorizationRequest {
  source: AgentIdentity;
  capability: string;
  input: JsonObject;
  envelope: Envelope<"task.submit">;
}

/** Input supplied to the trusted provenance-to-principal bridge. */
export interface VerifiedPrincipalResolutionRequest {
  source: AgentIdentity;
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
  capability: string;
  contract: CapabilityContractTuple;
  resultSchema?: JsonObject;
  resolve(value: JsonValue): void;
  reject(error: unknown): void;
  timer?: ReturnType<typeof setTimeout>;
  accepted: boolean;
  terminal: boolean;
  lastEventSeq: number;
  onProgress?: CallOptions["onProgress"];
}

interface LocalTask {
  storageKey: string;
  taskId: string;
  fingerprint: string;
  source: AgentIdentity;
  target: AgentRef;
  contract: CapabilityContractTuple;
  deadline: string;
  resultSchema?: JsonObject;
  submitMessageId: string;
  events: Envelope[];
  nextEventSeq: number;
  progressEvents: number;
  terminal: boolean;
  controller: AbortController;
  deadlineTimer?: ReturnType<typeof setTimeout>;
  retentionExpiresAt: number;
  policy?: TaskPolicyAuthorization;
  replay?: TaskReplayAdmission;
  replayWrite?: Promise<void>;
  replayWriteFailed?: boolean;
}

/** Lease and verified context retained through execution and data release. */
interface TaskPolicyAuthorization {
  engine: PolicyEngine;
  decision: PolicyAllowDecision;
  context: Pick<PolicyAuthorizationRequest, "principal" | "targetPrincipal" | "capability">;
}

/** Stable-principal replay state held for the task/result retention period. */
interface TaskReplayAdmission {
  ledger: ReplayLedger;
  record: ReplayLedgerRecord;
}

interface InboundDeduplication {
  fingerprint: string;
  taskId: string;
  events: Envelope[];
  expiresAt: number;
}

type HelloFrame = Extract<ProtocolHelloFrame, { role: "responder" }>;

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
const DEFAULT_MAX_TASK_TIMEOUT_MS = 5 * 60 * 1_000;
const DEFAULT_MAX_TASK_INPUT_BYTES = 256 * 1_024;
const DEFAULT_MAX_RESULT_BYTES = MAX_FRAME_BYTES;
const DEFAULT_MAX_PENDING_CALLS = 128;
const DEFAULT_MAX_LOCAL_TASKS = 128;
const DEFAULT_MAX_INBOUND_DEDUPE_ENTRIES = 256;
const DEFAULT_MAX_PROGRESS_EVENTS_PER_TASK = 256;
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

function jsonInputFromWire(data: unknown): string | Uint8Array | undefined {
  if (typeof data === "string") return data;
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
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

function isNumericLoopbackHost(host: string): boolean {
  const hostname = host.replace(/^\[|\]$/g, "");
  if (hostname === "::1") return true;
  if (isIP(hostname) !== 4) return false;
  return Number(hostname.split(".", 1)[0]) === 127;
}

function jsonBytes(value: JsonValue): number | undefined {
  try {
    const serialized = JSON.stringify(value);
    return typeof serialized === "string" ? Buffer.byteLength(serialized, "utf8") : undefined;
  } catch {
    return undefined;
  }
}

function isAuthorizationDecision(value: unknown): value is AuthorizationDecision {
  if (!isObject(value) || typeof value.effect !== "string") return false;
  if (value.effect === "allow") {
    return typeof value.ruleId === "string" && value.ruleId.length > 0 &&
      typeof value.policyGeneration === "number" && Number.isSafeInteger(value.policyGeneration) && value.policyGeneration >= 0 &&
      typeof value.leaseId === "string" && value.leaseId.length > 0;
  }
  return value.effect === "deny" && typeof value.code === "string" && value.code.length > 0;
}

function sameIdentity(actual: AgentIdentity, expected: AgentRef): boolean {
  return actual.agent_id === expected.agent_id &&
    (expected.instance_id === undefined || actual.instance_id === expected.instance_id);
}

function sameCapabilityContract(left: CapabilityContractTuple, right: CapabilityContractTuple): boolean {
  return left.capability_id === right.capability_id &&
    left.capability_version === right.capability_version &&
    left.capability_contract_digest === right.capability_contract_digest;
}

function sameOptionalSchema(left: JsonObject | undefined, right: JsonObject | undefined): boolean {
  if (left === undefined || right === undefined) return left === right;
  return canonicalize(left) === canonicalize(right);
}

function capabilityContractFromParams(params: Record<string, unknown>): CapabilityContractTuple | undefined {
  const candidate = {
    capability_id: params.capability_id,
    capability_version: params.capability_version,
    capability_contract_digest: params.capability_contract_digest,
  };
  return isCapabilityContractTuple(candidate) ? candidate : undefined;
}

/**
 * Native v2 lifecycle records spell the capability name `capability`, while
 * the mature internal lifecycle machinery uses `capability_id`.  Convert
 * only the closed fields it understands; the legacy envelope validator below
 * remains the final guard for every value and type.
 */
function nativeLifecycleParams(
  params: JsonObject,
  fields: readonly string[],
  includeCapabilityContract: boolean,
): JsonObject {
  const result: JsonObject = {};
  for (const field of fields) {
    if (!Object.hasOwn(params, field)) return {};
    result[field] = params[field]!;
  }
  if (!includeCapabilityContract) return result;
  const capability = params.capability ?? params.capability_id;
  if (capability === undefined || params.capability_version === undefined || params.capability_contract_digest === undefined) {
    return {};
  }
  result.capability_id = capability;
  result.capability_version = params.capability_version;
  result.capability_contract_digest = params.capability_contract_digest;
  return result;
}

interface ResolvedCapabilityContract {
  tuple: CapabilityContractTuple;
  capability?: Capability;
}

/** Routed records that can alter task, policy, or pending-call state. */
function requiresRoutedProvenance(type: Envelope["type"]): boolean {
  return type === "task.submit" || type === "task.cancel" || type === "task.accepted" ||
    type === "task.rejected" || type === "task.progress" || type === "task.completed" || type === "error";
}

/** Clone through canonical JSON and recursively freeze before invoking a handler. */
function immutableJsonObject(value: JsonObject): JsonObject {
  const parsed = parseStrictJson(canonicalize(value));
  if (!parsed.ok || !isObject(parsed.value)) throw new PolyMeshError("INVALID_INPUT", "Task input cannot be canonicalized", "parse");
  const root = parsed.value as JsonObject;
  const stack: JsonValue[] = [root];
  while (stack.length > 0) {
    const current = stack.pop()!;
    if (current === null || typeof current !== "object") continue;
    const children = Array.isArray(current) ? current : Object.values(current);
    for (const child of children) {
      if (child !== null && typeof child === "object") stack.push(child);
    }
    Object.freeze(current);
  }
  return root;
}

/**
 * Evaluate only the explicit, non-executable restricted schema profile.
 * Unsupported keywords are rejected by `validateRestrictedSchema` rather than
 * being silently skipped, and no attacker-controlled regular expression is
 * ever compiled.
 */
function matchesSchema(schema: JsonObject | undefined, value: unknown): boolean {
  if (!schema || Object.keys(schema).length === 0) return true;
  if (!isJsonValue(value) || validateRestrictedSchema(schema).ok === false) return false;
  const matches = (currentSchema: JsonObject, currentValue: JsonValue): boolean => {
    if ("const" in currentSchema && canonicalize(currentSchema.const as JsonValue) !== canonicalize(currentValue)) return false;
    if (Array.isArray(currentSchema.enum) && !currentSchema.enum.some((candidate) => canonicalize(candidate as JsonValue) === canonicalize(currentValue))) return false;
    if (Array.isArray(currentSchema.anyOf) && !currentSchema.anyOf.some((candidate) => isObject(candidate) && matches(candidate as JsonObject, currentValue))) return false;
    if (Array.isArray(currentSchema.oneOf) && currentSchema.oneOf.filter((candidate) => isObject(candidate) && matches(candidate as JsonObject, currentValue)).length !== 1) return false;
    if (Array.isArray(currentSchema.allOf) && !currentSchema.allOf.every((candidate) => isObject(candidate) && matches(candidate as JsonObject, currentValue))) return false;
    const acceptedTypes = Array.isArray(currentSchema.type) ? currentSchema.type : currentSchema.type === undefined ? [] : [currentSchema.type];
    const typeMatches = (type: unknown): boolean => {
      switch (type) {
        case "object": return isObject(currentValue);
        case "array": return Array.isArray(currentValue);
        case "string": return typeof currentValue === "string";
        case "number": return typeof currentValue === "number" && Number.isFinite(currentValue);
        case "integer": return typeof currentValue === "number" && Number.isSafeInteger(currentValue);
        case "boolean": return typeof currentValue === "boolean";
        case "null": return currentValue === null;
        default: return false;
      }
    };
    if (acceptedTypes.length > 0 && !acceptedTypes.some(typeMatches)) return false;
    if (typeof currentValue === "string") {
      if (typeof currentSchema.minLength === "number" && currentValue.length < currentSchema.minLength) return false;
      if (typeof currentSchema.maxLength === "number" && currentValue.length > currentSchema.maxLength) return false;
    }
    if (typeof currentValue === "number") {
      if (typeof currentSchema.minimum === "number" && currentValue < currentSchema.minimum) return false;
      if (typeof currentSchema.maximum === "number" && currentValue > currentSchema.maximum) return false;
    }
    if (Array.isArray(currentValue)) {
      if (typeof currentSchema.minItems === "number" && currentValue.length < currentSchema.minItems) return false;
      if (typeof currentSchema.maxItems === "number" && currentValue.length > currentSchema.maxItems) return false;
      if (isObject(currentSchema.items) && !currentValue.every((item) => matches(currentSchema.items as JsonObject, item))) return false;
    }
    if (isObject(currentValue)) {
      const required = Array.isArray(currentSchema.required) ? currentSchema.required : [];
      if (required.some((key) => typeof key !== "string" || !(key in currentValue))) return false;
      const properties = isObject(currentSchema.properties) ? currentSchema.properties : {};
      for (const [key, childSchema] of Object.entries(properties)) {
        if (key in currentValue && isObject(childSchema) && !matches(childSchema as JsonObject, currentValue[key]!)) return false;
      }
      if (currentSchema.additionalProperties === false && Object.keys(currentValue).some((key) => !(key in properties))) return false;
    }
    return true;
  };
  return matches(schema, value);
}

/**
 * Client for a single broker session.  It is an EventEmitter and emits
 * `ready`, `envelope`, `progress`, `receipt`, `protocolError`, and `close`.
 */
export class PolyMeshClient extends EventEmitter {
  readonly card: AgentCard;
  readonly cardDigest: string;
  readonly handlers = new Map<string, TaskHandler>();
  readonly defaultTimeoutMs: number;
  /** Profile selected at construction; it never changes during reconnects. */
  readonly profile: ClientProfile;

  private readonly now: () => number;
  private readonly handshakeTimeoutMs: number;
  private readonly authorize: NonNullable<ClientOptions["authorize"]>;
  private readonly idempotencyRetentionMs: number;
  private readonly maxTaskTimeoutMs: number;
  private readonly maxTaskInputBytes: number;
  private readonly maxResultBytes: number;
  private readonly maxPendingCalls: number;
  private readonly maxLocalTasks: number;
  private readonly maxInboundDedupeEntries: number;
  private readonly maxProgressEventsPerTask: number;
  private readonly heartbeatIntervalMs: number;
  private readonly pongTimeoutMs: number;
  private readonly inboundTimeoutMs: number;
  private readonly policyEngine?: PolicyEngine;
  private readonly resolveVerifiedPrincipal?: NonNullable<ClientOptions["resolveVerifiedPrincipal"]>;
  private readonly policyTargetPrincipal?: string;
  private readonly replayLedger?: ReplayLedger;
  private readonly resolveReplayPrincipal?: NonNullable<ClientOptions["resolveReplayPrincipal"]>;
  private readonly token?: string;
  private readonly nativeMeshHint?: string;
  private readonly nativeCompressionPreferences: readonly V2CompressionAlgorithm[];
  private readonly allowInsecureLoopbackDevelopment: boolean;
  private readonly identityProfile?: {
    privateKey: Ed25519PrivateKey;
    enrollments: EnrollmentStore;
    identity: CardIdentity;
    localPrincipal: EnrolledPrincipal;
  };
  private readonly tlsOptions?: ClientOptions["tls"];
  private readonly createWebSocket: NonNullable<ClientOptions["createWebSocket"]>;
  private configuredUrl?: string;
  private configuredTransport?: ClientTransport;
  private transport?: ClientTransport;
  private readyDeferred?: Deferred<this>;
  private handshakeTimer?: ReturnType<typeof setTimeout>;
  private nonce?: string;
  private peerNonce?: string;
  private sessionId?: string;
  private initiatorHello?: Extract<ProtocolHelloFrame, { role: "initiator" }>;
  private responderHello?: HelloFrame;
  private peerCard?: AgentCard;
  private peerCardDigest?: string;
  private peerIdentity?: AgentIdentity;
  private peerPrincipal?: EnrolledPrincipal;
  private nativeMeshId?: string;
  private nativeSessionId?: string;
  private nativeInit?: V2InitFrame;
  private nativeZstd?: V2ZstdStateMachine;
  /** Serializes asynchronous zstd wrapper writes in lifecycle order. */
  private nativeSendQueue: Promise<void> = Promise.resolve();
  private pendingByTask = new Map<string, Set<PendingCall>>();
  private pendingByMessage = new Map<string, PendingCall>();
  private localTasks = new Map<string, LocalTask>();
  private readonly inboundDedupe = new Map<string, InboundDeduplication>();
  private heartbeatTimer?: ReturnType<typeof setTimeout>;
  private lastValidInboundAt = 0;
  private nextPingAt = 0;
  private nextPingN = 0;
  private outstandingPing?: { n: number; deadline: number };

  phase: ClientPhase = "idle";

  constructor(options: ClientOptions) {
    super();
    if (!isAgentCard(options.card)) throw new TypeError("Client card is not a valid AgentCard");
    this.profile = options.profile ?? PROTOCOL_VERSION;
    if (this.profile !== PROTOCOL_VERSION && this.profile !== V2_PROTOCOL_VERSION) {
      throw new TypeError(`Unsupported PolyMesh profile: ${String(options.profile)}`);
    }
    if (options.meshId !== undefined && !isUuidV7(options.meshId)) {
      throw new TypeError("meshId must be a UUIDv7 when selecting the native v2 profile");
    }
    this.nativeMeshHint = options.meshId;
    const requestedCompression = options.compression ?? ["zstd", "none"];
    if (!Array.isArray(requestedCompression) || requestedCompression.length === 0 ||
      requestedCompression.some((algorithm) => algorithm !== "zstd" && algorithm !== "none") ||
      new Set(requestedCompression).size !== requestedCompression.length) {
      throw new TypeError("compression must be a non-empty unique list of zstd and/or none");
    }
    this.nativeCompressionPreferences = Object.freeze([
      ...requestedCompression,
      ...(requestedCompression.includes("none") ? [] : ["none" as const]),
    ]);
    if (this.profile === V2_PROTOCOL_VERSION && options.identity !== undefined) {
      throw new TypeError("The compact native v2 profile does not support the enrolled v0.1 identity handshake");
    }
    this.now = options.now ?? Date.now;
    let localCard = options.card;
    if (options.identity) {
      const enrollments = options.identity.enrollments instanceof EnrollmentStore
        ? options.identity.enrollments
        : new EnrollmentStore(options.identity.enrollments);
      const identity = createCardIdentityFromPrivateKey(options.identity.privateKey);
      if (localCard.identity !== undefined && (
        localCard.identity.key_id !== identity.key_id ||
        localCard.identity.public_key !== identity.public_key
      )) {
        throw new TypeError("Client Card identity does not match the configured signing key");
      }
      localCard = signAgentCard(localCard, options.identity.privateKey);
      const localPrincipal = verifyEnrolledCard(localCard, enrollments, this.now());
      if (!localPrincipal) {
        throw new TypeError("The local signed Card must be present in the enrolled identity store");
      }
      this.identityProfile = {
        privateKey: options.identity.privateKey,
        enrollments,
        identity,
        localPrincipal,
      };
    }
    this.card = localCard;
    this.cardDigest = cardDigest(localCard);
    this.configuredUrl = options.url;
    this.configuredTransport = options.transport as ClientTransport | undefined;
    this.token = options.token;
    this.allowInsecureLoopbackDevelopment = options.allowInsecureLoopbackDevelopment === true;
    this.tlsOptions = options.tls;
    this.defaultTimeoutMs = options.defaultTimeoutMs ?? 60_000;
    this.handshakeTimeoutMs = options.handshakeTimeoutMs ?? 5_000;
    this.authorize = options.authorize ?? ((request) => (
      STANDARD_METHODS.has(request.capability)
        ? { effect: "allow", ruleId: "builtin-standard-capability", policyGeneration: 0, leaseId: "builtin" }
        : { effect: "deny", code: "DEFAULT_DENY" }
    ));
    this.idempotencyRetentionMs = Math.max(IDEMPOTENCY_RETENTION_MS, options.idempotencyRetentionMs ?? IDEMPOTENCY_RETENTION_MS);
    this.maxTaskTimeoutMs = options.maxTaskTimeoutMs ?? DEFAULT_MAX_TASK_TIMEOUT_MS;
    this.maxTaskInputBytes = options.maxTaskInputBytes ?? DEFAULT_MAX_TASK_INPUT_BYTES;
    this.maxResultBytes = options.maxResultBytes ?? DEFAULT_MAX_RESULT_BYTES;
    this.maxPendingCalls = options.maxPendingCalls ?? DEFAULT_MAX_PENDING_CALLS;
    this.maxLocalTasks = options.maxLocalTasks ?? DEFAULT_MAX_LOCAL_TASKS;
    this.maxInboundDedupeEntries = options.maxInboundDedupeEntries ?? DEFAULT_MAX_INBOUND_DEDUPE_ENTRIES;
    this.maxProgressEventsPerTask = options.maxProgressEventsPerTask ?? DEFAULT_MAX_PROGRESS_EVENTS_PER_TASK;
    this.heartbeatIntervalMs = options.heartbeatIntervalMs ?? PING_INTERVAL_MS;
    this.pongTimeoutMs = options.pongTimeoutMs ?? PONG_TIMEOUT_MS;
    this.inboundTimeoutMs = options.inboundTimeoutMs ?? INBOUND_TIMEOUT_MS;
    this.policyEngine = options.policyEngine;
    this.resolveVerifiedPrincipal = options.resolveVerifiedPrincipal;
    this.policyTargetPrincipal = options.policyTargetPrincipal;
    this.replayLedger = options.replayLedger;
    this.resolveReplayPrincipal = options.resolveReplayPrincipal;
    if (!Number.isFinite(this.defaultTimeoutMs) || this.defaultTimeoutMs <= 0) {
      throw new RangeError("defaultTimeoutMs must be a positive finite number");
    }
    if (!Number.isFinite(this.handshakeTimeoutMs) || this.handshakeTimeoutMs <= 0) {
      throw new RangeError("handshakeTimeoutMs must be a positive finite number");
    }
    if (!Number.isFinite(this.idempotencyRetentionMs)) throw new RangeError("idempotencyRetentionMs must be finite");
    if (![this.maxTaskTimeoutMs, this.maxTaskInputBytes, this.maxResultBytes, this.maxPendingCalls, this.maxLocalTasks, this.maxInboundDedupeEntries, this.maxProgressEventsPerTask]
      .every((value) => Number.isSafeInteger(value) && value > 0)) {
      throw new RangeError("task and state limits must be positive safe integers");
    }
    if (this.maxResultBytes > MAX_FRAME_BYTES) throw new RangeError(`maxResultBytes must not exceed ${MAX_FRAME_BYTES}`);
    if (![this.heartbeatIntervalMs, this.pongTimeoutMs, this.inboundTimeoutMs].every((value) => Number.isFinite(value) && value > 0)) {
      throw new RangeError("heartbeat durations must be positive finite numbers");
    }
    if (this.token !== undefined && !decodeRuntimeToken(this.token)) {
      throw new TypeError("A runtime token must be exactly 32 random bytes encoded as base64url");
    }
    const hasAnyPolicyConfiguration = this.policyEngine !== undefined ||
      this.resolveVerifiedPrincipal !== undefined || this.policyTargetPrincipal !== undefined;
    if (hasAnyPolicyConfiguration &&
      (!this.policyEngine || !this.resolveVerifiedPrincipal ||
        typeof this.policyTargetPrincipal !== "string" || this.policyTargetPrincipal.length === 0)) {
      throw new TypeError("policyEngine, resolveVerifiedPrincipal, and policyTargetPrincipal must be configured together");
    }
    if (this.replayLedger !== undefined &&
      (typeof this.replayLedger.durable !== "boolean" || typeof this.replayLedger.admit !== "function" ||
        typeof this.replayLedger.recordArtifacts !== "function")) {
      throw new TypeError("replayLedger must provide durable, admit, and recordArtifacts members");
    }
    this.createWebSocket = options.createWebSocket ?? ((url, protocols, connectionOptions) => new WebSocket(url, protocols, connectionOptions as WebSocketClientOptions));
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

  /** Present only after a verified enrolled-key WSS handshake. */
  get brokerPrincipal(): EnrolledPrincipal | undefined {
    return this.peerPrincipal;
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

    let endpoint: URL;
    try {
      endpoint = new URL(url);
    } catch {
      throw new PolyMeshError("INVALID_ENDPOINT", "A valid WebSocket endpoint is required", "transport");
    }
    if (endpoint.protocol !== "ws:" && endpoint.protocol !== "wss:") {
      throw new PolyMeshError("INVALID_ENDPOINT", "PolyMesh WebSocket endpoints must use ws or wss", "transport");
    }
    if (this.identityProfile && endpoint.protocol !== "wss:") {
      throw new PolyMeshError("INSECURE_TRANSPORT_DISABLED", "The enrolled identity profile requires TLS 1.3 WSS", "transport");
    }
    if (endpoint.protocol === "wss:" && !this.identityProfile) {
      throw new PolyMeshError("AUTHENTICATION_FAILED", "WSS requires enrolled Ed25519 identity configuration", "identity");
    }
    if (endpoint.protocol === "ws:" && (!this.allowInsecureLoopbackDevelopment || !isNumericLoopbackHost(endpoint.hostname))) {
      throw new PolyMeshError(
        "INSECURE_TRANSPORT_DISABLED",
        "Plain WebSocket requires explicit numeric-loopback development mode",
        "transport",
      );
    }
    // Tokens in a URL leak through logs, copied links, proxies, redirects, and
    // telemetry.  PolyMesh has no query-string transport parameters.
    if (endpoint.username || endpoint.password || endpoint.hash || endpoint.search ||
      [...endpoint.searchParams.keys()].some((key) => key.toLowerCase() === "token")) {
      throw new PolyMeshError("INVALID_ENDPOINT", "Endpoint credentials, fragments, and query parameters are not permitted", "transport");
    }
    if (endpoint.protocol === "wss:" && this.token !== undefined) {
      throw new PolyMeshError("AUTHENTICATION_FAILED", "Runtime tokens are loopback-only and must not be sent to WSS endpoints", "identity");
    }
    this.configuredUrl = endpoint.toString();
    const connectionOptions: ClientWebSocketOptions = {
      ...(endpoint.protocol === "ws:" && this.token !== undefined ? { headers: { "x-polymesh-token": this.token } } : {}),
      ...(this.identityProfile === undefined ? {} : {
        ...(this.tlsOptions ?? {}),
        minVersion: "TLSv1.3" as const,
        rejectUnauthorized: true as const,
      }),
      perMessageDeflate: false,
      followRedirects: false,
    };
    return this.connectTransport(this.createWebSocket(
      this.configuredUrl,
      this.profile === V2_PROTOCOL_VERSION ? V2_SUBPROTOCOL : PROTOCOL_VERSION,
      connectionOptions,
    ));
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
    if (!targetAgentId || targetAgentId === "*" || !capability || !isObject(input) || !isJsonValue(input)) {
      throw new TypeError("targetAgentId, capability, and a bounded JSON object input are required");
    }
    const inputBytes = jsonBytes(input);
    if (inputBytes === undefined || inputBytes > this.maxTaskInputBytes) {
      throw new PolyMeshError("INPUT_TOO_LARGE", "Task input exceeds the configured byte limit", "resource");
    }
    if (this.pendingByMessage.size >= this.maxPendingCalls) {
      throw new PolyMeshError("OVERLOADED", "The client has reached its pending task limit", "resource", true);
    }

    const timeoutMs = options.timeoutMs ?? this.defaultTimeoutMs;
    const deadline = options.deadline ?? safeDeadline(this.now, timeoutMs);
    if (!isTimestamp(deadline)) throw new TypeError("deadline must be an RFC 3339 UTC timestamp with milliseconds");
    const deadlineMs = Date.parse(deadline);
    if (deadlineMs <= this.now()) throw new PolyMeshError("PMX.TASK.DEADLINE_EXCEEDED", "Task deadline has already elapsed", "task");
    if (deadlineMs > this.now() + this.maxTaskTimeoutMs) {
      throw new PolyMeshError("PMX.TASK.DEADLINE_EXCEEDED", "Task deadline exceeds the configured maximum", "task");
    }
    const taskId = options.taskId ?? uuidv7(this.now());
    if (!isUuidV7(taskId)) throw new TypeError("taskId must be a UUIDv7");
    const target: AgentRef = options.targetInstanceId === undefined
      ? { agent_id: targetAgentId }
      : { agent_id: targetAgentId, instance_id: options.targetInstanceId };
    const resolvedContract = this.resolveCallCapabilityContract(targetAgentId, capability, options);
    if (resolvedContract.capability) {
      if (options.resultSchema !== undefined && !sameOptionalSchema(options.resultSchema, resolvedContract.capability.result_schema)) {
        throw new TypeError("resultSchema must exactly match the pinned capability contract");
      }
      if (!matchesSchema(resolvedContract.capability.input_schema, input)) {
        throw new PolyMeshError("INVALID_INPUT", "Task input does not satisfy the pinned capability contract", "task");
      }
      const contractTimeoutMs = (resolvedContract.capability.timeout_ceiling_seconds ?? 300) * 1_000;
      if (deadlineMs > this.now() + Math.min(this.maxTaskTimeoutMs, contractTimeoutMs)) {
        throw new PolyMeshError("PMX.TASK.DEADLINE_EXCEEDED", "Task deadline exceeds the pinned capability timeout ceiling", "task");
      }
    }
    const envelope = createEnvelope({
      type: "task.submit",
      source: this.identity(),
      target,
      delivery: {
        mode: "at_least_once",
        idempotency_key: options.idempotencyKey ?? `submit:${taskId}`,
        deadline,
      },
      params: {
        task_id: taskId,
        method: capability,
        capability_version: resolvedContract.tuple.capability_version,
        capability_contract_digest: resolvedContract.tuple.capability_contract_digest,
        params: input,
        deadline,
      },
    });

    return new Promise<JsonValue>((resolve, reject) => {
      const pending: PendingCall = {
        taskId,
        submitMessageId: envelope.message_id,
        target,
        capability,
        contract: resolvedContract.tuple,
        resultSchema: options.resultSchema ?? resolvedContract.capability?.result_schema ?? this.resultSchemaFor(targetAgentId, capability),
        resolve,
        reject,
        accepted: false,
        terminal: false,
        lastEventSeq: 0,
        onProgress: options.onProgress,
      };
      const delay = Math.max(1, deadlineMs - this.now());
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
    this.nativeZstd?.close();
    this.nativeZstd = undefined;
    this.abortLocalTasks();
    const safeCode = isValidWebSocketCloseCode(code) ? code : 1000;
    const normalizedReason = sanitizeCloseReason(reason);
    const safeReason = normalizedReason === "invalid close reason" ? "client closed" : normalizedReason;
    const transport = this.transport;
    this.transport = undefined;
    if (this.phase !== "closed") this.phase = "closed";
    if (transport) {
      try {
        transport.close?.(safeCode, safeReason);
      } catch {
        transport.terminate?.();
      }
    }
    this.rejectOpenAndPending(new PolyMeshError("TRANSPORT_CLOSED", safeReason, "transport", true));
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
      const input = jsonInputFromWire(data);
      const bytes = typeof input === "string" ? Buffer.byteLength(input, "utf8") : input?.byteLength;
      if (input === undefined || bytes === undefined || bytes > MAX_FRAME_BYTES) {
        this.failSession(new PolyMeshError("MALFORMED_FRAME", "Frame is not a valid PolyMesh text frame", "parse"));
        return;
      }
      this.receive(input);
    };
    const onClose = (code?: number, reason?: Buffer | string) => {
      const close = normalizePeerClose(code ?? 1000, reason ?? "");
      this.onTransportClosed(close.code, close.reason);
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
    if (this.profile === V2_PROTOCOL_VERSION) {
      this.beginNativeV2Handshake();
      return;
    }
    this.nonce = randomNonce();
    this.initiatorHello = {
      type: "hello",
      v: "0.1",
      role: "initiator",
      agent_id: this.card.agent_id,
      instance_id: this.card.instance_id,
      nonce: this.nonce,
      ...(this.identityProfile === undefined ? {} : { security_profile: SECURE_IDENTITY_PROFILE }),
    };
    this.phase = "await_hello";
    this.handshakeTimer = setTimeout(() => {
      this.failSession(new PolyMeshError("HANDSHAKE_TIMEOUT", "Handshake did not complete in time", "protocol", true));
    }, this.handshakeTimeoutMs);
    this.sendRaw(this.initiatorHello);
  }

  /**
   * Native v2 deliberately selects a profile before any legacy hello/card
   * record is emitted. The mesh id here is only a routing hint; the broker's
   * v2.ack is authoritative and fences every subsequent envelope.
   */
  private beginNativeV2Handshake(): void {
    if (!this.transport || this.phase !== "idle") return;
    const init: V2InitFrame = {
      type: "v2.init",
      protocol: V2_PROFILE,
      profile: V2_PROFILE,
      mesh_id: this.nativeMeshHint ?? uuidv7(this.now()),
      agent_id: this.card.agent_id,
      instance_id: this.card.instance_id,
      nonce: uuidv7(this.now()),
      supported_profiles: [V2_PROFILE],
      compression: this.nativeCompressionPreferences,
    };
    this.nativeInit = init;
    this.phase = "await_hello";
    this.handshakeTimer = setTimeout(() => {
      this.failSession(new PolyMeshError("HANDSHAKE_TIMEOUT", "Native v2 handshake did not complete in time", "protocol", true));
    }, this.handshakeTimeoutMs);
    this.sendRaw(init);
  }

  private receive(input: string | Uint8Array): void {
    const parsed = parseStrictJson(input, { maxBytes: MAX_FRAME_BYTES });
    if (!parsed.ok) {
      this.failSession(new PolyMeshError(parsed.code, parsed.error, parsed.code === "RESOURCE_EXHAUSTED" ? "resource" : "parse"));
      return;
    }
    const frame: unknown = parsed.value;
    if (this.profile === V2_PROTOCOL_VERSION) {
      void this.receiveNativeV2Record(frame);
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
    if (this.phase === "await_auth") return this.receiveAuth(frame);
    if (this.phase === "await_ready") return this.receiveReady(frame);
    if (this.phase === "active") this.receiveEnvelope(frame);
  }

  /** Dispatch the compact v2 init/ack, zstd, and application vocabulary. */
  private async receiveNativeV2Record(frame: unknown, decodedFromZstdWrapper = false): Promise<void> {
    if (!isObject(frame)) {
      this.nativeProtocolFailure("PMX.PROTOCOL.MALFORMED_FRAME", "Native v2 record must be an object");
      return;
    }
    if (frame.type === "v2.error") {
      const error = frame as unknown as V2ErrorFrame;
      if (error.profile !== V2_PROFILE || typeof error.code !== "string" || typeof error.message !== "string") {
        this.nativeProtocolFailure("PMX.PROTOCOL.MALFORMED_FRAME", "Native v2 error record is malformed");
        return;
      }
      if ((this.nativeMeshId !== undefined && error.mesh_id !== this.nativeMeshId) ||
        (this.nativeSessionId !== undefined && error.session_id !== undefined && error.session_id !== this.nativeSessionId)) {
        this.nativeProtocolFailure("PMX.ROUTING.MESH_MISMATCH", "Native v2 error does not match the selected mesh/session");
        return;
      }
      const failure = new PolyMeshError(error.code, error.message, "protocol", error.retryable === true);
      if (this.phase === "active") this.emit("protocolError", failure);
      else this.failSession(failure);
      return;
    }
    if (this.phase === "await_hello") {
      this.receiveNativeV2Ack(frame);
      return;
    }
    if (this.phase !== "active" && this.phase !== "await_ready") {
      this.nativeProtocolFailure("PMX.SESSION.HANDSHAKE", "Native v2 record arrived outside an active session");
      return;
    }
    if (frame.type === "zstd.ready") {
      this.receiveNativeZstdReady(frame);
      return;
    }
    if (frame.type === "zstd.wrapper") {
      await this.receiveNativeZstdWrapper(frame);
      return;
    }
    if (frame.type === "zstd.propose") {
      // The client is the compact handshake initiator. A peer proposal would
      // create an ambiguous second state machine, so reject it fail closed.
      this.nativeProtocolFailure("PMX.PROTOCOL.COMPRESSION", "Unexpected zstd proposal from native v2 responder");
      return;
    }
    if (this.phase !== "active") {
      this.nativeProtocolFailure("PMX.SESSION.HANDSHAKE", "Native v2 application traffic arrived before compression negotiation completed");
      return;
    }
    if (this.nativeZstd?.active && !decodedFromZstdWrapper) {
      this.nativeProtocolFailure("PMX.PROTOCOL.COMPRESSION", "Native v2 application traffic must use zstd.wrapper after compression activates");
      return;
    }
    this.receiveNativeEnvelope(frame);
  }

  private receiveNativeV2Ack(frame: Record<string, unknown>): void {
    const ack = frame as unknown as V2AckFrame;
    const selectedProfile = frame.selected_profile;
    if (!this.nativeInit || ack.type !== "v2.ack" || ack.profile !== V2_PROFILE ||
      (ack.protocol !== undefined && ack.protocol !== V2_PROFILE) ||
      (selectedProfile !== undefined && selectedProfile !== V2_PROFILE) ||
      !isUuidV7(ack.mesh_id) || !isUuidV7(ack.session_id) ||
      (ack.compression !== "zstd" && ack.compression !== "none") ||
      !this.nativeCompressionPreferences.includes(ack.compression)) {
      this.nativeProtocolFailure("PMX.SESSION.PROFILE", "Native v2 acknowledgement does not match the proposed profile");
      return;
    }
    this.nativeMeshId = ack.mesh_id;
    this.nativeSessionId = ack.session_id;
    if (isAgentId(ack.agent_id) && isInstanceId(ack.instance_id)) {
      // A native ack may omit broker identity. When it includes a plausible
      // pair, retain it for pings and observability without making it an
      // authorization assertion.
      this.peerIdentity = { agent_id: ack.agent_id, instance_id: ack.instance_id };
    }
    if (ack.compression === "zstd") {
      try {
        this.nativeZstd = new V2ZstdStateMachine({ meshId: ack.mesh_id, sessionId: ack.session_id }, "initiator");
      } catch {
        this.nativeProtocolFailure("PMX.PROTOCOL.COMPRESSION", "Could not initialize native v2 zstd negotiation");
        return;
      }
    }
    this.phase = "await_ready";
    if (this.nativeZstd) {
      try {
        this.sendRaw(this.nativeZstd.createPropose());
      } catch {
        this.nativeProtocolFailure("PMX.PROTOCOL.COMPRESSION", "Could not propose native v2 zstd compression");
        return;
      }
      return;
    }
    this.finishNativeV2Ready();
  }

  /** Complete v2 only after the selected compression mode is usable. */
  private finishNativeV2Ready(): void {
    if (this.phase === "active") return;
    if (this.phase !== "await_ready") {
      this.nativeProtocolFailure("PMX.SESSION.HANDSHAKE", "Native v2 session entered an invalid ready state");
      return;
    }
    this.clearHandshakeTimer();
    this.phase = "active";
    this.startHeartbeat();
    this.readyDeferred?.resolve(this);
    this.emit("ready", this);
  }

  private receiveNativeZstdReady(frame: unknown): void {
    const machine = this.nativeZstd;
    if (!machine) {
      this.nativeProtocolFailure("PMX.PROTOCOL.COMPRESSION", "zstd.ready arrived without a zstd selection");
      return;
    }
    try {
      machine.receiveReady(frame);
      this.sendRaw(machine.createReady());
      if (machine.active) this.finishNativeV2Ready();
    } catch (error) {
      this.nativeProtocolFailure("PMX.PROTOCOL.COMPRESSION", error instanceof Error ? error.message : "Native zstd ready is invalid");
    }
  }

  private async receiveNativeZstdWrapper(frame: unknown): Promise<void> {
    const machine = this.nativeZstd;
    if (!machine) {
      this.nativeProtocolFailure("PMX.PROTOCOL.COMPRESSION", "zstd.wrapper arrived without a zstd selection");
      return;
    }
    try {
      const decoded = await machine.unwrap(frame);
      const parsed = parseStrictJson(decoded, { maxBytes: MAX_FRAME_BYTES });
      if (!parsed.ok) {
        this.nativeProtocolFailure("PMX.PROTOCOL.COMPRESSION", "Native zstd wrapper did not contain strict JSON");
        return;
      }
      await this.receiveNativeV2Record(parsed.value, true);
    } catch (error) {
      this.nativeProtocolFailure("PMX.PROTOCOL.COMPRESSION", error instanceof Error ? error.message : "Native zstd wrapper is invalid");
    }
  }

  private nativeProtocolFailure(code: string, message: string): void {
    const error = new PolyMeshError(code, message, "protocol");
    this.failSession(error);
  }

  /** Convert a native envelope into the legacy internal lifecycle shape. */
  private receiveNativeEnvelope(frame: Record<string, unknown>): void {
    const envelope = this.nativeEnvelopeAsLegacy(frame);
    if (!envelope) {
      this.emit("protocolError", new PolyMeshError("PMX.PROTOCOL.ENVELOPE", "Peer sent an invalid native v2 envelope", "parse"));
      return;
    }
    this.receiveEnvelope(envelope, true);
  }

  private nativeEnvelopeAsLegacy(frame: Record<string, unknown>): Envelope | undefined {
    const type = frame.type;
    const messageId = frame.message_id;
    const timestamp = frame.timestamp;
    const source = frame.source;
    const target = frame.target;
    const delivery = frame.delivery;
    const rawParams = frame.params;
    const inReplyTo = frame.in_reply_to;
    if (!this.nativeMeshId || frame.protocol !== V2_PROFILE || frame.profile !== V2_PROFILE ||
      frame.mesh_id !== this.nativeMeshId || typeof type !== "string" || !isUuidV7(messageId) ||
      !isTimestamp(timestamp) || !isObject(source) || !isObject(target) ||
      !isObject(delivery) || !isObject(rawParams) || !isJsonValue(rawParams) ||
      (inReplyTo !== undefined && !isUuidV7(inReplyTo))) {
      return undefined;
    }
    if (!isAgentId(source.agent_id) || !isInstanceId(source.instance_id) ||
      !isAgentId(target.agent_id) ||
      (target.instance_id !== undefined && !isInstanceId(target.instance_id)) ||
      !isUuidV7(delivery.delivery_id) || delivery.mode !== "at_least_once" ||
      typeof delivery.idempotency_key !== "string" || !isTimestamp(delivery.deadline)) {
      return undefined;
    }
    const params = rawParams as JsonObject;
    let legacyParams: JsonObject;
    switch (type) {
      case "task.submit": {
        const taskId = params.task_id;
        const capability = params.capability;
        const input = params.input;
        const deadline = params.deadline;
        if (!isUuidV7(taskId) || typeof capability !== "string" || !isObject(input) || !isTimestamp(deadline) ||
          deadline !== delivery.deadline) return undefined;
        const version = typeof params.capability_version === "string" ? params.capability_version : "1.0.0";
        let inferred: CapabilityContractTuple;
        try {
          inferred = capabilityContractTuple({ id: capability, version });
        } catch {
          return undefined;
        }
        const digest = typeof params.capability_contract_digest === "string"
          ? params.capability_contract_digest
          : inferred.capability_contract_digest;
        legacyParams = {
          task_id: taskId,
          method: capability,
          capability_version: version,
          capability_contract_digest: digest,
          params: input as JsonObject,
          deadline,
        };
        break;
      }
      case "task.accepted":
        legacyParams = nativeLifecycleParams(params, ["task_id", "event_seq", "accepted_at"], true);
        break;
      case "task.rejected":
        legacyParams = nativeLifecycleParams(params, ["task_id", "event_seq", "code", "message"], false);
        break;
      case "task.progress":
        legacyParams = nativeLifecycleParams(params, ["task_id", "event_seq", "progress"], false);
        break;
      case "task.completed":
        legacyParams = nativeLifecycleParams(params, ["task_id", "event_seq", "terminal"], true);
        break;
      case "task.cancel":
        legacyParams = params.reason === undefined
          ? { task_id: params.task_id }
          : { task_id: params.task_id, reason: params.reason };
        break;
      case "task.status":
      case "ping":
      case "pong":
      case "receipt":
      case "card":
        legacyParams = { ...params };
        break;
      case "error":
        legacyParams = {
          category: typeof params.category === "string" ? params.category : "protocol",
          code: params.code,
          message: params.message,
          retryable: params.retryable,
          retry_after_ms: params.retry_after_ms ?? null,
          ...(params.details === undefined ? {} : { details: params.details }),
        };
        break;
      default:
        return undefined;
    }
    const legacy: Envelope = {
      protocol: PROTOCOL_VERSION,
      type: type as Envelope["type"],
      message_id: messageId,
      timestamp,
      source: { agent_id: source.agent_id, instance_id: source.instance_id },
      target: target.instance_id === undefined
        ? { agent_id: target.agent_id }
        : { agent_id: target.agent_id, instance_id: target.instance_id },
      delivery: {
        mode: "at_least_once",
        idempotency_key: delivery.idempotency_key,
        deadline: delivery.deadline,
      },
      ...(inReplyTo === undefined ? {} : { in_reply_to: inReplyTo }),
      params: legacyParams,
    };
    return isEnvelope(legacy) ? legacy : undefined;
  }

  private receiveHello(frame: unknown): void {
    const validated = validateHandshakeFrame(frame);
    if (validated.ok === false || validated.value.type !== "hello" || validated.value.role !== "responder") {
      this.failSession(new PolyMeshError("MALFORMED_FRAME", "Invalid responder hello", "protocol"));
      return;
    }
    const hello: HelloFrame = validated.value;
    if (this.identityProfile ? hello.security_profile !== SECURE_IDENTITY_PROFILE : hello.security_profile !== undefined) {
      this.failSession(new PolyMeshError("SECURITY_PROFILE_MISMATCH", "Responder selected an unexpected security profile", "identity"));
      return;
    }
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
    this.responderHello = hello;
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
    const validated = validateHandshakeFrame(frame);
    if (validated.ok === false || validated.value.type !== "card" || validated.value.sid !== this.sessionId || validated.value.for_nonce !== this.nonce) {
      this.failSession(new PolyMeshError("MALFORMED_FRAME", "Invalid broker card", "protocol"));
      return;
    }
    const cardFrame: CardFrame = validated.value;
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
    const profile = this.identityProfile;
    if (profile) {
      const principal = verifyEnrolledCard(cardFrame.card, profile.enrollments, this.now());
      if (!principal || !cardFrame.card.identity ||
        principal.agent_id !== this.peerIdentity!.agent_id ||
        principal.key_id !== cardFrame.card.identity.key_id) {
        this.failSession(new PolyMeshError("AUTHENTICATION_FAILED", "Broker Card is not signed by an enrolled identity", "identity"));
        return;
      }
      this.peerPrincipal = principal;
      this.phase = "await_auth";
      try {
        this.sendRaw(createAuthProof(
          profile.identity,
          this.card.agent_id,
          this.sessionId!,
          this.secureTranscript(),
          profile.privateKey,
        ));
      } catch {
        this.failSession(new PolyMeshError("AUTHENTICATION_FAILED", "Unable to construct a TLS-bound authentication proof", "identity"));
      }
      return;
    }
    this.phase = "await_ready";
    this.sendRaw({
      type: "ready",
      sid: this.sessionId,
      self_card: this.cardDigest,
      peer_card: this.peerCardDigest,
    });
  }

  private receiveAuth(frame: unknown): void {
    const validated = validateHandshakeFrame(frame);
    if (validated.ok === false || validated.value.type !== "auth" || validated.value.sid !== this.sessionId) {
      this.failSession(new PolyMeshError("AUTHENTICATION_FAILED", "Invalid broker authentication proof", "identity"));
      return;
    }
    const profile = this.identityProfile;
    const peerCard = this.peerCard;
    if (!profile || !peerCard?.identity || !this.peerPrincipal ||
      validated.value.agent_id !== peerCard.agent_id ||
      validated.value.key_id !== peerCard.identity.key_id) {
      this.failSession(new PolyMeshError("AUTHENTICATION_FAILED", "Authentication proof does not match the enrolled Card", "identity"));
      return;
    }
    let principal: EnrolledPrincipal | undefined;
    try {
      principal = verifyAuthProof(validated.value as AuthFrame, this.secureTranscript(), profile.enrollments, this.now());
    } catch {
      principal = undefined;
    }
    if (!principal || principal.agent_id !== this.peerPrincipal.agent_id || principal.key_id !== this.peerPrincipal.key_id) {
      this.failSession(new PolyMeshError("AUTHENTICATION_FAILED", "Broker did not prove possession of its enrolled key", "identity"));
      return;
    }
    this.peerPrincipal = principal;
    this.phase = "await_ready";
    this.sendRaw({
      type: "ready",
      sid: this.sessionId,
      self_card: this.cardDigest,
      peer_card: this.peerCardDigest,
    });
  }

  private secureTranscript(): Buffer {
    if (!this.initiatorHello || !this.responderHello || !this.peerCardDigest || !this.transport) {
      throw new TypeError("Secure handshake transcript is incomplete");
    }
    const binding = tlsChannelBinding(this.transport);
    if (!binding) throw new TypeError("TLS 1.3 channel binding is unavailable");
    return authTranscript({
      initiator_hello: this.initiatorHello,
      responder_hello: this.responderHello,
      initiator_card_digest: this.cardDigest,
      responder_card_digest: this.peerCardDigest,
      tls_channel_binding: binding,
    });
  }

  private receiveReady(frame: unknown): void {
    const validated = validateHandshakeFrame(frame);
    if (validated.ok === false || validated.value.type !== "ready" || validated.value.sid !== this.sessionId ||
      validated.value.self_card !== this.peerCardDigest || validated.value.peer_card !== this.cardDigest ||
      (this.identityProfile !== undefined && this.peerPrincipal === undefined)) {
      this.failSession(new PolyMeshError("MALFORMED_FRAME", "Ready transcript does not match", "protocol"));
      return;
    }
    const ready: ReadyFrame = validated.value;
    void ready; // Retains the named frame shape in the public source documentation.
    this.clearHandshakeTimer();
    this.phase = "active";
    this.startHeartbeat();
    this.readyDeferred?.resolve(this);
    this.emit("ready", this);
  }

  /**
   * The native v2 broker has already authenticated and fenced a mesh-scoped
   * record before it reaches this adapter.  Its source can be a routed peer,
   * so do not apply the legacy broker-source/provenance checks a second time.
   */
  private receiveEnvelope(frame: unknown, native = false): void {
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
    if (!native && (envelope.type === "ping" || envelope.type === "pong" || envelope.type === "receipt") && !this.isBrokerSource(envelope.source)) {
      this.emit("protocolError", new PolyMeshError("SOURCE_IDENTITY_MISMATCH", "Control record was not sent by the authenticated broker", "identity"));
      return;
    }
    // A secure broker session authenticates the broker, not arbitrary source
    // claims it forwards. Every routed record that can affect policy, task,
    // cancellation, lifecycle, or error state therefore needs a fresh,
    // target-session-bound broker signature before it reaches a handler.
    if (!native && this.identityProfile && requiresRoutedProvenance(envelope.type) && !this.isBrokerSource(envelope.source) &&
      !this.hasValidRoutedProvenance(envelope)) {
      this.emit("protocolError", new PolyMeshError("ROUTED_PROVENANCE_INVALID", "Routed record lacks valid broker provenance", "identity"));
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
      case "receipt":
        // Receipt validation happens in the closed protocol validator above.
        // It is observability-only: no task, replay, or pending-call state is
        // changed from a peer-controlled acknowledgement.
        this.emit("receipt", envelope as Envelope<"receipt", ReceiptParams>);
        break;
      case "error":
        this.handleErrorEnvelope(envelope as Envelope<"error">);
        break;
      default:
        break;
    }
    this.emit("envelope", envelope);
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
    const attempts = [...(this.pendingByTask.get(taskId) ?? [])]
      .filter((attempt) => !attempt.terminal && sameIdentity(envelope.source, attempt.target));
    if (attempts.length === 0) {
      this.emit("protocolError", new PolyMeshError("SOURCE_IDENTITY_MISMATCH", "Lifecycle event was not sent by the expected executor", "identity"));
      return;
    }
    if (envelope.type === "task.accepted" || envelope.type === "task.rejected") {
      const pending = envelope.in_reply_to ? this.pendingByMessage.get(envelope.in_reply_to) : undefined;
      if (!pending || pending.taskId !== taskId || pending.terminal || !sameIdentity(envelope.source, pending.target)) {
        this.emit("protocolError", new PolyMeshError("PMX.TASK.FORGED_RESULT", "Admission event did not exactly correlate to a pending submission", "task"));
        return;
      }
      if (eventSeq === pending.lastEventSeq) return; // retransmission
      if (eventSeq !== 1 || pending.lastEventSeq !== 0) {
        this.finishPending(pending, new PolyMeshError("PMX.TASK.EVENT_CONFLICT", "Task admission sequence is invalid", "task", false, { task_id: taskId }));
        return;
      }
      pending.lastEventSeq = eventSeq;
      if (envelope.type === "task.accepted") {
        const echoedContract = capabilityContractFromParams(envelope.params as Record<string, unknown>);
        if (!echoedContract || !sameCapabilityContract(pending.contract, echoedContract)) {
          this.finishPending(pending, new PolyMeshError(
            "PMX.TASK.CONTRACT_MISMATCH",
            "Executor accepted a capability contract different from the one submitted",
            "protocol",
            false,
            { task_id: taskId },
          ));
          return;
        }
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
      this.synchronizeReplayAdmissions(attempts, eventSeq);
      for (const pending of attempts) {
        if (eventSeq === pending.lastEventSeq) continue; // retransmission
        if (!pending.accepted || eventSeq !== pending.lastEventSeq + 1) {
          this.finishPending(pending, new PolyMeshError("PMX.TASK.EVENT_CONFLICT", "Progress event is not causally contiguous", "task", false, { task_id: taskId }));
          continue;
        }
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
      const echoedContract = capabilityContractFromParams(envelope.params as Record<string, unknown>);
      if (!echoedContract) {
        for (const pending of attempts) this.finishPending(pending, new PolyMeshError("PMX.TASK.CONTRACT_MISMATCH", "Terminal event has no valid capability contract", "protocol", false, { task_id: taskId }));
        return;
      }
      this.synchronizeReplayAdmissions(attempts, eventSeq);
      for (const pending of attempts) {
        if (!sameCapabilityContract(pending.contract, echoedContract)) {
          this.finishPending(pending, new PolyMeshError(
            "PMX.TASK.CONTRACT_MISMATCH",
            "Terminal event does not match the submitted capability contract",
            "protocol",
            false,
            { task_id: taskId },
          ));
          continue;
        }
        if (eventSeq === pending.lastEventSeq) continue; // retransmission
        if (!pending.accepted || eventSeq !== pending.lastEventSeq + 1) {
          this.finishPending(pending, new PolyMeshError("PMX.TASK.EVENT_CONFLICT", "Terminal event is not causally contiguous", "task", false, { task_id: taskId }));
          continue;
        }
        pending.lastEventSeq = eventSeq;
        if (terminal.outcome === "succeeded" && "result" in terminal) {
          const result = terminal.result;
          if (!isJsonValue(result)) {
            this.finishPending(pending, new PolyMeshError("RESULT_SCHEMA_INVALID", "Terminal result is not valid JSON", "execution", false, { task_id: taskId }));
            continue;
          }
          const resultBytes = jsonBytes(result);
          if (resultBytes === undefined || resultBytes > this.maxResultBytes || !matchesSchema(pending.resultSchema, result)) {
            this.finishPending(pending, new PolyMeshError("RESULT_SCHEMA_INVALID", "Terminal result does not satisfy the pinned result contract", "execution", false, { task_id: taskId }));
          } else {
            this.finishPending(pending, undefined, result);
          }
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

  /**
   * A retransmitted submit can receive its canonical terminal event before a
   * broker has replayed the corresponding admission.  An already admitted
   * attempt for the same task and verified executor supplies the causal chain;
   * inherit only its contiguous sequence, never a peer-provided jump.
   */
  private synchronizeReplayAdmissions(attempts: PendingCall[], eventSeq: number): void {
    const admitted = attempts.filter((attempt) => attempt.accepted);
    if (admitted.length === 0) return;
    const inheritedSequence = Math.max(...admitted.map((attempt) => attempt.lastEventSeq));
    if (inheritedSequence < 1 || eventSeq !== inheritedSequence + 1) return;
    for (const pending of attempts) {
      if (!pending.accepted) {
        pending.accepted = true;
        pending.lastEventSeq = inheritedSequence;
      }
    }
  }

  private handleErrorEnvelope(envelope: Envelope<"error">): void {
    const params = envelope.params as Record<string, unknown>;
    const pending = envelope.in_reply_to ? this.pendingByMessage.get(envelope.in_reply_to) : undefined;
    // Error detail fields are diagnostics only.  They must never select or
    // settle a task; only an exact reply correlation can do that.
    if (!pending || pending.terminal) {
      this.emit("protocolError", new PolyMeshError("PMX.TASK.FORGED_ERROR", "Error did not exactly correlate to a pending submission", "task"));
      return;
    }
    if (!sameIdentity(envelope.source, pending.target) && !this.isBrokerSource(envelope.source)) {
      this.emit("protocolError", new PolyMeshError("SOURCE_IDENTITY_MISMATCH", "Error was not sent by the expected executor or broker", "identity"));
      return;
    }
    const category = typeof params.category === "string" ? params.category as ErrorCategory : "protocol";
    const error = new PolyMeshError(
      typeof params.code === "string" ? params.code : "PROTOCOL_ERROR",
      typeof params.message === "string" ? params.message : "Broker returned an error",
      category,
      params.retryable === true,
      { task_id: pending.taskId },
    );
    this.finishPending(pending, error);
  }

  private async handleSubmit(envelope: Envelope<"task.submit">): Promise<void> {
    const params = envelope.params as Record<string, unknown>;
    const taskId = typeof params.task_id === "string" ? params.task_id : undefined;
    const method = typeof params.method === "string" ? params.method : undefined;
    const input = isObject(params.params) ? params.params as JsonObject : undefined;
    const deadline = typeof params.deadline === "string" ? params.deadline : undefined;
    if (!taskId || !method || !input || !deadline) return;
    if (envelope.delivery.deadline !== deadline || !isTimestamp(deadline)) {
      this.sendTaskError(envelope, "PMX.TASK.DEADLINE_MISMATCH", "Delivery and task deadlines must match exactly");
      return;
    }
    const deadlineMs = Date.parse(deadline);
    if (deadlineMs <= this.now() || deadlineMs > this.now() + this.maxTaskTimeoutMs) {
      this.sendTaskError(envelope, "PMX.TASK.DEADLINE_EXCEEDED", "Task deadline is expired or exceeds the configured maximum");
      return;
    }
    const inputBytes = isJsonValue(input) ? jsonBytes(input) : undefined;
    if (inputBytes === undefined || inputBytes > this.maxTaskInputBytes) {
      this.sendTaskError(envelope, "INPUT_TOO_LARGE", "Task input exceeds the configured byte limit");
      return;
    }
    this.pruneInboundDedupe();
    this.pruneLocalTasks();
    const capability = this.card.capabilities.find((candidate) => candidate.id === method);
    const handler = this.handlers.get(method) ?? this.standardHandler(method);
    const durableReplayRequired = this.requiresDurableReplayProtection(capability, method);
    const configuredLedger = this.replayLedger;
    const replayPrincipal = configuredLedger || durableReplayRequired
      ? await this.resolveStableReplayPrincipal(envelope)
      : undefined;
    if (durableReplayRequired &&
      (!configuredLedger || configuredLedger.durable !== true || replayPrincipal === undefined)) {
      this.sendRejected(envelope, "REPLAY_PROTECTION_UNAVAILABLE", "Secure side-effecting work requires a durable replay ledger and verified stable principal");
      return;
    }
    const useReplayLedger = configuredLedger !== undefined && replayPrincipal !== undefined;
    const fingerprint = canonicalize({
      method,
      capability_version: params.capability_version as JsonValue,
      capability_contract_digest: params.capability_contract_digest as JsonValue,
      params: input,
      deadline,
    });
    const dedupeKey = this.inboundDedupeKey(envelope);
    const deliveryFingerprint = this.inboundFingerprint(envelope);
    if (!useReplayLedger) {
      const priorDelivery = this.inboundDedupe.get(dedupeKey);
      if (priorDelivery) {
        if (priorDelivery.fingerprint !== deliveryFingerprint) {
          this.sendTaskError(envelope, "PMX.DELIVERY.IDEMPOTENCY_CONFLICT", "Idempotency key was reused with different message semantics");
        } else {
          this.replayEvents(priorDelivery.events, envelope.message_id, envelope.source);
        }
        return;
      }
      const existing = this.findLocalTask(taskId, envelope.source);
      if (existing) {
        if (existing.fingerprint !== fingerprint || existing.source.agent_id !== envelope.source.agent_id || existing.source.instance_id !== envelope.source.instance_id) {
          this.sendTaskError(envelope, "PMX.TASK.ID_CONFLICT", "Task id was reused with different immutable input");
        } else {
          if (this.rememberInboundDedupe(dedupeKey, deliveryFingerprint, taskId, existing.events)) {
            this.replayEvents(existing.events, envelope.message_id, envelope.source);
          } else {
            this.sendTaskError(envelope, "OVERLOADED", "Inbound replay state is at capacity");
          }
        }
        return;
      }
    }
    if (!useReplayLedger && (this.localTasks.size >= this.maxLocalTasks || this.inboundDedupe.size >= this.maxInboundDedupeEntries)) {
      this.sendTaskError(envelope, "OVERLOADED", "Task admission state is at capacity");
      return;
    }
    if (!handler || !capability) {
      const rejection = this.sendRejected(envelope, "UNSUPPORTED_CAPABILITY", `Agent does not implement ${method}`);
      this.rememberInboundDedupe(dedupeKey, deliveryFingerprint, taskId, [rejection]);
      return;
    }
    const submittedContract = capabilityContractFromParams({
      capability_id: method,
      capability_version: params.capability_version,
      capability_contract_digest: params.capability_contract_digest,
    });
    const advertisedContract = capabilityContractTuple(capability);
    if (!submittedContract || !sameCapabilityContract(submittedContract, advertisedContract)) {
      const rejection = this.sendRejected(envelope, "CAPABILITY_CONTRACT_MISMATCH", "Task capability contract does not match the advertised capability");
      this.rememberInboundDedupe(dedupeKey, deliveryFingerprint, taskId, [rejection]);
      return;
    }
    const capabilityTimeoutMs = (capability.timeout_ceiling_seconds ?? 300) * 1_000;
    if (deadlineMs > this.now() + Math.min(this.maxTaskTimeoutMs, capabilityTimeoutMs)) {
      const rejection = this.sendRejected(envelope, "PMX.TASK.DEADLINE_EXCEEDED", "Task deadline exceeds the advertised capability timeout ceiling");
      this.rememberInboundDedupe(dedupeKey, deliveryFingerprint, taskId, [rejection]);
      return;
    }
    if (!matchesSchema(capability.input_schema, input)) {
      const rejection = this.sendRejected(envelope, "INVALID_INPUT", "Task input does not satisfy the capability input schema");
      this.rememberInboundDedupe(dedupeKey, deliveryFingerprint, taskId, [rejection]);
      return;
    }
    let executionInput = input;
    let policy: TaskPolicyAuthorization | undefined;
    const policyEngine = this.policyEngine;
    const resolveVerifiedPrincipal = this.resolveVerifiedPrincipal;
    const policyTargetPrincipal = this.policyTargetPrincipal;
    if (policyEngine && resolveVerifiedPrincipal && policyTargetPrincipal) {
      try {
        const principal = await resolveVerifiedPrincipal({ source: envelope.source, envelope });
        if (!isVerifiedPrincipal(principal)) throw new TypeError("Principal resolver returned an invalid principal");
        const policyDecision = await policyEngine.authorize({
          principal,
          targetPrincipal: policyTargetPrincipal,
          capability: method,
          input,
          taskId,
          messageId: envelope.message_id,
        });
        if (!isPolicyAuthorizationDecision(policyDecision) || policyDecision.effect !== "allow") {
          throw new PolyMeshError("AUTHORIZATION_DENIED", "Policy denied this task", "identity");
        }
        const constrainedInput = policyDecision.constrainedInput;
        const constrainedBytes = isJsonValue(constrainedInput) ? jsonBytes(constrainedInput) : undefined;
        if (!isObject(constrainedInput) || constrainedBytes === undefined || constrainedBytes > this.maxTaskInputBytes ||
          !matchesSchema(capability.input_schema, constrainedInput)) {
          throw new PolyMeshError("AUTHORIZATION_DENIED", "Policy produced an invalid scoped task input", "identity");
        }
        const context: TaskPolicyAuthorization["context"] = {
          principal,
          targetPrincipal: policyTargetPrincipal,
          capability: method,
        };
        if (!policyEngine.validateLease(policyDecision.leaseId, context, policyDecision.lease.fence)) {
          throw new PolyMeshError("AUTHORIZATION_DENIED", "Authorization lease is not valid", "identity");
        }
        executionInput = constrainedInput;
        policy = { engine: policyEngine, decision: policyDecision, context };
      } catch {
        const rejection = this.sendRejected(envelope, "AUTHORIZATION_DENIED", `Caller is not authorized for ${method}`);
        this.rememberInboundDedupe(dedupeKey, deliveryFingerprint, taskId, [rejection]);
        return;
      }
    } else {
      // Backwards-compatible explicit callback path.  It is never consulted
      // when a PolicyEngine is configured, so a resolver/policy failure cannot
      // silently turn into a legacy authorization decision.
      let decision: unknown;
      try {
        decision = await this.authorize({ source: envelope.source, capability: method, input, envelope });
      } catch {
        decision = undefined;
      }
      if (!isAuthorizationDecision(decision) || decision.effect !== "allow") {
        const rejection = this.sendRejected(envelope, "AUTHORIZATION_DENIED", `Caller is not authorized for ${method}`);
        this.rememberInboundDedupe(dedupeKey, deliveryFingerprint, taskId, [rejection]);
        return;
      }
    }
    // Authorizers may be asynchronous.  Re-check expiry immediately before
    // durable admission and handler start so delayed policy work cannot make
    // an expired task executable.
    if (deadlineMs <= this.now()) {
      const rejection = this.sendRejected(envelope, "PMX.TASK.DEADLINE_EXCEEDED", "Task deadline elapsed during authorization");
      this.rememberInboundDedupe(dedupeKey, deliveryFingerprint, taskId, [rejection]);
      return;
    }
    let replay: TaskReplayAdmission | undefined;
    if (configuredLedger && replayPrincipal) {
      try {
        const admission = await configuredLedger.admit({
          principal: replayPrincipal,
          target: this.identity(),
          envelope,
          taskId,
          now: this.now(),
          expiresAt: Math.max(deadlineMs, this.now()) + this.idempotencyRetentionMs,
        });
        if (admission.disposition !== "new") {
          if (admission.disposition === "duplicate") {
            if (admission.record.artifacts.events.length > 0) {
              this.replayEvents(admission.record.artifacts.events as Envelope[], envelope.message_id, envelope.source);
            } else {
              this.sendTaskError(envelope, "REPLAY_IN_PROGRESS", "A matching task is durably admitted but has no replayable outcome yet");
            }
          } else if (admission.disposition === "message-conflict") {
            this.sendTaskError(envelope, "PMX.DELIVERY.MESSAGE_ID_CONFLICT", "Message ID was reused with different semantics");
          } else if (admission.disposition === "idempotency-conflict") {
            this.sendTaskError(envelope, "PMX.DELIVERY.IDEMPOTENCY_CONFLICT", "Idempotency key was reused with different semantics");
          } else if (admission.disposition === "task-conflict") {
            this.sendTaskError(envelope, "PMX.TASK.ID_CONFLICT", "Task ID was reused with different immutable input");
          } else {
            this.sendTaskError(envelope, "OVERLOADED", "Replay ledger capacity is exhausted");
          }
          return;
        }
        replay = { ledger: configuredLedger, record: admission.record };
      } catch {
        this.sendRejected(envelope, "REPLAY_PROTECTION_UNAVAILABLE", "Replay admission could not be committed before task execution");
        return;
      }
    }
    if (this.localTasks.size >= this.maxLocalTasks) {
      this.sendTaskError(envelope, "OVERLOADED", "Task admission state is at capacity");
      return;
    }
    const task: LocalTask = {
      storageKey: this.localTaskStorageKey(taskId, envelope.source, replay),
      taskId,
      fingerprint,
      source: envelope.source,
      target: envelope.target,
      contract: advertisedContract,
      deadline,
      resultSchema: capability.result_schema,
      submitMessageId: envelope.message_id,
      events: [],
      nextEventSeq: 1,
      progressEvents: 0,
      terminal: false,
      controller: new AbortController(),
      retentionExpiresAt: Math.max(deadlineMs, this.now()) + this.idempotencyRetentionMs,
      ...(policy === undefined ? {} : { policy }),
      ...(replay === undefined ? {} : { replay }),
    };
    this.localTasks.set(task.storageKey, task);
    if (!useReplayLedger && !this.rememberInboundDedupe(dedupeKey, deliveryFingerprint, taskId, task.events)) {
      this.localTasks.delete(task.storageKey);
      this.sendTaskError(envelope, "OVERLOADED", "Inbound replay state is at capacity");
      return;
    }
    this.emitTaskEvent(task, "task.accepted", {
      task_id: taskId,
      event_seq: task.nextEventSeq++,
      accepted_at: new Date(this.now()).toISOString(),
      ...task.contract,
    }, envelope.message_id);
    if (task.replayWrite) {
      try {
        await task.replayWrite;
      } catch {
        this.localTasks.delete(task.storageKey);
        task.terminal = true;
        this.sendTaskError(envelope, "REPLAY_PROTECTION_UNAVAILABLE", "Admission artifact could not be durably stored");
        return;
      }
    }
    const remainingMs = Math.max(1, deadlineMs - this.now());
    task.deadlineTimer = setTimeout(() => {
      if (task.terminal) return;
      task.controller.abort();
      this.finishLocalTask(task, "cancelled", { code: "PMX.TASK.DEADLINE_EXCEEDED" });
    }, remainingMs);
    task.deadlineTimer.unref?.();
    const context: TaskContext = {
      taskId,
      source: envelope.source,
      deadline,
      signal: task.controller.signal,
      progress: (progress) => {
        if (task.terminal || task.progressEvents >= this.maxProgressEventsPerTask || !isObject(progress) || !isJsonValue(progress)) return;
        const visibleProgress = task.policy === undefined
          ? progress as JsonValue
          : this.filterPolicyArtifact(task.policy, progress as JsonValue);
        if (visibleProgress === undefined || !isObject(visibleProgress)) return;
        const progressBytes = jsonBytes(visibleProgress);
        if (progressBytes === undefined || progressBytes > this.maxTaskInputBytes) return;
        task.progressEvents += 1;
        this.emitTaskEvent(task, "task.progress", {
          task_id: taskId,
          event_seq: task.nextEventSeq++,
          progress: visibleProgress as JsonObject,
        });
      },
    };
    try {
      if (task.policy && !this.isPolicyLeaseValid(task.policy)) {
        this.finishLocalTask(task, "failed", undefined, {
          code: "AUTHORIZATION_DENIED",
          message: "Authorization lease expired or was revoked before execution",
        });
        return;
      }
      const handlerInput = immutableJsonObject(executionInput);
      const result = await handler(handlerInput, context);
      if (!task.terminal) this.finishLocalTask(task, "succeeded", result);
    } catch (error) {
      if (!task.terminal) this.finishLocalTask(task, "failed", error);
    }
  }

  private handleCancel(envelope: Envelope<"task.cancel">): void {
    const taskId = taskIdFrom(envelope);
    if (!taskId) return;
    const task = this.findLocalTask(taskId, envelope.source);
    if (!task) {
      this.sendErrorFor(envelope, "PMX.TASK.NOT_FOUND", "No task is eligible for cancellation", "task");
      return;
    }
    if (!sameIdentity(envelope.source, task.source) ||
      envelope.target.agent_id !== this.card.agent_id ||
      (envelope.target.instance_id !== undefined && envelope.target.instance_id !== this.card.instance_id)) {
      this.sendErrorFor(envelope, "AUTHORIZATION_DENIED", "Only the authenticated task owner may cancel this task", "identity");
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

  /**
   * Resolve a submission contract from a verified target card or an explicit
   * caller pin. The enrolled-key profile deliberately has no fallback: a
   * routed target that has not been card-verified cannot be invoked safely.
   *
   * The small legacy loopback API retains a clearly bounded compatibility
   * tuple for existing local examples that only advertised the protocol's
   * default 1.0.0/no-schema contract. An executor still compares it to its
   * card before handler admission, so non-default legacy capabilities must
   * be supplied explicitly through `capabilityContract`.
   */
  private resolveCallCapabilityContract(
    targetAgentId: string,
    method: string,
    options: CallOptions,
  ): ResolvedCapabilityContract {
    const explicit = options.capabilityContract;
    if (explicit !== undefined) {
      if (explicit.id !== method) throw new TypeError("capabilityContract.id must match the requested capability");
      const tuple = capabilityContractTuple(explicit);
      if (options.capabilityVersion !== undefined && options.capabilityVersion !== tuple.capability_version) {
        throw new TypeError("capabilityVersion does not match capabilityContract.version");
      }
      if (options.capabilityContractDigest !== undefined && options.capabilityContractDigest !== tuple.capability_contract_digest) {
        throw new TypeError("capabilityContractDigest does not match capabilityContract");
      }
      return { tuple, capability: explicit };
    }

    const peerCapability = this.peerIdentity?.agent_id === targetAgentId
      ? this.peerCard?.capabilities.find((entry) => entry.id === method)
      : undefined;
    if (peerCapability !== undefined) {
      const tuple = capabilityContractTuple(peerCapability);
      if (options.capabilityVersion !== undefined && options.capabilityVersion !== tuple.capability_version) {
        throw new TypeError("capabilityVersion does not match the authenticated target card");
      }
      if (options.capabilityContractDigest !== undefined && options.capabilityContractDigest !== tuple.capability_contract_digest) {
        throw new TypeError("capabilityContractDigest does not match the authenticated target card");
      }
      return { tuple, capability: peerCapability };
    }

    if (this.identityProfile) {
      throw new PolyMeshError(
        "CAPABILITY_CONTRACT_REQUIRED",
        "Enrolled secure sessions require a capability contract from a verified target card",
        "protocol",
      );
    }

    if (options.capabilityVersion !== undefined || options.capabilityContractDigest !== undefined) {
      const tuple = {
        capability_id: method,
        capability_version: options.capabilityVersion,
        capability_contract_digest: options.capabilityContractDigest,
      };
      if (!isCapabilityContractTuple(tuple)) {
        throw new TypeError("capabilityVersion and capabilityContractDigest must form a valid capability contract tuple");
      }
      return { tuple };
    }

    // Explicitly limited legacy compatibility: only the default 1.0.0
    // contract can be inferred. Any schema, side-effect, or version change
    // makes the executor reject this tuple before it invokes a handler.
    const legacy = { id: method, version: "1.0.0" } satisfies Capability;
    return { tuple: capabilityContractTuple(legacy), capability: legacy };
  }

  private resultSchemaFor(targetAgentId: string, capability: string): JsonObject | undefined {
    // A broker-local call has a card authenticated on this session. Routed
    // calls must provide a pinned result schema through CallOptions until the
    // secure card-discovery profile supplies a separately verified peer card.
    if (!this.peerCard || !this.peerIdentity || targetAgentId !== this.peerIdentity.agent_id) return undefined;
    return this.peerCard.capabilities.find((entry) => entry.id === capability)?.result_schema;
  }

  private isBrokerSource(source: AgentIdentity): boolean {
    return this.peerIdentity !== undefined &&
      source.agent_id === this.peerIdentity.agent_id &&
      source.instance_id === this.peerIdentity.instance_id;
  }

  /** Re-check the broker card/enrollment and verify its per-route signature. */
  private hasValidRoutedProvenance(envelope: Envelope): boolean {
    const profile = this.identityProfile;
    const card = this.peerCard;
    const identity = this.peerIdentity;
    const establishedPrincipal = this.peerPrincipal;
    const sessionId = this.sessionId;
    if (!profile || !card || !identity || !establishedPrincipal || !sessionId) return false;
    const enrolledBroker = verifyEnrolledCard(card, profile.enrollments, this.now());
    if (!enrolledBroker || enrolledBroker.agent_id !== establishedPrincipal.agent_id ||
      enrolledBroker.key_id !== establishedPrincipal.key_id ||
      identity.agent_id !== enrolledBroker.agent_id) {
      return false;
    }
    return verifyRoutedProvenance(envelope, {
      brokerPrincipal: enrolledBroker,
      brokerIdentity: identity,
      targetSessionId: sessionId,
      now: this.now(),
    });
  }

  /** A revoked, expired, or stale-generation lease may never release data. */
  private isPolicyLeaseValid(policy: TaskPolicyAuthorization): boolean {
    return policy.engine.validateLease(policy.decision.leaseId, policy.context, policy.decision.lease.fence);
  }

  /**
   * Policy filters are the sole output transform on the integrated path. A
   * failure is indistinguishable from a revoked lease to callers: no raw value
   * is retained in an event, cache, or outbound frame.
   */
  private filterPolicyArtifact(policy: TaskPolicyAuthorization, value: JsonValue): JsonValue | undefined {
    if (!this.isPolicyLeaseValid(policy)) return undefined;
    return policy.engine.filterForRelease(policy.decision.leaseId, policy.context, value);
  }

  /**
   * A secure identity or policy deployment may never execute an undeclared or
   * side-effecting capability behind a process-local replay cache. An absent
   * side-effect declaration follows the Card's conservative protocol default
   * of no side effects; an unadvertised capability is still treated as risky.
   */
  private requiresDurableReplayProtection(
    capability: AgentCard["capabilities"][number] | undefined,
    method: string,
  ): boolean {
    if (!this.identityProfile && !this.policyEngine) return false;
    if (STANDARD_METHODS.has(method)) return false;
    if (!capability) return true;
    if (capability.idempotency === "sensitive") return true;
    return capability.side_effects === "write" || capability.side_effects === "network" || capability.side_effects === "approval";
  }

  /**
   * Resolve a stable principal only through a caller-supplied trusted bridge,
   * the already-required policy principal resolver, or a direct enrolled peer
   * session.  Envelope identity assertions are never used as a fallback.
   */
  private async resolveStableReplayPrincipal(envelope: Envelope<"task.submit">): Promise<ReplayPrincipal | undefined> {
    try {
      if (this.resolveReplayPrincipal) {
        const principal = await this.resolveReplayPrincipal({ source: envelope.source, envelope });
        return isReplayPrincipal(principal) ? principal : undefined;
      }
      if (this.resolveVerifiedPrincipal) {
        const verified = await this.resolveVerifiedPrincipal({ source: envelope.source, envelope });
        return isVerifiedPrincipal(verified) ? replayPrincipalFromVerified(verified) : undefined;
      }
      if (this.peerPrincipal && this.peerIdentity && sameIdentity(envelope.source, this.peerIdentity)) {
        return replayPrincipalFromVerified({
          principalId: this.peerPrincipal.principal_id,
          ...(this.peerPrincipal.key_id === undefined ? {} : { keyId: this.peerPrincipal.key_id }),
        });
      }
    } catch {
      // Resolver failures are handled as a fail-closed replay-protection
      // failure by the caller when a secure side-effecting task is involved.
    }
    return undefined;
  }

  private localTaskStorageKey(taskId: string, source: AgentIdentity, replay?: TaskReplayAdmission): string {
    return replay?.record.keys.task ?? `${source.agent_id}\0${source.instance_id}\0${taskId}`;
  }

  private findLocalTask(taskId: string, source: AgentIdentity): LocalTask | undefined {
    for (const task of this.localTasks.values()) {
      if (task.taskId === taskId && sameIdentity(task.source, source)) return task;
    }
    return undefined;
  }

  /** Persist the complete recipient-visible replay artifact before sending it. */
  private queueReplayArtifact(task: LocalTask, envelope: Envelope): Promise<void> {
    if (!task.replay) {
      this.sendEnvelope(envelope);
      return Promise.resolve();
    }
    const previous = task.replayWrite ?? Promise.resolve();
    const write = previous.then(async () => {
      await task.replay!.ledger.recordArtifacts({
        taskKey: task.replay!.record.keys.task,
        artifacts: { events: task.events, terminal: task.terminal },
        expiresAt: task.retentionExpiresAt,
      });
      this.sendEnvelope(envelope);
    });
    task.replayWrite = write;
    void write.catch(() => {
      task.replayWriteFailed = true;
      task.controller.abort();
    });
    return write;
  }

  private inboundDedupeKey(envelope: Envelope<"task.submit">): string {
    return [
      envelope.source.agent_id,
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

  private rememberInboundDedupe(key: string, fingerprint: string, taskId: string, events: Envelope[]): boolean {
    const existing = this.inboundDedupe.get(key);
    if (existing) return existing.fingerprint === fingerprint;
    if (this.inboundDedupe.size >= this.maxInboundDedupeEntries) return false;
    this.inboundDedupe.set(key, {
      fingerprint,
      taskId,
      events,
      expiresAt: this.now() + this.idempotencyRetentionMs,
    });
    return true;
  }

  private pruneInboundDedupe(): void {
    const now = this.now();
    for (const [key, record] of this.inboundDedupe) {
      if (record.expiresAt <= now) this.inboundDedupe.delete(key);
    }
  }

  private pruneLocalTasks(): void {
    const now = this.now();
    for (const [storageKey, task] of this.localTasks) {
      if (!task.terminal && Date.parse(task.deadline) <= now) {
        task.controller.abort();
        this.finishLocalTask(task, "cancelled", { code: "PMX.TASK.DEADLINE_EXCEEDED" });
      }
      if (task.terminal && task.retentionExpiresAt <= now) {
        if (task.deadlineTimer) clearTimeout(task.deadlineTimer);
        this.localTasks.delete(storageKey);
      }
    }
  }

  /** Replay lifecycle records while correlating a replayed admission to this submission. */
  private replayEvents(events: readonly Envelope[], submitMessageId: string, recipient?: AgentIdentity): void {
    for (const event of events) {
      const inReplyTo = event.type === "task.accepted" || event.type === "task.rejected"
        ? submitMessageId
        : event.in_reply_to;
      const replay: Envelope = {
        ...event,
        message_id: uuidv7(this.now()),
        timestamp: new Date(this.now()).toISOString(),
        ...(recipient === undefined ? {} : {
          target: { agent_id: recipient.agent_id, instance_id: recipient.instance_id },
        }),
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
    this.sendErrorFor(submit, code, message, "task");
  }

  private sendErrorFor(envelope: Envelope, code: string, message: string, category: ErrorCategory): void {
    this.sendEnvelope(createEnvelope({
      type: "error",
      source: this.identity(),
      target: envelope.source,
      delivery: {
        mode: "at_least_once",
        idempotency_key: `error:${envelope.message_id}`,
        deadline: envelope.delivery.deadline,
      },
      in_reply_to: envelope.message_id,
      params: { category, code, message, retryable: false, retry_after_ms: null },
    }));
  }

  private finishLocalTask(
    task: LocalTask,
    outcome: "succeeded" | "failed" | "cancelled",
    value: unknown,
    controlledFailure?: { code: string; message: string },
  ): void {
    if (task.terminal) return;
    let finalOutcome = outcome;
    let finalFailure = controlledFailure;
    if (outcome === "succeeded" && task.policy && !this.isPolicyLeaseValid(task.policy)) {
      finalOutcome = "failed";
      finalFailure = {
        code: "AUTHORIZATION_DENIED",
        message: "Authorization lease expired or was revoked before result release",
      };
    }
    const terminal: Record<string, JsonValue> = {
      completed_at: new Date(this.now()).toISOString(),
    };
    if (finalOutcome === "succeeded") {
      let normalized: JsonValue | undefined;
      let failure: { code: string; message: string } | undefined;
      try {
        if (typeof value === "string" && Buffer.byteLength(value, "utf8") > this.maxResultBytes) {
          failure = { code: "RESULT_TOO_LARGE", message: "Handler result exceeds the configured result limit" };
        }
        if (!failure && !isJsonValue(value)) throw new TypeError("Result is not bounded JSON");
        const serialized = JSON.stringify(value);
        if (typeof serialized !== "string") failure = { code: "RESULT_SCHEMA_INVALID", message: "Handler result is not JSON-serializable" };
        else if (Buffer.byteLength(serialized, "utf8") > this.maxResultBytes) failure = { code: "RESULT_TOO_LARGE", message: "Handler result exceeds the configured result limit" };
        else {
          const parsed = parseStrictJson(serialized, { maxBytes: this.maxResultBytes });
          if (!parsed.ok) failure = { code: "RESULT_SCHEMA_INVALID", message: "Handler result is not valid bounded JSON" };
          else normalized = parsed.value;
        }
      } catch {
        failure = { code: "RESULT_SCHEMA_INVALID", message: "Handler result is not JSON-serializable" };
      }
      if (!failure && (!isJsonValue(normalized) || !matchesSchema(task.resultSchema, normalized))) {
        failure = { code: "RESULT_SCHEMA_INVALID", message: "Handler result does not satisfy the capability result schema" };
      }
      if (!failure && task.policy) {
        const filtered = this.filterPolicyArtifact(task.policy, normalized!);
        if (filtered === undefined || !isJsonValue(filtered)) {
          failure = { code: "AUTHORIZATION_DENIED", message: "Authorization lease expired or was revoked before result release" };
        } else {
          normalized = filtered;
        }
      }
      // The filtered artifact is what leaves the trust boundary. Validate it
      // too so a filter cannot widen or otherwise corrupt the wire contract.
      if (!failure && (!isJsonValue(normalized) || !matchesSchema(task.resultSchema, normalized))) {
        failure = { code: "RESULT_SCHEMA_INVALID", message: "Filtered result does not satisfy the capability result schema" };
      }
      if (failure) {
        finalOutcome = "failed";
        finalFailure = failure;
      } else {
        terminal.result = normalized!;
      }
    } else if (finalOutcome === "cancelled") terminal.cancellation = isObject(value) && isJsonValue(value) ? value as JsonObject : { code: "CANCELLED" };
    if (finalOutcome === "failed") {
      // Raw exceptions may contain paths, tokens, provider responses, or
      // stack-derived internals. Keep that detail local.
      terminal.error = finalFailure ?? { code: "EXECUTION_FAILED", message: "Task handler failed" };
    }
    terminal.outcome = finalOutcome;
    task.terminal = true;
    if (task.deadlineTimer) clearTimeout(task.deadlineTimer);
    task.deadlineTimer = undefined;
    task.retentionExpiresAt = Math.max(Date.parse(task.deadline), this.now()) + this.idempotencyRetentionMs;
    this.emitTaskEvent(task, "task.completed", {
      task_id: task.taskId,
      event_seq: task.nextEventSeq++,
      ...task.contract,
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
    void this.queueReplayArtifact(task, envelope);
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
    if (this.profile === V2_PROTOCOL_VERSION) {
      this.sendNativeEnvelope(envelope);
      return;
    }
    this.sendRaw(envelope);
  }

  /** Map the stable internal task API onto the selected native-v2 wire shape. */
  private nativeEnvelopeFromLegacy(envelope: Envelope): V2NativeEnvelope {
    const meshId = this.nativeMeshId;
    if (!meshId || !isUuidV7(meshId)) {
      throw new PolyMeshError("PMX.SESSION.PROFILE", "Native v2 mesh identity has not been selected", "protocol");
    }
    const deadline = envelope.delivery.deadline ?? safeDeadline(this.now, this.defaultTimeoutMs);
    if (!isTimestamp(deadline)) {
      throw new PolyMeshError("PMX.PROTOCOL.ENVELOPE", "Native v2 delivery deadline is invalid", "protocol");
    }
    const params = this.nativeParamsFromLegacy(envelope, deadline);
    return {
      protocol: V2_PROFILE,
      profile: V2_PROFILE,
      mesh_id: meshId,
      type: envelope.type,
      message_id: envelope.message_id,
      timestamp: envelope.timestamp,
      source: {
        agent_id: envelope.source.agent_id,
        instance_id: envelope.source.instance_id,
      },
      target: envelope.target.instance_id === undefined
        ? { agent_id: envelope.target.agent_id }
        : { agent_id: envelope.target.agent_id, instance_id: envelope.target.instance_id },
      delivery: {
        delivery_id: uuidv7(this.now()),
        mode: "at_least_once",
        idempotency_key: envelope.delivery.idempotency_key,
        deadline,
      },
      ...(envelope.in_reply_to === undefined ? {} : { in_reply_to: envelope.in_reply_to }),
      params: this.nativeParamsFromLegacy(envelope, deadline),
    } as V2NativeEnvelope;
  }

  /** Translate only fields whose spelling changed between the selected profiles. */
  private nativeParamsFromLegacy(envelope: Envelope, deliveryDeadline: string): JsonObject {
    const params = envelope.params as JsonObject;
    if (envelope.type === "task.submit") {
      const taskId = params.task_id;
      const capability = params.method;
      const input = params.params;
      const deadline = deliveryDeadline;
      if (!isUuidV7(taskId) || typeof capability !== "string" || !isJsonValue(input) || !isTimestamp(deadline)) {
        throw new PolyMeshError("PMX.PROTOCOL.ENVELOPE", "Legacy task submit cannot be represented as a native v2 task", "protocol");
      }
      const native: JsonObject = {
        task_id: taskId,
        capability,
        input,
        deadline,
      };
      if (typeof params.capability_version === "string") native.capability_version = params.capability_version;
      if (typeof params.capability_contract_digest === "string") {
        native.capability_contract_digest = params.capability_contract_digest;
      }
      return native;
    }
    if (envelope.type === "task.accepted" || envelope.type === "task.completed") {
      const native: JsonObject = { ...params };
      const capabilityId = native.capability_id;
      delete native.capability_id;
      if (capabilityId !== undefined) native.capability = capabilityId;
      return native;
    }
    if (envelope.type === "error") {
      if (typeof params.code !== "string" || typeof params.message !== "string" || typeof params.retryable !== "boolean") {
        throw new PolyMeshError("PMX.PROTOCOL.ENVELOPE", "Legacy error cannot be represented as a native v2 error", "protocol");
      }
      return {
        code: params.code,
        message: params.message,
        retryable: params.retryable,
        ...(isObject(params.details) && isJsonValue(params.details) ? { details: params.details as JsonObject } : {}),
      };
    }
    return { ...params };
  }

  /**
   * zstd wrapping is asynchronous in both Node and browser runtimes. Keep
   * application writes ordered, while retaining raw JSON for the short
   * post-ack/pre-ready barrier where wrappers are explicitly forbidden.
   */
  private sendNativeEnvelope(envelope: Envelope): void {
    const native = this.nativeEnvelopeFromLegacy(envelope);
    if (!this.nativeZstd?.active) {
      this.sendRaw(native);
      return;
    }
    const payload = Buffer.from(JSON.stringify(native), "utf8");
    const write = this.nativeSendQueue.then(async () => {
      if (this.phase !== "active") {
        throw new PolyMeshError("TRANSPORT_CLOSED", "Native v2 session closed before compressed frame could be sent", "transport", true);
      }
      const machine = this.nativeZstd;
      if (!machine?.active) {
        // A close/reset can happen while a previous wrapper is completing;
        // never emit a raw record after compression has been negotiated.
        throw new PolyMeshError("PMX.PROTOCOL.COMPRESSION", "Native v2 compression is no longer active", "protocol");
      }
      this.sendRaw(await machine.wrap(payload));
    });
    this.nativeSendQueue = write.catch((error) => {
      if (this.phase !== "closed") {
        const message = error instanceof Error ? error.message : "Native v2 compression failed";
        this.failSession(new PolyMeshError("PMX.PROTOCOL.COMPRESSION", message, "protocol"));
      }
    });
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
    this.nativeZstd?.close();
    this.nativeZstd = undefined;
    this.abortLocalTasks();
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
    this.nativeZstd?.close();
    this.nativeZstd = undefined;
    this.abortLocalTasks();
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

  private abortLocalTasks(): void {
    for (const task of this.localTasks.values()) {
      if (task.deadlineTimer) clearTimeout(task.deadlineTimer);
      task.deadlineTimer = undefined;
      task.controller.abort();
      // A disconnected session must not let an ignored AbortSignal turn into
      // a late lifecycle transition or data release.
      task.terminal = true;
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

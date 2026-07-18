/**
 * Protocol primitives shared by the broker and clients.
 *
 * The reference implementation deliberately keeps these helpers dependency-free
 * (apart from Node's crypto module) so the wire format remains easy to audit.
 */
import { createHash, randomBytes } from "node:crypto";

export const PROTOCOL_VERSION = "polymesh.0.1" as const;
export const HANDSHAKE_VERSION = "0.1" as const;
export const CARD_VERSION = "1.0" as const;
export const MAX_FRAME_BYTES = 1_048_576;

export const MESSAGE_TYPES = [
  "card",
  "task.submit",
  "task.accepted",
  "task.rejected",
  "task.progress",
  "task.completed",
  "task.cancel",
  "task.status",
  "ping",
  "pong",
  "error",
] as const;

export type MessageType = (typeof MESSAGE_TYPES)[number];
export type EnvelopeType = MessageType;
export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export interface JsonObject {
  [key: string]: JsonValue;
}

export interface AgentRef {
  agent_id: string;
  instance_id?: string;
}

export interface AgentIdentity extends AgentRef {
  instance_id: string;
}

export interface Delivery {
  mode: "at_least_once";
  idempotency_key: string;
  deadline?: string;
}

export interface Envelope<
  T extends MessageType = MessageType,
  P extends JsonObject = JsonObject,
> {
  protocol: typeof PROTOCOL_VERSION;
  type: T;
  message_id: string;
  timestamp: string;
  source: AgentIdentity;
  target: AgentRef;
  delivery: Delivery;
  in_reply_to?: string;
  params: P;
}

/** A backwards-friendly name for an application envelope. */
export type Message<T extends MessageType = MessageType, P extends JsonObject = JsonObject> = Envelope<T, P>;

export interface Endpoint {
  transport: "websocket" | "unix";
  url: string;
  scope: "loopback" | "lan" | "remote";
  security?: "none" | "token" | "mutual";
}

export interface Capability {
  id: string;
  version: string;
  description?: string;
  input_schema?: JsonObject;
  result_schema?: JsonObject;
  idempotency?: "pure" | "idempotent" | "sensitive";
  side_effects?: "none" | "read" | "write" | "network" | "approval";
  approval?: "never" | "always" | "threshold";
  cancellation?: "none" | "best_effort" | "supported";
  timeout_ceiling_seconds?: number;
}

export interface Limits {
  max_task_timeout_ms?: number;
  max_tasks_per_principal?: number;
  max_input_bytes?: number;
  max_result_bytes?: number;
}

export interface AgentCard {
  card_version: typeof CARD_VERSION;
  agent_id: string;
  instance_id: string;
  display_name?: string;
  issued_at: string;
  expires_at: string;
  revision: number;
  endpoints?: Endpoint[];
  capabilities: Capability[];
  limits?: Limits;
  metadata?: {
    description?: string;
    tags?: string[];
    icon?: string;
    [key: string]: JsonValue | undefined;
  };
}

/** JSON Schema form of the base application envelope (draft 2020-12). */
export const ENVELOPE_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://polymesh.dev/schemas/envelope.json",
  type: "object",
  required: ["protocol", "type", "message_id", "timestamp", "source", "target", "delivery", "params"],
  properties: {
    protocol: { const: PROTOCOL_VERSION },
    type: { type: "string", enum: MESSAGE_TYPES },
    message_id: { type: "string", pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" },
    timestamp: { type: "string", format: "date-time" },
    source: {
      type: "object",
      required: ["agent_id", "instance_id"],
      properties: { agent_id: { type: "string" }, instance_id: { type: "string" } },
    },
    target: {
      type: "object",
      required: ["agent_id"],
      properties: { agent_id: { type: "string" }, instance_id: { type: "string" } },
    },
    delivery: {
      type: "object",
      required: ["mode", "idempotency_key"],
      properties: {
        mode: { const: "at_least_once" },
        idempotency_key: { type: "string" },
        deadline: { type: "string", format: "date-time" },
      },
    },
    in_reply_to: { type: "string" },
    params: { type: "object" },
  },
} as const;

/** JSON Schema form of an Agent Card (draft 2020-12). */
export const AGENT_CARD_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  required: ["card_version", "agent_id", "instance_id", "issued_at", "expires_at", "revision", "capabilities"],
  properties: {
    card_version: { const: CARD_VERSION },
    agent_id: { type: "string", pattern: "^[a-zA-Z][a-zA-Z0-9._-]*$" },
    instance_id: { type: "string" },
    display_name: { type: "string" },
    issued_at: { type: "string", format: "date-time" },
    expires_at: { type: "string", format: "date-time" },
    revision: { type: "integer", minimum: 1 },
    endpoints: { type: "array" },
    capabilities: { type: "array", minItems: 1 },
    limits: { type: "object" },
    metadata: { type: "object" },
  },
} as const;

export const envelopeSchema = ENVELOPE_SCHEMA;
export const agentCardSchema = AGENT_CARD_SCHEMA;

export type ErrorCategory =
  | "parse"
  | "protocol"
  | "identity"
  | "routing"
  | "delivery"
  | "resource"
  | "task"
  | "execution"
  | "internal";

export type ErrorParams = JsonObject & {
  category: ErrorCategory;
  code: string;
  message: string;
  retryable: boolean;
  retry_after_ms: number | null;
  details?: JsonObject;
};

export interface TaskSubmitParams extends JsonObject {
  task_id: string;
  method: string;
  params: JsonObject;
  deadline: string;
}

export interface TaskAcceptedParams extends JsonObject {
  task_id: string;
  event_seq: number;
  accepted_at: string;
}

export interface TaskRejectedParams extends JsonObject {
  task_id: string;
  event_seq: number;
  code: string;
  message: string;
}

export interface TaskProgressParams extends JsonObject {
  task_id: string;
  event_seq: number;
  progress: JsonObject;
}

export interface TaskCompletedParams extends JsonObject {
  task_id: string;
  event_seq: number;
  terminal: JsonObject;
}

export type HelloFrame = {
  type: "hello";
  v: typeof HANDSHAKE_VERSION;
  role: "initiator";
  agent_id: string;
  instance_id: string;
  nonce: string;
} | {
  type: "hello";
  v: typeof HANDSHAKE_VERSION;
  role: "responder";
  agent_id: string;
  instance_id: string;
  nonce: string;
  echo: string;
  sid: string;
};

export interface CardFrame {
  type: "card";
  sid: string;
  for_nonce: string;
  digest: string;
  card: AgentCard;
}

export interface ReadyFrame {
  type: "ready";
  sid: string;
  self_card: string;
  peer_card: string;
}

export type HandshakeFrame = HelloFrame | CardFrame | ReadyFrame;

export type ValidationResult<T> =
  | { ok: true; value: T }
  | { ok: false; error: string };

export class ProtocolError extends Error {
  readonly category: ErrorCategory;
  readonly code: string;
  readonly retryable: boolean;

  constructor(
    code: string,
    message = code,
    category: ErrorCategory = "protocol",
    retryable = false,
  ) {
    super(message);
    this.name = "ProtocolError";
    this.code = code;
    this.category = category;
    this.retryable = retryable;
  }
}

const MESSAGE_TYPE_SET = new Set<string>(MESSAGE_TYPES);
const ERROR_CATEGORY_SET = new Set<string>([
  "parse",
  "protocol",
  "identity",
  "routing",
  "delivery",
  "resource",
  "task",
  "execution",
  "internal",
]);
const UUID_V7_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const AGENT_ID_RE = /^[a-zA-Z][a-zA-Z0-9._-]*$/;
const CAPABILITY_ID_RE = /^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)*\.[a-zA-Z][a-zA-Z0-9._-]*$/;
const SEMVER_RE = /^\d+\.\d+\.\d+$/;
const RFC3339_MILLIS_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

let lastUuidTimestamp = -1;
let lastUuidRandom = 0n;
const MAX_UUID_RANDOM = (1n << 74n) - 1n;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasString(value: Record<string, unknown>, key: string): value is Record<string, unknown> & Record<string, string> {
  return typeof value[key] === "string";
}

function isFiniteInteger(value: unknown, minimum = Number.MIN_SAFE_INTEGER): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= minimum;
}

function validationFailure<T = never>(error: string): ValidationResult<T> {
  return { ok: false, error };
}

/** True when value can be represented in a JSON text without lossy values. */
export function isJsonValue(value: unknown, seen = new WeakSet<object>()): value is JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value !== "object") return false;
  if (seen.has(value)) return false;
  seen.add(value);
  const values = Array.isArray(value) ? value : Object.values(value);
  const valid = values.every((entry) => isJsonValue(entry, seen));
  seen.delete(value);
  return valid;
}

export function isUuidV7(value: unknown): value is string {
  return typeof value === "string" && UUID_V7_RE.test(value);
}

export function isAgentId(value: unknown): value is string {
  return typeof value === "string" && AGENT_ID_RE.test(value);
}

export function isBase64Url(value: unknown, bytes?: number): value is string {
  if (typeof value !== "string" || !BASE64URL_RE.test(value)) return false;
  try {
    const decoded = Buffer.from(value, "base64url");
    return decoded.length > 0 && (bytes === undefined || decoded.length === bytes) && decoded.toString("base64url") === value;
  } catch {
    return false;
  }
}

export function isInstanceId(value: unknown): value is string {
  return isBase64Url(value, 16);
}

export function isNonce(value: unknown): value is string {
  return isBase64Url(value, 32);
}

/** RFC 3339 UTC timestamp with the millisecond precision required by v0.1. */
export function isTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || !RFC3339_MILLIS_UTC_RE.test(value)) return false;
  const millis = Date.parse(value);
  return Number.isFinite(millis) && new Date(millis).toISOString() === value;
}

/**
 * Generate a UUIDv7. Values generated by this process are monotonic even when
 * several calls land in one millisecond or the wall clock moves backwards.
 */
export function uuidv7(now = Date.now()): string {
  if (!Number.isSafeInteger(now) || now < 0 || now > 0xffff_ffff_ffff) {
    throw new RangeError("UUIDv7 timestamp must fit in 48 bits");
  }
  if (now > lastUuidTimestamp) {
    lastUuidTimestamp = now;
    lastUuidRandom = BigInt(`0x${randomBytes(10).toString("hex")}`) & MAX_UUID_RANDOM;
  } else if (lastUuidRandom < MAX_UUID_RANDOM) {
    lastUuidRandom += 1n;
  } else {
    lastUuidTimestamp += 1;
    lastUuidRandom = BigInt(`0x${randomBytes(10).toString("hex")}`) & MAX_UUID_RANDOM;
  }

  const bytes = Buffer.allocUnsafe(16);
  let timestamp = BigInt(lastUuidTimestamp);
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number(timestamp & 0xffn);
    timestamp >>= 8n;
  }
  const randA = Number(lastUuidRandom >> 62n);
  const randB = lastUuidRandom & ((1n << 62n) - 1n);
  bytes[6] = 0x70 | (randA >> 8);
  bytes[7] = randA & 0xff;
  bytes[8] = 0x80 | Number((randB >> 56n) & 0x3fn);
  for (let index = 9; index < 16; index += 1) {
    const shift = BigInt((15 - index) * 8);
    bytes[index] = Number((randB >> shift) & 0xffn);
  }
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export const randomInstanceId = (): string => randomBytes(16).toString("base64url");
export const randomNonce = (): string => randomBytes(32).toString("base64url");

function nonceBytes(nonce: string | Uint8Array): Buffer {
  if (typeof nonce === "string") {
    if (!isNonce(nonce)) throw new ProtocolError("MALFORMED_NONCE", "Nonce must be a 32-byte base64url value", "parse");
    return Buffer.from(nonce, "base64url");
  }
  return Buffer.from(nonce);
}

/** Derive the handshake session id from the two raw nonce values. */
export function deriveSessionId(initiatorNonce: string | Uint8Array, responderNonce: string | Uint8Array): string {
  return createHash("sha256")
    .update(`${PROTOCOL_VERSION}\0`, "utf8")
    .update(nonceBytes(initiatorNonce))
    .update(nonceBytes(responderNonce))
    .digest("base64url");
}

/** RFC 8785-style canonical JSON suitable for protocol fingerprints and cards. */
export function canonicalize(value: JsonValue): string {
  const stack = new WeakSet<object>();
  const visit = (entry: JsonValue): string => {
    if (entry === null || typeof entry === "boolean" || typeof entry === "string") return JSON.stringify(entry);
    if (typeof entry === "number") {
      if (!Number.isFinite(entry)) throw new TypeError("Canonical JSON does not allow non-finite numbers");
      return JSON.stringify(entry);
    }
    if (typeof entry !== "object") throw new TypeError("Canonical JSON contains a non-JSON value");
    if (stack.has(entry)) throw new TypeError("Canonical JSON cannot contain a cycle");
    stack.add(entry);
    try {
      if (Array.isArray(entry)) return `[${entry.map((item) => visit(item)).join(",")}]`;
      const object = entry as JsonObject;
      return `{${Object.keys(object)
        .sort()
        .map((key) => `${JSON.stringify(key)}:${visit(object[key]!)}`)
        .join(",")}}`;
    } finally {
      stack.delete(entry);
    }
  };
  return visit(value);
}

export const canonicalJson = canonicalize;

export function sha256(value: JsonValue | string): string {
  const input = typeof value === "string" ? value : canonicalize(value);
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/** SHA-256 hex digest of the RFC-8785-style canonical Agent Card JSON. */
export function cardDigest(card: AgentCard): string {
  return sha256(card as unknown as JsonObject);
}

export const digestCard = cardDigest;
export const canonicalCardDigest = cardDigest;

export function validateCapability(value: unknown): ValidationResult<Capability> {
  if (!isRecord(value)) return validationFailure("Capability must be an object");
  if (!hasString(value, "id") || !CAPABILITY_ID_RE.test(value.id)) return validationFailure("Capability id is invalid");
  if (!hasString(value, "version") || !SEMVER_RE.test(value.version)) return validationFailure("Capability version is invalid");
  if (value.description !== undefined && typeof value.description !== "string") return validationFailure("Capability description must be a string");
  if (value.input_schema !== undefined && !isRecord(value.input_schema)) return validationFailure("Capability input_schema must be an object");
  if (value.result_schema !== undefined && !isRecord(value.result_schema)) return validationFailure("Capability result_schema must be an object");
  if (value.idempotency !== undefined && !["pure", "idempotent", "sensitive"].includes(String(value.idempotency))) return validationFailure("Capability idempotency is invalid");
  if (value.side_effects !== undefined && !["none", "read", "write", "network", "approval"].includes(String(value.side_effects))) return validationFailure("Capability side_effects is invalid");
  if (value.approval !== undefined && !["never", "always", "threshold"].includes(String(value.approval))) return validationFailure("Capability approval is invalid");
  if (value.cancellation !== undefined && !["none", "best_effort", "supported"].includes(String(value.cancellation))) return validationFailure("Capability cancellation is invalid");
  if (value.timeout_ceiling_seconds !== undefined && !isFiniteInteger(value.timeout_ceiling_seconds, 1)) return validationFailure("Capability timeout_ceiling_seconds is invalid");
  return { ok: true, value: value as unknown as Capability };
}

export function validateAgentCard(value: unknown, now = Date.now()): ValidationResult<AgentCard> {
  if (!isRecord(value)) return validationFailure("Card must be an object");
  if (value.card_version !== CARD_VERSION) return validationFailure(`Card version must be ${CARD_VERSION}`);
  if (!isAgentId(value.agent_id)) return validationFailure("Card agent_id is invalid");
  if (!isInstanceId(value.instance_id)) return validationFailure("Card instance_id is invalid");
  if (!isTimestamp(value.issued_at) || !isTimestamp(value.expires_at)) return validationFailure("Card timestamps are invalid");
  if (Date.parse(value.expires_at) <= Date.parse(value.issued_at)) return validationFailure("Card expires_at must be after issued_at");
  if (!isFiniteInteger(value.revision, 1)) return validationFailure("Card revision is invalid");
  if (!Array.isArray(value.capabilities) || value.capabilities.length === 0) return validationFailure("Card capabilities must be non-empty");
  for (const capability of value.capabilities) {
    const result = validateCapability(capability);
    if (result.ok === false) return validationFailure(result.error);
  }
  for (const requiredCapability of [
    "org.polymesh.agent.ping",
    "org.polymesh.agent.info",
    "org.polymesh.capabilities.list",
  ]) {
    if (!value.capabilities.some((capability) => isRecord(capability) && capability.id === requiredCapability)) {
      return validationFailure(`Card is missing required capability ${requiredCapability}`);
    }
  }
  if (value.display_name !== undefined && typeof value.display_name !== "string") return validationFailure("Card display_name must be a string");
  if (value.endpoints !== undefined) {
    if (!Array.isArray(value.endpoints)) return validationFailure("Card endpoints must be an array");
    for (const endpoint of value.endpoints) {
      if (!isRecord(endpoint) || !["websocket", "unix"].includes(String(endpoint.transport)) || typeof endpoint.url !== "string" || !["loopback", "lan", "remote"].includes(String(endpoint.scope))) {
        return validationFailure("Card endpoint is invalid");
      }
      try {
        // Unix endpoints are URI-shaped too (for example unix:///run/pm.sock).
        new URL(endpoint.url);
      } catch {
        return validationFailure("Card endpoint URL is invalid");
      }
      if (endpoint.security !== undefined && !["none", "token", "mutual"].includes(String(endpoint.security))) return validationFailure("Card endpoint security is invalid");
    }
  }
  if (value.limits !== undefined && (!isRecord(value.limits) || !Object.values(value.limits).every((limit) => isFiniteInteger(limit, 0)))) return validationFailure("Card limits are invalid");
  if (value.metadata !== undefined && (!isRecord(value.metadata) || !isJsonValue(value.metadata))) return validationFailure("Card metadata is invalid");
  // `now` is intentionally optional: callers checking a cached card can validate
  // shape without treating expiry as a parse failure.
  if (!Number.isFinite(now)) return validationFailure("Validation clock is invalid");
  return { ok: true, value: value as unknown as AgentCard };
}

export function isAgentCard(value: unknown): value is AgentCard {
  return validateAgentCard(value).ok;
}

export function isCardExpired(card: Pick<AgentCard, "expires_at">, now = Date.now()): boolean {
  return !isTimestamp(card.expires_at) || Date.parse(card.expires_at) <= now;
}

export const STANDARD_CAPABILITIES: readonly Capability[] = Object.freeze([
  Object.freeze({ id: "org.polymesh.agent.ping", version: "1.0.0", idempotency: "pure", side_effects: "none" }),
  Object.freeze({ id: "org.polymesh.agent.info", version: "1.0.0", idempotency: "pure", side_effects: "none" }),
  Object.freeze({ id: "org.polymesh.capabilities.list", version: "1.0.0", idempotency: "pure", side_effects: "none" }),
]);

export interface CreateAgentCardOptions extends Omit<AgentCard, "card_version" | "instance_id" | "issued_at" | "expires_at" | "revision" | "capabilities"> {
  instance_id?: string;
  issued_at?: string;
  expires_at?: string;
  revision?: number;
  capabilities?: Capability[];
  /** Include the three mandatory baseline capabilities (default: true). */
  include_standard_capabilities?: boolean;
}

export function createAgentCard(options: CreateAgentCardOptions): AgentCard {
  const now = new Date();
  const issuedAt = options.issued_at ?? now.toISOString();
  const expiresAt = options.expires_at ?? new Date(now.getTime() + 60 * 60 * 1000).toISOString();
  const supplied = options.capabilities ?? [];
  const capabilities = options.include_standard_capabilities === false
    ? supplied
    : [...STANDARD_CAPABILITIES, ...supplied.filter((candidate) => !STANDARD_CAPABILITIES.some((base) => base.id === candidate.id))];
  return {
    card_version: CARD_VERSION,
    agent_id: options.agent_id,
    instance_id: options.instance_id ?? randomInstanceId(),
    ...(options.display_name === undefined ? {} : { display_name: options.display_name }),
    issued_at: issuedAt,
    expires_at: expiresAt,
    revision: options.revision ?? 1,
    ...(options.endpoints === undefined ? {} : { endpoints: options.endpoints }),
    capabilities,
    ...(options.limits === undefined ? {} : { limits: options.limits }),
    ...(options.metadata === undefined ? {} : { metadata: options.metadata }),
  };
}

function validateParams(type: MessageType, params: JsonObject): string | undefined {
  const taskId = params.task_id;
  const eventSeq = params.event_seq;
  switch (type) {
    case "card":
      if (!isAgentCard(params.card) || typeof params.digest !== "string" || params.digest.length === 0) return "Invalid card params";
      return undefined;
    case "task.submit":
      if (!isUuidV7(taskId) || typeof params.method !== "string" || !CAPABILITY_ID_RE.test(params.method) || !isRecord(params.params) || !isTimestamp(params.deadline)) return "Invalid task.submit params";
      return undefined;
    case "task.accepted":
      if (!isUuidV7(taskId) || eventSeq !== 1 || !isTimestamp(params.accepted_at)) return "Invalid task.accepted params";
      return undefined;
    case "task.rejected":
      if (!isUuidV7(taskId) || eventSeq !== 1 || typeof params.code !== "string" || typeof params.message !== "string") return "Invalid task.rejected params";
      return undefined;
    case "task.progress":
      if (!isUuidV7(taskId) || !isFiniteInteger(eventSeq, 2) || !isRecord(params.progress)) return "Invalid task.progress params";
      return undefined;
    case "task.completed":
      if (!isUuidV7(taskId) || !isFiniteInteger(eventSeq, 2) || !isRecord(params.terminal) || !["succeeded", "failed", "cancelled"].includes(String(params.terminal.outcome))) return "Invalid task.completed params";
      return undefined;
    case "task.cancel":
      if (!isUuidV7(taskId) || (params.reason !== undefined && typeof params.reason !== "string")) return "Invalid task.cancel params";
      return undefined;
    case "task.status":
      if (params.kind === "query" && isUuidV7(taskId)) return undefined;
      if (params.kind === "snapshot" && isUuidV7(taskId)) return undefined;
      return "Invalid task.status params";
    case "ping":
    case "pong":
      return isFiniteInteger(params.n, 0) ? undefined : `Invalid ${type} params`;
    case "error":
      if (!ERROR_CATEGORY_SET.has(String(params.category)) || typeof params.code !== "string" || typeof params.message !== "string" || typeof params.retryable !== "boolean" || !(params.retry_after_ms === null || isFiniteInteger(params.retry_after_ms, 0)) || (params.details !== undefined && !isRecord(params.details))) return "Invalid error params";
      return undefined;
  }
}

/** Validate a complete, application-level v0.1 envelope. */
export function validateEnvelope(value: unknown): ValidationResult<Envelope> {
  if (!isRecord(value)) return validationFailure("Envelope must be an object");
  if (value.protocol !== PROTOCOL_VERSION) return validationFailure(`Unsupported protocol: ${String(value.protocol)}`);
  if (typeof value.type !== "string" || !MESSAGE_TYPE_SET.has(value.type)) return validationFailure("Envelope type is invalid");
  if (!isUuidV7(value.message_id)) return validationFailure("Envelope message_id must be UUIDv7");
  if (!isTimestamp(value.timestamp)) return validationFailure("Envelope timestamp is invalid");
  if (!isRecord(value.source) || !isAgentId(value.source.agent_id) || !isInstanceId(value.source.instance_id)) return validationFailure("Envelope source is invalid");
  if (!isRecord(value.target) || !(isAgentId(value.target.agent_id) || value.target.agent_id === "*") || (value.target.instance_id !== undefined && !isInstanceId(value.target.instance_id))) return validationFailure("Envelope target is invalid");
  if (!isRecord(value.delivery) || value.delivery.mode !== "at_least_once" || typeof value.delivery.idempotency_key !== "string" || value.delivery.idempotency_key.length === 0 || !isTimestamp(value.delivery.deadline)) return validationFailure("Envelope delivery is invalid");
  if (value.in_reply_to !== undefined && (typeof value.in_reply_to !== "string" || value.in_reply_to.length === 0)) return validationFailure("Envelope in_reply_to is invalid");
  if (!isRecord(value.params) || !isJsonValue(value.params)) return validationFailure("Envelope params must be a JSON object");
  const parameterError = validateParams(value.type as MessageType, value.params as JsonObject);
  if (parameterError) return validationFailure(parameterError);
  return { ok: true, value: value as unknown as Envelope };
}

export function isEnvelope(value: unknown): value is Envelope {
  return validateEnvelope(value).ok;
}

export function validateHandshakeFrame(value: unknown): ValidationResult<HandshakeFrame> {
  if (!isRecord(value) || typeof value.type !== "string") return validationFailure("Handshake frame must be an object");
  if (value.type === "hello") {
    if (value.v !== HANDSHAKE_VERSION || !["initiator", "responder"].includes(String(value.role)) || !isAgentId(value.agent_id) || !isInstanceId(value.instance_id) || !isNonce(value.nonce)) return validationFailure("Invalid hello frame");
    if (value.role === "responder" && (!isNonce(value.echo) || !isBase64Url(value.sid, 32))) return validationFailure("Invalid responder hello frame");
    if (value.role === "initiator" && (value.echo !== undefined || value.sid !== undefined)) return validationFailure("Initiator hello cannot include echo or sid");
    return { ok: true, value: value as unknown as HelloFrame };
  }
  if (value.type === "card") {
    if (!isBase64Url(value.sid, 32) || !isNonce(value.for_nonce) || typeof value.digest !== "string" || !/^[0-9a-f]{64}$/i.test(value.digest)) return validationFailure("Invalid card frame");
    const card = validateAgentCard(value.card);
    return card.ok === true ? { ok: true, value: value as unknown as CardFrame } : validationFailure(card.error);
  }
  if (value.type === "ready") {
    if (!isBase64Url(value.sid, 32) || typeof value.self_card !== "string" || typeof value.peer_card !== "string") return validationFailure("Invalid ready frame");
    return { ok: true, value: value as unknown as ReadyFrame };
  }
  return validationFailure("Unknown handshake frame type");
}

export function isHandshakeFrame(value: unknown): value is HandshakeFrame {
  return validateHandshakeFrame(value).ok;
}

export interface CreateEnvelopeOptions<T extends MessageType = MessageType, P extends JsonObject = JsonObject> {
  type: T;
  source: AgentIdentity;
  target: AgentRef;
  params?: P;
  delivery?: Partial<Delivery>;
  /** Convenience alternative to delivery.idempotency_key. */
  idempotency_key?: string;
  /** Convenience camelCase alternative to delivery.idempotency_key. */
  idempotencyKey?: string;
  deadline?: string;
  in_reply_to?: string;
  message_id?: string;
  timestamp?: string;
}

export interface EnvelopeOverrides {
  delivery?: Partial<Delivery>;
  idempotency_key?: string;
  idempotencyKey?: string;
  deadline?: string;
  in_reply_to?: string;
  message_id?: string;
  timestamp?: string;
}

export function createEnvelope<T extends MessageType, P extends JsonObject>(options: CreateEnvelopeOptions<T, P>): Envelope<T, P>;
export function createEnvelope<T extends MessageType, P extends JsonObject>(type: T, source: AgentIdentity, target: AgentRef, params: P, overrides?: EnvelopeOverrides): Envelope<T, P>;
export function createEnvelope<T extends MessageType, P extends JsonObject>(
  optionsOrType: CreateEnvelopeOptions<T, P> | T,
  source?: AgentIdentity,
  target?: AgentRef,
  params?: P,
  overrides: EnvelopeOverrides = {},
): Envelope<T, P> {
  const options: CreateEnvelopeOptions<T, P> = typeof optionsOrType === "string"
    ? { type: optionsOrType, source: source!, target: target!, params: params!, ...overrides }
    : optionsOrType;
  const messageId = options.message_id ?? uuidv7();
  const idempotencyKey = options.delivery?.idempotency_key ?? options.idempotency_key ?? options.idempotencyKey ?? `${options.type}:${messageId}`;
  // An application envelope always carries a deadline.  A one-minute default
  // preserves the strict v0.1 wire shape while keeping control messages easy
  // to construct through the small reference API.
  const deadline = options.delivery?.deadline ?? options.deadline ?? new Date(Date.now() + 60_000).toISOString();
  const timestamp = options.timestamp ?? new Date().toISOString();
  return {
    protocol: PROTOCOL_VERSION,
    type: options.type,
    message_id: messageId,
    timestamp,
    source: { agent_id: options.source.agent_id, instance_id: options.source.instance_id },
    target: options.target.instance_id === undefined
      ? { agent_id: options.target.agent_id }
      : { agent_id: options.target.agent_id, instance_id: options.target.instance_id },
    delivery: { mode: "at_least_once", idempotency_key: idempotencyKey, deadline },
    ...(options.in_reply_to === undefined ? {} : { in_reply_to: options.in_reply_to }),
    params: (options.params ?? {}) as P,
  };
}

export interface CreateErrorEnvelopeOptions extends Omit<CreateEnvelopeOptions<"error", ErrorParams>, "type" | "params"> {
  category: ErrorCategory;
  code: string;
  message: string;
  retryable?: boolean;
  retry_after_ms?: number | null;
  details?: JsonObject;
}

export interface ErrorInput {
  category: ErrorCategory;
  code: string;
  message: string;
  retryable: boolean;
  retry_after_ms?: number | null;
  details?: JsonObject;
}

export function createErrorEnvelope(options: CreateErrorEnvelopeOptions): Envelope<"error", ErrorParams>;
export function createErrorEnvelope(source: AgentIdentity, target: AgentRef, error: ErrorInput, overrides?: EnvelopeOverrides): Envelope<"error", ErrorParams>;
export function createErrorEnvelope(
  optionsOrSource: CreateErrorEnvelopeOptions | AgentIdentity,
  target?: AgentRef,
  error?: ErrorInput,
  overrides?: EnvelopeOverrides,
): Envelope<"error", ErrorParams> {
  if (target !== undefined) {
    return createEnvelope<"error", ErrorParams>({
      type: "error",
      source: optionsOrSource as AgentIdentity,
      target,
      params: {
        ...error!,
        retry_after_ms: error!.retry_after_ms ?? null,
      } as ErrorParams,
      ...overrides,
    });
  }
  const options = optionsOrSource as CreateErrorEnvelopeOptions;
  return createEnvelope<"error", ErrorParams>({
    ...options,
    type: "error",
    params: {
      category: options.category,
      code: options.code,
      message: options.message,
      retryable: options.retryable ?? false,
      retry_after_ms: options.retry_after_ms ?? null,
      ...(options.details === undefined ? {} : { details: options.details }),
    },
  });
}

export const createError = createErrorEnvelope;

export function encodeUnixFrame(payload: string | JsonValue): Buffer {
  const body = Buffer.from(typeof payload === "string" ? payload : JSON.stringify(payload), "utf8");
  if (body.byteLength > MAX_FRAME_BYTES) throw new ProtocolError("FRAME_TOO_LARGE", `Frame exceeds ${MAX_FRAME_BYTES} bytes`, "resource");
  const framed = Buffer.allocUnsafe(body.byteLength + 4);
  framed.writeUInt32BE(body.byteLength, 0);
  body.copy(framed, 4);
  return framed;
}

export interface DecodedUnixFrames {
  frames: string[];
  remainder: Buffer;
}

/** Decode as many complete Unix-socket frames as are present in a buffer. */
export function decodeUnixFrames(chunk: Uint8Array, maxFrameBytes = MAX_FRAME_BYTES): DecodedUnixFrames {
  const buffer = Buffer.from(chunk);
  const frames: string[] = [];
  let offset = 0;
  while (offset + 4 <= buffer.length) {
    const length = buffer.readUInt32BE(offset);
    if (length > maxFrameBytes) throw new ProtocolError("FRAME_TOO_LARGE", `Frame exceeds ${maxFrameBytes} bytes`, "resource");
    if (offset + 4 + length > buffer.length) break;
    frames.push(buffer.subarray(offset + 4, offset + 4 + length).toString("utf8"));
    offset += 4 + length;
  }
  return { frames, remainder: buffer.subarray(offset) };
}

export const decodeUnixFrame = decodeUnixFrames;

export type WireData = string | Buffer | Uint8Array | JsonValue;
export type WireMessageListener = (data: string, isBinary: boolean) => void;
export type WireCloseListener = (code: number, reason: Buffer) => void;
export type WireErrorListener = (error: Error) => void;
export type WireOpenListener = () => void;

export interface WireMessageEvent {
  data: string;
}

/**
 * A small in-memory, WebSocket-shaped transport used by integration tests and
 * by embedders that want to exercise routing without opening a port.
 */
export class WireTransport {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;

  readonly CONNECTING = WireTransport.CONNECTING;
  readonly OPEN = WireTransport.OPEN;
  readonly CLOSING = WireTransport.CLOSING;
  readonly CLOSED = WireTransport.CLOSED;
  readyState = WireTransport.OPEN;
  onmessage?: (event: WireMessageEvent) => void;
  onclose?: (event: { code: number; reason: string }) => void;
  onerror?: (event: { error: Error }) => void;

  private peer?: WireTransport;
  private readonly messageListeners = new Set<WireMessageListener>();
  private readonly closeListeners = new Set<WireCloseListener>();
  private readonly errorListeners = new Set<WireErrorListener>();
  private readonly openListeners = new Set<WireOpenListener>();

  /** @internal */
  connect(peer: WireTransport): void {
    this.peer = peer;
  }

  get isOpen(): boolean {
    return this.readyState === WireTransport.OPEN;
  }

  on(event: "message", listener: WireMessageListener): this;
  on(event: "close", listener: WireCloseListener): this;
  on(event: "error", listener: WireErrorListener): this;
  on(event: "open", listener: WireOpenListener): this;
  on(event: "message" | "close" | "error" | "open", listener: WireMessageListener | WireCloseListener | WireErrorListener | WireOpenListener): this {
    if (event === "message") this.messageListeners.add(listener as WireMessageListener);
    else if (event === "close") this.closeListeners.add(listener as WireCloseListener);
    else if (event === "error") this.errorListeners.add(listener as WireErrorListener);
    else this.openListeners.add(listener as WireOpenListener);
    return this;
  }

  once(event: "message", listener: WireMessageListener): this;
  once(event: "close", listener: WireCloseListener): this;
  once(event: "error", listener: WireErrorListener): this;
  once(event: "open", listener: WireOpenListener): this;
  once(event: "message" | "close" | "error" | "open", listener: WireMessageListener | WireCloseListener | WireErrorListener | WireOpenListener): this {
    const wrapped = ((...args: [string, boolean] | [number, Buffer] | [Error] | []) => {
      if (event === "message") this.off("message", wrapped as WireMessageListener);
      else if (event === "close") this.off("close", wrapped as WireCloseListener);
      else if (event === "error") this.off("error", wrapped as WireErrorListener);
      else this.off("open", wrapped as WireOpenListener);
      (listener as (...listenerArgs: typeof args) => void)(...args);
    }) as WireMessageListener & WireCloseListener & WireErrorListener & WireOpenListener;
    if (event === "message") return this.on("message", wrapped as WireMessageListener);
    if (event === "close") return this.on("close", wrapped as WireCloseListener);
    if (event === "error") return this.on("error", wrapped as WireErrorListener);
    return this.on("open", wrapped as WireOpenListener);
  }

  off(event: "message", listener: WireMessageListener): this;
  off(event: "close", listener: WireCloseListener): this;
  off(event: "error", listener: WireErrorListener): this;
  off(event: "open", listener: WireOpenListener): this;
  off(event: "message" | "close" | "error" | "open", listener: WireMessageListener | WireCloseListener | WireErrorListener | WireOpenListener): this {
    if (event === "message") this.messageListeners.delete(listener as WireMessageListener);
    else if (event === "close") this.closeListeners.delete(listener as WireCloseListener);
    else if (event === "error") this.errorListeners.delete(listener as WireErrorListener);
    else this.openListeners.delete(listener as WireOpenListener);
    return this;
  }

  addEventListener(event: "message", listener: (event: WireMessageEvent) => void): void;
  addEventListener(event: "close", listener: (event: { code: number; reason: string }) => void): void;
  addEventListener(event: "error", listener: (event: { error: Error }) => void): void;
  addEventListener(event: "message" | "close" | "error", listener: ((event: WireMessageEvent) => void) | ((event: { code: number; reason: string }) => void) | ((event: { error: Error }) => void)): void {
    if (event === "message") this.on("message", (data) => (listener as (message: WireMessageEvent) => void)({ data }));
    else if (event === "close") this.on("close", (code, reason) => (listener as (close: { code: number; reason: string }) => void)({ code, reason: reason.toString() }));
    else this.on("error", (error) => (listener as (error: { error: Error }) => void)({ error }));
  }

  send(data: WireData, callback?: (error?: Error) => void): void {
    if (!this.isOpen || !this.peer || !this.peer.isOpen) {
      const error = new ProtocolError("TRANSPORT_CLOSED", "Cannot send on a closed wire", "routing", true);
      callback?.(error);
      throw error;
    }
    let text: string;
    const isBinary = Buffer.isBuffer(data) || data instanceof Uint8Array;
    try {
      if (typeof data === "string") text = data;
      else if (isBinary) text = Buffer.from(data).toString("utf8");
      else text = JSON.stringify(data);
      if (Buffer.byteLength(text, "utf8") > MAX_FRAME_BYTES) throw new ProtocolError("FRAME_TOO_LARGE", `Frame exceeds ${MAX_FRAME_BYTES} bytes`, "resource");
    } catch (cause) {
      const error = cause instanceof Error ? cause : new Error(String(cause));
      callback?.(error);
      this.emitError(error);
      throw error;
    }
    const peer = this.peer;
    queueMicrotask(() => {
      if (!this.isOpen || !peer.isOpen) {
        callback?.(new ProtocolError("TRANSPORT_CLOSED", "Wire closed before the frame was delivered", "routing", true));
        return;
      }
      peer.receive(text, isBinary);
      callback?.();
    });
  }

  close(code = 1000, reason = ""): void {
    this.finishClose(code, reason, true);
  }

  terminate(): void {
    this.close(1006, "terminated");
  }

  private receive(data: string, isBinary = false): void {
    for (const listener of this.messageListeners) listener(data, isBinary);
    this.onmessage?.({ data });
  }

  private emitError(error: Error): void {
    for (const listener of this.errorListeners) listener(error);
    this.onerror?.({ error });
  }

  /** @internal */
  emitOpen(): void {
    for (const listener of this.openListeners) listener();
  }

  private finishClose(code: number, reason: string, closePeer: boolean): void {
    if (this.readyState === WireTransport.CLOSED) return;
    this.readyState = WireTransport.CLOSED;
    const reasonBuffer = Buffer.from(reason);
    for (const listener of this.closeListeners) listener(code, reasonBuffer);
    this.onclose?.({ code, reason });
    if (closePeer && this.peer) this.peer.finishClose(code, reason, false);
  }
}

export type WirePair = [WireTransport, WireTransport] & {
  a: WireTransport;
  b: WireTransport;
  left: WireTransport;
  right: WireTransport;
};

export function createWirePair(): WirePair {
  const a = new WireTransport();
  const b = new WireTransport();
  a.connect(b);
  b.connect(a);
  const pair = [a, b] as WirePair;
  pair.a = a;
  pair.b = b;
  pair.left = a;
  pair.right = b;
  queueMicrotask(() => {
    if (a.isOpen) a.emitOpen();
    if (b.isOpen) b.emitOpen();
  });
  return pair;
}

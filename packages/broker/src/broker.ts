/**
 * WebSocket router for the PolyMesh reference implementation.
 *
 * This deliberately stays a router: task execution and task persistence live
 * in agents.  The broker authenticates a connection, performs the mandatory
 * hello/card/ready exchange, records the live agent lease, then forwards
 * validated envelopes without rewriting their sender or recipient fields.
 */

import { createServer, type IncomingMessage, type Server as HttpServer } from "node:http";
import { createServer as createSecureServer, type Server as HttpsServer } from "node:https";
import { isIP, type AddressInfo } from "node:net";
import type { Duplex } from "node:stream";
import type { TlsOptions } from "node:tls";
import * as zlib from "node:zlib";
import WebSocket, { WebSocketServer } from "ws";

import {
  MAX_FRAME_BYTES,
  MAX_ROUTED_PROVENANCE_LIFETIME_MS,
  PROTOCOL_VERSION,
  SECURE_IDENTITY_PROFILE,
  V2_COMPRESSION_ALGORITHMS,
  V2_ERROR_CODES,
  V2_NATIVE_ENVELOPE_TYPES,
  V2_PROFILE,
  EnrollmentStore,
  ProtocolError,
  authTranscript,
  capabilityContractTuple,
  cardDigest,
  canonicalize,
  createRoutedProvenance,
  envelopeSemanticDigest,
  createAuthProof,
  createCardIdentityFromPrivateKey,
  deriveSessionId,
  isAgentCard,
  isCapabilityContractTuple,
  isEnvelope,
  isJsonValue,
  isTimestamp,
  isUuidV7,
  parseStrictJson,
  randomInstanceId,
  randomNonce,
  signAgentCard,
  uuidv7,
  verifyAuthProof,
  verifyEnrolledCard,
  type AgentCard,
  type AuthFrame,
  type CardIdentity,
  type CardFrame,
  type CapabilityContractTuple,
  type Ed25519PrivateKey,
  type Enrollment,
  type Envelope,
  type EnvelopeType,
  type HelloFrame,
  type ReceiptDisposition,
  type ReadyFrame,
  type VerifiedPrincipal,
  type WireTransport,
  type JsonObject,
  type JsonValue,
  type V2AckFrame,
  type V2CompressionAlgorithm,
  type V2ErrorCode,
  type V2ErrorFrame,
  type V2InitFrame,
  type V2NativeEnvelope,
  type V2NativeEnvelopeType,
  validateHandshakeFrame,
} from "./protocol.js";
import {
  DuplicateAgentError,
  DurableIdentityCollisionError,
  DurableRegistry,
  InvalidRegistrationError,
  Registry,
  type DurableRegistryEntry,
  type RegistryEntry,
} from "./registry.js";
import {
  type DurableStore,
  type DurableTaskRoute,
  type InboxRecord,
  type OutboxRecord,
  type PersistIngressResult,
  type RecoveryReport,
} from "./durable-store.js";
import type {
  V2InboxRecord,
  V2PersistEnvelopeInput,
  V2PersistEnvelopeResult,
} from "./durable-store-v2.js";
import {
  HealthState,
  createRoutePin,
  isCurrentInstanceFence,
  resolvePinnedRoute,
  selectWeightedRendezvous,
  type RoutePin,
  type RoutingInstance,
} from "./routing.js";
import {
  CompressionTransportError,
  V2ZstdStateMachine,
  compressionAllowedForRecord,
  compressionRateLimitCharges,
  initializeZstd,
  validateDecompressedOutput,
  type CompressionNegotiation,
  type CompressionNegotiationResult,
  type CompressionOffer,
  type CompressionFrameMetadata,
  negotiateCompression,
} from "./compression.js";
import {
  V2_HANDSHAKE_VERSION,
  V2_PROTOCOL_VERSION,
  V2_SUBPROTOCOL,
  V2_TLS_EXPORTER_LABEL,
  attachV2DeliveryMetadata,
  createV2AuthProof,
  createV2CompressionSelected,
  deriveV2SessionId,
  hasV2DeliveryMetadata,
  isDeliveryReceiptRecord,
  isV2IngressEnvelope,
  isV2Envelope,
  v2AuthTranscript,
  v2CompressionFrameMetadata,
  v2EnvelopeAsLegacy,
  v2EnvelopeSemanticDigest,
  validateV2CompressionFrame,
  validateV2CompressionOffer,
  validateV2CompressionRecordBinding,
  validateV2CompressionSelected,
  validateV2Envelope,
  validateV2HelloFrame,
  verifyV2AuthProof,
  type DeliveryReceiptRecord,
  type V2CompressionFrame,
  type V2CompressionSelectedRecord,
  type V2Envelope,
  type V2IngressEnvelope,
  type V2HelloFrame,
} from "./v2.js";
import {
  type HierarchicalRateLimiter,
  type RateLimitCharge,
  type RateLimitContext,
  type RateLimitDecision,
} from "./rate-limit.js";
import {
  RuntimeTokenAuthority,
  normalizePeerClose,
  tlsChannelBinding,
  validateWebSocketUpgrade,
  type TokenRotationOptions,
} from "./security.js";

export const POLYMESH_PATH = "/polymesh";
export const HANDSHAKE_TIMEOUT_MS = 5_000;
export const DEFAULT_HTTP_HEADER_BYTES = 8 * 1024;
export const DEFAULT_HTTP_HEADER_COUNT = 64;
export const DEFAULT_HTTP_HEADER_TIMEOUT_MS = 5_000;
export const DEFAULT_HTTP_REQUEST_TIMEOUT_MS = 10_000;
/** Admission-control defaults. These are hard ceilings, not advisory hints. */
export const DEFAULT_MAX_PENDING_HANDSHAKES = 8;
export const DEFAULT_MAX_OPEN_SESSIONS = 32;
export const DEFAULT_MAX_PENDING_TASK_ROUTES = 1_024;
export const DEFAULT_MAX_PENDING_TASK_ROUTES_PER_SESSION = 32;
export const DEFAULT_MAX_REPLAY_LEDGER_ENTRIES = 4_096;
export const DEFAULT_MAX_LIFECYCLE_EVENTS_PER_ROUTE = 256;
export const MIN_REPLAY_RETENTION_MS = 24 * 60 * 60 * 1_000;

/** TLS material for the enrolled mutual-TLS transport profile. */
export interface BrokerTlsOptions extends TlsOptions {
  key: NonNullable<TlsOptions["key"]>;
  cert: NonNullable<TlsOptions["cert"]>;
}

/** Local material required for the fail-closed enrolled-key WSS profile. */
export interface BrokerIdentityOptions {
  privateKey: Ed25519PrivateKey;
  /** Explicit local enrollment. Cards and mDNS records never add entries. */
  enrollments: EnrollmentStore | readonly Enrollment[];
}

/**
 * Minimal durable mailbox surface used by the compact native v2 profile.
 *
 * It is deliberately separate from the pre-existing relay `DurableStore`:
 * native envelopes have a different wire shape (`profile`, root `mesh_id`,
 * and nested `delivery_id`) and must never be silently coerced into a legacy
 * outbox row. `SqliteV2DurableStore` implements this interface.
 */
export interface NativeV2DurableStore {
  persistEnvelopeAndInbox(input: V2PersistEnvelopeInput): Promise<V2PersistEnvelopeResult>;
  replayInbox?(options: {
    target: string;
    cursor?: string | number;
    limit?: number;
    statuses?: readonly ("pending" | "delivered" | "acknowledged" | "expired")[];
  }): Promise<{ deliveries: readonly V2InboxRecord[] }>;
  markDelivered?(target: string, envelopeId: string, deliveredAt?: number): Promise<V2InboxRecord | undefined>;
}

type JsonRecord = Record<string, unknown>;

/**
 * Node exposes zstd in recent runtimes, but the broker must remain usable in
 * an older runtime when compression is disabled. A namespace import plus this
 * narrow runtime probe avoids making a missing optional codec prevent a
 * normal v0.1/v0.2 broker from starting.
 */
interface ZstdCodec {
  compress(input: Uint8Array): Buffer;
  decompress(input: Uint8Array, maxOutputLength: number): Buffer;
}

function runtimeZstdCodec(): ZstdCodec | undefined {
  const runtime = zlib as unknown as {
    zstdCompressSync?: (input: Uint8Array) => Uint8Array;
    zstdDecompressSync?: (input: Uint8Array, options: { maxOutputLength: number }) => Uint8Array;
  };
  if (typeof runtime.zstdCompressSync !== "function" || typeof runtime.zstdDecompressSync !== "function") return undefined;
  return {
    compress: (input) => Buffer.from(runtime.zstdCompressSync!(input)),
    decompress: (input, maxOutputLength) => Buffer.from(runtime.zstdDecompressSync!(input, { maxOutputLength })),
  };
}

function sameCompressionNegotiation(left: CompressionNegotiation, right: CompressionNegotiation): boolean {
  if (left.algorithm !== right.algorithm) return false;
  if (left.algorithm === "none") return true;
  return left.limits !== undefined && right.limits !== undefined &&
    left.limits.maxCompressedBytes === right.limits.maxCompressedBytes &&
    left.limits.maxUncompressedBytes === right.limits.maxUncompressedBytes &&
    left.limits.maxExpansionRatio === right.limits.maxExpansionRatio;
}

/** The minimum send/receive surface shared by `ws` and WireTransport. */
export interface BrokerTransport {
  send(data: string, ...args: unknown[]): unknown;
  close?(code?: number, reason?: string): unknown;
  terminate?(): unknown;
  on?(event: string, listener: (...args: any[]) => void): unknown;
  onMessage?(listener: (data: string) => void): unknown;
  onClose?(listener: (reason?: unknown) => void): unknown;
  onError?(listener: (error: Error) => void): unknown;
  readyState?: number;
  /** Native WebSocket negotiated subprotocol when an HTTP upgrade was used. */
  protocol?: string;
}

export interface BrokerOptions {
  port?: number;
  host?: string;
  /** Exactly 32 CSPRNG bytes, encoded as unpadded base64url. */
  token?: string;
  /** TLS 1.3 mutual-authentication listener configuration for LAN/remote use. */
  tls?: BrokerTlsOptions;
  /** Required whenever a TLS listener is enabled. */
  identity?: BrokerIdentityOptions;
  /**
   * Permit `ws://` only for an explicitly selected numeric-loopback
   * development listener. It still requires a runtime token.
   */
  allowInsecureLoopbackDevelopment?: boolean;
  /** Exact browser origins permitted to make a WebSocket upgrade. Empty by default. */
  allowedOrigins?: readonly string[];
  /** Identity presented by the broker during the card exchange. */
  card?: AgentCard;
  agentId?: string;
  instanceId?: string;
  registry?: Registry<BrokerPeer, AgentCard>;
  /**
   * Explicitly opt into the v0.2 multi-instance directory for this broker.
   * The legacy v0.1 registry continues to use one live record per agent ID.
   */
  meshId?: string;
  /** Enable weighted multi-instance routing for the configured mesh. */
  multiInstanceRouting?: boolean;
  /**
   * Optional v0.2 durable fact store. When configured, instance registration
   * and task ingress are committed before the broker exposes stored work.
   */
  durableStore?: DurableStore;
  /** Stable broker-node identity recorded in durable session facts. */
  durableNodeId?: string;
  /**
   * Multi-instance identity binding normally requires the enrolled identity
   * profile. This escape hatch exists only for explicitly local test/dev
   * environments; it must never be enabled for a remote relay.
   */
  allowInsecureMultiInstanceDevelopment?: boolean;
  /** Optional, hierarchical v0.2 admission controller. Disabled by default. */
  rateLimiter?: HierarchicalRateLimiter;
  /** Local compression capabilities, negotiated only by `negotiatePeerCompression` after READY. */
  compressionOffer?: CompressionOffer;
  /** Let an otherwise mutually supported zstd offer select zstd. Defaults to false. */
  allowZstdCompression?: boolean;
  /**
   * Enable the compact `v2.init` / `v2.ack` SDK session in addition to the
   * pre-existing relay v2 hello/card/ready path. It is on by default because
   * it is independently token/mTLS authenticated and has no legacy fallback.
   */
  enableNativeV2?: boolean;
  /** Optional compact-profile mailbox for atomic envelope + inbox storage. */
  nativeV2Store?: NativeV2DurableStore;
  /**
   * Serve the distinct `polymesh.0.2` session profile. It requires the
   * durable/multi-instance relay configuration and never changes v0.1
   * sessions. Defaults to true when `durableStore` is configured.
   */
  enableV2?: boolean;
  ttlMs?: number;
  handshakeTimeoutMs?: number;
  maxFrameBytes?: number;
  maxHttpHeaderBytes?: number;
  maxHttpHeaderCount?: number;
  httpHeaderTimeoutMs?: number;
  httpRequestTimeoutMs?: number;
  /** Maximum transport connections still completing hello/card/ready. */
  maxPendingHandshakes?: number;
  /** Maximum concurrent inbound sessions, including handshakes. */
  maxOpenSessions?: number;
  /** Maximum retained task-route records. New work is rejected before allocation. */
  maxPendingTaskRoutes?: number;
  /** Maximum live task routes attributable to one authenticated session. */
  maxPendingTaskRoutesPerSession?: number;
  /** Maximum replay-ledger entries retained in this broker process. */
  maxReplayLedgerEntries?: number;
  /** Maximum lifecycle records retained for a single route. */
  maxLifecycleEventsPerRoute?: number;
  /** Replay and terminal-tombstone retention. Values below 24 hours are raised to the protocol minimum. */
  replayRetentionMs?: number;
  now?: () => number;
  onPeerConnected?: (peer: BrokerPeer) => void;
  onPeerDisconnected?: (peer: BrokerPeer, reason?: unknown) => void;
  onEnvelope?: (envelope: Envelope, peer: BrokerPeer) => void;
}

export interface AttachOptions {
  /** Used only for a pre-existing non-HTTP transport. */
  token?: string;
  /**
   * Pin an in-memory transport to one profile instead of inferring its first
   * handshake record. `polymesh.0.2` selects the compact native SDK branch;
   * `v2` remains the historical hello/card/ready relay branch.
   */
  profile?: "v1" | "v2" | "native-v2" | typeof V2_PROTOCOL_VERSION;
}

export type PeerPhase = "await_hello" | "await_card" | "await_auth" | "await_ready" | "active" | "closed";
/** `v2` is the older relay profile; native-v2 is selected by `v2.init`. */
export type WireProfile = "v1" | "v2" | "native-v2";

export interface BrokerPeer {
  transport: BrokerTransport;
  phase: PeerPhase;
  authenticated: boolean;
  /** Opaque per-transport identifier used before and after hello for quotas. */
  connectionId: string;
  /** Runtime-token epoch that admitted this session, never a claimed identity. */
  authEpoch?: number;
  /** Enrolled principal after the TLS-bound Ed25519 proof has verified. */
  verifiedPrincipal?: VerifiedPrincipal;
  agentId?: string;
  instanceId?: string;
  card?: AgentCard;
  cardDigest?: string;
  sessionId?: string;
  initiatorNonce?: string;
  responderNonce?: string;
  initiatorHello?: Extract<HelloFrame, { role: "initiator" }>;
  responderHello?: Extract<HelloFrame, { role: "responder" }>;
  leaseId?: string;
  /** v0.2 directory metadata; never trust these values from an envelope. */
  meshId?: string;
  registrationFence?: number;
  sessionFence?: number;
  health?: HealthState;
  compression?: CompressionNegotiation;
  /** Selected at HTTP upgrade or from the first strictly validated hello. */
  profile?: WireProfile;
  v2InitiatorHello?: V2HelloFrame;
  v2ResponderHello?: V2HelloFrame;
  /** Compact native-v2 selected codec and post-ack zstd state, if any. */
  nativeV2Compression?: V2CompressionAlgorithm;
  nativeV2Zstd?: V2ZstdStateMachine;
  /** Prevents a second init from racing asynchronous zstd initialisation. */
  nativeV2InitPending?: boolean;
  connectedAt: number;
}

interface TaskRoute {
  taskId: string;
  /** Exact capability contract pinned by the owner and admitted by the executor. */
  contract: CapabilityContractTuple;
  owner: { agentId: string; instanceId: string; sessionId?: string };
  executor: { agentId: string; instanceId: string; sessionId?: string };
  submitMessageId: string;
  /** Every equivalent retransmission that may receive admission correlation. */
  submitMessageIds: Set<string>;
  createdAt: number;
  deadline?: string;
  immutableFingerprint: string;
  /** State is advanced only by an exact, causally valid lifecycle record. */
  lifecycle: "submitted" | "accepted" | "rejected" | "completed" | "closed";
  nextEventSeq: number;
  events: Map<number, string>;
  capacityReserved: boolean;
  retainedUntil: number;
  /** A v0.2 route pins the exact selected physical executor and fences. */
  routePin?: RoutePin;
}

/** Inputs for a durable v0.2 ingress transaction owned by this broker. */
export interface DurableIngressOptions {
  /** Stable relay delivery id; generated when omitted. */
  deliveryId?: string;
  /** Reuse a previously computed semantic digest after strict envelope validation. */
  semanticFingerprint?: string;
}

export interface DurableIngressAdmission {
  result: PersistIngressResult;
  /** The process-local target when its pinned instance is currently connected. */
  target?: RegistryEntry<BrokerPeer, AgentCard>;
  /** Non-recursive v0.2 stored receipt emitted only after commit. */
  receipt?: {
    type: "delivery.receipt";
    v: "0.2";
    delivery_id: string;
    message_id: string;
    state: "stored";
  };
}

export interface DurableDispatchOptions {
  leaseId?: string;
  leaseMs?: number;
  limit?: number;
}

export interface DurableDispatchResult {
  leased: number;
  sent: number;
  unavailable: number;
  invalid: number;
}

/** Process-local connection index record for one durable-routing instance. */
interface LiveRoutingInstance extends RoutingInstance {
  peer: BrokerPeer;
  card: AgentCard;
  leaseId: string;
  registeredAt: number;
  expiresAt: number;
}

interface ReplayLedgerRecord {
  semanticDigest: string;
  expiresAt: number;
}

/** Immutable native-v2 source/target session binding for a task lifecycle. */
interface NativeV2TaskRoute {
  taskId: string;
  submitMessageId: string;
  source: { agentId: string; instanceId: string; sessionId: string };
  target: { agentId: string; instanceId: string; sessionId: string };
  deadlineAt: number;
  expiresAt: number;
}

interface PreAuthenticatedTransport {
  /** Undefined for the mTLS + enrolled-key profile; tokens are loopback-only. */
  authEpoch?: number;
  /** An HTTP upgrade capacity reservation held until attach consumes it. */
  reservedHandshake: boolean;
  profile?: WireProfile;
}

class IdentityCollisionError extends Error {
  constructor() {
    super("A different authenticated principal already owns this logical agent ID");
    this.name = "IdentityCollisionError";
  }
}

function dateFromNow(ms: number): string {
  return new Date(Date.now() + ms).toISOString();
}

function defaultBrokerCard(agentId: string, instanceId: string): AgentCard {
  return {
    card_version: "1.0",
    agent_id: agentId,
    instance_id: instanceId,
    display_name: "PolyMesh Broker",
    issued_at: new Date().toISOString(),
    // A broker is normally long-lived, but a finite expiry keeps the card
    // schema honest and gives reconnecting peers a refresh point.
    expires_at: dateFromNow(24 * 60 * 60 * 1_000),
    revision: 1,
    capabilities: [
      { id: "org.polymesh.agent.ping", version: "1.0.0" },
      { id: "org.polymesh.agent.info", version: "1.0.0" },
      { id: "org.polymesh.capabilities.list", version: "1.0.0" },
    ],
  };
}

function websocketStateOpen(transport: BrokerTransport): boolean {
  // `readyState` is absent on the in-memory transport.  ws.OPEN is 1.
  return transport.readyState === undefined || transport.readyState === WebSocket.OPEN;
}

function asFrameInput(data: unknown): string | Uint8Array | undefined {
  if (typeof data === "string") return data;
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return undefined;
}

function frameByteLength(input: string | Uint8Array): number {
  return typeof input === "string" ? Buffer.byteLength(input, "utf8") : input.byteLength;
}

function taskIdOf(envelope: Envelope): string | undefined {
  const value = (envelope.params as JsonRecord | undefined)?.task_id;
  return typeof value === "string" ? value : undefined;
}

function taskContractOf(envelope: Envelope<"task.submit"> | Envelope): CapabilityContractTuple | undefined {
  const params = envelope.params as JsonRecord;
  const candidate = {
    capability_id: envelope.type === "task.submit" ? params.method : params.capability_id,
    capability_version: params.capability_version,
    capability_contract_digest: params.capability_contract_digest,
  };
  return isCapabilityContractTuple(candidate) ? candidate : undefined;
}

function sameCapabilityContract(left: CapabilityContractTuple, right: CapabilityContractTuple): boolean {
  return left.capability_id === right.capability_id &&
    left.capability_version === right.capability_version &&
    left.capability_contract_digest === right.capability_contract_digest;
}

function isLifecycle(type: EnvelopeType): boolean {
  return type === "task.accepted" || type === "task.rejected" || type === "task.progress" || type === "task.completed";
}

/** The compact v2 profile uses a closed JSON object at every wire boundary. */
function isJsonRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyNativeV2Keys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).every((key) => keys.includes(key));
}

function hasNativeV2Keys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return keys.every((key) => Object.hasOwn(value, key));
}

const NATIVE_V2_AGENT_ID_RE = /^(?:[a-z]|[a-z][a-z0-9._-]*[a-z0-9])$/;
const NATIVE_V2_INSTANCE_ID_RE = /^[A-Za-z0-9._-]+$/;
const NATIVE_V2_IDEMPOTENCY_KEY_RE = /^[A-Za-z0-9._~:\-]+$/;

function isNativeV2AgentId(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 255 && NATIVE_V2_AGENT_ID_RE.test(value);
}

function isNativeV2InstanceId(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 255 && NATIVE_V2_INSTANCE_ID_RE.test(value);
}

function isNativeV2Compression(value: unknown): value is V2CompressionAlgorithm {
  return typeof value === "string" && (V2_COMPRESSION_ALGORITHMS as readonly string[]).includes(value);
}

function isNativeV2ErrorCode(value: unknown): value is V2ErrorCode {
  return typeof value === "string" && (V2_ERROR_CODES as readonly string[]).includes(value);
}

function isNativeV2InitRecord(value: unknown): value is V2InitFrame {
  return isJsonRecord(value) && value.type === "v2.init";
}

/**
 * Validate the compact profile's initial record before it can establish an
 * identity.  A caller may hint a mesh, but the broker never adopts it.
 */
function validateNativeV2Init(value: unknown): V2InitFrame | undefined {
  if (!isJsonRecord(value)) return undefined;
  const allowed = ["type", "protocol", "profile", "supported_profiles", "mesh_id", "agent_id", "instance_id", "nonce", "compression"];
  const required = ["type", "profile", "agent_id", "instance_id", "nonce"];
  if (!hasNativeV2Keys(value, required) || !hasOnlyNativeV2Keys(value, allowed) ||
    value.type !== "v2.init" || value.profile !== V2_PROFILE ||
    (value.protocol !== undefined && value.protocol !== V2_PROFILE) ||
    (value.mesh_id !== undefined && !isUuidV7(value.mesh_id)) ||
    !isNativeV2AgentId(value.agent_id) || !isNativeV2InstanceId(value.instance_id) || !isUuidV7(value.nonce)) {
    return undefined;
  }
  if (value.supported_profiles !== undefined) {
    if (!Array.isArray(value.supported_profiles) || value.supported_profiles.length === 0 ||
      new Set(value.supported_profiles).size !== value.supported_profiles.length ||
      !value.supported_profiles.every((profile) => profile === V2_PROFILE) ||
      !value.supported_profiles.includes(V2_PROFILE)) return undefined;
  }
  if (value.compression !== undefined) {
    if (!Array.isArray(value.compression) || value.compression.length === 0 ||
      new Set(value.compression).size !== value.compression.length ||
      !value.compression.every((algorithm) => isNativeV2Compression(algorithm))) return undefined;
  }
  return value as unknown as V2InitFrame;
}

function isNativeV2Address(value: unknown, identity: boolean): boolean {
  if (!isJsonRecord(value)) return false;
  const allowed = ["agent_id", "instance_id"];
  const required = identity ? ["agent_id", "instance_id"] : ["agent_id"];
  return hasNativeV2Keys(value, required) && hasOnlyNativeV2Keys(value, allowed) &&
    isNativeV2AgentId(value.agent_id) &&
    (value.instance_id === undefined || isNativeV2InstanceId(value.instance_id));
}

/** Closed structural validation for a native-v2 application envelope. */
function validateNativeV2Envelope(value: unknown): V2NativeEnvelope | undefined {
  if (!isJsonRecord(value)) return undefined;
  const allowed = ["protocol", "profile", "mesh_id", "type", "message_id", "timestamp", "source", "target", "delivery", "in_reply_to", "params"];
  const required = ["protocol", "profile", "mesh_id", "type", "message_id", "timestamp", "source", "target", "delivery", "params"];
  if (!hasNativeV2Keys(value, required) || !hasOnlyNativeV2Keys(value, allowed) ||
    value.protocol !== V2_PROFILE || value.profile !== V2_PROFILE || !isUuidV7(value.mesh_id) ||
    typeof value.type !== "string" || !(V2_NATIVE_ENVELOPE_TYPES as readonly string[]).includes(value.type) ||
    !isUuidV7(value.message_id) || !isTimestamp(value.timestamp) ||
    !isNativeV2Address(value.source, true) || !isNativeV2Address(value.target, false) ||
    (value.in_reply_to !== undefined && !isUuidV7(value.in_reply_to)) ||
    !isJsonRecord(value.params) || !isJsonValue(value.params) || !isJsonRecord(value.delivery)) {
    return undefined;
  }
  const delivery = value.delivery;
  if (!hasNativeV2Keys(delivery, ["delivery_id", "mode", "idempotency_key", "deadline"]) ||
    !hasOnlyNativeV2Keys(delivery, ["delivery_id", "mode", "idempotency_key", "deadline"]) ||
    !isUuidV7(delivery.delivery_id) || delivery.mode !== "at_least_once" ||
    typeof delivery.idempotency_key !== "string" || delivery.idempotency_key.length === 0 ||
    delivery.idempotency_key.length > 256 || !NATIVE_V2_IDEMPOTENCY_KEY_RE.test(delivery.idempotency_key) ||
    !isTimestamp(delivery.deadline)) {
    return undefined;
  }
  const params = value.params;
  if (value.type === "task.submit") {
    if (!hasNativeV2Keys(params, ["task_id", "capability", "input", "deadline"]) ||
      !hasOnlyNativeV2Keys(params, ["task_id", "capability", "capability_version", "capability_contract_digest", "input", "deadline"]) ||
      !isUuidV7(params.task_id) || !isNativeV2AgentId(params.capability) || !isJsonValue(params.input) ||
      !isTimestamp(params.deadline) || params.deadline !== delivery.deadline ||
      (params.capability_version !== undefined && (typeof params.capability_version !== "string" || !/^\d+\.\d+\.\d+$/.test(params.capability_version))) ||
      (params.capability_contract_digest !== undefined && (typeof params.capability_contract_digest !== "string" || !/^[0-9a-f]{64}$/i.test(params.capability_contract_digest)))) {
      return undefined;
    }
  }
  if (value.type === "error") {
    if (!hasNativeV2Keys(params, ["code", "message", "retryable"]) ||
      !hasOnlyNativeV2Keys(params, ["code", "message", "retryable", "details"]) ||
      !isNativeV2ErrorCode(params.code) || typeof params.message !== "string" || params.message.length === 0 ||
      params.message.length > 1_024 || typeof params.retryable !== "boolean" ||
      (params.details !== undefined && (!isJsonRecord(params.details) || !isJsonValue(params.details)))) {
      return undefined;
    }
  }
  return value as unknown as V2NativeEnvelope;
}

function nativeV2TaskId(envelope: V2NativeEnvelope): string | undefined {
  const taskId = (envelope.params as JsonRecord).task_id;
  return isUuidV7(taskId) ? taskId : undefined;
}

function isNativeV2Lifecycle(type: V2NativeEnvelopeType): boolean {
  return type === "task.accepted" || type === "task.rejected" || type === "task.progress" || type === "task.completed";
}

function nativeEndpointMatchesPeer(
  endpoint: { agentId: string; instanceId: string; sessionId: string },
  peer: BrokerPeer,
): boolean {
  return peer.profile === "native-v2" && peer.agentId === endpoint.agentId &&
    peer.instanceId === endpoint.instanceId && peer.sessionId === endpoint.sessionId;
}

function nativeTargetMatchesEndpoint(
  target: V2NativeEnvelope["target"],
  endpoint: { agentId: string; instanceId: string },
): boolean {
  return target.agent_id === endpoint.agentId &&
    (target.instance_id === undefined || target.instance_id === endpoint.instanceId);
}

function nativeV2ContractFields(params: JsonRecord): JsonObject {
  const capability = typeof params.capability === "string" ? params.capability : undefined;
  const capabilityVersion = typeof params.capability_version === "string" ? params.capability_version : undefined;
  const contractDigest = typeof params.capability_contract_digest === "string" ? params.capability_contract_digest : undefined;
  return {
    ...(capability === undefined ? {} : { capability }),
    ...(capabilityVersion === undefined ? {} : { capability_version: capabilityVersion }),
    ...(contractDigest === undefined ? {} : { capability_contract_digest: contractDigest }),
  };
}

/** Records whose claimed remote source can change task or policy state. */
function requiresRoutedProvenance(type: EnvelopeType): boolean {
  return type === "task.submit" || type === "task.cancel" || isLifecycle(type) || type === "error";
}

/**
 * A local WebSocket router.  `start()` is idempotent and returns the broker so
 * callers can write `await new Broker({ port: 0 }).start()`.
 */
export class Broker {
  readonly options: Readonly<BrokerOptions>;
  readonly card: AgentCard;
  readonly cardDigest: string;
  readonly registry: Registry<BrokerPeer, AgentCard>;

  private readonly now: () => number;
  private readonly handshakeTimeoutMs: number;
  private readonly maxFrameBytes: number;
  private readonly maxHttpHeaderBytes: number;
  private readonly maxHttpHeaderCount: number;
  private readonly httpHeaderTimeoutMs: number;
  private readonly httpRequestTimeoutMs: number;
  private readonly maxPendingHandshakes: number;
  private readonly maxOpenSessions: number;
  private readonly maxPendingTaskRoutes: number;
  private readonly maxPendingTaskRoutesPerSession: number;
  private readonly maxReplayLedgerEntries: number;
  private readonly maxLifecycleEventsPerRoute: number;
  private readonly replayRetentionMs: number;
  private readonly allowedOrigins: readonly string[];
  private readonly meshId?: string;
  /** Broker-owned UUIDv7 mesh scope for the compact native v2 profile. */
  readonly nativeV2MeshId: string;
  private readonly multiInstanceRouting: boolean;
  private readonly allowInsecureMultiInstanceDevelopment: boolean;
  private readonly durableStore?: DurableStore;
  private readonly durableRegistry?: DurableRegistry<BrokerPeer, AgentCard>;
  private readonly durableNodeId?: string;
  private readonly rateLimiter?: HierarchicalRateLimiter;
  private readonly compressionOffer: CompressionOffer;
  private readonly allowZstdCompression: boolean;
  private readonly v2Enabled: boolean;
  private readonly nativeV2Enabled: boolean;
  private readonly nativeV2Store?: NativeV2DurableStore;
  private readonly supportedSubprotocols: readonly string[];
  private readonly tokenAuthority?: RuntimeTokenAuthority;
  private readonly identityProfile?: {
    privateKey: Ed25519PrivateKey;
    enrollments: EnrollmentStore;
    identity: CardIdentity;
    localPrincipal: VerifiedPrincipal;
  };
  private readonly peers = new Set<BrokerPeer>();
  /** Live compact-profile sessions, fenced by broker mesh + peer session. */
  private readonly nativeV2Peers = new Map<string, BrokerPeer>();
  private readonly nativeV2Tasks = new Map<string, NativeV2TaskRoute>();
  private readonly nativeV2RoutesBySubmitMessageId = new Map<string, string>();
  private readonly nativeV2ReplayLedger = new Map<string, ReplayLedgerRecord>();
  /** Process-local sockets keyed by a durable v0.2 instance identity. */
  private readonly routingInstances = new Map<string, LiveRoutingInstance>();
  /** Monotonic registration sequence per mesh/logical/physical instance. */
  private readonly nextRegistrationFence = new Map<string, number>();
  /** Monotonic fence allocated to each in-memory v0.2 route record. */
  private nextRouteFence = 0;
  private readonly pendingTasks = new Map<string, TaskRoute>();
  private readonly routesBySubmitMessageId = new Map<string, string>();
  /** Per-session reservations for live routes. Terminal tombstones do not consume them. */
  private readonly pendingRoutesBySession = new Map<string, number>();
  /** Message-id reuse protection. This is recorded before forwarding a valid envelope. */
  private readonly replayLedger = new Map<string, ReplayLedgerRecord>();
  /** Durable close/cleanup writes that must finish before broker shutdown. */
  private readonly pendingDurableMutations = new Set<Promise<unknown>>();
  /** Coalesces durable wake-ups so READY/ingress bursts do not self-lease rows. */
  private durableDispatchInFlight?: Promise<DurableDispatchResult>;
  private readonly handshakeTimers = new WeakMap<BrokerPeer, ReturnType<typeof setTimeout>>();
  private readonly preAuthenticatedTransports = new WeakMap<object, PreAuthenticatedTransport>();
  /** Upgrades reserved before WebSocket allocation, then consumed by attach. */
  private pendingUpgradeReservations = 0;
  private server?: HttpServer | HttpsServer;
  private wsServer?: WebSocketServer;
  private cleanupTimer?: ReturnType<typeof setInterval>;
  private tokenRotationTimer?: ReturnType<typeof setTimeout>;
  private closing = false;

  constructor(options: BrokerOptions = {}) {
    this.options = { ...options };
    this.now = options.now ?? Date.now;
    this.handshakeTimeoutMs = options.handshakeTimeoutMs ?? HANDSHAKE_TIMEOUT_MS;
    this.maxFrameBytes = options.maxFrameBytes ?? MAX_FRAME_BYTES;
    this.maxHttpHeaderBytes = options.maxHttpHeaderBytes ?? DEFAULT_HTTP_HEADER_BYTES;
    this.maxHttpHeaderCount = options.maxHttpHeaderCount ?? DEFAULT_HTTP_HEADER_COUNT;
    this.httpHeaderTimeoutMs = options.httpHeaderTimeoutMs ?? DEFAULT_HTTP_HEADER_TIMEOUT_MS;
    this.httpRequestTimeoutMs = options.httpRequestTimeoutMs ?? DEFAULT_HTTP_REQUEST_TIMEOUT_MS;
    this.maxPendingHandshakes = options.maxPendingHandshakes ?? DEFAULT_MAX_PENDING_HANDSHAKES;
    this.maxOpenSessions = options.maxOpenSessions ?? DEFAULT_MAX_OPEN_SESSIONS;
    this.maxPendingTaskRoutes = options.maxPendingTaskRoutes ?? DEFAULT_MAX_PENDING_TASK_ROUTES;
    this.maxPendingTaskRoutesPerSession = options.maxPendingTaskRoutesPerSession ?? DEFAULT_MAX_PENDING_TASK_ROUTES_PER_SESSION;
    this.maxReplayLedgerEntries = options.maxReplayLedgerEntries ?? DEFAULT_MAX_REPLAY_LEDGER_ENTRIES;
    this.maxLifecycleEventsPerRoute = options.maxLifecycleEventsPerRoute ?? DEFAULT_MAX_LIFECYCLE_EVENTS_PER_ROUTE;
    this.replayRetentionMs = Math.max(MIN_REPLAY_RETENTION_MS, options.replayRetentionMs ?? MIN_REPLAY_RETENTION_MS);
    this.allowedOrigins = Object.freeze([...(options.allowedOrigins ?? [])]);
    this.meshId = options.meshId;
    // The compact native profile never accepts a caller-chosen mesh scope.
    // A UUIDv7 is allocated once per Broker instance and becomes visible only
    // in v2.ack, after the transport itself was authenticated.
    this.nativeV2MeshId = uuidv7(this.now());
    this.multiInstanceRouting = options.multiInstanceRouting === true;
    this.allowInsecureMultiInstanceDevelopment = options.allowInsecureMultiInstanceDevelopment === true;
    this.durableStore = options.durableStore;
    this.rateLimiter = options.rateLimiter;
    this.compressionOffer = Object.freeze({
      algorithms: [...(options.compressionOffer?.algorithms ?? ["none"])],
      ...(options.compressionOffer?.limits === undefined ? {} : { limits: { ...options.compressionOffer.limits } }),
    });
    this.allowZstdCompression = options.allowZstdCompression === true;
    this.v2Enabled = options.enableV2 ?? this.durableStore !== undefined;
    this.nativeV2Enabled = options.enableNativeV2 !== false;
    this.nativeV2Store = options.nativeV2Store;
    this.supportedSubprotocols = Object.freeze(this.v2Enabled || this.nativeV2Enabled
      ? [V2_SUBPROTOCOL, PROTOCOL_VERSION]
      : [PROTOCOL_VERSION]);
    if (!Number.isInteger(this.maxFrameBytes) || this.maxFrameBytes <= 0 || this.maxFrameBytes > MAX_FRAME_BYTES) {
      throw new RangeError(`maxFrameBytes must be between 1 and ${MAX_FRAME_BYTES}`);
    }
    if (!Number.isFinite(this.handshakeTimeoutMs) || this.handshakeTimeoutMs <= 0) {
      throw new RangeError("handshakeTimeoutMs must be a positive finite number");
    }
    if (!Number.isInteger(this.maxHttpHeaderBytes) || this.maxHttpHeaderBytes < 1_024) {
      throw new RangeError("maxHttpHeaderBytes must be an integer of at least 1024 bytes");
    }
    if (!Number.isInteger(this.maxHttpHeaderCount) || this.maxHttpHeaderCount < 1) {
      throw new RangeError("maxHttpHeaderCount must be a positive integer");
    }
    if (![this.httpHeaderTimeoutMs, this.httpRequestTimeoutMs].every((value) => Number.isFinite(value) && value > 0)) {
      throw new RangeError("HTTP timeouts must be positive finite durations");
    }
    if (this.httpHeaderTimeoutMs > this.httpRequestTimeoutMs) {
      throw new RangeError("httpHeaderTimeoutMs must not exceed httpRequestTimeoutMs");
    }
    if (![this.maxPendingHandshakes, this.maxOpenSessions, this.maxPendingTaskRoutes, this.maxPendingTaskRoutesPerSession, this.maxReplayLedgerEntries, this.maxLifecycleEventsPerRoute]
      .every((value) => Number.isInteger(value) && value > 0)) {
      throw new RangeError("broker admission limits must be positive integers");
    }
    if (!Number.isFinite(this.replayRetentionMs) || this.replayRetentionMs < MIN_REPLAY_RETENTION_MS) {
      throw new RangeError(`replayRetentionMs must be at least ${MIN_REPLAY_RETENTION_MS} ms`);
    }
    if (this.allowedOrigins.some((origin) => typeof origin !== "string" || origin.length === 0 || /[\r\n]/.test(origin))) {
      throw new TypeError("allowedOrigins must contain exact non-empty origin strings");
    }
    if (this.multiInstanceRouting && (typeof this.meshId !== "string" || this.meshId.length === 0 || this.meshId.length > 255)) {
      throw new TypeError("multiInstanceRouting requires a bounded meshId");
    }
    if (this.durableStore && !this.multiInstanceRouting) {
      throw new TypeError("durableStore requires the opt-in multiInstanceRouting profile");
    }
    if (this.v2Enabled && (!this.durableStore || !this.multiInstanceRouting)) {
      throw new TypeError("The polymesh.0.2 profile requires durableStore and multiInstanceRouting");
    }
    if (options.token !== undefined) this.tokenAuthority = new RuntimeTokenAuthority(options.token, this.now);

    const instanceId = options.instanceId ?? randomInstanceId();
    const agentId = options.agentId ?? "org.polymesh.broker";
    let localCard = options.card ?? defaultBrokerCard(agentId, instanceId);
    if (!isAgentCard(localCard)) throw new TypeError("Broker card is not a valid AgentCard");
    if (options.identity) {
      const enrollments = options.identity.enrollments instanceof EnrollmentStore
        ? options.identity.enrollments
        : new EnrollmentStore(options.identity.enrollments);
      const identity = createCardIdentityFromPrivateKey(options.identity.privateKey);
      if (localCard.identity !== undefined && (
        localCard.identity.key_id !== identity.key_id ||
        localCard.identity.public_key !== identity.public_key
      )) {
        throw new TypeError("Broker Card identity does not match the configured signing key");
      }
      localCard = signAgentCard(localCard, options.identity.privateKey);
      const localPrincipal = verifyEnrolledCard(localCard, enrollments, this.now());
      if (!localPrincipal) {
        throw new TypeError("The local signed Broker Card must be present in the enrolled identity store");
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
    this.registry = options.registry ?? new Registry<BrokerPeer, AgentCard>({ ttlMs: options.ttlMs, clock: this.now });
    if (this.multiInstanceRouting && !this.identityProfile && !this.allowInsecureMultiInstanceDevelopment) {
      throw new TypeError("multiInstanceRouting requires the enrolled identity profile outside explicit local development");
    }
    if (this.multiInstanceRouting && this.rateLimiter?.enabled && !this.rateLimiter.distributed && !this.allowInsecureMultiInstanceDevelopment) {
      throw new TypeError("multi-instance rate limiting requires a shared AtomicTokenBucketStore");
    }
    if (this.durableStore) {
      this.durableRegistry = new DurableRegistry<BrokerPeer, AgentCard>({
        store: this.durableStore,
        meshId: this.meshId!,
        ttlMs: this.registry.ttlMs,
        clock: this.now,
      });
      this.durableNodeId = options.durableNodeId ?? `${this.card.agent_id}:${this.card.instance_id}`;
      if (typeof this.durableNodeId !== "string" || this.durableNodeId.length === 0 || this.durableNodeId.length > 512) {
        throw new TypeError("durableNodeId must be a bounded non-empty string");
      }
    }
  }

  /** TCP port once started (including OS-assigned port for `port: 0`). */
  get port(): number | undefined {
    const address = this.server?.address();
    return typeof address === "object" && address ? address.port : undefined;
  }

  get host(): string {
    return this.options.host ?? "127.0.0.1";
  }

  get url(): string | undefined {
    const port = this.port;
    if (port === undefined) return undefined;
    const host = this.host.includes(":") ? `[${this.host}]` : this.host;
    return `${this.options.tls ? "wss" : "ws"}://${host}:${port}${POLYMESH_PATH}`;
  }

  /** Current token generation; useful for observability without exposing secret material. */
  get authEpoch(): number | undefined {
    return this.tokenAuthority?.authEpoch;
  }

  /** Compact native-v2 mesh scope assigned once for this broker instance. */
  get nativeMeshId(): string {
    return this.nativeV2MeshId;
  }

  /**
   * Atomically rotate a loopback runtime token. Hard rotation immediately
   * tears down all authenticated sessions. Normal rotation permits the prior
   * token only during its bounded overlap and then tears down old-epoch peers.
   */
  rotateToken(token: string, options: TokenRotationOptions = {}): number {
    if (!this.tokenAuthority) throw new ProtocolError("AUTHENTICATION_FAILED", "No runtime token is configured", "identity");
    const epoch = this.tokenAuthority.rotate(token, options);
    if (this.tokenRotationTimer) clearTimeout(this.tokenRotationTimer);
    if (options.hard === true) {
      for (const peer of [...this.peers]) this.closePeer(peer, "credential rotated");
      return epoch;
    }
    const overlapMs = options.overlapMs ?? 30_000;
    this.tokenRotationTimer = setTimeout(() => {
      this.tokenAuthority?.clearExpiredPrevious();
      for (const peer of [...this.peers]) {
        if (peer.authEpoch !== undefined && peer.authEpoch < epoch) this.closePeer(peer, "credential rotated");
      }
    }, overlapMs);
    this.tokenRotationTimer.unref?.();
    return epoch;
  }

  address(): AddressInfo | string | null | undefined {
    return this.server?.address();
  }

  /** Snapshot of active, fully handshaken peers. */
  listPeers(): BrokerPeer[] {
    return [...this.peers].filter((peer) => peer.phase === "active");
  }

  /** Snapshot of the v0.2 process-local connection index without socket handles. */
  listRoutingInstances(): readonly Omit<LiveRoutingInstance, "peer">[] {
    return [...this.routingInstances.values()].map(({ peer: _peer, ...instance }) => ({ ...instance }));
  }

  /**
   * Negotiate a transport codec only after this peer completed READY. The
   * broker stores metadata, while a transport adapter owns actual zstd bytes.
   */
  negotiatePeerCompression(peer: BrokerPeer, remote: CompressionOffer): CompressionNegotiationResult {
    const result = negotiateCompression(this.compressionOffer, remote, {
      ready: peer.phase === "active",
      // A configured zstd preference is not enough: a broker running on an
      // older Node runtime must select the explicit `none` fallback instead
      // of negotiating a codec it cannot actually enforce.
      allowZstd: this.allowZstdCompression && runtimeZstdCodec() !== undefined,
    });
    if (result.ok) peer.compression = result.value;
    return result;
  }

  /**
   * Fenced health mutation for a v0.2 instance. A stale close/renewal cannot
   * change the health of a replacement session that acquired a newer fence.
   */
  setInstanceHealth(
    agentId: string,
    instanceId: string,
    health: HealthState,
    expected: { registrationFence: number; sessionFence: number; sessionId: string },
  ): boolean | Promise<boolean> {
    if (!this.multiInstanceRouting || !this.meshId || !Object.values(HealthState).includes(health)) return false;
    const instance = this.routingInstances.get(this.routingInstanceKey(this.meshId, agentId, instanceId));
    if (!instance || !isCurrentInstanceFence(instance, expected)) return false;
    if (this.durableRegistry) {
      return this.persistInstanceHealth(instance, health, expected);
    }
    instance.health = health;
    instance.peer.health = health;
    return true;
  }

  private async persistInstanceHealth(
    instance: LiveRoutingInstance,
    health: HealthState,
    expected: { registrationFence: number; sessionFence: number; sessionId: string },
  ): Promise<boolean> {
    const durableRegistry = this.durableRegistry;
    if (!durableRegistry) return false;
    const persisted = await durableRegistry.renewDurable({
      meshId: instance.meshId,
      agentId: instance.agentId,
      instanceId: instance.instanceId,
      registrationFence: expected.registrationFence,
      sessionFence: expected.sessionFence,
      expiresAt: instance.expiresAt,
      health,
    });
    if (!persisted) return false;
    const current = this.routingInstances.get(this.routingInstanceKey(instance.meshId, instance.agentId, instance.instanceId));
    if (!current || !isCurrentInstanceFence(current, expected)) return false;
    current.health = health;
    current.peer.health = health;
    return true;
  }

  /**
   * Apply relay-owned capacity policy under the current registration fence.
   * No Card or envelope field can call this method, preventing a target from
   * inflating its own rendezvous weight.
   */
  setInstanceCapacityPolicy(
    agentId: string,
    instanceId: string,
    policy: { capacity?: number; capacityWeight?: number },
    expected: { registrationFence: number; sessionFence: number; sessionId: string },
  ): boolean | Promise<boolean> {
    if (!this.multiInstanceRouting || !this.meshId) return false;
    if ((policy.capacity !== undefined && (!Number.isSafeInteger(policy.capacity) || policy.capacity < 0)) ||
      (policy.capacityWeight !== undefined && (!Number.isFinite(policy.capacityWeight) || policy.capacityWeight <= 0))) {
      throw new RangeError("Routing capacity policy is invalid");
    }
    const instance = this.routingInstances.get(this.routingInstanceKey(this.meshId, agentId, instanceId));
    if (!instance || !isCurrentInstanceFence(instance, expected)) return false;
    if (this.durableStore) {
      return this.persistInstanceCapacity(instance, policy, expected);
    }
    if (policy.capacity !== undefined) instance.capacity = policy.capacity;
    if (policy.capacityWeight !== undefined) instance.capacityWeight = policy.capacityWeight;
    return true;
  }

  private async persistInstanceCapacity(
    instance: LiveRoutingInstance,
    policy: { capacity?: number; capacityWeight?: number },
    expected: { registrationFence: number; sessionFence: number; sessionId: string },
  ): Promise<boolean> {
    const store = this.durableStore;
    if (!store?.updateInstanceCapacity) return false;
    const persisted = await store.updateInstanceCapacity({
      meshId: instance.meshId,
      agentId: instance.agentId,
      instanceId: instance.instanceId,
      registrationFence: expected.registrationFence,
      sessionFence: expected.sessionFence,
      ...(policy.capacity === undefined ? {} : { capacity: policy.capacity }),
      ...(policy.capacityWeight === undefined ? {} : { capacityWeight: policy.capacityWeight }),
      updatedAt: this.now(),
    });
    if (!persisted) return false;
    const current = this.routingInstances.get(this.routingInstanceKey(instance.meshId, instance.agentId, instance.instanceId));
    if (!current || !isCurrentInstanceFence(current, expected)) return false;
    if (policy.capacity !== undefined) current.capacity = policy.capacity;
    if (policy.capacityWeight !== undefined) current.capacityWeight = policy.capacityWeight;
    return true;
  }

  /**
   * Reclaim durable outbox leases and mark expired instance leases offline.
   * Socket indexes remain intentionally process-local and are never rebuilt
   * from this result; reconnecting sessions populate them through READY.
   */
  async recoverDurable(now = this.now()): Promise<RecoveryReport | undefined> {
    const report = await this.durableStore?.recover(now);
    this.wakeDurableDispatcher();
    return report;
  }

  /**
   * Atomically persist broker ingress dedupe, a physical task route, and its
   * target outbox row. This is the v0.2 relay admission boundary: callers
   * must emit `delivery.receipt(state="stored")` only from the returned
   * receipt, never after a mere socket write.
   *
   * The public method is intentionally async even though better-sqlite3 uses
   * synchronous BEGIN IMMEDIATE internally, so PostgreSQL/remote stores can
   * implement the same interface without changing broker call sites.
   */
  async persistDurableIngress(
    peer: BrokerPeer,
    envelope: Envelope | V2Envelope,
    options: DurableIngressOptions = {},
  ): Promise<DurableIngressAdmission> {
    const store = this.durableStore;
    if (!store || !this.multiInstanceRouting || !this.meshId) {
      throw new ProtocolError("DURABLE_STORAGE_DISABLED", "This broker was not configured with a durable v0.2 store", "internal");
    }
    const v2 = (envelope as { protocol?: unknown }).protocol === V2_PROTOCOL_VERSION;
    if (v2 && !isV2Envelope(envelope)) {
      throw new ProtocolError("MALFORMED_FRAME", "Durable v0.2 ingress is not a valid mesh envelope", "parse");
    }
    if (v2 && !isV2IngressEnvelope(envelope)) {
      throw new ProtocolError("DELIVERY_METADATA_FORBIDDEN", "Only the relay may attach v0.2 delivery metadata", "identity");
    }
    const logical = v2 ? v2EnvelopeAsLegacy(envelope as V2Envelope) : envelope as Envelope;
    if (peer.phase !== "active" || !peer.agentId || !peer.instanceId ||
      logical.source.agent_id !== peer.agentId || logical.source.instance_id !== peer.instanceId) {
      throw new ProtocolError("SOURCE_IDENTITY_MISMATCH", "Durable ingress requires an active authenticated source session", "identity");
    }
    if (logical.type === "receipt") {
      throw new ProtocolError("RECEIPT_NON_RECURSIVE", "Receipts are not durable ingress payloads", "protocol");
    }
    const sourcePrincipalId = this.routingPrincipal(peer);
    if (!sourcePrincipalId) {
      throw new ProtocolError("AUTHENTICATION_FAILED", "Durable ingress requires an authenticated principal", "identity");
    }
    const now = this.now();
    const deadline = logical.delivery.deadline;
    const deadlineAt = deadline === undefined ? Number.NaN : Date.parse(deadline);
    if (!Number.isFinite(deadlineAt) || deadlineAt <= now) {
      throw new ProtocolError("PMX.TASK.DEADLINE_EXCEEDED", "Durable ingress deadline has elapsed", "task");
    }
    const semanticFingerprint = options.semanticFingerprint ?? (v2
      ? v2EnvelopeSemanticDigest(envelope as V2Envelope)
      : envelopeSemanticDigest(logical));
    const taskId = taskIdOf(logical);
    const contract = logical.type === "task.submit" ? taskContractOf(logical) : undefined;
    if (logical.type === "task.submit" && (!taskId || !contract)) {
      throw new ProtocolError("MALFORMED_FRAME", "Task submission has no valid durable route identity", "parse");
    }

    let route: DurableTaskRoute | undefined;
    let target: RegistryEntry<BrokerPeer, AgentCard> | undefined;
    const existingRoute = taskId === undefined ? undefined : await store.getRoute(this.meshId, taskId);
    if (taskId && contract) {
      const immutableFingerprint = this.taskImmutableFingerprint(logical, contract);
      if (existingRoute) {
        if (existingRoute.immutableFingerprint !== immutableFingerprint) {
          throw new ProtocolError("PMX.TASK.ID_CONFLICT", "Task ID was reused with different immutable input", "task");
        }
        if (existingRoute.ownerAgentId !== peer.agentId || existingRoute.ownerInstanceId !== peer.instanceId ||
          (existingRoute.ownerSessionId !== undefined && existingRoute.ownerSessionId !== peer.sessionId)) {
          throw new ProtocolError("STALE_FENCE", "Task retry was received from a session other than the pinned route owner", "identity", true);
        }
        route = existingRoute;
        target = this.lookupRegisteredInstance(existingRoute.executorAgentId, existingRoute.executorInstanceId);
      } else {
        target = this.selectDurableTarget(logical, v2 ? "v2" : undefined);
        const selected = this.routingInstances.get(this.routingInstanceKey(this.meshId, target.agentId, target.instanceId));
        if (!selected) throw new ProtocolError("TARGET_UNAVAILABLE", "Selected target disconnected before route persistence", "routing", true);
        route = {
          meshId: this.meshId,
          taskId,
          ownerPrincipalId: sourcePrincipalId,
          ownerAgentId: peer.agentId,
          ownerInstanceId: peer.instanceId,
          ...(peer.sessionId === undefined ? {} : { ownerSessionId: peer.sessionId }),
          executorPrincipalId: selected.principalId,
          executorAgentId: target.agentId,
          executorInstanceId: target.instanceId,
          ...(target.sessionId === undefined ? {} : { executorSessionId: target.sessionId }),
          immutableFingerprint,
          deadlineAt,
          routeFence: ++this.nextRouteFence,
          state: "SUBMITTED",
          createdAt: now,
          updatedAt: now,
          retainedUntil: Math.max(deadlineAt, now) + this.replayRetentionMs,
        };
      }
    } else if (existingRoute && taskId && (
      logical.type === "task.cancel" ||
      isLifecycle(logical.type) ||
      logical.type === "task.status"
    )) {
      route = existingRoute;
      const statusKind = logical.type === "task.status"
        ? (logical.params as JsonRecord).kind
        : undefined;
      const statusQuery = statusKind === "query";
      const statusSnapshot = statusKind === "snapshot";
      const fromOwner = peer.agentId === existingRoute.ownerAgentId && peer.instanceId === existingRoute.ownerInstanceId &&
        (existingRoute.ownerSessionId === undefined || existingRoute.ownerSessionId === peer.sessionId);
      const fromExecutor = peer.agentId === existingRoute.executorAgentId && peer.instanceId === existingRoute.executorInstanceId &&
        (existingRoute.executorSessionId === undefined || existingRoute.executorSessionId === peer.sessionId);
      const targetIsExecutor = logical.target.agent_id === existingRoute.executorAgentId &&
        (logical.target.instance_id === undefined || logical.target.instance_id === existingRoute.executorInstanceId);
      const targetIsOwner = logical.target.agent_id === existingRoute.ownerAgentId &&
        (logical.target.instance_id === undefined || logical.target.instance_id === existingRoute.ownerInstanceId);
      const ownerToExecutor = logical.type === "task.cancel" || statusQuery;
      const executorToOwner = isLifecycle(logical.type) || statusSnapshot;
      if ((ownerToExecutor && (!fromOwner || !targetIsExecutor)) ||
        (executorToOwner && (!fromExecutor || !targetIsOwner)) ||
        (!ownerToExecutor && !executorToOwner)) {
        throw new ProtocolError("SOURCE_IDENTITY_MISMATCH", "Task route direction does not match its pinned owner/executor", "identity");
      }
      const targetAgentId = ownerToExecutor ? existingRoute.executorAgentId : existingRoute.ownerAgentId;
      const targetInstanceId = ownerToExecutor ? existingRoute.executorInstanceId : existingRoute.ownerInstanceId;
      target = this.lookupRegisteredInstance(targetAgentId, targetInstanceId);
    } else {
      target = this.selectDurableTarget(logical, v2 ? "v2" : undefined);
    }

    const targetsOwner = existingRoute !== undefined && (
      isLifecycle(logical.type) ||
      (logical.type === "task.status" && (logical.params as JsonRecord).kind === "snapshot")
    );
    const physicalTargetAgentId = targetsOwner
      ? existingRoute.ownerAgentId
      : route?.executorAgentId ?? target?.agentId;
    const physicalTargetInstanceId = targetsOwner
      ? existingRoute.ownerInstanceId
      : route?.executorInstanceId ?? target?.instanceId;
    if (!physicalTargetAgentId || !physicalTargetInstanceId) {
      // A known persisted route may outlive a local socket. It is still safe
      // to enqueue to its immutable physical target, but it cannot be created
      // without a concrete target identity in the first place.
      throw new ProtocolError("TARGET_UNAVAILABLE", "No physical target is available for durable ingress", "routing", true);
    }
    const deliveryId = options.deliveryId ?? uuidv7(now);
    const physicalEnvelope = (v2
      ? attachV2DeliveryMetadata({
        ...(envelope as V2Envelope),
        target: { mesh_id: this.meshId, agent_id: physicalTargetAgentId, instance_id: physicalTargetInstanceId },
      } as V2IngressEnvelope, deliveryId)
      : {
        ...logical,
        target: { agent_id: physicalTargetAgentId, instance_id: physicalTargetInstanceId },
      }) as unknown as JsonObject;
    const inbox: InboxRecord = {
      scope: "ingress",
      meshId: this.meshId,
      sourcePrincipalId,
      sourceAgentId: peer.agentId,
      sourceInstanceId: peer.instanceId,
      targetAgentId: logical.target.agent_id,
      ...(logical.target.instance_id === undefined ? {} : { targetInstanceId: logical.target.instance_id }),
      idempotencyKey: logical.delivery.idempotency_key,
      semanticFingerprint,
      messageId: logical.message_id,
      envelope: physicalEnvelope,
      selectedInstanceId: physicalTargetInstanceId,
      createdAt: now,
      expiresAt: Math.max(deadlineAt, now) + this.replayRetentionMs,
    };
    const outbox: OutboxRecord = {
      deliveryId,
      meshId: this.meshId,
      targetAgentId: physicalTargetAgentId,
      targetInstanceId: physicalTargetInstanceId,
      envelope: physicalEnvelope,
      state: "PENDING",
      attempt: 0,
      createdAt: now,
      updatedAt: now,
      expiresAt: deadlineAt,
    };
    // Only a submission creates/claims the immutable task route. Subsequent
    // pinned cancellation and lifecycle traffic has the opposite direction
    // for one half of the route, so it is durably queued without pretending to
    // create a second owner→executor ingress record.
    const routeForIngress = logical.type === "task.submit" ? route : undefined;
    const sourceFence = peer.registrationFence !== undefined && peer.sessionFence !== undefined && peer.sessionId !== undefined
      ? {
        registrationFence: peer.registrationFence,
        sessionFence: peer.sessionFence,
        sessionId: peer.sessionId,
      }
      : undefined;
    const result = await store.persistIngress({
      inbox,
      ...(routeForIngress === undefined ? {} : { route: routeForIngress }),
      outbox,
      ...(sourceFence === undefined ? {} : { sourceFence }),
    });
    if (result.disposition === "conflict") return { result };
    const persistedTarget = this.lookupRegisteredInstance(physicalTargetAgentId, physicalTargetInstanceId) ?? target;
    const persistedDeliveryId = result.outbox?.deliveryId ?? result.inbox.outboxDeliveryId;
    return {
      result,
      ...(persistedTarget === undefined ? {} : { target: persistedTarget }),
      ...(persistedDeliveryId === undefined ? {} : {
        receipt: {
          type: "delivery.receipt",
          v: V2_HANDSHAKE_VERSION,
          delivery_id: persistedDeliveryId,
          message_id: logical.message_id,
          state: "stored",
        },
      }),
    };
  }

  /**
   * Lease and attempt locally connected durable outbox rows. A successful
   * socket write moves a row only to SENT_AWAITING_RECEIPT; callers must use
   * acknowledgeDurableDelivery after a matching durable receipt before it is
   * considered delivered. Rows with no live connection retain their lease
   * until crash/recovery reclaims it, so they are never discarded as a write.
   */
  async dispatchDurableOutbox(options: DurableDispatchOptions = {}): Promise<DurableDispatchResult> {
    const store = this.durableStore;
    if (!store) throw new ProtocolError("DURABLE_STORAGE_DISABLED", "This broker has no durable outbox", "internal");
    const now = this.now();
    // A process can stay alive across a target reconnect. Reclaim here as
    // well as at startup so a failed/old dispatcher lease never requires a
    // fresh ingress or process restart before it can be retried.
    await store.reclaimExpiredDispatchLeases(now);
    const leased = await store.leasePendingOutbox({
      now,
      leaseId: options.leaseId ?? `${this.durableNodeId ?? "broker"}:${uuidv7(now)}`,
      leaseMs: options.leaseMs ?? Math.max(1_000, Math.min(this.registry.ttlMs, 30_000)),
      limit: options.limit ?? 100,
    });
    const leaseId = leased[0]?.dispatchLeaseId;
    let sent = 0;
    let unavailable = 0;
    let invalid = 0;
    for (const record of leased) {
      const recordLeaseId = record.dispatchLeaseId ?? leaseId;
      const v2 = isV2Envelope(record.envelope);
      if (!recordLeaseId || (!v2 && !isEnvelope(record.envelope))) {
        invalid += 1;
        if (recordLeaseId) await store.releaseOutboxLease({ deliveryId: record.deliveryId, leaseId: recordLeaseId, now: this.now() });
        continue;
      }
      const target = this.lookupRegisteredInstance(record.targetAgentId, record.targetInstanceId);
      if (!target || !target.transport) {
        unavailable += 1;
        await store.releaseOutboxLease({ deliveryId: record.deliveryId, leaseId: recordLeaseId, now: this.now() });
        continue;
      }
      if (!await this.isPinnedDurableOutboxTarget(record, target.transport)) {
        unavailable += 1;
        await store.releaseOutboxLease({ deliveryId: record.deliveryId, leaseId: recordLeaseId, now: this.now() });
        continue;
      }
      const wrote = v2
        ? target.transport.profile === "v2" && this.sendV2Envelope(target.transport, record.envelope as unknown as V2Envelope)
        : this.dispatchLegacyDurableEnvelope(target.transport, record.envelope as unknown as Envelope);
      if (!wrote) {
        unavailable += 1;
        // sendRaw returned false before a successful socket write, so this
        // lease can safely be returned to PENDING for the next READY wake.
        await store.releaseOutboxLease({ deliveryId: record.deliveryId, leaseId: recordLeaseId, now: this.now() });
        continue;
      }
      const updated = await store.markOutboxSent({ deliveryId: record.deliveryId, leaseId: recordLeaseId, now: this.now() });
      if (updated) sent += 1;
    }
    return { leased: leased.length, sent, unavailable, invalid };
  }

  /** Wake durable retry after startup, target READY, or newly stored ingress. */
  private wakeDurableDispatcher(): void {
    if (!this.durableStore || this.closing || this.durableDispatchInFlight) return;
    const run = this.dispatchDurableOutbox();
    this.durableDispatchInFlight = run;
    void run.then(
      () => {
        if (this.durableDispatchInFlight === run) this.durableDispatchInFlight = undefined;
      },
      () => {
        // The durable fact remains PENDING/LEASED and a later READY or
        // ingress wake will retry. Never let a background wake reject into a
        // WebSocket callback as an unhandled promise.
        if (this.durableDispatchInFlight === run) this.durableDispatchInFlight = undefined;
      },
    );
  }

  /** A matching durable receipt is the only transition to DELIVERED. */
  async acknowledgeDurableDelivery(deliveryId: string, receiptState: "stored" | "delivered" = "delivered"): Promise<OutboxRecord | undefined> {
    if (!this.durableStore) throw new ProtocolError("DURABLE_STORAGE_DISABLED", "This broker has no durable outbox", "internal");
    return this.durableStore.acknowledgeOutbox({ deliveryId, now: this.now(), receiptState });
  }

  /**
   * A durable task outbox remains pinned to the session selected at ingress.
   * A reconnect with the same logical instance ID is a new session, not an
   * implicit task handoff.
   */
  private async isPinnedDurableOutboxTarget(record: OutboxRecord, target: BrokerPeer): Promise<boolean> {
    if (!this.durableStore || !this.meshId || target.phase !== "active" ||
      target.agentId !== record.targetAgentId || target.instanceId !== record.targetInstanceId) return false;
    const candidate = isV2Envelope(record.envelope)
      ? v2EnvelopeAsLegacy(record.envelope)
      : isEnvelope(record.envelope)
        ? record.envelope as unknown as Envelope
        : undefined;
    const taskId = candidate === undefined ? undefined : taskIdOf(candidate);
    if (!taskId) return true;
    const route = await this.durableStore.getRoute(this.meshId, taskId);
    if (!route) return true;
    const expectedSessionId = route.executorAgentId === record.targetAgentId && route.executorInstanceId === record.targetInstanceId
      ? route.executorSessionId
      : route.ownerAgentId === record.targetAgentId && route.ownerInstanceId === record.targetInstanceId
        ? route.ownerSessionId
        : undefined;
    return expectedSessionId === undefined || expectedSessionId === target.sessionId;
  }

  private dispatchLegacyDurableEnvelope(target: BrokerPeer, envelope: Envelope): boolean {
    const source = [...this.peers].find((peer) => peer.phase === "active" &&
      peer.agentId === envelope.source.agent_id && peer.instanceId === envelope.source.instance_id);
    return source
      ? this.forwardEnvelope(source, target, envelope)
      : this.identityProfile === undefined
        ? this.sendEnvelope(target, envelope)
        : false;
  }

  /** Start the HTTP/WebSocket listener. */
  async start(): Promise<this> {
    if (this.server?.listening) return this;
    if (this.server) throw new Error("Broker is already starting");
    this.closing = false;
    this.assertSecureListenerConfiguration();
    await this.recoverDurable();

    const requestListener = (request: IncomingMessage, response: import("node:http").ServerResponse) => this.handleHttp(request, response);
    const server = this.options.tls
      ? createSecureServer({
        ...this.options.tls,
        // Secure profiles do not negotiate below TLS 1.3 and require an
        // enrolled client certificate.  A PSK profile needs a separate,
        // authenticated transcript implementation and is intentionally not
        // silently substituted here.
        minVersion: "TLSv1.3",
        requestCert: true,
        rejectUnauthorized: true,
        enableTrace: false,
        requestTimeout: this.httpRequestTimeoutMs,
        headersTimeout: this.httpHeaderTimeoutMs,
        maxHeaderSize: this.maxHttpHeaderBytes,
        insecureHTTPParser: false,
      }, requestListener)
      : createServer({
        requestTimeout: this.httpRequestTimeoutMs,
        headersTimeout: this.httpHeaderTimeoutMs,
        maxHeaderSize: this.maxHttpHeaderBytes,
        insecureHTTPParser: false,
      }, requestListener);
    server.maxHeadersCount = this.maxHttpHeaderCount;
    server.headersTimeout = this.httpHeaderTimeoutMs;
    server.requestTimeout = this.httpRequestTimeoutMs;
    server.keepAliveTimeout = this.httpHeaderTimeoutMs;
    const wsServer = new WebSocketServer({
      noServer: true,
      maxPayload: this.maxFrameBytes,
      clientTracking: false,
      perMessageDeflate: false,
      // The profiles are distinct: choose only an explicitly offered PolyMesh
      // subprotocol and prefer v0.2 where both sides opted in.
      handleProtocols: (protocols) => this.supportedSubprotocols.find((protocol) => protocols.has(protocol)) || false,
    });
    this.server = server;
    this.wsServer = wsServer;

    server.on("upgrade", (request, socket, head) => {
      // Some of the broader Node server typings permit an omitted `head`;
      // WebSocket upgrade processing treats that as an empty buffered tail.
      void this.handleUpgrade(request, socket, head ?? Buffer.alloc(0));
    });
    server.on("clientError", (_error, socket) => {
      // Do not reflect parser errors.  A terse response avoids turning the
      // HTTP parser into an oracle and releases the file descriptor promptly.
      this.rejectUpgrade(socket, 400, "Bad Request");
    });
    server.on("error", () => {
      // The listen promise and callers receive startup errors.  Runtime socket
      // errors are handled by ws/connection close events.
    });
    wsServer.on("connection", (socket, request) => {
      const transport = socket as unknown as BrokerTransport;
      const admission = this.consumePreAuthenticatedTransport(transport);
      if (!admission) {
        // A direct call to wsServer.emit("connection") is not an
        // authentication mechanism.  Fail closed if it bypassed validation.
        try {
          socket.close(1008, "authentication required");
        } catch {
          socket.terminate();
        }
        return;
      }
      this.attachPreAuthenticated(transport, admission.authEpoch, admission.reservedHandshake, admission.profile);
    });

    try {
      await new Promise<void>((resolve, reject) => {
        const onError = (error: Error) => {
          server.off("listening", onListening);
          reject(error);
        };
        const onListening = () => {
          server.off("error", onError);
          resolve();
        };
        server.once("error", onError);
        server.once("listening", onListening);
        server.listen(this.options.port ?? 7337, this.host);
      });
    } catch (error) {
      this.wsServer = undefined;
      this.server = undefined;
      wsServer.close();
      server.close();
      if ((error as NodeJS.ErrnoException).code === "EADDRINUSE") {
        throw new ProtocolError("PORT_IN_USE", `Port ${this.options.port ?? 7337} is already in use`, "resource");
      }
      throw error;
    }

    const interval = Math.max(1_000, Math.min(this.registry.ttlMs / 2, 30_000));
    this.cleanupTimer = setInterval(() => this.cleanup(), interval);
    this.cleanupTimer.unref?.();
    return this;
  }

  /** Alias for integrations that call a server `listen` method. */
  listen(): Promise<this> {
    return this.start();
  }

  /**
   * Attach an already-created transport, primarily for deterministic in-memory
   * tests. It is deliberately token-authenticated too: a public
   * `authenticated: true` bypass would turn an adapter bug into a policy
   * bypass. The remote end must initiate the ordinary hello/card/ready flow.
   */
  attach(transport: BrokerTransport | WireTransport, options: AttachOptions = {}): BrokerPeer {
    const normalized = transport as unknown as BrokerTransport;
    const verification = this.tokenAuthority?.verify(options.token) ?? { valid: false };
    if (!verification.valid || verification.authEpoch === undefined) {
      return this.rejectAttachment(normalized, "AUTHENTICATION_FAILED", "A valid PolyMesh runtime token is required", "identity");
    }
    const profile = options.profile === V2_PROTOCOL_VERSION ? "native-v2" : options.profile;
    return this.attachPreAuthenticated(normalized, verification.authEpoch, false, profile);
  }

  private attachPreAuthenticated(
    transport: BrokerTransport,
    authEpoch: number | undefined,
    consumesReservation: boolean,
    explicitProfile?: WireProfile,
  ): BrokerPeer {
    if (consumesReservation) this.releaseUpgradeReservation();
    if (!this.canAdmitPeer()) {
      return this.rejectAttachment(transport, "OVERLOADED", "Broker connection capacity is exhausted", "resource", true);
    }
    const peer: BrokerPeer = {
      transport,
      phase: "await_hello",
      authenticated: true,
      connectionId: uuidv7(this.now()),
      authEpoch,
      ...(explicitProfile === undefined ? {} : { profile: explicitProfile }),
      connectedAt: this.now(),
    };
    this.peers.add(peer);
    this.bindTransport(peer);
    this.handshakeTimers.set(
      peer,
      setTimeout(() => {
        if (peer.phase !== "active" && peer.phase !== "closed") {
          this.failHandshake(peer, "HANDSHAKE_TIMEOUT", "Handshake did not complete within five seconds", "protocol");
        }
      }, this.handshakeTimeoutMs),
    );
    return peer;
  }

  private consumePreAuthenticatedTransport(transport: BrokerTransport): PreAuthenticatedTransport | undefined {
    const target = transport as unknown as object;
    const admission = this.preAuthenticatedTransports.get(target);
    if (admission !== undefined) this.preAuthenticatedTransports.delete(target);
    return admission;
  }

  /** Alias that reads naturally in transport adapters. */
  accept(transport: BrokerTransport | WireTransport, options?: AttachOptions): BrokerPeer {
    return this.attach(transport, options);
  }

  private routingInstanceKey(meshId: string, agentId: string, instanceId: string): string {
    return `${meshId}\0${agentId}\0${instanceId}`;
  }

  private trackDurableMutation<T>(operation: Promise<T>): void {
    this.pendingDurableMutations.add(operation);
    void operation.then(
      () => this.pendingDurableMutations.delete(operation),
      () => this.pendingDurableMutations.delete(operation),
    );
  }

  private routingLogicalKey(meshId: string, agentId: string): string {
    return `${meshId}\0${agentId}`;
  }

  private routingPrincipal(peer: BrokerPeer): string | undefined {
    if (peer.verifiedPrincipal) return peer.verifiedPrincipal.principal_id;
    if (!this.allowInsecureMultiInstanceDevelopment || !peer.agentId || !peer.instanceId) return undefined;
    // This is deliberately available only behind the explicit local-dev
    // option. Remote routing must obtain a principal from the secure profile.
    return `local-dev:${peer.agentId}`;
  }

  private asRegistryEntry(instance: LiveRoutingInstance): RegistryEntry<BrokerPeer, AgentCard> {
    return {
      agentId: instance.agentId,
      instanceId: instance.instanceId,
      sessionId: instance.sessionId,
      leaseId: instance.leaseId,
      card: instance.card,
      transport: instance.peer,
      registeredAt: instance.registeredAt,
      expiresAt: instance.expiresAt,
    };
  }

  private registerRoutingInstance(
    peer: BrokerPeer,
    durable?: DurableRegistryEntry<BrokerPeer, AgentCard>,
  ): RegistryEntry<BrokerPeer, AgentCard> {
    if (!this.meshId || !peer.agentId || !peer.instanceId || !peer.sessionId || !peer.card) {
      throw new InvalidRegistrationError("v0.2 routing registration is incomplete");
    }
    const principalId = this.routingPrincipal(peer);
    if (!principalId) throw new InvalidRegistrationError("v0.2 routing requires an authenticated principal");
    const now = this.now();
    const logicalKey = this.routingLogicalKey(this.meshId, peer.agentId);
    for (const candidate of this.routingInstances.values()) {
      if (this.routingLogicalKey(candidate.meshId, candidate.agentId) !== logicalKey || candidate.leaseExpiresAt <= now) continue;
      if (candidate.principalId !== principalId) throw new IdentityCollisionError();
    }
    const key = this.routingInstanceKey(this.meshId, peer.agentId, peer.instanceId);
    const prior = this.routingInstances.get(key);
    const nextFence = durable?.registrationFence ?? Math.max(this.nextRegistrationFence.get(key) ?? 0, prior?.registrationFence ?? 0) + 1;
    const nextSessionFence = durable?.sessionFence ?? nextFence;
    this.nextRegistrationFence.set(key, Math.max(this.nextRegistrationFence.get(key) ?? 0, nextFence));
    const instance: LiveRoutingInstance = {
      meshId: this.meshId,
      agentId: peer.agentId,
      instanceId: peer.instanceId,
      principalId,
      sessionId: peer.sessionId,
      registrationFence: nextFence,
      sessionFence: nextSessionFence,
      health: durable?.health ?? HealthState.HEALTHY,
      cardValid: true,
      cardExpiresAt: Date.parse(peer.card.expires_at),
      leaseExpiresAt: durable?.expiresAt ?? now + this.registry.ttlMs,
      capabilities: peer.card.capabilities.map((capability) => capability.id),
      ...(durable?.capacity === undefined ? {} : { capacity: durable.capacity }),
      ...(durable?.capacityWeight === undefined ? {} : { capacityWeight: durable.capacityWeight }),
      currentInflight: 0,
      peer,
      card: peer.card,
      leaseId: durable?.leaseId ?? `v2:${nextFence}:${peer.sessionId}`,
      registeredAt: durable?.registeredAt ?? now,
      expiresAt: durable?.expiresAt ?? now + this.registry.ttlMs,
    };
    this.routingInstances.set(key, instance);
    peer.meshId = this.meshId;
    peer.registrationFence = nextFence;
    peer.sessionFence = nextSessionFence;
    peer.health = instance.health;
    // A replacement session wins immediately. Its stale close callback is
    // fenced by `removeRoutingInstance` below, so it cannot erase this row.
    if (prior && prior.peer !== peer && prior.peer.phase !== "closed") {
      this.closePeer(prior.peer, "instance session replaced");
    }
    return this.asRegistryEntry(instance);
  }

  private registerLivePeer(
    peer: BrokerPeer,
    durable?: DurableRegistryEntry<BrokerPeer, AgentCard>,
  ): RegistryEntry<BrokerPeer, AgentCard> {
    if (this.multiInstanceRouting) return this.registerRoutingInstance(peer, durable);
    return this.registry.register({
      agentId: peer.agentId!,
      instanceId: peer.instanceId!,
      sessionId: peer.sessionId,
      card: peer.card,
      transport: peer,
    });
  }

  /** Commit an authenticated v0.2 instance before publishing its socket. */
  private async registerDurableLivePeer(peer: BrokerPeer): Promise<RegistryEntry<BrokerPeer, AgentCard>> {
    const durableRegistry = this.durableRegistry;
    if (!durableRegistry) return this.registerLivePeer(peer);
    if (!this.meshId || !peer.agentId || !peer.instanceId || !peer.sessionId || !peer.card) {
      throw new InvalidRegistrationError("durable v0.2 registration is incomplete");
    }
    const principalId = this.routingPrincipal(peer);
    if (!principalId) throw new InvalidRegistrationError("durable v0.2 routing requires an authenticated principal");
    const now = this.now();
    const durable = await durableRegistry.registerDurable({
      meshId: this.meshId,
      agentId: peer.agentId,
      instanceId: peer.instanceId,
      sessionId: peer.sessionId,
      principalId,
      card: peer.card,
      cardDigest: peer.cardDigest,
      cardRevision: peer.card.revision,
      cardExpiresAt: Date.parse(peer.card.expires_at),
      health: HealthState.HEALTHY,
      transport: peer,
      ownerBrokerNodeId: this.durableNodeId,
      sessionExpiresAt: now + this.registry.ttlMs,
    });
    if (peer.phase === "closed") {
      await durableRegistry.removeDurable({
        meshId: this.meshId,
        agentId: peer.agentId,
        instanceId: peer.instanceId,
        registrationFence: durable.registrationFence,
        sessionFence: durable.sessionFence,
      });
      throw new InvalidRegistrationError("connection closed before durable registration completed");
    }
    try {
      return this.registerLivePeer(peer, durable);
    } catch (error) {
      await durableRegistry.removeDurable({
        meshId: this.meshId,
        agentId: peer.agentId,
        instanceId: peer.instanceId,
        registrationFence: durable.registrationFence,
        sessionFence: durable.sessionFence,
      });
      throw error;
    }
  }

  private removeRoutingInstance(peer: BrokerPeer): boolean {
    if (!this.multiInstanceRouting || !peer.meshId || !peer.agentId || !peer.instanceId ||
      peer.registrationFence === undefined || peer.sessionFence === undefined || !peer.sessionId) return false;
    const key = this.routingInstanceKey(peer.meshId, peer.agentId, peer.instanceId);
    const current = this.routingInstances.get(key);
    if (!current || !isCurrentInstanceFence(current, {
      sessionId: peer.sessionId,
      registrationFence: peer.registrationFence,
      sessionFence: peer.sessionFence,
    })) return false;
    this.routingInstances.delete(key);
    if (this.durableRegistry) {
      // A normal disconnect changes reachability; it is not an instruction to
      // erase the durable directory record. Retaining the fenced physical
      // instance lets the relay keep its mailbox/route facts through a
      // temporary socket loss. Failed pre-READY registration is still
      // removed explicitly by registerDurableLivePeer.
      const offline = this.durableRegistry.renewDurable({
        meshId: peer.meshId,
        agentId: peer.agentId,
        instanceId: peer.instanceId,
        registrationFence: peer.registrationFence,
        sessionFence: peer.sessionFence,
        expiresAt: current.expiresAt,
        health: HealthState.OFFLINE,
      }).catch(() => undefined);
      this.trackDurableMutation(offline);
    }
    return true;
  }

  private touchRoutingInstance(peer: BrokerPeer): boolean {
    if (!this.multiInstanceRouting || !peer.meshId || !peer.agentId || !peer.instanceId ||
      peer.registrationFence === undefined || peer.sessionFence === undefined || !peer.sessionId) return false;
    const current = this.routingInstances.get(this.routingInstanceKey(peer.meshId, peer.agentId, peer.instanceId));
    if (!current || !isCurrentInstanceFence(current, {
      sessionId: peer.sessionId,
      registrationFence: peer.registrationFence,
      sessionFence: peer.sessionFence,
    })) return false;
    const expiresAt = this.now() + this.registry.ttlMs;
    current.leaseExpiresAt = expiresAt;
    current.expiresAt = expiresAt;
    if (current.health === HealthState.SUSPECT) {
      current.health = HealthState.HEALTHY;
      peer.health = HealthState.HEALTHY;
    }
    if (this.durableRegistry) {
      const renewal = this.durableRegistry.renewDurable({
        meshId: peer.meshId,
        agentId: peer.agentId,
        instanceId: peer.instanceId,
        registrationFence: peer.registrationFence,
        sessionFence: peer.sessionFence,
        expiresAt,
        health: current.health,
      }).catch(() => undefined);
      this.trackDurableMutation(renewal);
    }
    return true;
  }

  /**
   * Durable v0.2 ingress revalidates its registration/session fence before
   * accepting new work. The database renewal commits first so a failed CAS
   * cannot leave this broker routing on a merely process-local heartbeat.
   */
  private async touchDurableRoutingInstance(peer: BrokerPeer): Promise<boolean> {
    if (!this.multiInstanceRouting || !peer.meshId || !peer.agentId || !peer.instanceId ||
      peer.registrationFence === undefined || peer.sessionFence === undefined || !peer.sessionId) return false;
    const current = this.routingInstances.get(this.routingInstanceKey(peer.meshId, peer.agentId, peer.instanceId));
    if (!current || !isCurrentInstanceFence(current, {
      sessionId: peer.sessionId,
      registrationFence: peer.registrationFence,
      sessionFence: peer.sessionFence,
    })) return false;
    const expiresAt = this.now() + this.registry.ttlMs;
    const health = current.health === HealthState.SUSPECT ? HealthState.HEALTHY : current.health;
    if (this.durableRegistry) {
      const persisted = await this.durableRegistry.renewDurable({
        meshId: peer.meshId,
        agentId: peer.agentId,
        instanceId: peer.instanceId,
        registrationFence: peer.registrationFence,
        sessionFence: peer.sessionFence,
        expiresAt,
        health,
      });
      if (!persisted) return false;
    }
    // Re-check after the await: a replacement may have become live while the
    // durable renewal was in flight.
    const stillCurrent = this.routingInstances.get(this.routingInstanceKey(peer.meshId, peer.agentId, peer.instanceId));
    if (!stillCurrent || !isCurrentInstanceFence(stillCurrent, {
      sessionId: peer.sessionId,
      registrationFence: peer.registrationFence,
      sessionFence: peer.sessionFence,
    })) return false;
    stillCurrent.leaseExpiresAt = expiresAt;
    stillCurrent.expiresAt = expiresAt;
    stillCurrent.health = health;
    peer.health = health;
    return true;
  }

  private lookupRegisteredInstance(agentId: string, instanceId?: string): RegistryEntry<BrokerPeer, AgentCard> | undefined {
    if (!this.multiInstanceRouting) return this.registry.lookup(agentId, instanceId);
    if (!this.meshId || instanceId === undefined) return undefined;
    const entry = this.routingInstances.get(this.routingInstanceKey(this.meshId, agentId, instanceId));
    if (!entry || entry.leaseExpiresAt <= this.now()) return undefined;
    return this.asRegistryEntry(entry);
  }

  private lookupPinnedExecutor(route: TaskRoute): RegistryEntry<BrokerPeer, AgentCard> | undefined {
    if (!this.multiInstanceRouting || !route.routePin) {
      return this.lookupRegisteredInstance(route.executor.agentId, route.executor.instanceId);
    }
    const resolved = resolvePinnedRoute([...this.routingInstances.values()], route.routePin, { now: this.now() });
    return resolved.ok ? this.asRegistryEntry(resolved.instance) : undefined;
  }

  private createRoutePinForTarget(target: RegistryEntry<BrokerPeer, AgentCard>): { routePin: RoutePin } {
    if (!this.meshId) throw new Error("v0.2 route pinning requires a mesh ID");
    const instance = this.routingInstances.get(this.routingInstanceKey(this.meshId, target.agentId, target.instanceId));
    if (!instance) throw new Error("Selected routing instance disappeared before route pinning");
    return { routePin: createRoutePin(instance, { routeFence: ++this.nextRouteFence }) };
  }

  /** Safely expire leases and task routing metadata. */
  cleanup(): void {
    const expired = this.registry.cleanup();
    for (const entry of expired) {
      const peer = entry.transport;
      if (peer && peer.phase !== "closed") this.closePeer(peer, "registry lease expired");
    }
    if (this.multiInstanceRouting) {
      for (const instance of [...this.routingInstances.values()]) {
        if (instance.leaseExpiresAt <= this.now() && instance.peer.phase !== "closed") {
          instance.health = HealthState.OFFLINE;
          instance.peer.health = HealthState.OFFLINE;
          this.closePeer(instance.peer, "routing instance lease expired");
        }
      }
    }
    if (this.durableRegistry) {
      this.trackDurableMutation(this.durableRegistry.cleanupDurable(this.now()).catch(() => []));
    }
    this.pruneRouteAndReplayState();
    this.pruneNativeV2State();
  }

  async close(): Promise<void> {
    if (this.closing) return;
    this.closing = true;
    if (this.cleanupTimer) clearInterval(this.cleanupTimer);
    this.cleanupTimer = undefined;
    if (this.tokenRotationTimer) clearTimeout(this.tokenRotationTimer);
    this.tokenRotationTimer = undefined;

    for (const peer of [...this.peers]) this.closePeer(peer, "broker shutting down");
    if (this.pendingDurableMutations.size > 0) {
      await Promise.allSettled([...this.pendingDurableMutations]);
    }
    this.registry.clear();
    this.routingInstances.clear();
    this.nextRegistrationFence.clear();
    this.pendingTasks.clear();
    this.routesBySubmitMessageId.clear();
    this.pendingRoutesBySession.clear();
    this.replayLedger.clear();
    this.nativeV2Peers.clear();
    this.nativeV2Tasks.clear();
    this.nativeV2RoutesBySubmitMessageId.clear();
    this.nativeV2ReplayLedger.clear();

    const wsServer = this.wsServer;
    const server = this.server;
    this.wsServer = undefined;
    this.server = undefined;
    await Promise.all([
      wsServer
        ? new Promise<void>((resolve) => wsServer.close(() => resolve()))
        : Promise.resolve(),
      server
        ? new Promise<void>((resolve) => server.close(() => resolve()))
        : Promise.resolve(),
    ]);
  }

  private handleHttp(request: IncomingMessage, response: import("node:http").ServerResponse): void {
    if (request.url === "/.well-known/polymesh" && request.method === "GET") {
      const endpoint = this.url;
      response.writeHead(200, {
        "content-type": "application/polymesh+json; charset=utf-8",
        "cache-control": "max-age=60",
        ...(this.options.tls ? { "strict-transport-security": "max-age=31536000" } : {}),
      });
      response.end(
        JSON.stringify({
          v: "0.1",
          agent_id: this.card.agent_id,
          instance_id: this.card.instance_id,
          endpoints: endpoint ? [{ transport: "websocket", url: endpoint }] : [],
        }),
      );
      return;
    }
    response.writeHead(404, { "content-type": "application/json; charset=utf-8" });
    response.end(JSON.stringify({ error: "not found" }));
  }

  private async handleUpgrade(
    request: IncomingMessage,
    socket: Duplex,
    head: Buffer,
  ): Promise<void> {
    if (request.url !== POLYMESH_PATH) {
      this.rejectUpgrade(socket, 404, "Not Found");
      return;
    }
    const upgrade = validateWebSocketUpgrade(request, {
      path: POLYMESH_PATH,
      subprotocols: this.supportedSubprotocols,
      allowedOrigins: this.allowedOrigins,
    });
    if (!upgrade.ok) {
      this.rejectUpgrade(socket, upgrade.status, upgrade.statusText, upgrade.headers);
      return;
    }
    let authEpoch: number | undefined;
    if (this.options.tls) {
      const tlsSocket = request.socket as unknown as { authorized?: boolean; getProtocol?: () => string | null };
      // `rejectUnauthorized` performs the certificate check; this defensive
      // check makes a proxy/adapter that strips it fail closed as well.
      if (tlsSocket.authorized !== true || tlsSocket.getProtocol?.() !== "TLSv1.3") {
        this.rejectUpgrade(socket, 403, "Forbidden");
        return;
      }
    } else {
      const verification = this.tokenAuthority?.verify(upgrade.token) ?? { valid: false };
      if (!verification.valid || verification.authEpoch === undefined) {
        this.rejectUpgrade(socket, 403, "Forbidden");
        return;
      }
      authEpoch = verification.authEpoch;
    }
    const wsServer = this.wsServer;
    if (!wsServer) {
      this.rejectUpgrade(socket, 503, "Service Unavailable", { "Retry-After": "1" });
      return;
    }
    // Reserve before allocating WebSocket/session state. This closes the
    // gap where many valid HTTP upgrades could otherwise allocate sockets
    // before their handshake limits are checked.
    if (!this.reserveUpgradeAdmission()) {
      this.rejectUpgrade(socket, 429, "Too Many Requests", { "Retry-After": "1" });
      return;
    }
    try {
      wsServer.handleUpgrade(request, socket, head, (ws) => {
        this.preAuthenticatedTransports.set(ws as unknown as object, {
          ...(authEpoch === undefined ? {} : { authEpoch }),
          reservedHandshake: true,
          ...(upgrade.subprotocol === V2_SUBPROTOCOL ? { profile: "v2" as const } : { profile: "v1" as const }),
        });
        wsServer.emit("connection", ws, request);
      });
    } catch {
      this.releaseUpgradeReservation();
      this.rejectUpgrade(socket, 400, "Bad Request");
    }
  }

  private bindTransport(peer: BrokerPeer): void {
    const transport = peer.transport;
    const onMessage = (data: unknown, isBinary?: boolean) => {
      if (isBinary) {
        this.failHandshakeOrError(peer, "MALFORMED_FRAME", "Binary WebSocket frames are not supported", "parse");
        return;
      }
      const input = asFrameInput(data);
      if (input === undefined || frameByteLength(input) > this.maxFrameBytes) {
        this.failHandshakeOrError(peer, "MALFORMED_FRAME", "Frame exceeds the maximum size", "parse");
        return;
      }
      this.receive(peer, input);
    };
    const onClose = (code?: unknown, reason?: unknown) => {
      const close = normalizePeerClose(code, reason);
      // Native close metadata is untrusted transport input.  The local close
      // path never sends a second close frame after this callback.
      this.closePeer(peer, close.reason, false);
    };
    const onError = (_error: unknown) => this.closePeer(peer, "transport error");

    if (typeof transport.on === "function") {
      transport.on("message", onMessage);
      transport.on("close", onClose);
      transport.on("error", onError);
    } else {
      transport.onMessage?.((data) => onMessage(data, false));
      transport.onClose?.(onClose);
      transport.onError?.((error) => onError(error));
    }
  }

  private receive(peer: BrokerPeer, input: string | Uint8Array): void {
    if (peer.phase !== "active" && this.rateLimiter) {
      const admission = this.admitHandshakeRateLimit(peer, frameByteLength(input));
      if (!admission.allowed) {
        this.failHandshake(peer, admission.code ?? "RATE_LIMITED", "Handshake admission rate limit exceeded", "resource");
        return;
      }
    }
    // A compression wrapper carries a base64url payload which can legitimately
    // be larger than the normal protocol string field limit. The outer frame
    // remains bounded by maxFrameBytes and decoded application records are
    // re-parsed with their normal strict limits before routing.
    const parsed = parseStrictJson(input, {
      maxBytes: this.maxFrameBytes,
      maxStringBytes: this.maxFrameBytes,
    });
    if (parsed.ok === false) {
      this.failHandshakeOrError(
        peer,
        parsed.code,
        "Frame is not valid strict JSON",
        parsed.code === "RESOURCE_EXHAUSTED" ? "resource" : "parse",
      );
      return;
    }
    const frame: unknown = parsed.value;

    if (peer.phase === "await_hello") {
      this.receiveHello(peer, frame);
      return;
    }
    if (peer.phase === "await_card") {
      this.receiveCard(peer, frame);
      return;
    }
    if (peer.phase === "await_auth") {
      this.receiveAuth(peer, frame);
      return;
    }
    if (peer.phase === "await_ready") {
      this.receiveReady(peer, frame);
      return;
    }
    if (peer.phase === "active") {
      if (peer.profile === "v2") {
        void this.receiveV2Record(peer, frame);
      } else if (peer.profile === "native-v2") {
        void this.receiveNativeV2Record(peer, frame);
      } else {
        this.receiveEnvelope(peer, frame);
      }
    }
  }

  private receiveHello(peer: BrokerPeer, frame: unknown): void {
    const nativeInit = isNativeV2InitRecord(frame);
    // The compact SDK profile shares the `polymesh.0.2` WebSocket
    // subprotocol with the historical relay profile, but has an unambiguous
    // first record. Select it only from `v2.init`; no legacy hello is ever
    // structurally interpreted as a native init.
    if (nativeInit || peer.profile === "native-v2") {
      this.receiveNativeV2Init(peer, frame);
      return;
    }
    const looksLikeV2 = typeof frame === "object" && frame !== null && !Array.isArray(frame) &&
      (frame as Record<string, unknown>).v === V2_HANDSHAKE_VERSION;
    // v0.2 is selected by the WebSocket subprotocol, never opportunistically
    // by a sender-controlled hello field. In-memory transports may opt in by
    // passing AttachOptions.profile: "v2"; native upgrades obtain it from
    // Sec-WebSocket-Protocol. This prevents a v1 connection from silently
    // becoming a durable v2 session.
    if (peer.profile === "v2") {
      this.receiveV2Hello(peer, frame);
      return;
    }
    if (looksLikeV2) {
      this.failHandshake(peer, "UNSUPPORTED_PROTOCOL_VERSION", "PolyMesh 0.2 requires the polymesh.0.2 subprotocol", "protocol");
      return;
    }
    if (peer.profile === undefined) peer.profile = "v1";
    const validated = validateHandshakeFrame(frame);
    if (validated.ok === false || validated.value.type !== "hello" || validated.value.role !== "initiator") {
      this.failHandshake(peer, "UNSUPPORTED_PROTOCOL_VERSION", "Expected an initiator hello for PolyMesh 0.1", "protocol");
      return;
    }
    const hello: HelloFrame = validated.value;
    if (this.identityProfile ? hello.security_profile !== SECURE_IDENTITY_PROFILE : hello.security_profile !== undefined) {
      this.failHandshake(peer, "SECURITY_PROFILE_MISMATCH", "Peer selected an unexpected security profile", "identity");
      return;
    }
    if (hello.agent_id === this.card.agent_id && hello.instance_id === this.card.instance_id) {
      this.failHandshake(peer, "SELF_CONNECTION", "An agent cannot connect to itself", "identity");
      return;
    }
    peer.agentId = hello.agent_id;
    peer.instanceId = hello.instance_id;
    peer.initiatorNonce = hello.nonce;
    peer.initiatorHello = hello;
    peer.responderNonce = randomNonce();
    peer.sessionId = deriveSessionId(peer.initiatorNonce, peer.responderNonce);
    peer.phase = "await_card";
    const responderHello: Extract<HelloFrame, { role: "responder" }> = {
      type: "hello",
      v: "0.1",
      role: "responder",
      agent_id: this.card.agent_id,
      instance_id: this.card.instance_id,
      nonce: peer.responderNonce,
      echo: peer.initiatorNonce,
      sid: peer.sessionId,
      ...(this.identityProfile === undefined ? {} : { security_profile: SECURE_IDENTITY_PROFILE }),
    };
    peer.responderHello = responderHello;
    this.sendRaw(peer, responderHello);
  }

  /**
   * Compact native-v2 session establishment. This is intentionally separate
   * from `receiveV2Hello`: the latter is the established relay v2 profile
   * with its own durable card/auth/ready transcript.
   */
  private receiveNativeV2Init(peer: BrokerPeer, frame: unknown): void {
    if (!this.nativeV2Enabled) {
      this.failNativeV2Handshake(peer, "PMX.SESSION.PROFILE", "The native polymesh.0.2 profile is disabled");
      return;
    }
    if (peer.phase !== "await_hello" || peer.nativeV2InitPending) {
      this.failNativeV2Handshake(peer, "PMX.SESSION.HANDSHAKE", "A native v2 session may be initialized once");
      return;
    }
    const init = validateNativeV2Init(frame);
    if (!init) {
      this.failNativeV2Handshake(peer, "PMX.SESSION.HANDSHAKE", "v2.init does not match the selected native profile");
      return;
    }
    if (init.agent_id === this.card.agent_id && init.instance_id === this.card.instance_id) {
      this.failNativeV2Handshake(peer, "PMX.SESSION.AUTH", "An agent cannot connect to itself");
      return;
    }
    peer.nativeV2InitPending = true;
    void this.completeNativeV2Init(peer, init);
  }

  /** Select zstd only when the peer offered it and the portable codec loads. */
  private async completeNativeV2Init(peer: BrokerPeer, init: V2InitFrame): Promise<void> {
    let compression: V2CompressionAlgorithm = "none";
    // The compact profile defaults to zstd when both sides can use it. The
    // legacy relay remains intentionally governed by allowZstdCompression.
    if (init.compression?.includes("zstd") && this.options.allowZstdCompression !== false) {
      try {
        await initializeZstd();
        compression = "zstd";
      } catch {
        // An unavailable optional WASM codec is a safe negotiated `none`, not
        // a reason to expose a session which claims a codec it cannot enforce.
        compression = "none";
      }
    }
    if (peer.phase !== "await_hello" || peer.nativeV2InitPending !== true || this.closing) return;

    peer.nativeV2InitPending = false;
    peer.profile = "native-v2";
    peer.meshId = this.nativeV2MeshId;
    peer.sessionId = uuidv7(this.now());
    peer.agentId = init.agent_id;
    peer.instanceId = init.instance_id;
    peer.initiatorNonce = init.nonce;
    peer.nativeV2Compression = compression;
    if (compression === "zstd") {
      peer.nativeV2Zstd = new V2ZstdStateMachine({
        meshId: this.nativeV2MeshId,
        sessionId: peer.sessionId,
      }, "responder");
    }
    this.registerNativeV2Peer(peer);
    peer.phase = "active";
    this.clearHandshakeTimer(peer);

    const ack: V2AckFrame = {
      type: "v2.ack",
      protocol: V2_PROFILE,
      profile: V2_PROFILE,
      mesh_id: this.nativeV2MeshId,
      session_id: peer.sessionId,
      agent_id: this.card.agent_id,
      instance_id: this.card.instance_id,
      compression,
    };
    if (!this.sendRaw(peer, ack)) return;
    this.options.onPeerConnected?.(peer);
    await this.drainNativeV2Inbox(peer);
  }

  /** Receive native application records and the post-ack JSON zstd controls. */
  private async receiveNativeV2Record(peer: BrokerPeer, frame: unknown): Promise<void> {
    try {
      const type = isJsonRecord(frame) && typeof frame.type === "string" ? frame.type : undefined;
      if (type === "zstd.propose" || type === "zstd.ready") {
        this.receiveNativeV2ZstdControl(peer, frame);
        return;
      }
      if (type === "zstd.wrapper") {
        await this.receiveNativeV2ZstdWrapper(peer, frame);
        return;
      }
      await this.receiveNativeV2Envelope(peer, frame);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Native v2 record could not be processed";
      await this.sendNativeV2Error(peer, "PMX.PROTOCOL.ENVELOPE", message, undefined, false);
    }
  }

  private receiveNativeV2ZstdControl(peer: BrokerPeer, frame: unknown): void {
    const machine = peer.nativeV2Zstd;
    if (peer.nativeV2Compression !== "zstd" || !machine) {
      void this.sendNativeV2Error(peer, "PMX.PROTOCOL.COMPRESSION", "zstd was not selected for this session", undefined, false);
      return;
    }
    try {
      if (isJsonRecord(frame) && frame.type === "zstd.propose") {
        machine.receivePropose(frame);
        this.sendRaw(peer, machine.createReady());
        return;
      }
      if (isJsonRecord(frame) && frame.type === "zstd.ready") {
        machine.receiveReady(frame);
        return;
      }
      throw new CompressionTransportError("PMX.PROTOCOL.COMPRESSION", "Unknown native zstd control record");
    } catch (error) {
      machine.close();
      const message = error instanceof Error ? error.message : "Native zstd control record is invalid";
      void this.sendNativeV2Error(peer, "PMX.PROTOCOL.COMPRESSION", message, undefined, false);
    }
  }

  private async receiveNativeV2ZstdWrapper(peer: BrokerPeer, frame: unknown): Promise<void> {
    const machine = peer.nativeV2Zstd;
    if (peer.nativeV2Compression !== "zstd" || !machine) {
      await this.sendNativeV2Error(peer, "PMX.PROTOCOL.COMPRESSION", "zstd was not selected for this session", undefined, false);
      return;
    }
    try {
      const payload = await machine.unwrap(frame);
      const parsed = parseStrictJson(payload, { maxBytes: this.maxFrameBytes });
      if (!parsed.ok) throw new CompressionTransportError("PMX.PROTOCOL.COMPRESSION", "zstd.wrapper did not contain bounded strict JSON");
      await this.receiveNativeV2Envelope(peer, parsed.value);
    } catch (error) {
      machine.close();
      const message = error instanceof Error ? error.message : "Native zstd wrapper is invalid";
      await this.sendNativeV2Error(peer, "PMX.PROTOCOL.COMPRESSION", message, undefined, false);
    }
  }

  /** Validate mesh/session source fencing before a native envelope is routed. */
  private async receiveNativeV2Envelope(peer: BrokerPeer, frame: unknown): Promise<void> {
    const envelope = validateNativeV2Envelope(frame);
    if (!envelope) {
      await this.sendNativeV2Error(peer, "PMX.PROTOCOL.ENVELOPE", "Frame is not a valid native v2 envelope", undefined, false);
      return;
    }
    if (peer.meshId !== this.nativeV2MeshId || envelope.mesh_id !== this.nativeV2MeshId) {
      await this.sendNativeV2Error(peer, "PMX.ROUTING.MESH_MISMATCH", "Envelope mesh_id does not match this broker session", envelope.message_id, false);
      return;
    }
    if (envelope.source.agent_id !== peer.agentId || envelope.source.instance_id !== peer.instanceId || !peer.sessionId) {
      await this.sendNativeV2Error(peer, "PMX.ROUTING.FENCE", "Envelope source does not match the authenticated native session", envelope.message_id, false);
      return;
    }
    const replay = this.admitNativeV2Replay(peer, envelope);
    if (replay === "conflict") {
      await this.sendNativeV2Error(peer, "PMX.DELIVERY.IDEMPOTENCY_CONFLICT", "message_id was reused with different native envelope semantics", envelope.message_id, false);
      return;
    }
    if (replay === "overloaded") {
      await this.sendNativeV2Error(peer, "PMX.INTERNAL", "Native replay ledger capacity is exhausted", envelope.message_id, true);
      return;
    }
    if (envelope.type === "task.submit" && Date.parse(envelope.delivery.deadline) <= this.now()) {
      await this.sendNativeV2Error(peer, "PMX.TASK.DEADLINE_EXCEEDED", "Task deadline has already elapsed", envelope.message_id, false);
      return;
    }
    await this.routeNativeV2Envelope(peer, envelope);
  }

  /** Native routing is deliberately profile-local: no invisible v2-to-v1 downgrade. */
  private async routeNativeV2Envelope(peer: BrokerPeer, envelope: V2NativeEnvelope): Promise<void> {
    if (envelope.target.agent_id === this.card.agent_id &&
      (envelope.target.instance_id === undefined || envelope.target.instance_id === this.card.instance_id)) {
      await this.handleNativeV2BrokerEnvelope(peer, envelope);
      return;
    }
    if (envelope.type === "task.submit") {
      await this.routeNativeV2TaskSubmit(peer, envelope);
      return;
    }
    if (isNativeV2Lifecycle(envelope.type)) {
      await this.routeNativeV2Lifecycle(peer, envelope);
      return;
    }
    if (envelope.type === "task.cancel") {
      await this.routeNativeV2Cancel(peer, envelope);
      return;
    }
    const target = this.lookupNativeV2Target(envelope.target);
    if (!target) {
      await this.sendNativeV2Error(peer, "PMX.ROUTING.TARGET_UNAVAILABLE", "No native v2 target is connected", envelope.message_id, true);
      return;
    }
    await this.forwardNativeV2Envelope(peer, target, envelope);
  }

  private async routeNativeV2TaskSubmit(peer: BrokerPeer, envelope: V2NativeEnvelope): Promise<void> {
    const taskId = nativeV2TaskId(envelope);
    if (!taskId || !peer.sessionId) {
      await this.sendNativeV2Error(peer, "PMX.PROTOCOL.ENVELOPE", "task.submit is missing a valid task_id", envelope.message_id, false);
      return;
    }
    const existing = this.nativeV2Tasks.get(taskId);
    if (existing) {
      if (!nativeEndpointMatchesPeer(existing.source, peer)) {
        await this.sendNativeV2Error(peer, "PMX.ROUTING.FENCE", "Task retry was received from a different native session", envelope.message_id, false);
        return;
      }
      const target = this.lookupNativeV2ExactTarget(existing.target.agentId, existing.target.instanceId);
      if (!target || !nativeEndpointMatchesPeer(existing.target, target)) {
        await this.sendNativeV2Error(peer, "PMX.ROUTING.FENCE", "Task target session has been replaced", envelope.message_id, true);
        return;
      }
      await this.forwardNativeV2Envelope(peer, target, envelope);
      return;
    }
    const deadlineAt = Date.parse(envelope.delivery.deadline);
    if (!Number.isFinite(deadlineAt) || deadlineAt <= this.now()) {
      await this.sendNativeV2Error(peer, "PMX.TASK.DEADLINE_EXCEEDED", "Task deadline has elapsed", envelope.message_id, false);
      return;
    }
    const target = this.lookupNativeV2Target(envelope.target);
    if (!target || !target.sessionId) {
      await this.sendNativeV2Error(peer, "PMX.ROUTING.TARGET_UNAVAILABLE", "No native v2 executor is connected", envelope.message_id, true);
      return;
    }
    const route: NativeV2TaskRoute = {
      taskId,
      submitMessageId: envelope.message_id,
      source: { agentId: peer.agentId!, instanceId: peer.instanceId!, sessionId: peer.sessionId },
      target: { agentId: target.agentId!, instanceId: target.instanceId!, sessionId: target.sessionId },
      deadlineAt,
      expiresAt: Math.max(deadlineAt, this.now()) + this.replayRetentionMs,
    };
    this.nativeV2Tasks.set(taskId, route);
    this.nativeV2RoutesBySubmitMessageId.set(envelope.message_id, taskId);
    if (!await this.forwardNativeV2Envelope(peer, target, envelope)) this.removeNativeV2Task(route);
  }

  private async routeNativeV2Lifecycle(peer: BrokerPeer, envelope: V2NativeEnvelope): Promise<void> {
    const taskId = nativeV2TaskId(envelope);
    const route = taskId === undefined ? undefined : this.nativeV2Tasks.get(taskId);
    if (!route || !nativeEndpointMatchesPeer(route.target, peer) || !nativeTargetMatchesEndpoint(envelope.target, route.source)) {
      await this.sendNativeV2Error(peer, "PMX.ROUTING.FENCE", "Lifecycle record does not match its native task route", envelope.message_id, false);
      return;
    }
    if ((envelope.type === "task.accepted" || envelope.type === "task.rejected") && envelope.in_reply_to !== route.submitMessageId) {
      await this.sendNativeV2Error(peer, "PMX.TASK.EVENT_CONFLICT", "Task admission is not correlated to the submitted native message", envelope.message_id, false);
      return;
    }
    const owner = this.lookupNativeV2ExactTarget(route.source.agentId, route.source.instanceId);
    if (!owner || !nativeEndpointMatchesPeer(route.source, owner)) {
      await this.sendNativeV2Error(peer, "PMX.ROUTING.FENCE", "Task owner session has been replaced", envelope.message_id, true);
      return;
    }
    const forwarded = await this.forwardNativeV2Envelope(peer, owner, envelope);
    if (forwarded && (envelope.type === "task.rejected" || envelope.type === "task.completed")) this.removeNativeV2Task(route);
  }

  private async routeNativeV2Cancel(peer: BrokerPeer, envelope: V2NativeEnvelope): Promise<void> {
    const taskId = nativeV2TaskId(envelope);
    const route = taskId === undefined ? undefined : this.nativeV2Tasks.get(taskId);
    if (!route || !nativeEndpointMatchesPeer(route.source, peer) || !nativeTargetMatchesEndpoint(envelope.target, route.target)) {
      await this.sendNativeV2Error(peer, "PMX.ROUTING.FENCE", "Cancellation does not match its native task route", envelope.message_id, false);
      return;
    }
    const executor = this.lookupNativeV2ExactTarget(route.target.agentId, route.target.instanceId);
    if (!executor || !nativeEndpointMatchesPeer(route.target, executor)) {
      await this.sendNativeV2Error(peer, "PMX.ROUTING.FENCE", "Task executor session has been replaced", envelope.message_id, true);
      return;
    }
    await this.forwardNativeV2Envelope(peer, executor, envelope);
  }

  private async handleNativeV2BrokerEnvelope(peer: BrokerPeer, envelope: V2NativeEnvelope): Promise<void> {
    if (envelope.type === "ping") {
      await this.sendNativeV2Envelope(peer, this.createNativeV2Envelope(peer, "pong", envelope.params, envelope.message_id, envelope.delivery.deadline));
      return;
    }
    if (envelope.type !== "task.submit") {
      await this.sendNativeV2Error(peer, "PMX.ROUTING.TARGET_UNAVAILABLE", "The broker only accepts native ping and task.submit records", envelope.message_id, false);
      return;
    }
    const params = envelope.params as JsonRecord;
    const taskId = nativeV2TaskId(envelope);
    const capability = typeof params.capability === "string" ? params.capability : undefined;
    if (!taskId || !capability) {
      await this.sendNativeV2Error(peer, "PMX.PROTOCOL.ENVELOPE", "Native task submission is malformed", envelope.message_id, false);
      return;
    }
    const result = capability === "org.polymesh.agent.ping"
      ? {} as JsonValue
      : capability === "org.polymesh.agent.info"
        ? this.card as unknown as JsonValue
        : capability === "org.polymesh.capabilities.list"
          ? this.card.capabilities.map(({ id, version }) => ({ id, version })) as unknown as JsonValue
          : undefined;
    if (result === undefined) {
      await this.sendNativeV2Envelope(peer, this.createNativeV2Envelope(peer, "task.rejected", {
        task_id: taskId,
        event_seq: 1,
        code: "PMX.TASK.REJECTED",
        message: `Broker does not implement ${capability}`,
      }, envelope.message_id, envelope.delivery.deadline));
      return;
    }
    const contract = nativeV2ContractFields(params);
    await this.sendNativeV2Envelope(peer, this.createNativeV2Envelope(peer, "task.accepted", {
      task_id: taskId,
      event_seq: 1,
      accepted_at: new Date(this.now()).toISOString(),
      ...contract,
    }, envelope.message_id, envelope.delivery.deadline));
    await this.sendNativeV2Envelope(peer, this.createNativeV2Envelope(peer, "task.completed", {
      task_id: taskId,
      event_seq: 2,
      ...contract,
      terminal: { outcome: "succeeded", result, completed_at: new Date(this.now()).toISOString() },
    }, undefined, envelope.delivery.deadline));
  }

  private createNativeV2Envelope(
    target: BrokerPeer,
    type: V2NativeEnvelopeType,
    params: JsonObject,
    inReplyTo?: string,
    deadline = new Date(this.now() + 60_000).toISOString(),
  ): V2NativeEnvelope {
    if (!target.agentId || !target.instanceId) throw new Error("Cannot address a native v2 peer before init");
    const messageId = uuidv7(this.now());
    return {
      protocol: V2_PROFILE,
      profile: V2_PROFILE,
      mesh_id: this.nativeV2MeshId,
      type,
      message_id: messageId,
      timestamp: new Date(this.now()).toISOString(),
      source: { agent_id: this.card.agent_id, instance_id: this.card.instance_id },
      target: { agent_id: target.agentId, instance_id: target.instanceId },
      delivery: {
        delivery_id: uuidv7(this.now()),
        mode: "at_least_once",
        idempotency_key: `${type}:${messageId}`,
        deadline,
      },
      ...(inReplyTo === undefined ? {} : { in_reply_to: inReplyTo }),
      params,
    } as V2NativeEnvelope;
  }

  private async sendNativeV2Error(
    peer: BrokerPeer,
    code: V2ErrorCode,
    message: string,
    inReplyTo?: string,
    retryable = false,
  ): Promise<void> {
    if (peer.phase !== "active" || peer.profile !== "native-v2") return;
    const envelope = this.createNativeV2Envelope(peer, "error", {
      code,
      message: message.slice(0, 1_024),
      retryable,
    }, inReplyTo);
    await this.sendNativeV2Envelope(peer, envelope);
  }

  private failNativeV2Handshake(peer: BrokerPeer, code: V2ErrorCode, message: string): void {
    if (peer.phase === "closed") return;
    const error: V2ErrorFrame = {
      type: "v2.error",
      protocol: V2_PROFILE,
      profile: V2_PROFILE,
      // Even a rejected init identifies the broker mesh that made the
      // decision. A client-provided pre-init mesh hint is never echoed.
      mesh_id: this.nativeV2MeshId,
      ...(peer.sessionId === undefined ? {} : { session_id: peer.sessionId }),
      code,
      message: message.slice(0, 1_024),
      retryable: false,
    };
    this.sendRaw(peer, error);
    // In-memory and browser-shaped transports enqueue `send`; closing in the
    // same turn can otherwise cancel the bounded v2.error before the client
    // sees it. The record is sent first, then the session is fail-closed.
    queueMicrotask(() => this.closePeer(peer, `${code}: ${message}`));
  }

  private nativeV2PeerKey(agentId: string, instanceId: string): string {
    return `${this.nativeV2MeshId}\0${agentId}\0${instanceId}`;
  }

  private nativeV2InboxTarget(agentId: string, instanceId: string): string {
    return this.nativeV2PeerKey(agentId, instanceId);
  }

  /** A replacement can never inherit the replaced peer's native task routes. */
  private registerNativeV2Peer(peer: BrokerPeer): void {
    if (!peer.agentId || !peer.instanceId || !peer.sessionId) throw new Error("Native v2 init has no session identity");
    const key = this.nativeV2PeerKey(peer.agentId, peer.instanceId);
    const prior = this.nativeV2Peers.get(key);
    this.nativeV2Peers.set(key, peer);
    if (prior && prior !== peer && prior.phase !== "closed") this.closePeer(prior, "native v2 session replaced");
  }

  private removeNativeV2Peer(peer: BrokerPeer): void {
    if (!peer.agentId || !peer.instanceId) return;
    const key = this.nativeV2PeerKey(peer.agentId, peer.instanceId);
    if (this.nativeV2Peers.get(key) === peer) this.nativeV2Peers.delete(key);
    peer.nativeV2Zstd?.close();
    if (!peer.sessionId) return;
    for (const route of [...this.nativeV2Tasks.values()]) {
      if (nativeEndpointMatchesPeer(route.source, peer) || nativeEndpointMatchesPeer(route.target, peer)) {
        this.removeNativeV2Task(route);
      }
    }
  }

  private removeNativeV2Task(route: NativeV2TaskRoute): void {
    if (this.nativeV2Tasks.get(route.taskId) !== route) return;
    this.nativeV2Tasks.delete(route.taskId);
    if (this.nativeV2RoutesBySubmitMessageId.get(route.submitMessageId) === route.taskId) {
      this.nativeV2RoutesBySubmitMessageId.delete(route.submitMessageId);
    }
  }

  private lookupNativeV2ExactTarget(agentId: string, instanceId: string): BrokerPeer | undefined {
    const target = this.nativeV2Peers.get(this.nativeV2PeerKey(agentId, instanceId));
    return target?.phase === "active" && target.profile === "native-v2" ? target : undefined;
  }

  /** Deterministic logical-agent selection; exact instance delivery never falls back. */
  private lookupNativeV2Target(target: V2NativeEnvelope["target"]): BrokerPeer | undefined {
    if (target.instance_id !== undefined) return this.lookupNativeV2ExactTarget(target.agent_id, target.instance_id);
    const candidates = [...this.nativeV2Peers.values()]
      .filter((peer) => peer.phase === "active" && peer.profile === "native-v2" && peer.agentId === target.agent_id)
      .sort((left, right) => (left.instanceId ?? "").localeCompare(right.instanceId ?? ""));
    return candidates[0];
  }

  /** Persist first when configured, then expose the same immutable envelope to a live peer. */
  private async forwardNativeV2Envelope(
    source: BrokerPeer,
    target: BrokerPeer,
    envelope: V2NativeEnvelope,
  ): Promise<boolean> {
    if (!target.agentId || !target.instanceId || !target.sessionId || target.phase !== "active" || target.profile !== "native-v2") {
      await this.sendNativeV2Error(source, "PMX.ROUTING.TARGET_UNAVAILABLE", "Native target session is unavailable", envelope.message_id, true);
      return false;
    }
    const store = this.nativeV2Store;
    if (store) {
      try {
        await store.persistEnvelopeAndInbox({
          id: envelope.delivery.delivery_id,
          mesh_id: this.nativeV2MeshId,
          profile: V2_PROFILE,
          envelope: envelope as unknown as JsonObject,
          target: this.nativeV2InboxTarget(target.agentId, target.instanceId),
          created_at: this.now(),
        });
      } catch {
        await this.sendNativeV2Error(source, "PMX.INTERNAL", "Native envelope could not be durably stored", envelope.message_id, true);
        return false;
      }
    }
    const sent = await this.sendNativeV2Envelope(target, envelope);
    if (sent && store?.markDelivered) {
      try {
        await store.markDelivered(this.nativeV2InboxTarget(target.agentId, target.instanceId), envelope.delivery.delivery_id, this.now());
      } catch {
        // The delivery fact is already stored. A later SSE/replay reader can
        // safely see it as pending instead of treating a local mark failure as
        // a successfully acknowledged transport delivery.
      }
    }
    return sent;
  }

  /** Send raw JSON until zstd reaches its bilateral ready barrier. */
  private async sendNativeV2Envelope(peer: BrokerPeer, envelope: V2NativeEnvelope): Promise<boolean> {
    const machine = peer.nativeV2Zstd;
    if (peer.nativeV2Compression === "zstd" && machine?.active) {
      try {
        const payload = Buffer.from(JSON.stringify(envelope), "utf8");
        const wrapper = await machine.wrap(payload);
        return this.sendRaw(peer, wrapper);
      } catch {
        // A compression failure must not silently claim an encoded delivery.
        // Raw native records remain valid during this experimental profile and
        // preserve availability without changing the selected session scope.
      }
    }
    return this.sendRaw(peer, envelope);
  }

  /** Replay pending durable native inbox entries when the exact peer reconnects. */
  private async drainNativeV2Inbox(peer: BrokerPeer): Promise<void> {
    const store = this.nativeV2Store;
    if (!store?.replayInbox || !peer.agentId || !peer.instanceId || peer.phase !== "active") return;
    const target = this.nativeV2InboxTarget(peer.agentId, peer.instanceId);
    try {
      const page = await store.replayInbox({ target, limit: 100, statuses: ["pending"] });
      for (const delivery of page.deliveries) {
        const envelope = validateNativeV2Envelope(delivery.envelope);
        if (!envelope || envelope.mesh_id !== this.nativeV2MeshId ||
          envelope.target.agent_id !== peer.agentId || envelope.target.instance_id !== peer.instanceId) continue;
        if (await this.sendNativeV2Envelope(peer, envelope) && store.markDelivered) {
          await store.markDelivered(target, delivery.envelope_id, this.now());
        }
      }
    } catch {
      // Inbox recovery is best effort. The transaction remains durable and
      // will be retried by the next connection or an SSE mailbox reader.
    }
  }

  private admitNativeV2Replay(peer: BrokerPeer, envelope: V2NativeEnvelope): "new" | "duplicate" | "conflict" | "overloaded" {
    this.pruneNativeV2State();
    let semanticDigest: string;
    try {
      const { message_id: _messageId, timestamp: _timestamp, ...semantic } = envelope;
      void _messageId;
      void _timestamp;
      semanticDigest = canonicalize(semantic as unknown as JsonObject);
    } catch {
      return "conflict";
    }
    const key = `${this.nativeV2MeshId}\0${peer.agentId ?? ""}\0${peer.instanceId ?? ""}\0${envelope.message_id}`;
    const prior = this.nativeV2ReplayLedger.get(key);
    if (prior) return prior.semanticDigest === semanticDigest ? "duplicate" : "conflict";
    if (this.nativeV2ReplayLedger.size >= this.maxReplayLedgerEntries) return "overloaded";
    const deadlineAt = Date.parse(envelope.delivery.deadline);
    this.nativeV2ReplayLedger.set(key, {
      semanticDigest,
      expiresAt: Math.max(this.now(), Number.isFinite(deadlineAt) ? deadlineAt : this.now()) + this.replayRetentionMs,
    });
    return "new";
  }

  private pruneNativeV2State(now = this.now()): void {
    for (const route of [...this.nativeV2Tasks.values()]) {
      if (route.expiresAt <= now || route.deadlineAt <= now) this.removeNativeV2Task(route);
    }
    for (const [key, record] of this.nativeV2ReplayLedger) {
      if (record.expiresAt <= now) this.nativeV2ReplayLedger.delete(key);
    }
  }

  /** Strict v0.2 hello branch: no v1 hello can enter this session. */
  private receiveV2Hello(peer: BrokerPeer, frame: unknown): void {
    if (!this.v2Enabled || !this.meshId || !this.durableStore) {
      this.failHandshake(peer, "UNSUPPORTED_PROTOCOL_VERSION", "The durable PolyMesh 0.2 profile is not enabled", "protocol");
      return;
    }
    const validated = validateV2HelloFrame(frame);
    if (validated.ok === false || validated.value.role !== "initiator") {
      this.failHandshake(peer, "UNSUPPORTED_PROTOCOL_VERSION", "Expected an initiator hello for PolyMesh 0.2", "protocol");
      return;
    }
    const hello = validated.value;
    if (peer.profile !== undefined && peer.profile !== "v2") {
      this.failHandshake(peer, "UNSUPPORTED_PROTOCOL_VERSION", "WebSocket subprotocol and hello version disagree", "protocol");
      return;
    }
    // Mesh scope is an authenticated session property. An optional caller
    // hint may agree with it, but can never select a different scope.
    if (hello.mesh_id !== undefined && hello.mesh_id !== this.meshId) {
      this.failHandshake(peer, "MESH_SCOPE_MISMATCH", "hello.mesh_id does not match the authenticated relay mesh", "identity");
      return;
    }
    if (this.identityProfile ? hello.security_profile !== SECURE_IDENTITY_PROFILE : hello.security_profile !== undefined) {
      this.failHandshake(peer, "SECURITY_PROFILE_MISMATCH", "Peer selected an unexpected security profile", "identity");
      return;
    }
    if (hello.agent_id === this.card.agent_id && hello.instance_id === this.card.instance_id) {
      this.failHandshake(peer, "SELF_CONNECTION", "An agent cannot connect to itself", "identity");
      return;
    }
    peer.profile = "v2";
    peer.meshId = this.meshId;
    peer.agentId = hello.agent_id;
    peer.instanceId = hello.instance_id;
    peer.initiatorNonce = hello.nonce;
    peer.v2InitiatorHello = hello;
    peer.responderNonce = randomNonce();
    peer.sessionId = deriveV2SessionId(peer.initiatorNonce, peer.responderNonce);
    peer.phase = "await_card";
    const responderHello: V2HelloFrame = {
      type: "hello",
      v: V2_HANDSHAKE_VERSION,
      role: "responder",
      agent_id: this.card.agent_id,
      instance_id: this.card.instance_id,
      nonce: peer.responderNonce,
      echo: peer.initiatorNonce,
      sid: peer.sessionId,
      mesh_id: this.meshId,
      ...(this.identityProfile === undefined ? {} : { security_profile: SECURE_IDENTITY_PROFILE }),
    };
    peer.v2ResponderHello = responderHello;
    this.sendRaw(peer, responderHello);
  }

  private receiveCard(peer: BrokerPeer, frame: unknown): void {
    const validated = validateHandshakeFrame(frame);
    if (validated.ok === false || validated.value.type !== "card") {
      this.failHandshake(peer, "MALFORMED_FRAME", "Invalid card handshake frame", "parse");
      return;
    }
    const cardFrame: CardFrame = validated.value;
    if (cardFrame.sid !== peer.sessionId || cardFrame.for_nonce !== peer.responderNonce) {
      this.failHandshake(peer, "MALFORMED_FRAME", "Card transcript does not match the handshake", "protocol");
      return;
    }
    if (cardFrame.card.agent_id !== peer.agentId || cardFrame.card.instance_id !== peer.instanceId) {
      this.failHandshake(peer, "SOURCE_IDENTITY_MISMATCH", "Card identity does not match hello identity", "identity");
      return;
    }
    if (Date.parse(cardFrame.card.expires_at) <= this.now()) {
      this.failHandshake(peer, "CARD_EXPIRED", "Agent card has expired", "protocol");
      return;
    }
    const actualDigest = cardDigest(cardFrame.card);
    if (actualDigest !== cardFrame.digest) {
      this.failHandshake(peer, "CARD_DIGEST_MISMATCH", "Card digest does not match card contents", "protocol");
      return;
    }
    peer.card = cardFrame.card;
    peer.cardDigest = actualDigest;
    const profile = this.identityProfile;
    if (profile) {
      const principal = verifyEnrolledCard(cardFrame.card, profile.enrollments, this.now());
      if (!principal || !cardFrame.card.identity ||
        principal.agent_id !== peer.agentId ||
        principal.key_id !== cardFrame.card.identity.key_id) {
        this.failHandshake(peer, "AUTHENTICATION_FAILED", "Peer Card is not signed by an enrolled identity", "identity");
        return;
      }
      const existing = this.registry.lookup(peer.agentId!);
      const existingPrincipal = existing?.transport?.verifiedPrincipal;
      if (existingPrincipal && existingPrincipal.key_id !== principal.key_id) {
        this.failHandshake(peer, "IDENTITY_COLLISION", "A different enrolled key already owns this agent ID", "identity");
        return;
      }
      if (existingPrincipal && existingPrincipal.key_id === principal.key_id && existing.instanceId === peer.instanceId) {
        this.failHandshake(peer, "INSTANCE_ID_COLLISION", "This enrolled instance ID is already active", "identity");
        return;
      }
      peer.verifiedPrincipal = principal;
      peer.phase = "await_auth";
    } else {
      peer.phase = "await_ready";
    }
    this.sendRaw(peer, {
      type: "card",
      sid: peer.sessionId,
      for_nonce: peer.initiatorNonce,
      digest: this.cardDigest,
      card: this.card,
    });
  }

  private receiveAuth(peer: BrokerPeer, frame: unknown): void {
    const validated = validateHandshakeFrame(frame);
    if (validated.ok === false || validated.value.type !== "auth" || validated.value.sid !== peer.sessionId) {
      this.failHandshake(peer, "AUTHENTICATION_FAILED", "Invalid peer authentication proof", "identity");
      return;
    }
    const profile = this.identityProfile;
    const peerCard = peer.card;
    if (!profile || !peerCard?.identity || !peer.verifiedPrincipal ||
      validated.value.agent_id !== peer.agentId ||
      validated.value.key_id !== peerCard.identity.key_id) {
      this.failHandshake(peer, "AUTHENTICATION_FAILED", "Authentication proof does not match the enrolled Card", "identity");
      return;
    }
    let principal: VerifiedPrincipal | undefined;
    try {
      principal = peer.profile === "v2"
        ? verifyV2AuthProof(validated.value as AuthFrame, this.secureTranscript(peer), profile.enrollments, this.now())
        : verifyAuthProof(validated.value as AuthFrame, this.secureTranscript(peer), profile.enrollments, this.now());
    } catch {
      principal = undefined;
    }
    if (!principal || principal.key_id !== peer.verifiedPrincipal.key_id || principal.agent_id !== peer.verifiedPrincipal.agent_id) {
      this.failHandshake(peer, "AUTHENTICATION_FAILED", "Peer did not prove possession of its enrolled key", "identity");
      return;
    }
    peer.verifiedPrincipal = principal;
    peer.phase = "await_ready";
    try {
      const proof = peer.profile === "v2"
        ? createV2AuthProof(
          this.card.agent_id,
          profile.identity.key_id,
          peer.sessionId!,
          this.secureTranscript(peer),
          profile.privateKey,
        )
        : createAuthProof(
          profile.identity,
          this.card.agent_id,
          peer.sessionId!,
          this.secureTranscript(peer),
          profile.privateKey,
        );
      this.sendRaw(peer, proof);
    } catch {
      this.failHandshake(peer, "AUTHENTICATION_FAILED", "Unable to construct broker authentication proof", "identity");
    }
  }

  private secureTranscript(peer: BrokerPeer): Buffer {
    if (peer.profile === "v2") {
      if (!peer.v2InitiatorHello || !peer.v2ResponderHello || !peer.cardDigest) {
        throw new TypeError("v0.2 secure handshake transcript is incomplete");
      }
      const binding = tlsChannelBinding(peer.transport, V2_TLS_EXPORTER_LABEL);
      if (!binding) throw new TypeError("TLS 1.3 channel binding is unavailable");
      return v2AuthTranscript({
        initiator_hello: peer.v2InitiatorHello,
        responder_hello: peer.v2ResponderHello,
        initiator_card_digest: peer.cardDigest,
        responder_card_digest: this.cardDigest,
        tls_channel_binding: binding,
      });
    }
    if (!peer.initiatorHello || !peer.responderHello || !peer.cardDigest) {
      throw new TypeError("Secure handshake transcript is incomplete");
    }
    const binding = tlsChannelBinding(peer.transport);
    if (!binding) throw new TypeError("TLS 1.3 channel binding is unavailable");
    return authTranscript({
      initiator_hello: peer.initiatorHello,
      responder_hello: peer.responderHello,
      initiator_card_digest: peer.cardDigest,
      responder_card_digest: this.cardDigest,
      tls_channel_binding: binding,
    });
  }

  private receiveReady(peer: BrokerPeer, frame: unknown): void {
    const validated = validateHandshakeFrame(frame);
    if (
      validated.ok === false ||
      validated.value.type !== "ready" ||
      !peer.agentId ||
      !peer.instanceId ||
      !peer.card ||
      (this.identityProfile !== undefined && peer.verifiedPrincipal === undefined)
    ) {
      this.failHandshake(peer, "MALFORMED_FRAME", "Ready transcript does not match the handshake", "protocol");
      return;
    }
    const ready: ReadyFrame = validated.value;
    if (ready.sid !== peer.sessionId || ready.self_card !== peer.cardDigest || ready.peer_card !== this.cardDigest) {
      this.failHandshake(peer, "MALFORMED_FRAME", "Ready transcript does not match the handshake", "protocol");
      return;
    }

    if (this.durableRegistry) {
      void this.completeDurableReady(peer, ready);
      return;
    }
    try {
      this.activateReadyPeer(peer, ready, this.registerLivePeer(peer));
    } catch (error) {
      this.failReadyRegistration(peer, error);
    }
  }

  private async completeDurableReady(peer: BrokerPeer, ready: ReadyFrame): Promise<void> {
    try {
      const record = await this.registerDurableLivePeer(peer);
      // A client can close while SQLite is committing. Never revive a closed
      // socket from a late durable callback; remove only the exact new fence.
      if (peer.phase === "closed") {
        if (this.durableRegistry && peer.meshId && peer.agentId && peer.instanceId &&
          peer.registrationFence !== undefined && peer.sessionFence !== undefined) {
          await this.durableRegistry.removeDurable({
            meshId: peer.meshId,
            agentId: peer.agentId,
            instanceId: peer.instanceId,
            registrationFence: peer.registrationFence,
            sessionFence: peer.sessionFence,
          });
        }
        return;
      }
      this.activateReadyPeer(peer, ready, record);
    } catch (error) {
      this.failReadyRegistration(peer, error);
    }
  }

  private activateReadyPeer(peer: BrokerPeer, ready: ReadyFrame, record: RegistryEntry<BrokerPeer, AgentCard>): void {
    peer.leaseId = record.leaseId;
    peer.phase = "active";
    this.clearHandshakeTimer(peer);
    this.sendRaw(peer, {
      type: "ready",
      sid: peer.sessionId,
      self_card: this.cardDigest,
      peer_card: peer.cardDigest,
    });
    this.options.onPeerConnected?.(peer);
    // A target reconnect is the normal wake path for durable offline work.
    // The dispatcher checks the route/session pin before it writes anything.
    this.wakeDurableDispatcher();
  }

  /**
   * Dispatch the closed post-READY v0.2 transport vocabulary. Compression is
   * intentionally outside the application envelope grammar, so a wrapper
   * must be decoded, size-checked, and bound to its declared record type
   * before it ever reaches the normal durable ingress path.
   */
  private async receiveV2Record(peer: BrokerPeer, frame: unknown): Promise<void> {
    try {
      const type = typeof frame === "object" && frame !== null && !Array.isArray(frame)
        ? (frame as { type?: unknown }).type
        : undefined;
      if (type === "compression.offer") {
        this.receiveV2CompressionOffer(peer, frame);
        return;
      }
      if (type === "compression.selected") {
        this.receiveV2CompressionSelected(peer, frame);
        return;
      }
      if (type === "compression.frame") {
        await this.receiveV2CompressedFrame(peer, frame);
        return;
      }
      await this.receiveV2Envelope(peer, frame);
    } catch {
      // No untrusted transport record may escape as a rejected promise from a
      // WebSocket callback. The durable fact path is fail-closed below.
      this.sendError(peer, "COMPRESSION_PROCESSING_FAILED", "Could not process the v0.2 transport record", "protocol", undefined, {}, true);
    }
  }

  /** Select exactly one codec/limit tuple after a peer's strict capability offer. */
  private receiveV2CompressionOffer(peer: BrokerPeer, frame: unknown): void {
    const offered = validateV2CompressionOffer(frame, { ready: peer.phase === "active" });
    if (!offered.ok) {
      this.sendCompressionError(peer, offered.code, offered.error);
      return;
    }
    const prior = peer.compression;
    const result = this.negotiatePeerCompression(peer, offered.value);
    if (!result.ok) {
      this.sendCompressionError(peer, result.code, "No safe compression algorithm can be selected");
      return;
    }
    // Replacing an active codec/limit set would make an in-flight record
    // ambiguous. Accept a retransmitted equal offer, but fence a change until
    // a future explicit rekey/renegotiation extension exists.
    if (prior && !sameCompressionNegotiation(prior, result.value)) {
      peer.compression = prior;
      this.sendCompressionError(peer, "COMPRESSION_SELECTED_MISMATCH", "Compression renegotiation cannot change an active selection");
      return;
    }
    this.sendRaw(peer, createV2CompressionSelected(result.value));
  }

  /** A selected record only acknowledges the immutable selection we made from an offer. */
  private receiveV2CompressionSelected(peer: BrokerPeer, frame: unknown): void {
    if (!peer.compression) {
      this.sendCompressionError(peer, "COMPRESSION_SELECTED_MISMATCH", "Compression selection was not preceded by a peer offer");
      return;
    }
    const selected = validateV2CompressionSelected(frame, {
      ready: peer.phase === "active",
      expected: peer.compression,
    });
    if (!selected.ok) this.sendCompressionError(peer, selected.code, selected.error);
  }

  /**
   * Decode one self-contained zstd wrapper. Declared limits are checked
   * before codec work, actual output is checked before JSON parsing, and the
   * decoded record type is bound before normal v0.2 validation/rate routing.
   */
  private async receiveV2CompressedFrame(peer: BrokerPeer, value: unknown): Promise<void> {
    const negotiation = peer.compression ?? { algorithm: "none" as const };
    const parsedFrame = validateV2CompressionFrame(value, {
      ready: peer.phase === "active",
      negotiation,
    });
    if (!parsedFrame.ok) {
      this.sendCompressionError(peer, parsedFrame.code, parsedFrame.error);
      return;
    }
    const frame = parsedFrame.value;
    const codec = runtimeZstdCodec();
    if (!codec || negotiation.algorithm !== "zstd" || !negotiation.limits) {
      this.sendCompressionError(peer, "COMPRESSION_NOT_NEGOTIATED", "zstd is not available for this broker session");
      return;
    }
    const metadata = v2CompressionFrameMetadata(frame);
    let decoded: Buffer;
    try {
      // Node's maxOutputLength stops allocation before an oversized zstd
      // payload becomes a decompression bomb. The declared metadata is still
      // verified after decoding because a codec output is untrusted too.
      decoded = codec.decompress(Buffer.from(frame.payload, "base64url"), negotiation.limits.maxUncompressedBytes);
    } catch {
      this.sendCompressionError(peer, "COMPRESSION_FRAME_INVALID", "Compressed payload could not be decoded within negotiated limits");
      return;
    }
    const output = validateDecompressedOutput(negotiation, metadata, decoded.byteLength);
    if (!output.ok) {
      this.sendCompressionError(peer, output.code, "Compressed payload output violates negotiated limits");
      return;
    }
    const decodedRecord = parseStrictJson(decoded, { maxBytes: negotiation.limits.maxUncompressedBytes });
    if (!decodedRecord.ok) {
      this.sendCompressionError(peer, decodedRecord.code === "RESOURCE_EXHAUSTED" ? "COMPRESSION_LIMIT_EXCEEDED" : "COMPRESSION_FRAME_INVALID", "Compressed payload is not a valid strict JSON record");
      return;
    }
    const binding = validateV2CompressionRecordBinding(frame, decodedRecord.value);
    if (!binding.ok) {
      this.sendCompressionError(peer, binding.code, "Compressed metadata does not match the decoded record");
      return;
    }
    await this.receiveV2Envelope(peer, decodedRecord.value, metadata);
  }

  private sendCompressionError(peer: BrokerPeer, code: string, message: string): void {
    const resource = code === "COMPRESSION_LIMIT_EXCEEDED" ||
      code === "COMPRESSION_EXPANSION_LIMIT" ||
      code === "COMPRESSION_OUTPUT_SIZE_MISMATCH";
    this.sendError(peer, code, message, resource ? "resource" : "protocol", undefined, {}, true);
  }

  private failReadyRegistration(peer: BrokerPeer, error: unknown): void {
    if (error instanceof IdentityCollisionError || error instanceof DurableIdentityCollisionError ||
      (error instanceof Error && error.message.includes("IDENTITY_COLLISION"))) {
      this.failHandshake(peer, "IDENTITY_COLLISION", error instanceof Error ? error.message : "Agent identity is already bound", "identity");
      return;
    }
    if (error instanceof DuplicateAgentError) {
      this.failHandshake(peer, "DUPLICATE_CONNECTION", error.message, "routing");
      return;
    }
    this.failHandshake(peer, "INTERNAL_ERROR", "Could not register agent", "internal");
  }

  /**
   * v0.2 application ingress is deliberately separate from the legacy router:
   * it commits the inbox/route/outbox transaction before returning the
   * transport-level stored receipt and only then wakes dispatch.
   */
  private async receiveV2Envelope(
    peer: BrokerPeer,
    frame: unknown,
    compressionMetadata?: CompressionFrameMetadata,
  ): Promise<void> {
    if (isDeliveryReceiptRecord(frame)) {
      const receiptRateLimit = this.admitReceiptRateLimit(peer, frame);
      if (!receiptRateLimit.allowed) {
        this.sendError(
          peer,
          receiptRateLimit.code ?? "RATE_LIMITED",
          "Broker receipt rate limit exceeded",
          "resource",
          undefined,
          {},
          true,
          receiptRateLimit.retry_after_ms,
        );
        return;
      }
      await this.receiveV2DeliveryReceipt(peer, frame);
      return;
    }
    const validated = validateV2Envelope(frame);
    if (validated.ok === false) {
      this.sendError(peer, "MALFORMED_FRAME", "Frame is not a valid PolyMesh 0.2 envelope", "parse");
      return;
    }
    const envelope = validated.value;
    if (!this.meshId || peer.meshId !== this.meshId || envelope.source.mesh_id !== this.meshId || envelope.target.mesh_id !== this.meshId) {
      this.sendError(peer, "MESH_SCOPE_MISMATCH", "v0.2 mesh identity does not match the authenticated session", "identity", envelope.message_id);
      return;
    }
    if (envelope.source.agent_id !== peer.agentId || envelope.source.instance_id !== peer.instanceId) {
      this.sendError(peer, "SOURCE_IDENTITY_MISMATCH", "Envelope source does not match the authenticated connection", "identity", envelope.message_id);
      return;
    }
    if (hasV2DeliveryMetadata(envelope)) {
      this.sendError(peer, "DELIVERY_METADATA_FORBIDDEN", "Only the relay may attach v0.2 delivery metadata", "identity", envelope.message_id);
      return;
    }
    const legacy = v2EnvelopeAsLegacy(envelope);
    const rateLimit = this.admitEnvelopeRateLimit(peer, legacy, compressionMetadata);
    if (!rateLimit.allowed) {
      this.sendError(
        peer,
        rateLimit.code ?? "RATE_LIMITED",
        "Broker admission rate limit exceeded",
        "resource",
        envelope.message_id,
        {},
        true,
        rateLimit.retry_after_ms,
      );
      return;
    }
    // Rate limits gate all durable writes, including renewal. This keeps a
    // noisy authenticated session from turning the registration CAS itself
    // into an unbounded database workload.
    if (!await this.touchDurableRoutingInstance(peer)) {
      this.sendError(peer, "STALE_FENCE", "The v0.2 session no longer owns the active durable registration fence", "identity", envelope.message_id, {}, true);
      return;
    }
    try {
      const admission = await this.persistDurableIngress(peer, envelope, {
        semanticFingerprint: v2EnvelopeSemanticDigest(envelope),
      });
      if (admission.result.disposition === "conflict") {
        this.sendError(peer, admission.result.code, "Durable ingress conflicts with an existing immutable record", "delivery", envelope.message_id);
        return;
      }
      if (!admission.receipt || !this.sendRaw(peer, admission.receipt)) return;
      this.emitEnvelope(peer, legacy);
      // Waking is best effort because the fact is already durable. A restart
      // will reclaim/wake it again; a socket write never changes it directly
      // to DELIVERED.
      this.wakeDurableDispatcher();
    } catch (error) {
      const protocol = error instanceof ProtocolError ? error : undefined;
      this.sendError(
        peer,
        protocol?.code ?? "INTERNAL_ERROR",
        protocol?.message ?? "Durable ingress could not be committed",
        protocol?.category ?? "internal",
        envelope.message_id,
        {},
        protocol?.retryable ?? true,
      );
    }
  }

  /** Authenticate a non-recursive durable delivery receipt against its outbox. */
  private async receiveV2DeliveryReceipt(peer: BrokerPeer, receipt: DeliveryReceiptRecord): Promise<void> {
    const store = this.durableStore;
    if (!store || peer.phase !== "active" || peer.profile !== "v2") return;
    // A replacement session can reuse the same logical instance ID. Its
    // predecessor must not settle an outbox after it lost the durable
    // registration/session fence, even if an old receipt was already queued
    // in the transport. Revalidate the fenced registration first.
    if (!await this.touchDurableRoutingInstance(peer)) return;
    const outbox = await store.getOutbox(receipt.delivery_id);
    if (!outbox || outbox.targetAgentId !== peer.agentId || outbox.targetInstanceId !== peer.instanceId) return;
    const envelope = outbox.envelope;
    if (!isV2Envelope(envelope) || !hasV2DeliveryMetadata(envelope) ||
      envelope.delivery_id !== receipt.delivery_id || envelope.message_id !== receipt.message_id ||
      !await this.isPinnedDurableOutboxTarget(outbox, peer)) return;
    await store.acknowledgeOutbox({ deliveryId: receipt.delivery_id, now: this.now(), receiptState: receipt.state });
  }

  private receiveEnvelope(peer: BrokerPeer, frame: unknown): void {
    if (!isEnvelope(frame)) {
      this.sendError(peer, "MALFORMED_FRAME", "Frame is not a valid PolyMesh envelope", "parse");
      return;
    }
    const envelope = frame as Envelope;
    if (envelope.source.agent_id !== peer.agentId || envelope.source.instance_id !== peer.instanceId) {
      this.sendError(
        peer,
        "SOURCE_IDENTITY_MISMATCH",
        "Envelope source does not match the authenticated connection",
        "identity",
        envelope.message_id,
      );
      return;
    }
    // Provenance is created only after this authenticated ingress check. A
    // sender-supplied attachment would otherwise let one routed peer try to
    // smuggle an attestation into another route or create nested signatures.
    if (envelope.provenance !== undefined) {
      this.sendError(peer, "PROVENANCE_FORBIDDEN", "Only the broker may attach routed provenance", "identity", envelope.message_id);
      return;
    }

    // Receipts are broker-local, terminal control observations. They are
    // intentionally neither replay-ledger inputs nor routable application
    // traffic, and a receipt must never itself trigger another receipt. They
    // still consume a bounded control budget so they cannot become a cheap
    // parser or database-adjacent flood primitive.
    if (envelope.type === "receipt") {
      const receiptRateLimit = this.admitReceiptRateLimit(peer, envelope);
      if (!receiptRateLimit.allowed) {
        this.sendError(
          peer,
          receiptRateLimit.code ?? "RATE_LIMITED",
          "Broker receipt rate limit exceeded",
          "resource",
          envelope.message_id,
          {},
          true,
          receiptRateLimit.retry_after_ms,
        );
      }
      return;
    }

    const rateLimit = this.admitEnvelopeRateLimit(peer, envelope);
    if (!rateLimit.allowed) {
      this.sendError(
        peer,
        rateLimit.code ?? "RATE_LIMITED",
        "Broker admission rate limit exceeded",
        "resource",
        envelope.message_id,
        {},
        true,
        rateLimit.retry_after_ms,
      );
      return;
    }

    let semanticDigest: string;
    try {
      semanticDigest = envelopeSemanticDigest(envelope);
    } catch {
      this.sendError(peer, "MALFORMED_FRAME", "Envelope semantics cannot be canonicalized", "parse", envelope.message_id);
      return;
    }
    const replay = this.admitReplayEnvelope(peer, envelope, semanticDigest);
    if (replay === "conflict") {
      this.sendError(
        peer,
        "PMX.DELIVERY.MESSAGE_ID_CONFLICT",
        "message_id was reused with different message semantics",
        "delivery",
        envelope.message_id,
      );
      this.sendReceipt(peer, envelope, semanticDigest, "rejected");
      return;
    }
    if (replay === "overloaded") {
      this.sendError(
        peer,
        "OVERLOADED",
        "Broker replay ledger capacity is exhausted",
        "resource",
        envelope.message_id,
        {},
        true,
      );
      return;
    }
    if (this.multiInstanceRouting) this.touchRoutingInstance(peer);
    else this.registry.touch(peer.agentId!, { sessionId: peer.sessionId });

    // A direct ping to the broker gets a fast, signed-by-session response.
    if (envelope.target.agent_id === this.card.agent_id) {
      if (envelope.target.instance_id !== undefined && envelope.target.instance_id !== this.card.instance_id) {
        this.sendError(peer, "TARGET_UNAVAILABLE", "Target broker instance is unavailable", "routing", envelope.message_id, {
          target: this.card.agent_id,
          instance_id: envelope.target.instance_id,
        }, true);
        this.sendReceipt(peer, envelope, semanticDigest, "rejected");
        return;
      }
      if (envelope.type === "ping") {
        this.sendPong(peer, envelope as Envelope<"ping">);
        this.emitEnvelope(peer, envelope);
        this.sendReceipt(peer, envelope, semanticDigest, replay === "duplicate" ? "duplicate" : "accepted");
        return;
      }
      if (envelope.type === "task.submit") {
        this.handleBrokerTask(peer, envelope as Envelope<"task.submit">);
        this.emitEnvelope(peer, envelope);
        this.sendReceipt(peer, envelope, semanticDigest, replay === "duplicate" ? "duplicate" : "accepted");
        return;
      }
    }
    const routed = this.routeEnvelope(peer, envelope);
    if (routed) this.emitEnvelope(peer, envelope);
    this.sendReceipt(peer, envelope, semanticDigest, routed ? (replay === "duplicate" ? "duplicate" : "accepted") : "rejected");
  }

  private routeEnvelope(peer: BrokerPeer, envelope: Envelope): boolean {
    const taskId = taskIdOf(envelope);
    if (envelope.type === "task.submit" && taskId) {
      const declaredDeadline = envelope.delivery.deadline;
      const deadlineAt = declaredDeadline ? Date.parse(declaredDeadline) : Number.NaN;
      if (!Number.isFinite(deadlineAt) || deadlineAt <= this.now()) {
        this.sendError(peer, "PMX.TASK.DEADLINE_EXCEEDED", "Task deadline has already elapsed", "task", envelope.message_id);
        return false;
      }
      const contract = taskContractOf(envelope);
      if (!contract) {
        this.sendError(peer, "MALFORMED_FRAME", "Task submission has no valid capability contract", "parse", envelope.message_id);
        return false;
      }
      const prior = this.pendingTasks.get(taskId);
      const immutableFingerprint = canonicalize({
        method: (envelope.params as JsonRecord).method as never,
        capability_version: contract.capability_version,
        capability_contract_digest: contract.capability_contract_digest,
        params: (envelope.params as JsonRecord).params as never,
        deadline: (envelope.params as JsonRecord).deadline as never,
      } as never);
      if (prior && !this.isExactRoutePeer(prior.owner, peer)) {
        this.sendError(peer, "PMX.TASK.ID_CONFLICT", "Task ID is already assigned to another route", "task", envelope.message_id, {
          task_id: taskId,
        });
        return false;
      }
      if (prior && prior.immutableFingerprint !== immutableFingerprint) {
        this.sendError(peer, "PMX.TASK.ID_CONFLICT", "Task ID was reused with different immutable input", "task", envelope.message_id, {
          task_id: taskId,
        });
        return false;
      }
      if (prior) {
        if (!this.addSubmitMessageId(prior, envelope.message_id)) {
          this.sendError(peer, "OVERLOADED", "Too many retransmissions for this task route", "resource", envelope.message_id, {}, true);
          return false;
        }
        const currentTarget = this.lookupPinnedExecutor(prior);
        if (!currentTarget || currentTarget.sessionId !== prior.executor.sessionId) {
          this.sendError(peer, this.executorUnavailableCode(), this.executorUnavailableMessage(), "routing", envelope.message_id, {
            task_id: taskId,
            target: prior.executor.agentId,
          }, true);
          return false;
        }
        return this.forwardEnvelope(peer, currentTarget.transport!, envelope);
      }

      // A new task chooses one eligible instance exactly once. The selected
      // physical target and its fences are immediately retained in `route`.
      const target = this.lookupTarget(peer, envelope);
      if (!target) return false;

      if (!this.reserveTaskRoute(peer, target)) {
        this.sendError(peer, "OVERLOADED", "Broker task-route capacity is exhausted", "resource", envelope.message_id, {}, true);
        return false;
      }
      const route: TaskRoute = {
          taskId,
          contract,
          owner: { agentId: peer.agentId!, instanceId: peer.instanceId!, sessionId: peer.sessionId },
          executor: { agentId: target.agentId, instanceId: target.instanceId, sessionId: target.sessionId },
          submitMessageId: envelope.message_id,
          submitMessageIds: new Set([envelope.message_id]),
          createdAt: this.now(),
          deadline: declaredDeadline,
          immutableFingerprint,
          lifecycle: "submitted",
          nextEventSeq: 1,
          events: new Map(),
          capacityReserved: true,
          retainedUntil: Math.max(deadlineAt, this.now()) + this.replayRetentionMs,
          ...(this.multiInstanceRouting ? this.createRoutePinForTarget(target) : {}),
        };
      this.pendingTasks.set(taskId, route);
      this.routesBySubmitMessageId.set(envelope.message_id, taskId);
      if (!this.forwardEnvelope(peer, target.transport!, envelope)) {
        this.deleteRoute(route);
        return false;
      }
      return true;
    }

    if (isLifecycle(envelope.type) && taskId) {
      const route = this.pendingTasks.get(taskId);
      if (
        !route ||
        !this.isExactRoutePeer(route.executor, peer) ||
        envelope.target.agent_id !== route.owner.agentId ||
        (envelope.target.instance_id !== undefined && envelope.target.instance_id !== route.owner.instanceId)
      ) {
        this.sendError(peer, "PMX.TASK.FORGED_RESULT", "Lifecycle event is not authorized for this task", "task", envelope.message_id, {
          task_id: taskId,
        });
        return false;
      }
      if (route.lifecycle === "closed") {
        this.sendError(peer, "PMX.TASK.TERMINAL", "Task route is no longer active", "task", envelope.message_id, {
          task_id: taskId,
        });
        return false;
      }
      const lifecycle = this.admitLifecycle(route, envelope);
      if (lifecycle === "event-conflict") {
        this.sendError(peer, "PMX.TASK.EVENT_CONFLICT", "Lifecycle sequence was reused with different content", "task", envelope.message_id, {
          task_id: taskId,
        });
        return false;
      }
      if (lifecycle === "overloaded") {
        this.sendError(peer, "OVERLOADED", "Lifecycle history capacity is exhausted", "resource", envelope.message_id, {}, true);
        return false;
      }
      if (lifecycle === "invalid") {
        this.sendError(peer, "PMX.TASK.INVALID_LIFECYCLE", "Lifecycle event is not a valid causal transition", "task", envelope.message_id, {
          task_id: taskId,
        });
        return false;
      }
      const owner = this.lookupRegisteredInstance(route.owner.agentId, route.owner.instanceId);
      if (!owner || owner.sessionId !== route.owner.sessionId) {
        this.sendError(peer, "TARGET_UNAVAILABLE", "Task owner is no longer connected", "routing", envelope.message_id, {
          target: route.owner.agentId,
          task_id: taskId,
        }, true);
        return false;
      }
      return this.forwardEnvelope(peer, owner.transport!, envelope);
    }

    if (envelope.type === "task.cancel" && taskId) {
      const route = this.pendingTasks.get(taskId);
      if (!route || route.lifecycle === "closed") {
        this.sendError(peer, "PMX.TASK.NOT_FOUND", "No active task route exists for this cancellation", "task", envelope.message_id, {
          task_id: taskId,
        });
        return false;
      }
      if (!this.isExactRoutePeer(route.owner, peer)) {
        this.sendError(peer, "AUTHORIZATION_DENIED", "Only the task owner may cancel a task", "identity", envelope.message_id, {
          task_id: taskId,
        });
        return false;
      }
      if (
        route.lifecycle === "rejected" ||
        route.lifecycle === "completed" ||
        envelope.target.agent_id !== route.executor.agentId ||
        (envelope.target.instance_id !== undefined && envelope.target.instance_id !== route.executor.instanceId)
      ) {
        this.sendError(peer, "PMX.TASK.TERMINAL", "Cancellation target or task state is no longer cancellable", "task", envelope.message_id, {
          task_id: taskId,
        });
        return false;
      }
      const executor = this.lookupPinnedExecutor(route);
      if (!executor || executor.sessionId !== route.executor.sessionId) {
        this.sendError(peer, this.executorUnavailableCode(), this.executorUnavailableMessage(), "routing", envelope.message_id, {
          task_id: taskId,
          target: route.executor.agentId,
        }, true);
        return false;
      }
      return this.forwardEnvelope(peer, executor.transport!, envelope);
    }

    if (envelope.type === "error") return this.routeCorrelatedError(peer, envelope as Envelope<"error">);
    if (envelope.type === "card") {
      this.sendError(peer, "UNSUPPORTED_METHOD", "Post-ready card envelopes are not routable", "protocol", envelope.message_id);
      return false;
    }

    const target = this.lookupTarget(peer, envelope);
    if (!target) return false;
    return this.sendEnvelope(target.transport!, envelope);
  }

  /** Invoke observer hooks only after routing/admission has accepted a record. */
  private emitEnvelope(peer: BrokerPeer, envelope: Envelope): void {
    try {
      this.options.onEnvelope?.(envelope, peer);
    } catch {
      // Observer failures must not turn a validated peer record into a broker
      // crash or influence routing state.
    }
  }

  /** Build admission identity solely from the authenticated connection. */
  private rateLimitContext(peer: BrokerPeer, targetAgentId: string): RateLimitContext {
    const socket = peer.transport as unknown as { _socket?: { remoteAddress?: unknown } };
    const remoteAddress = socket._socket?.remoteAddress;
    return {
      meshId: this.meshId ?? "local",
      principalId: peer.verifiedPrincipal?.principal_id ?? (peer.agentId ? `legacy:${peer.agentId}` : undefined),
      credentialId: peer.verifiedPrincipal?.key_id ?? (peer.authEpoch === undefined ? undefined : `runtime-token:${peer.authEpoch}`),
      targetAgentId,
      preAuthIp: typeof remoteAddress === "string" && remoteAddress.length > 0 ? remoteAddress : "local",
      connectionId: peer.connectionId,
    };
  }

  /** Debit every configured hierarchy before an envelope reaches replay or route state. */
  private admitEnvelopeRateLimit(
    peer: BrokerPeer,
    envelope: Envelope,
    compressionMetadata?: CompressionFrameMetadata,
  ): RateLimitDecision {
    const charges: RateLimitCharge[] = [
      { operation: "envelope_count", cost: 1 },
    ];
    if (compressionMetadata) {
      // The wrapper was structurally and codec-validated before this point.
      // Debit both compressed and declared/actual uncompressed bytes in the
      // same hierarchy transaction as the logical task admission below.
      try {
        charges.push(...compressionRateLimitCharges(compressionMetadata));
      } catch {
        return {
          allowed: false,
          code: "RATE_LIMIT_UNAVAILABLE",
          retry_after_ms: null,
          bucketKeys: [],
        };
      }
    } else {
      let uncompressedBytes = 0;
      try {
        uncompressedBytes = Buffer.byteLength(JSON.stringify(envelope), "utf8");
      } catch {
        // The protocol validator already rejects non-JSON values. Keep a
        // defensive fail-closed charge if a future envelope implementation
        // introduces a hostile toJSON hook.
        uncompressedBytes = this.maxFrameBytes;
      }
      charges.push({ operation: "uncompressed_bytes", cost: Math.max(1, uncompressedBytes) });
    }
    if (envelope.type === "task.submit") charges.push({ operation: "task_submissions", cost: 1 });
    if (envelope.type === "ping" || envelope.type === "pong" || envelope.type === "error") {
      charges.push({ operation: "control", cost: 1 });
    }
    return this.admitRateLimit(peer, envelope.target.agent_id, charges);
  }

  private admitHandshakeRateLimit(peer: BrokerPeer, bytes: number): RateLimitDecision {
    return this.admitRateLimit(peer, this.card.agent_id, [
      { operation: "handshake", cost: 1 },
      { operation: "uncompressed_bytes", cost: Math.max(1, bytes) },
    ], { missingScopeBehavior: "skip" });
  }

  /** Receipts are non-recursive controls, but they still have finite cost. */
  private admitReceiptRateLimit(peer: BrokerPeer, receipt: unknown): RateLimitDecision {
    let bytes = this.maxFrameBytes;
    try {
      const encoded = JSON.stringify(receipt);
      if (typeof encoded === "string") bytes = Buffer.byteLength(encoded, "utf8");
    } catch {
      // Leave the maximum defensive charge in place for hostile future
      // control-record shapes with unsafe serialization hooks.
    }
    return this.admitRateLimit(peer, peer.agentId ?? this.card.agent_id, [
      { operation: "envelope_count", cost: 1 },
      { operation: "control", cost: 1 },
      { operation: "uncompressed_bytes", cost: Math.max(1, bytes) },
    ]);
  }

  /**
   * A coordinator outage must fail closed, never escape a message callback
   * (where it could become an unhandled rejection) or let work reach durable
   * state without a quota decision.
   */
  private admitRateLimit(
    peer: BrokerPeer,
    targetAgentId: string,
    charges: readonly RateLimitCharge[],
    options?: { missingScopeBehavior?: "reject" | "skip" },
  ): RateLimitDecision {
    if (!this.rateLimiter) return { allowed: true, code: undefined, retry_after_ms: 0, bucketKeys: [] };
    try {
      return this.rateLimiter.admitFailClosed(this.rateLimitContext(peer, targetAgentId), charges, options);
    } catch {
      return {
        allowed: false,
        code: "RATE_LIMITED",
        retry_after_ms: null,
        failures: [],
        bucketKeys: [],
      };
    }
  }

  private routeSessionKey(identity: { agentId: string; instanceId: string; sessionId?: string }): string {
    return `${identity.agentId}\0${identity.instanceId}\0${identity.sessionId ?? ""}`;
  }

  private peerSessionKey(peer: BrokerPeer): string {
    return this.routeSessionKey({
      agentId: peer.agentId ?? "",
      instanceId: peer.instanceId ?? "",
      sessionId: peer.sessionId,
    });
  }

  private isExactRoutePeer(identity: { agentId: string; instanceId: string; sessionId?: string }, peer: BrokerPeer): boolean {
    return identity.agentId === peer.agentId &&
      identity.instanceId === peer.instanceId &&
      identity.sessionId === peer.sessionId;
  }

  /** Reserve route capacity before allocating an in-memory task record. */
  private reserveTaskRoute(owner: BrokerPeer, executor: RegistryEntry<BrokerPeer, AgentCard>): boolean {
    this.pruneRouteAndReplayState();
    if (this.pendingTasks.size >= this.maxPendingTaskRoutes) return false;
    const keys = new Set([
      this.peerSessionKey(owner),
      this.routeSessionKey({ agentId: executor.agentId, instanceId: executor.instanceId, sessionId: executor.sessionId }),
    ]);
    for (const key of keys) {
      if ((this.pendingRoutesBySession.get(key) ?? 0) >= this.maxPendingTaskRoutesPerSession) return false;
    }
    for (const key of keys) this.pendingRoutesBySession.set(key, (this.pendingRoutesBySession.get(key) ?? 0) + 1);
    this.incrementRoutingInflight(executor);
    return true;
  }

  private incrementRoutingInflight(executor: RegistryEntry<BrokerPeer, AgentCard>): void {
    if (!this.multiInstanceRouting || !this.meshId) return;
    const instance = this.routingInstances.get(this.routingInstanceKey(this.meshId, executor.agentId, executor.instanceId));
    if (instance && instance.sessionId === executor.sessionId) {
      instance.currentInflight = (instance.currentInflight ?? 0) + 1;
    }
  }

  private decrementRoutingInflight(executor: TaskRoute["executor"]): void {
    if (!this.multiInstanceRouting || !this.meshId) return;
    const instance = this.routingInstances.get(this.routingInstanceKey(this.meshId, executor.agentId, executor.instanceId));
    if (instance && instance.sessionId === executor.sessionId) {
      instance.currentInflight = Math.max(0, (instance.currentInflight ?? 0) - 1);
    }
  }

  private releaseRouteCapacity(route: TaskRoute): void {
    if (!route.capacityReserved) return;
    route.capacityReserved = false;
    this.decrementRoutingInflight(route.executor);
    const keys = new Set([
      this.routeSessionKey(route.owner),
      this.routeSessionKey(route.executor),
    ]);
    for (const key of keys) {
      const count = this.pendingRoutesBySession.get(key) ?? 0;
      if (count <= 1) this.pendingRoutesBySession.delete(key);
      else this.pendingRoutesBySession.set(key, count - 1);
    }
  }

  private deleteRoute(route: TaskRoute): void {
    if (this.pendingTasks.get(route.taskId) !== route) return;
    this.pendingTasks.delete(route.taskId);
    this.releaseRouteCapacity(route);
    for (const messageId of route.submitMessageIds) {
      if (this.routesBySubmitMessageId.get(messageId) === route.taskId) this.routesBySubmitMessageId.delete(messageId);
    }
  }

  private addSubmitMessageId(route: TaskRoute, messageId: string): boolean {
    if (route.submitMessageIds.has(messageId)) return true;
    // The bounded replay set also caps untrusted `in_reply_to` correlation
    // state. It shares the lifecycle ceiling because both belong to one task.
    if (route.submitMessageIds.size >= this.maxLifecycleEventsPerRoute) return false;
    route.submitMessageIds.add(messageId);
    this.routesBySubmitMessageId.set(messageId, route.taskId);
    return true;
  }

  private admitLifecycle(route: TaskRoute, envelope: Envelope): "accepted" | "duplicate" | "invalid" | "event-conflict" | "overloaded" {
    const params = envelope.params as JsonRecord;
    const sequence = params.event_seq;
    if (typeof sequence !== "number" || !Number.isSafeInteger(sequence) || sequence < 1) return "invalid";
    if ((envelope.type === "task.accepted" || envelope.type === "task.rejected") &&
      (!envelope.in_reply_to || !route.submitMessageIds.has(envelope.in_reply_to))) {
      return "invalid";
    }
    if (envelope.type === "task.accepted" || envelope.type === "task.completed") {
      const echoedContract = taskContractOf(envelope);
      if (!echoedContract || !sameCapabilityContract(route.contract, echoedContract)) return "invalid";
    }
    let digest: string;
    try {
      // Envelope IDs, timestamps, and delivery IDs change on retransmission;
      // the lifecycle semantics must not. Correlation is checked separately.
      digest = canonicalize({
        type: envelope.type,
        source: envelope.source,
        target: envelope.target,
        params: envelope.params,
      } as never);
    } catch {
      return "invalid";
    }
    const previous = route.events.get(sequence);
    if (previous !== undefined) return previous === digest ? "duplicate" : "event-conflict";
    if (route.events.size >= this.maxLifecycleEventsPerRoute) return "overloaded";
    if (sequence !== route.nextEventSeq) return "invalid";

    if (envelope.type === "task.accepted") {
      if (route.lifecycle !== "submitted") return "invalid";
      route.lifecycle = "accepted";
    } else if (envelope.type === "task.rejected") {
      if (route.lifecycle !== "submitted") return "invalid";
      route.lifecycle = "rejected";
      this.releaseRouteCapacity(route);
    } else if (envelope.type === "task.progress") {
      if (route.lifecycle !== "accepted") return "invalid";
    } else if (envelope.type === "task.completed") {
      if (route.lifecycle !== "accepted") return "invalid";
      route.lifecycle = "completed";
      this.releaseRouteCapacity(route);
    } else {
      return "invalid";
    }
    route.events.set(sequence, digest);
    route.nextEventSeq = sequence + 1;
    return "accepted";
  }

  /** Only forward executor errors that are exactly correlated to a route. */
  private routeCorrelatedError(peer: BrokerPeer, envelope: Envelope<"error">): boolean {
    const messageId = envelope.in_reply_to;
    const route = messageId ? this.pendingTasks.get(this.routesBySubmitMessageId.get(messageId) ?? "") : undefined;
    if (
      !route ||
      (route.lifecycle !== "submitted" && route.lifecycle !== "accepted") ||
      !this.isExactRoutePeer(route.executor, peer) ||
      envelope.target.agent_id !== route.owner.agentId ||
      (envelope.target.instance_id !== undefined && envelope.target.instance_id !== route.owner.instanceId)
    ) {
      this.sendError(peer, "PMX.TASK.FORGED_ERROR", "Error is not authorized for a live task route", "task", envelope.message_id);
      return false;
    }
    const owner = this.lookupRegisteredInstance(route.owner.agentId, route.owner.instanceId);
    if (!owner || owner.sessionId !== route.owner.sessionId) {
      this.sendError(peer, "TARGET_UNAVAILABLE", "Task owner is no longer connected", "routing", envelope.message_id, {
        task_id: route.taskId,
        target: route.owner.agentId,
      }, true);
      return false;
    }
    return this.forwardEnvelope(peer, owner.transport!, envelope);
  }

  /** Insert a semantic message-id fingerprint before any forwarding side effect. */
  private admitReplayEnvelope(
    peer: BrokerPeer,
    envelope: Envelope,
    semanticDigest: string = envelopeSemanticDigest(envelope),
  ): "new" | "duplicate" | "conflict" | "overloaded" {
    this.pruneRouteAndReplayState();
    const key = this.replayLedgerKey(peer, envelope.message_id);
    const prior = this.replayLedger.get(key);
    if (prior) return prior.semanticDigest === semanticDigest ? "duplicate" : "conflict";
    if (this.replayLedger.size >= this.maxReplayLedgerEntries) return "overloaded";
    const deadline = envelope.delivery.deadline ? Date.parse(envelope.delivery.deadline) : Number.NaN;
    this.replayLedger.set(key, {
      semanticDigest,
      expiresAt: Math.max(this.now(), Number.isFinite(deadline) ? deadline : this.now()) + this.replayRetentionMs,
    });
    return "new";
  }

  private replayLedgerKey(peer: BrokerPeer, messageId: string): string {
    // Stable enrolled keys survive instance restarts; the legacy loopback
    // fallback remains scoped to the authenticated session identity.
    const securePrincipal = peer.verifiedPrincipal?.principal_id;
    return securePrincipal
      ? `${securePrincipal}\0${messageId}`
      : `${peer.agentId ?? ""}\0${peer.instanceId ?? ""}\0${messageId}`;
  }

  private pruneRouteAndReplayState(now = this.now()): void {
    for (const route of [...this.pendingTasks.values()]) {
      const deadline = route.deadline ? Date.parse(route.deadline) : Number.NaN;
      if ((route.lifecycle === "submitted" || route.lifecycle === "accepted") && Number.isFinite(deadline) && deadline <= now) {
        route.lifecycle = "closed";
        this.releaseRouteCapacity(route);
      }
      if (route.retainedUntil <= now) this.deleteRoute(route);
    }
    for (const [key, record] of this.replayLedger) {
      if (record.expiresAt <= now) this.replayLedger.delete(key);
    }
  }

  private taskImmutableFingerprint(envelope: Envelope, contract: CapabilityContractTuple): string {
    return canonicalize({
      method: (envelope.params as JsonRecord).method as never,
      capability_version: contract.capability_version,
      capability_contract_digest: contract.capability_contract_digest,
      params: (envelope.params as JsonRecord).params as never,
      deadline: (envelope.params as JsonRecord).deadline as never,
    } as never);
  }

  /** Pure durable-ingress selection: it reports rather than emits wire errors. */
  private selectDurableTarget(envelope: Envelope, requiredProfile?: WireProfile): RegistryEntry<BrokerPeer, AgentCard> {
    if (!this.multiInstanceRouting || !this.meshId) {
      throw new ProtocolError("DURABLE_STORAGE_DISABLED", "Durable target selection requires v0.2 multi-instance routing", "internal");
    }
    const params = envelope.params as JsonRecord;
    const routingKey = taskIdOf(envelope) ?? `${envelope.source.instance_id}\0${envelope.delivery.idempotency_key}`;
    // A v0.2 envelope can only be delivered to a v0.2 session. Falling back
    // to a legacy peer would be an invisible protocol downgrade.
    const candidates = requiredProfile === "v2"
      ? [...this.routingInstances.values()].filter((instance) => instance.peer.profile === "v2")
      : [...this.routingInstances.values()];
    const selection = selectWeightedRendezvous(candidates, {
      meshId: this.meshId,
      targetAgentId: envelope.target.agent_id,
      targetInstanceId: envelope.target.instance_id,
      routingKey,
      now: this.now(),
      ...(envelope.type === "task.submit" && typeof params.method === "string"
        ? { requiredCapability: params.method }
        : {}),
    });
    if (!selection.ok) {
      throw new ProtocolError(
        selection.code,
        selection.code === "IDENTITY_COLLISION"
          ? "Target logical agent has conflicting principal bindings"
          : selection.code === "TARGET_UNAVAILABLE"
            ? "Target instance is unavailable"
            : "No live agent has that id",
        "routing",
        selection.retryable,
      );
    }
    return this.asRegistryEntry(selection.selected);
  }

  private lookupTarget(peer: BrokerPeer, envelope: Envelope): RegistryEntry<BrokerPeer, AgentCard> | undefined {
    if (this.multiInstanceRouting && this.meshId) {
      const params = envelope.params as JsonRecord;
      const routingKey = taskIdOf(envelope) ?? `${envelope.source.instance_id}\0${envelope.delivery.idempotency_key}`;
      const selection = selectWeightedRendezvous([...this.routingInstances.values()], {
        meshId: this.meshId,
        targetAgentId: envelope.target.agent_id,
        targetInstanceId: envelope.target.instance_id,
        routingKey,
        now: this.now(),
        ...(envelope.type === "task.submit" && typeof params.method === "string"
          ? { requiredCapability: params.method }
          : {}),
      });
      if (!selection.ok) {
        const unavailable = selection.code === "TARGET_UNAVAILABLE";
        this.sendError(
          peer,
          selection.code,
          selection.code === "IDENTITY_COLLISION"
            ? "Target logical agent has conflicting principal bindings"
            : unavailable
              ? "Target instance is unavailable"
              : "No live agent has that id",
          "routing",
          envelope.message_id,
          {
            target: envelope.target.agent_id,
            instance_id: envelope.target.instance_id ?? null,
            ...(selection.reason === undefined ? {} : { reason: selection.reason }),
          },
          selection.retryable,
        );
        return undefined;
      }
      return this.asRegistryEntry(selection.selected);
    }
    const target = this.registry.lookup(envelope.target.agent_id, envelope.target.instance_id);
    if (!target) {
      const agentExists = this.registry.lookup(envelope.target.agent_id);
      this.sendError(
        peer,
        agentExists ? "TARGET_UNAVAILABLE" : "UNKNOWN_TARGET",
        agentExists ? "Target instance is unavailable" : "No live agent has that id",
        "routing",
        envelope.message_id,
        { target: envelope.target.agent_id, instance_id: envelope.target.instance_id ?? null },
        true,
      );
      return undefined;
    }
    return target;
  }

  private sendPong(peer: BrokerPeer, ping: Envelope): void {
    const n = (ping.params as JsonRecord).n;
    const pong = this.makeEnvelope("pong", peer, { n }, ping.message_id);
    this.sendEnvelope(peer, pong);
  }

  /**
   * A receipt is emitted only after the replay/admission path has recorded a
   * disposition. It is addressed back to the submitting session and never
   * enters the router, so it cannot create acknowledgement loops.
   */
  private sendReceipt(
    peer: BrokerPeer,
    received: Envelope,
    semanticDigest: string,
    disposition: ReceiptDisposition,
  ): void {
    if (peer.phase !== "active" || !peer.agentId || !peer.instanceId) return;
    this.sendEnvelope(peer, this.makeEnvelope("receipt", peer, {
      received_message_id: received.message_id,
      semantic_digest: semanticDigest,
      disposition,
    }, received.message_id));
  }

  /** Serve the three standard broker capabilities without pretending it is a routed peer. */
  private handleBrokerTask(peer: BrokerPeer, submit: Envelope<"task.submit">): void {
    const params = submit.params as JsonRecord;
    const taskId = typeof params.task_id === "string" ? params.task_id : undefined;
    const method = typeof params.method === "string" ? params.method : undefined;
    if (!taskId || !method) {
      this.sendError(peer, "MALFORMED_FRAME", "Broker task submission is malformed", "parse", submit.message_id);
      return;
    }
    const reject = (code: string, message: string) => {
      this.sendEnvelope(peer, this.makeEnvelope("task.rejected", peer, {
        task_id: taskId,
        event_seq: 1,
        code,
        message,
      }, submit.message_id));
    };
    if (Date.parse(String(params.deadline)) <= this.now()) {
      reject("PMX.TASK.DEADLINE_EXCEEDED", "Task deadline has already elapsed");
      return;
    }
    const capability = this.card.capabilities.find((entry) => entry.id === method);
    if (!capability) {
      reject("UNSUPPORTED_CAPABILITY", `Broker does not implement ${method}`);
      return;
    }
    const submittedContract = taskContractOf(submit);
    const advertisedContract = capabilityContractTuple(capability);
    if (!submittedContract || !sameCapabilityContract(submittedContract, advertisedContract)) {
      reject("CAPABILITY_CONTRACT_MISMATCH", "Task capability contract does not match the broker's advertised capability");
      return;
    }
    let result: JsonRecord | AgentCard | Array<Pick<AgentCard["capabilities"][number], "id" | "version">>;
    if (method === "org.polymesh.agent.ping") result = {};
    else if (method === "org.polymesh.agent.info") result = this.card;
    else if (method === "org.polymesh.capabilities.list") {
      result = this.card.capabilities.map(({ id, version }) => ({ id, version }));
    } else {
      reject("UNSUPPORTED_CAPABILITY", `Broker does not implement ${method}`);
      return;
    }
    this.sendEnvelope(peer, this.makeEnvelope("task.accepted", peer, {
      task_id: taskId,
      event_seq: 1,
      accepted_at: new Date(this.now()).toISOString(),
      ...advertisedContract,
    }, submit.message_id));
    this.sendEnvelope(peer, this.makeEnvelope("task.completed", peer, {
      task_id: taskId,
      event_seq: 2,
      ...advertisedContract,
      terminal: {
        outcome: "succeeded",
        result,
        completed_at: new Date(this.now()).toISOString(),
      },
    }));
  }

  private makeEnvelope(type: EnvelopeType, target: BrokerPeer, params: JsonRecord, inReplyTo?: string): Envelope {
    const targetAgent = target.agentId;
    const targetInstance = target.instanceId;
    if (!targetAgent || !targetInstance) throw new Error("Cannot send an envelope before peer identity is known");
    return {
      protocol: PROTOCOL_VERSION,
      type,
      message_id: uuidv7(),
      timestamp: new Date(this.now()).toISOString(),
      source: { agent_id: this.card.agent_id, instance_id: this.card.instance_id },
      target: { agent_id: targetAgent, instance_id: targetInstance },
      delivery: {
        mode: "at_least_once",
        idempotency_key: `${type}:${uuidv7()}`,
        deadline: new Date(this.now() + 60_000).toISOString(),
      },
      ...(inReplyTo ? { in_reply_to: inReplyTo } : {}),
      params,
    } as Envelope;
  }

  /** Construct an outbound record only for an already-selected v0.2 peer. */
  private makeV2Envelope(type: EnvelopeType, target: BrokerPeer, params: JsonRecord, inReplyTo?: string): V2Envelope {
    const targetAgent = target.agentId;
    const targetInstance = target.instanceId;
    if (!this.meshId || !targetAgent || !targetInstance) throw new Error("Cannot send a v0.2 envelope before mesh and peer identity are known");
    return {
      protocol: V2_PROTOCOL_VERSION,
      type,
      message_id: uuidv7(),
      timestamp: new Date(this.now()).toISOString(),
      source: { mesh_id: this.meshId, agent_id: this.card.agent_id, instance_id: this.card.instance_id },
      target: { mesh_id: this.meshId, agent_id: targetAgent, instance_id: targetInstance },
      delivery: {
        mode: "at_least_once",
        idempotency_key: `${type}:${uuidv7()}`,
        deadline: new Date(this.now() + 60_000).toISOString(),
      },
      ...(inReplyTo ? { in_reply_to: inReplyTo } : {}),
      params: params as JsonObject,
    } as V2Envelope;
  }

  private sendError(
    peer: BrokerPeer,
    code: string,
    message: string,
    category: string,
    inReplyTo?: string,
    details: JsonRecord = {},
    retryable = false,
    retryAfterMs: number | null = null,
  ): void {
    if (peer.phase !== "active" || !peer.agentId || !peer.instanceId) {
      this.failHandshake(peer, code, message, category);
      return;
    }
    const params = {
      category,
      code,
      message,
      retryable,
      retry_after_ms: retryAfterMs,
      details,
    };
    if (peer.profile === "v2") {
      this.sendV2Envelope(peer, this.makeV2Envelope("error", peer, params, inReplyTo));
    } else {
      this.sendEnvelope(peer, this.makeEnvelope("error", peer, params, inReplyTo));
    }
  }

  /**
   * Forward a record after adding a target-session-bound broker attestation in
   * the enrolled WSS profile.  The legacy explicit-loopback development
   * profile intentionally preserves its existing transport-only behaviour.
   */
  private forwardEnvelope(source: BrokerPeer, target: BrokerPeer, envelope: Envelope): boolean {
    const profile = this.identityProfile;
    if (!profile || !requiresRoutedProvenance(envelope.type)) return this.sendEnvelope(target, envelope);
    if (!source.verifiedPrincipal || !source.sessionId || !target.sessionId ||
      !source.agentId || !source.instanceId || !target.agentId || !target.instanceId ||
      source.verifiedPrincipal.agent_id !== source.agentId ||
      envelope.source.agent_id !== source.agentId || envelope.source.instance_id !== source.instanceId ||
      envelope.target.agent_id !== target.agentId ||
      (envelope.target.instance_id !== undefined && envelope.target.instance_id !== target.instanceId)) {
      this.sendError(source, "AUTHENTICATION_FAILED", "Secure routed provenance cannot be established", "identity", envelope.message_id);
      return false;
    }
    const now = this.now();
    const deadline = Date.parse(envelope.delivery.deadline ?? "");
    const expiresAt = Math.min(now + MAX_ROUTED_PROVENANCE_LIFETIME_MS, deadline);
    if (!Number.isFinite(expiresAt) || expiresAt <= now) {
      this.sendError(source, "PMX.TASK.DEADLINE_EXCEEDED", "Routed provenance expired before forwarding", "task", envelope.message_id);
      return false;
    }
    try {
      const provenance = createRoutedProvenance({
        envelope,
        broker: {
          agent_id: this.card.agent_id,
          instance_id: this.card.instance_id,
          key_id: profile.localPrincipal.key_id,
        },
        sourcePrincipal: source.verifiedPrincipal,
        sourceSessionId: source.sessionId,
        targetSessionId: target.sessionId,
        issuedAt: new Date(now).toISOString(),
        expiresAt: new Date(expiresAt).toISOString(),
        privateKey: profile.privateKey,
      });
      return this.sendEnvelope(target, { ...envelope, provenance });
    } catch {
      this.sendError(source, "AUTHENTICATION_FAILED", "Secure routed provenance could not be signed", "identity", envelope.message_id);
      return false;
    }
  }

  private sendEnvelope(peer: BrokerPeer, envelope: Envelope): boolean {
    return this.sendRaw(peer, envelope);
  }

  /**
   * Compress only independently routable v0.2 envelopes after an explicit
   * zstd selection. Auth, READY, delivery receipts, and compression control
   * records always use sendRaw, so no security/control record is recursive or
   * dependent on an implicit compression stream.
   */
  private sendV2Envelope(peer: BrokerPeer, envelope: V2Envelope): boolean {
    const negotiation = peer.compression;
    if (negotiation?.algorithm !== "zstd" || !negotiation.limits || !compressionAllowedForRecord(envelope.type)) {
      return this.sendRaw(peer, envelope);
    }
    const codec = runtimeZstdCodec();
    if (!codec) return this.sendRaw(peer, envelope);
    let uncompressed: Buffer;
    try {
      uncompressed = Buffer.from(JSON.stringify(envelope), "utf8");
    } catch {
      return false;
    }
    if (uncompressed.byteLength === 0 || uncompressed.byteLength > negotiation.limits.maxUncompressedBytes) {
      // A selected codec is per-record optional. A bounded raw record remains
      // valid and is safer than emitting a wrapper that violates its own
      // negotiated declaration.
      return this.sendRaw(peer, envelope);
    }
    try {
      const compressed = codec.compress(uncompressed);
      const frame: V2CompressionFrame = {
        type: "compression.frame",
        v: V2_HANDSHAKE_VERSION,
        algorithm: "zstd",
        record_type: envelope.type,
        compressed_bytes: compressed.byteLength,
        uncompressed_bytes: uncompressed.byteLength,
        payload: compressed.toString("base64url"),
      };
      // A ratio/size check protects outbound interoperability too. Prefer a
      // normal envelope when the record gains size from compression or its
      // base64 wrapper would exceed the wire maximum.
      const frameValidation = validateV2CompressionFrame(frame, { ready: true, negotiation });
      const wrapperBytes = Buffer.byteLength(JSON.stringify(frame), "utf8");
      if (!frameValidation.ok || compressed.byteLength >= uncompressed.byteLength || wrapperBytes > this.maxFrameBytes) {
        return this.sendRaw(peer, envelope);
      }
      return this.sendRaw(peer, frame);
    } catch {
      // Codec failures are local transport failures, not a reason to fail an
      // already durable record. The uncompressed profile remains available.
      return this.sendRaw(peer, envelope);
    }
  }

  private sendRaw(peer: BrokerPeer, value: unknown): boolean {
    if (peer.phase === "closed" || !websocketStateOpen(peer.transport)) return false;
    try {
      const serialized = JSON.stringify(value);
      if (Buffer.byteLength(serialized, "utf8") > this.maxFrameBytes) {
        this.closePeer(peer, "outbound frame exceeds maximum size");
        return false;
      }
      peer.transport.send(serialized);
      return true;
    } catch (error) {
      this.closePeer(peer, error);
      return false;
    }
  }

  private failHandshakeOrError(peer: BrokerPeer, code: string, message: string, category: string): void {
    if (peer.phase === "active") this.sendError(peer, code, message, category);
    else this.failHandshake(peer, code, message, category);
  }

  private failHandshake(peer: BrokerPeer, code: string, message: string, category: string): void {
    if (peer.phase === "closed") return;
    this.sendRaw(peer, {
      type: "error",
      params: { category, code, message, retryable: false, retry_after_ms: null, details: {} },
    });
    this.closePeer(peer, `${code}: ${message}`);
  }

  private closePeer(peer: BrokerPeer, reason?: unknown, closeTransport = true): void {
    if (peer.phase === "closed") return;
    const wasActive = peer.phase === "active";
    peer.phase = "closed";
    this.clearHandshakeTimer(peer);
    this.peers.delete(peer);
    if (peer.profile === "native-v2") {
      this.removeNativeV2Peer(peer);
    } else if (this.multiInstanceRouting) {
      this.removeRoutingInstance(peer);
    } else if (peer.agentId) {
      this.registry.remove(peer.agentId, { sessionId: peer.sessionId, transport: peer });
    }

    // A disconnected participant cannot safely commit a further transition on
    // its pinned route. Retain the tombstone, release active capacity, and do
    // not silently rebind it to a later session with the same claimed ID.
    if (wasActive && peer.agentId && peer.instanceId) {
      for (const route of [...this.pendingTasks.values()]) {
        const executorDisconnected = this.isExactRoutePeer(route.executor, peer);
        const ownerDisconnected = this.isExactRoutePeer(route.owner, peer);
        if ((route.lifecycle === "submitted" || route.lifecycle === "accepted") && (executorDisconnected || ownerDisconnected)) {
          route.lifecycle = "closed";
          this.releaseRouteCapacity(route);
        }
        if (executorDisconnected) {
          const owner = this.lookupRegisteredInstance(route.owner.agentId, route.owner.instanceId);
          if (owner && owner.sessionId === route.owner.sessionId) {
            this.sendError(
              owner.transport!,
              this.executorUnavailableCode(),
              this.multiInstanceRouting
                ? "Pinned task executor disconnected before a terminal result"
                : "Task executor disconnected before a terminal result",
              "routing",
              route.submitMessageId,
              { task_id: route.taskId, target: peer.agentId },
              true,
            );
          }
        }
      }
    }
    if (wasActive) this.options.onPeerDisconnected?.(peer, reason);

    if (closeTransport) {
      try {
        if (typeof peer.transport.close === "function") peer.transport.close(1000, "PolyMesh connection closed");
        else peer.transport.terminate?.();
      } catch {
        // Transport teardown is best effort and is intentionally idempotent.
      }
    }
  }

  /** v0.1 keeps its established availability error; v0.2 exposes pinning. */
  private executorUnavailableCode(): "TARGET_UNAVAILABLE" | "PMX.ROUTING.PINNED_INSTANCE_UNAVAILABLE" {
    return this.multiInstanceRouting ? "PMX.ROUTING.PINNED_INSTANCE_UNAVAILABLE" : "TARGET_UNAVAILABLE";
  }

  private executorUnavailableMessage(): string {
    return this.multiInstanceRouting ? "Pinned task executor is unavailable" : "Task executor is unavailable";
  }

  private clearHandshakeTimer(peer: BrokerPeer): void {
    const timer = this.handshakeTimers.get(peer);
    if (timer) clearTimeout(timer);
    this.handshakeTimers.delete(peer);
  }

  private pendingHandshakeCount(): number {
    let count = this.pendingUpgradeReservations;
    for (const peer of this.peers) {
      if (peer.phase === "await_hello" || peer.phase === "await_card" || peer.phase === "await_auth" || peer.phase === "await_ready") count += 1;
    }
    return count;
  }

  /** Check capacity before creating a connection/session object. */
  private canAdmitPeer(): boolean {
    return this.peers.size < this.maxOpenSessions && this.pendingHandshakeCount() < this.maxPendingHandshakes;
  }

  /** Reserve capacity at the HTTP layer before WebSocket allocation. */
  private reserveUpgradeAdmission(): boolean {
    if (this.peers.size + this.pendingUpgradeReservations >= this.maxOpenSessions) return false;
    if (this.pendingHandshakeCount() >= this.maxPendingHandshakes) return false;
    this.pendingUpgradeReservations += 1;
    return true;
  }

  private releaseUpgradeReservation(): void {
    if (this.pendingUpgradeReservations > 0) this.pendingUpgradeReservations -= 1;
  }

  /** Reject pre-handshake input without adding it to the peer/session set. */
  private rejectAttachment(
    transport: BrokerTransport,
    code: string,
    message: string,
    category: string,
    retryable = false,
  ): BrokerPeer {
    const peer: BrokerPeer = {
      transport,
      phase: "closed",
      authenticated: false,
      // Keep even rejected transports distinguishable for the short period
      // in which diagnostics or admission metrics inspect the peer object.
      // Quota keys must never collapse every rejected socket into one bucket.
      connectionId: uuidv7(this.now()),
      connectedAt: this.now(),
    };
    try {
      transport.send(JSON.stringify({
        type: "error",
        params: { category, code, message, retryable, retry_after_ms: retryable ? 1_000 : null, details: {} },
      }));
    } catch {
      // The rejected transport may already have disappeared.
    }
    try {
      transport.close?.(retryable ? 1013 : 1008, retryable ? "overloaded" : "authentication failed");
    } catch {
      transport.terminate?.();
    }
    return peer;
  }

  private assertSecureListenerConfiguration(): void {
    if (this.options.tls && !this.identityProfile) {
      throw new ProtocolError(
        "AUTHENTICATION_FAILED",
        "TLS listeners require an enrolled Ed25519 identity profile",
        "identity",
      );
    }
    if (!this.options.tls && !this.tokenAuthority) {
      throw new ProtocolError(
        "AUTHENTICATION_FAILED",
        "A 32-byte loopback runtime token is required before starting a listener",
        "identity",
      );
    }
    if (!this.options.tls && (!this.options.allowInsecureLoopbackDevelopment || !isNumericLoopbackHost(this.host))) {
      throw new ProtocolError(
        "INSECURE_TRANSPORT_DISABLED",
        "Plain WebSocket is restricted to an explicitly enabled numeric-loopback development listener",
        "protocol",
      );
    }
  }

  private rejectUpgrade(
    socket: Duplex,
    status: number,
    statusText: string,
    headers: Record<string, string> = {},
  ): void {
    if (socket.destroyed) return;
    const lines = [`HTTP/1.1 ${status} ${statusText}`, "Connection: close", "Content-Length: 0"];
    for (const [name, value] of Object.entries(headers)) lines.push(`${name}: ${value}`);
    try {
      socket.write(`${lines.join("\r\n")}\r\n\r\n`);
    } finally {
      socket.destroy();
    }
  }
}

function isNumericLoopbackHost(host: string): boolean {
  if (host === "::1") return true;
  if (isIP(host) !== 4) return false;
  return Number(host.split(".", 1)[0]) === 127;
}

export default Broker;

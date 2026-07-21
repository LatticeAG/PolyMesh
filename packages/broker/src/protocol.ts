/**
 * Protocol primitives shared by the broker and clients.
 *
 * The reference implementation deliberately keeps these helpers dependency-free
 * (apart from Node's crypto module) so the wire format remains easy to audit.
 */
import {
  KeyObject,
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign as ed25519Sign,
  verify as ed25519Verify,
} from "node:crypto";
import { TextDecoder } from "node:util";

export const PROTOCOL_VERSION = "polymesh.0.1" as const;
export const HANDSHAKE_VERSION = "0.1" as const;
export const CARD_VERSION = "1.0" as const;
/**
 * PolyMesh 0.2 is a separate selected wire profile.  These constants live
 * alongside the legacy values so callers can make the profile choice before
 * they begin a handshake; v0.2 fields must never be interpreted as optional
 * extensions of a v0.1 session.
 */
export const V2_PROTOCOL_VERSION = "polymesh.0.2" as const;
export const V2_HANDSHAKE_VERSION = "0.2" as const;
export const V2_CARD_VERSION = "2.0" as const;
export const V2_SUBPROTOCOL = V2_PROTOCOL_VERSION;
/** A v0.2 SID is the unpadded base64url encoding of 32 SHA-256 bytes. */
export const V2_SID_BYTES = 32;
export const V2_SID_LENGTH = 43;
export const V2_SID_PATTERN = "^[A-Za-z0-9_-]{43}$";
export const V2_SID_DOMAIN = "PMX-SID/0.2\0" as const;
export const V2_HANDSHAKE_TRANSCRIPT_DOMAIN = "PMX-HANDSHAKE/0.2\0" as const;
export const V2_AUTH_PAIR_DOMAIN = "PMX-AUTH-PAIR/0.2\0" as const;
export const V2_CARD_DIGEST_DOMAIN = "PMX-CARD-DIGEST/0.2\0" as const;
export const V2_SEMANTIC_DIGEST_DOMAIN = "PMX-SEMANTIC/0.2\0" as const;
/** Canonical uppercase Crockford-base32 mesh identifier grammar. */
export const V2_MESH_ID_PATTERN = "^msh_[0-9A-HJKMNP-TV-Z]{26}$";
export const V2_RECORD_DIGEST_PATTERN = V2_SID_PATTERN;
/**
 * These are declarations rather than a fallback mechanism.  A transport
 * selects exactly one profile before any record is accepted.
 */
export const PROTOCOL_PROFILE_SELECTIONS = Object.freeze({
  v0_1: Object.freeze({
    protocol: PROTOCOL_VERSION,
    handshake_version: HANDSHAKE_VERSION,
    card_version: CARD_VERSION,
  }),
  v0_2: Object.freeze({
    protocol: V2_PROTOCOL_VERSION,
    handshake_version: V2_HANDSHAKE_VERSION,
    card_version: V2_CARD_VERSION,
  }),
});
export const MAX_FRAME_BYTES = 1_048_576;
/**
 * The only cryptographic identity profile implemented by the reference
 * secure transport.  It is deliberately an explicit profile instead of a
 * best-effort addition to the legacy loopback handshake: silently falling
 * back would turn a missing proof into an identity downgrade.
 */
export const SECURE_IDENTITY_PROFILE = "enrolled-ed25519-tls-1.3" as const;
export const IDENTITY_ALGORITHM = "Ed25519" as const;
export const ED25519_PUBLIC_KEY_BYTES = 32;
export const ED25519_SIGNATURE_BYTES = 64;
/**
 * A broker attestation is added only while forwarding a routed application
 * record in the enrolled WSS profile.  It is deliberately an envelope
 * attachment (rather than a claimed source field) so a target can bind a
 * routed claim to the broker it authenticated during its own session.
 */
export const ROUTED_PROVENANCE_VERSION = "pmx.broker-provenance/1" as const;
export const MAX_ROUTED_PROVENANCE_LIFETIME_MS = 60_000;
/**
 * Parsing limits apply before application objects are constructed.  A frame
 * size limit alone does not protect a process from a deeply nested or highly
 * branched JSON value.
 */
export const MAX_JSON_DEPTH = 32;
export const MAX_JSON_NODES = 10_000;
export const MAX_JSON_OBJECT_MEMBERS = 1_024;
export const MAX_JSON_ARRAY_ITEMS = 4_096;
export const MAX_JSON_STRING_BYTES = 65_536;
export const MAX_CARD_BYTES = 64 * 1_024;
export const MAX_PUBLIC_CARD_BYTES = 8 * 1_024;
export const MAX_CAPABILITIES_PER_CARD = 64;
export const MAX_ENDPOINTS_PER_CARD = 8;
export const MAX_SCHEMA_BYTES_PER_CAPABILITY = 16 * 1_024;
export const MAX_IDEMPOTENCY_KEY_BYTES = 256;

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
  "receipt",
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

/** The broker identity named by a signed routed-provenance attestation. */
export interface RoutedProvenanceBroker {
  agent_id: string;
  instance_id: string;
  key_id: string;
}

/** The enrolled source principal that the broker observed on ingress. */
export interface RoutedProvenancePrincipal {
  principal_id: string;
  agent_id: string;
  key_id: string;
}

/**
 * Broker-signed provenance for a routed record.  `source_session_id` binds
 * the source-side ingress session; `target_session_id` binds delivery to the
 * recipient's current broker session and prevents cross-session replay.
 */
export interface RoutedProvenance {
  version: typeof ROUTED_PROVENANCE_VERSION;
  broker: RoutedProvenanceBroker;
  source_principal: RoutedProvenancePrincipal;
  source: AgentIdentity;
  target: AgentRef;
  source_session_id: string;
  target_session_id: string;
  envelope_digest: string;
  issued_at: string;
  expires_at: string;
  signature: string;
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
  /** Present only on broker-forwarded secure-profile records. */
  provenance?: RoutedProvenance;
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

/**
 * The immutable identifier a task owner pins from an advertised capability.
 *
 * `capability_id` intentionally appears in replies even though a submission
 * calls it `method`: accepting an arbitrary version/digest without restating
 * the capability name would leave a type-confusion gap in lifecycle records.
 */
export interface CapabilityContractTuple extends JsonObject {
  capability_id: string;
  capability_version: string;
  capability_contract_digest: string;
}

export interface Limits {
  max_task_timeout_ms?: number;
  max_tasks_per_principal?: number;
  max_input_bytes?: number;
  max_result_bytes?: number;
}

/** A self-contained public half of an enrolled Ed25519 identity. */
export interface CardIdentity {
  alg: typeof IDENTITY_ALGORITHM;
  /** base64url(SHA-256(public_key_raw_bytes)). */
  key_id: string;
  /** Unpadded base64url encoding of exactly 32 Ed25519 public-key bytes. */
  public_key: string;
}

/**
 * Enrollment is a local trust decision, not data learned from a Card.  The
 * key is deliberately stored alongside the claimed agent ID so a holder of a
 * generic token cannot choose a privileged agent name during hello.
 */
export interface Enrollment {
  agent_id: string;
  key_id: string;
  public_key: string;
  enabled?: boolean;
  expires_at?: string;
}

export interface VerifiedPrincipal {
  principal_id: string;
  agent_id: string;
  key_id: string;
  public_key: string;
  auth_strength: "enrolled-key";
}

/** Inputs required to create a broker-signed routed provenance attachment. */
export interface CreateRoutedProvenanceOptions {
  envelope: Envelope;
  broker: RoutedProvenanceBroker;
  sourcePrincipal: VerifiedPrincipal;
  sourceSessionId: string;
  targetSessionId: string;
  expiresAt: string;
  privateKey: Ed25519PrivateKey;
  issuedAt?: string;
}

/** Trusted context required when a recipient verifies routed provenance. */
export interface VerifyRoutedProvenanceOptions {
  /** Principal established by the recipient's card/enrollment/auth handshake. */
  brokerPrincipal: VerifiedPrincipal;
  /** The same broker identity asserted in that authenticated handshake. */
  brokerIdentity: AgentIdentity;
  /** Current recipient-to-broker session identifier. */
  targetSessionId: string;
  now?: number;
}

/** Accepted Node key inputs for the Ed25519 signing helpers. */
export type Ed25519PrivateKey = KeyObject | string | Buffer;

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
  /** Required by the enrolled-key secure transport profile. */
  identity?: CardIdentity;
  /** Ed25519 signature over the canonical card excluding this field. */
  signature?: string;
}

/** The profile choice is made before a session begins and remains immutable. */
export type ProtocolProfileVersion = typeof PROTOCOL_VERSION | typeof V2_PROTOCOL_VERSION;
export type ProtocolHandshakeVersion = typeof HANDSHAKE_VERSION | typeof V2_HANDSHAKE_VERSION;
export type ProtocolCardVersion = typeof CARD_VERSION | typeof V2_CARD_VERSION;
export type ProtocolProfileSelection =
  | typeof PROTOCOL_PROFILE_SELECTIONS.v0_1
  | typeof PROTOCOL_PROFILE_SELECTIONS.v0_2;

/**
 * v0.2 declarations intentionally do not extend the v0.1 record interfaces.
 * The two profiles have different required fields and therefore must be
 * selected, not structurally merged.
 */
export type V2MeshId = string;
export type V2SessionId = string;
export type V2Digest = string;
export type V2Nonce = string;
export type V2HandshakeRole = "initiator" | "responder";
export type V2TransportProfile =
  | "local-unix/1"
  | "loopback-wss/1"
  | "enrolled-wss/1"
  | "remote-relay/1"
  | "deckagent-carrier/1";
export type V2Extension = "compression/zstd";
export type V2AuthenticationMethod =
  | "local-unix"
  | "mtls-enrolled"
  | "oauth-dpop"
  | "oauth-mtls"
  | "deckagent-bound";

/**
 * The compact native-v2 SDK profile records published in `schemas/v2/`.
 *
 * These names are deliberately additive.  The longer-lived v0.2 relay
 * declarations below (`V2HelloFrame`, `V2AgentCard`, and friends) retain
 * their existing wire contracts; a new SDK client explicitly selects this
 * profile with a `v2.init` record instead of structurally merging it into a
 * legacy hello frame.
 */
export const V2_PROFILE = V2_PROTOCOL_VERSION;
export const V2_SUPPORTED_PROFILES = [V2_PROTOCOL_VERSION] as const;
export type V2Profile = (typeof V2_SUPPORTED_PROFILES)[number];

/** A native-v2 mesh identifier is a broker-generated UUIDv7. */
export type V2NativeMeshId = string;
export type V2NativeSessionId = string;
export type V2NativeNonce = string;

export const V2_COMPRESSION_ALGORITHMS = ["zstd", "none"] as const;
export type V2CompressionAlgorithm = (typeof V2_COMPRESSION_ALGORITHMS)[number];

/** Closed native-v2 error vocabulary shared by the schema bundle and SDKs. */
export const V2_ERROR_CODES = [
  "PMX.SESSION.AUTH",
  "PMX.SESSION.PROFILE",
  "PMX.SESSION.TRANSPORT",
  "PMX.SESSION.HANDSHAKE",
  "PMX.SESSION.CLOSED",
  "PMX.TASK.DEADLINE_EXCEEDED",
  "PMX.TASK.EVENT_CONFLICT",
  "PMX.TASK.NOT_FOUND",
  "PMX.TASK.REJECTED",
  "PMX.TASK.CANCELLED",
  "PMX.PROTOCOL.COMPRESSION",
  "PMX.PROTOCOL.MALFORMED_FRAME",
  "PMX.PROTOCOL.VERSION",
  "PMX.PROTOCOL.ENVELOPE",
  "PMX.ROUTING.MESH_MISMATCH",
  "PMX.ROUTING.TARGET_UNAVAILABLE",
  "PMX.ROUTING.FENCE",
  "PMX.DELIVERY.DUPLICATE",
  "PMX.DELIVERY.IDEMPOTENCY_CONFLICT",
  "PMX.DELIVERY.CURSOR_EXPIRED",
  "PMX.INTERNAL",
] as const;
export type V2ErrorCode = (typeof V2_ERROR_CODES)[number];

/** Stable locations of the native-v2 JSON Schema bundle. */
export const V2_NATIVE_SCHEMA_IDS = Object.freeze({
  common: "https://schemas.polymesh.dev/v2/common.json",
  envelope: "https://schemas.polymesh.dev/v2/envelope-v2.json",
  handshake: "https://schemas.polymesh.dev/v2/handshake-v2.json",
  card: "https://schemas.polymesh.dev/v2/card-v2.json",
});

/** Agent addresses in native-v2 envelopes inherit mesh scope from the envelope. */
export interface V2NativeAgentRef {
  agent_id: string;
  instance_id?: string;
}

export interface V2NativeAgentIdentity extends V2NativeAgentRef {
  instance_id: string;
}

/** `delivery_id` belongs to the nested delivery structure, never the envelope root. */
export interface V2NativeDelivery {
  delivery_id: string;
  mode: "at_least_once";
  idempotency_key: string;
  deadline: string;
}

export const V2_NATIVE_ENVELOPE_TYPES = [
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
  "receipt",
  "error",
] as const;
export type V2NativeEnvelopeType = (typeof V2_NATIVE_ENVELOPE_TYPES)[number];

/** Native-v2 task submission params use capability/input, not v0.1 method/params. */
export type V2NativeTaskSubmitParams = JsonObject & {
  task_id: string;
  capability: string;
  input: JsonValue;
  deadline: string;
  capability_version?: string;
  capability_contract_digest?: string;
};

/** A mesh-scoped native-v2 application envelope. */
export interface V2NativeEnvelope<
  T extends V2NativeEnvelopeType = V2NativeEnvelopeType,
  P extends JsonObject = JsonObject,
> {
  protocol: V2Profile;
  profile: V2Profile;
  mesh_id: V2NativeMeshId;
  type: T;
  message_id: string;
  timestamp: string;
  source: V2NativeAgentIdentity;
  target: V2NativeAgentRef;
  delivery: V2NativeDelivery;
  in_reply_to?: string;
  params: P;
}

/** Client profile proposal. `mesh_id` is optional until the broker selects one. */
export interface V2InitFrame {
  type: "v2.init";
  /** Accepted for explicitness but not required on the compact handshake. */
  protocol?: V2Profile;
  profile: V2Profile;
  supported_profiles?: readonly V2Profile[];
  mesh_id?: V2NativeMeshId;
  agent_id: string;
  instance_id: string;
  nonce: V2NativeNonce;
  compression?: readonly V2CompressionAlgorithm[];
}

/** Broker profile selection and session establishment response. */
export interface V2AckFrame {
  type: "v2.ack";
  /** Accepted for explicitness but not required on the compact handshake. */
  protocol?: V2Profile;
  profile: V2Profile;
  mesh_id: V2NativeMeshId;
  session_id: V2NativeSessionId;
  agent_id?: string;
  instance_id?: string;
  compression: V2CompressionAlgorithm;
}

/** Bounded handshake failure that can be emitted before a session exists. */
export interface V2ErrorFrame {
  type: "v2.error";
  /** Accepted for explicitness but not required on the compact handshake. */
  protocol?: V2Profile;
  profile: V2Profile;
  mesh_id?: V2NativeMeshId;
  session_id?: V2NativeSessionId;
  code: V2ErrorCode;
  message: string;
  retryable?: boolean;
}

export type V2NativeHandshakeRecord = V2InitFrame | V2AckFrame | V2ErrorFrame;
/** Aliases make the profile-specific names clear at SDK call sites. */
export type V2ProfileInitFrame = V2InitFrame;
export type V2ProfileAckFrame = V2AckFrame;
export type V2ProfileErrorFrame = V2ErrorFrame;
export type V2ProfileHandshakeRecord = V2NativeHandshakeRecord;

/** A native-v2 card advertises its primary and supported protocol profiles. */
export interface V2NativeCapability {
  id: string;
  version: string;
  description?: string;
  input_schema?: JsonObject;
  result_schema?: JsonObject;
  contract_digest?: string;
}

export interface V2NativeAgentCard {
  card_version: typeof V2_CARD_VERSION;
  profile: V2Profile;
  profiles: readonly V2Profile[];
  mesh_id: V2NativeMeshId;
  agent_id: string;
  instance_id: string;
  display_name?: string;
  issued_at: string;
  expires_at: string;
  revision: number;
  capabilities: readonly V2NativeCapability[];
  metadata?: JsonObject;
  signature?: string;
}

/** Limits a peer is willing to receive; they are not send authorization. */
export interface V2ReceiveLimits {
  max_wire_bytes: number;
  max_json_bytes: number;
  max_uncompressed_bytes: number;
  max_expansion_ratio: number;
}

/** v0.2 addresses carry authenticated mesh scope at the wire boundary. */
export interface V2AgentRef {
  /** Required remotely; only a selected single-mesh local profile may omit it. */
  mesh_id?: V2MeshId;
  agent_id: string;
  instance_id?: string;
}

export interface V2AgentIdentity extends V2AgentRef {
  instance_id: string;
}

/** The immutable v0.2 delivery fields carried by an application envelope. */
export interface V2Delivery {
  delivery_id: string;
  mode: "at_least_once";
  idempotency_key: string;
  deadline: string;
}

export const V2_APPLICATION_MESSAGE_TYPES = [
  "task.submit",
  "task.accepted",
  "task.rejected",
  "task.progress",
  "task.completed",
  "task.cancel",
  "task.status",
  "error",
] as const;

export type V2ApplicationMessageType = (typeof V2_APPLICATION_MESSAGE_TYPES)[number];

/**
 * The base v0.2 application-envelope shape.  Type-specific `params` remain
 * deliberately separate from transport-control records.
 */
export interface V2ApplicationEnvelope<
  T extends V2ApplicationMessageType = V2ApplicationMessageType,
  P extends JsonObject = JsonObject,
> {
  protocol: typeof V2_PROTOCOL_VERSION;
  type: T;
  message_id: string;
  timestamp: string;
  source: V2AgentIdentity;
  target: V2AgentRef;
  delivery: V2Delivery;
  in_reply_to?: string;
  params: P;
}

/** Authentication metadata is correlation material, never a raw credential. */
export interface V2Authentication {
  method: V2AuthenticationMethod;
  principal_id: string;
  credential_id: string;
  key_id?: V2Digest;
  /** Canonical decimal unsigned-64 string. */
  auth_epoch: string;
  channel_binding: V2Digest;
}

/** The v0.2 initiator hello has no SID because the responder derives it. */
export interface V2HelloInitiatorFrame {
  type: "hello";
  v: typeof V2_HANDSHAKE_VERSION;
  profile: typeof V2_PROTOCOL_VERSION;
  role: "initiator";
  agent_id: string;
  instance_id: string;
  /** Omitted only by the separately selected local-only profile. */
  mesh_id?: V2MeshId;
  nonce: V2Nonce;
  transport_profile: V2TransportProfile;
  receive_limits: V2ReceiveLimits;
  extensions: readonly V2Extension[];
}

/** The responder hello binds the initiator nonce and supplies the session SID. */
export interface V2HelloResponderFrame {
  type: "hello";
  v: typeof V2_HANDSHAKE_VERSION;
  profile: typeof V2_PROTOCOL_VERSION;
  role: "responder";
  agent_id: string;
  instance_id: string;
  /** Omitted only by the separately selected local-only profile. */
  mesh_id?: V2MeshId;
  nonce: V2Nonce;
  echo: V2Nonce;
  sid: V2SessionId;
  transport_profile: V2TransportProfile;
  receive_limits: V2ReceiveLimits;
  extensions: readonly V2Extension[];
}

export type V2HelloFrame = V2HelloInitiatorFrame | V2HelloResponderFrame;

/** The post-hello auth record binds one role to the exact hello transcript. */
export interface V2AuthFrame {
  type: "auth";
  v: typeof V2_HANDSHAKE_VERSION;
  sid: V2SessionId;
  role: V2HandshakeRole;
  mesh_id: V2MeshId;
  transcript_hash: V2Digest;
  authentication: V2Authentication;
  /** Opaque, profile-specific proof; it is never a bearer token. */
  proof?: string;
}

/** A v0.2 capability advertises the complete contract that it commits to. */
export interface V2Capability {
  id: string;
  version: string;
  contract_digest: V2Digest;
  description?: string;
  input_schema: JsonObject;
  result_schema: JsonObject;
  idempotency: "pure" | "idempotent" | "sensitive";
  side_effects: "none" | "read" | "write" | "network" | "approval" | "execution";
  approval: "never" | "always" | "threshold";
  cancellation: "none" | "best_effort" | "supported";
  timeout_ceiling_seconds: number;
}

export interface V2Endpoint {
  transport: "unix" | "wss" | "remote-relay";
  url: string;
  scope: "loopback" | "lan" | "remote";
  security?: "local-unix" | "enrolled-wss" | "remote-relay";
}

export interface V2CardLimits {
  max_task_timeout_ms?: number;
  max_tasks_per_principal?: number;
  max_input_bytes?: number;
  max_result_bytes?: number;
}

/** A signed, mesh-scoped v0.2 Agent Card. */
export interface V2AgentCard {
  card_version: typeof V2_CARD_VERSION;
  mesh_id: V2MeshId;
  agent_id: string;
  instance_id: string;
  display_name?: string;
  issued_at: string;
  expires_at: string;
  revision: number;
  identity: CardIdentity;
  endpoints?: readonly V2Endpoint[];
  capabilities: readonly V2Capability[];
  limits?: V2CardLimits;
  metadata?: {
    description?: string;
    tags?: readonly string[];
    icon?: string;
  };
  signature: string;
}

/** The Card transport record is separate from an application envelope. */
export interface V2CardFrame {
  type: "card";
  v: typeof V2_HANDSHAKE_VERSION;
  sid: V2SessionId;
  role: V2HandshakeRole;
  mesh_id: V2MeshId;
  card_digest: V2Digest;
  card: V2AgentCard;
}

/** The final bilateral handshake barrier before application/control traffic. */
export interface V2ReadyFrame {
  type: "ready";
  v: typeof V2_HANDSHAKE_VERSION;
  sid: V2SessionId;
  role: V2HandshakeRole;
  mesh_id: V2MeshId;
  transcript_hash: V2Digest;
  auth_digest: V2Digest;
  self_card_digest: V2Digest;
  peer_card_digest: V2Digest;
  receive_limits: V2ReceiveLimits;
  extensions: readonly V2Extension[];
}

export interface V2CardUpdateFrame {
  type: "card.update";
  v: typeof V2_HANDSHAKE_VERSION;
  sid: V2SessionId;
  role: V2HandshakeRole;
  mesh_id: V2MeshId;
  previous_card_digest: V2Digest;
  card_digest: V2Digest;
  card: V2AgentCard;
}

/** A receipt is durable delivery correlation, never task-state authority. */
export type V2DeliveryReceiptRecord = {
  type: "delivery.receipt";
  v: typeof V2_HANDSHAKE_VERSION;
  sid: V2SessionId;
  mesh_id: V2MeshId;
  delivery_id: string;
  message_id: string;
  record_digest: V2Digest;
  semantic_digest: V2Digest;
} & (
  | { state: "stored" | "duplicate"; code?: never }
  | { state: "rejected"; code: string }
);

export interface V2ResumeEntry {
  partition_id: string;
  fence: string;
  received_through: string;
}

export interface V2DeliveryResumeFrame {
  type: "delivery.resume";
  v: typeof V2_HANDSHAKE_VERSION;
  sid: V2SessionId;
  mesh_id: V2MeshId;
  partitions: readonly V2ResumeEntry[];
}

export interface V2ResumeAckEntry {
  partition_id: string;
  fence: string;
  state: "available" | "unavailable" | "stale_fence";
  replay_from?: string;
  available_through?: string;
  code?: string;
}

export interface V2DeliveryResumeAckFrame {
  type: "delivery.resume.ack";
  v: typeof V2_HANDSHAKE_VERSION;
  sid: V2SessionId;
  mesh_id: V2MeshId;
  partitions: readonly V2ResumeAckEntry[];
}

export interface V2PingFrame {
  type: "ping";
  v: typeof V2_HANDSHAKE_VERSION;
  sid: V2SessionId;
  mesh_id: V2MeshId;
  n: string;
}

export interface V2PongFrame extends Omit<V2PingFrame, "type"> {
  type: "pong";
}

/** Bounded control diagnostic with no task-state authority. */
export interface V2SessionErrorFrame {
  type: "session.error";
  v: typeof V2_HANDSHAKE_VERSION;
  sid: V2SessionId;
  mesh_id: V2MeshId;
  in_reply_to?: string;
  code: string;
  message: string;
  retryable: boolean;
  retry_after_ms?: number | null;
  details?: JsonObject;
}

/** Base v0.2 handshake/control vocabulary prior to compression extensions. */
export type V2HandshakeRecord =
  | V2HelloFrame
  | V2AuthFrame
  | V2CardFrame
  | V2ReadyFrame
  | V2CardUpdateFrame;
export type V2TransportControlRecord =
  | V2DeliveryReceiptRecord
  | V2DeliveryResumeFrame
  | V2DeliveryResumeAckFrame
  | V2PingFrame
  | V2PongFrame
  | V2SessionErrorFrame;

/** Strict syntactic guards for values which establish the v0.2 wire scope. */
export function isV2MeshId(value: unknown): value is V2MeshId {
  return typeof value === "string" && new RegExp(V2_MESH_ID_PATTERN).test(value);
}

export function isV2SessionId(value: unknown): value is V2SessionId {
  return typeof value === "string" && new RegExp(V2_SID_PATTERN).test(value) && isBase64Url(value, V2_SID_BYTES);
}

export function isV2ProtocolProfile(value: unknown): value is typeof PROTOCOL_PROFILE_SELECTIONS.v0_2 {
  return isRecord(value) &&
    value.protocol === V2_PROTOCOL_VERSION &&
    value.handshake_version === V2_HANDSHAKE_VERSION &&
    value.card_version === V2_CARD_VERSION;
}

/** Shared Draft 2020-12 vocabulary for the distinct v0.2 profile. */
export const V2_COMMON_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://polymesh.dev/schemas/v2/common.json",
  title: "PolyMesh v2 common wire values",
  $defs: {
    UuidV7: {
      type: "string",
      pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    },
    Digest: { type: "string", pattern: V2_SID_PATTERN },
    Nonce: { type: "string", pattern: V2_SID_PATTERN },
    Signature: { type: "string", pattern: "^[A-Za-z0-9_-]{86}$" },
    MeshId: { type: "string", pattern: V2_MESH_ID_PATTERN },
    AgentId: {
      type: "string",
      minLength: 1,
      maxLength: 128,
      pattern: "^[a-z][a-z0-9._-]*[a-z0-9]$|^[a-z]$",
    },
    InstanceId: { type: "string", pattern: "^[A-Za-z0-9_-]{22}$" },
    UInt64: { type: "string", pattern: "^(0|[1-9][0-9]{0,19})$" },
    DateTimeMs: {
      type: "string",
      format: "date-time",
      pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$",
    },
    Semver: {
      type: "string",
      pattern: "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$",
    },
    CapabilityId: {
      type: "string",
      minLength: 3,
      maxLength: 192,
      pattern: "^[a-z][a-z0-9]*(?:\\.[a-z][a-z0-9-]*)+$",
    },
    IdempotencyKey: {
      type: "string",
      minLength: 1,
      maxLength: 256,
      pattern: "^[A-Za-z0-9._~:-]+$",
    },
    OpaqueId: {
      type: "string",
      minLength: 1,
      maxLength: 192,
      pattern: "^[A-Za-z0-9._:-]+$",
    },
    ErrorCode: {
      type: "string",
      minLength: 3,
      maxLength: 128,
      pattern: "^[A-Z][A-Z0-9_.]+$",
    },
    JsonValue: {
      anyOf: [
        { type: "null" },
        { type: "boolean" },
        { type: "number" },
        { type: "string", maxLength: MAX_FRAME_BYTES },
        { type: "array", maxItems: MAX_JSON_ARRAY_ITEMS, items: { $ref: "#/$defs/JsonValue" } },
        { type: "object", maxProperties: MAX_JSON_OBJECT_MEMBERS, additionalProperties: { $ref: "#/$defs/JsonValue" } },
      ],
    },
    JsonObject: {
      type: "object",
      maxProperties: MAX_JSON_OBJECT_MEMBERS,
      additionalProperties: { $ref: "#/$defs/JsonValue" },
    },
    SourceAddress: {
      type: "object",
      additionalProperties: false,
      required: ["agent_id", "instance_id"],
      properties: {
        mesh_id: { $ref: "#/$defs/MeshId" },
        agent_id: { $ref: "#/$defs/AgentId" },
        instance_id: { $ref: "#/$defs/InstanceId" },
      },
    },
    TargetAddress: {
      type: "object",
      additionalProperties: false,
      required: ["agent_id"],
      properties: {
        mesh_id: { $ref: "#/$defs/MeshId" },
        agent_id: { $ref: "#/$defs/AgentId" },
        instance_id: { $ref: "#/$defs/InstanceId" },
      },
    },
    Delivery: {
      type: "object",
      additionalProperties: false,
      required: ["delivery_id", "mode", "idempotency_key", "deadline"],
      properties: {
        delivery_id: { $ref: "#/$defs/UuidV7" },
        mode: { const: "at_least_once" },
        idempotency_key: { $ref: "#/$defs/IdempotencyKey" },
        deadline: { $ref: "#/$defs/DateTimeMs" },
      },
    },
    CapabilityTuple: {
      type: "object",
      required: ["capability", "capability_version", "capability_contract_digest"],
      properties: {
        capability: { $ref: "#/$defs/CapabilityId" },
        capability_version: { $ref: "#/$defs/Semver" },
        capability_contract_digest: { $ref: "#/$defs/Digest" },
      },
    },
    StructuredError: {
      type: "object",
      additionalProperties: false,
      required: ["category", "code", "message", "retryable"],
      properties: {
        category: { type: "string", enum: ["parse", "protocol", "identity", "routing", "delivery", "resource", "task", "execution", "internal"] },
        code: { $ref: "#/$defs/ErrorCode" },
        message: { type: "string", minLength: 1, maxLength: 512 },
        retryable: { type: "boolean" },
        retry_after_ms: { type: ["integer", "null"], minimum: 0, maximum: 86_400_000 },
        details: { $ref: "#/$defs/JsonObject" },
      },
    },
    Cancellation: {
      type: "object",
      additionalProperties: false,
      required: ["code"],
      properties: {
        code: { $ref: "#/$defs/ErrorCode" },
        message: { type: "string", maxLength: 512 },
      },
    },
  },
} as const;

/**
 * Closed application-envelope schema for the selected `polymesh.0.2`
 * profile.  It is intentionally separate from the legacy `ENVELOPE_SCHEMA`:
 * delivery_id is nested under delivery and mesh scope is part of each address.
 */
export const V2_APPLICATION_ENVELOPE_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://polymesh.dev/schemas/v2/envelope.json",
  title: "PolyMesh v2 application envelope",
  type: "object",
  additionalProperties: false,
  required: ["protocol", "type", "message_id", "timestamp", "source", "target", "delivery", "params"],
  properties: {
    protocol: { const: V2_PROTOCOL_VERSION },
    type: { type: "string", enum: V2_APPLICATION_MESSAGE_TYPES },
    message_id: { $ref: "common.json#/$defs/UuidV7" },
    timestamp: { $ref: "common.json#/$defs/DateTimeMs" },
    source: { $ref: "common.json#/$defs/SourceAddress" },
    target: { $ref: "common.json#/$defs/TargetAddress" },
    delivery: { $ref: "common.json#/$defs/Delivery" },
    in_reply_to: { $ref: "common.json#/$defs/UuidV7" },
    params: { type: "object" },
  },
  allOf: [
    { if: { properties: { type: { const: "task.submit" } } }, then: { properties: { params: { $ref: "#/$defs/TaskSubmit" } } } },
    { if: { properties: { type: { const: "task.accepted" } } }, then: { required: ["in_reply_to"], properties: { params: { $ref: "#/$defs/TaskAccepted" } } } },
    { if: { properties: { type: { const: "task.rejected" } } }, then: { required: ["in_reply_to"], properties: { params: { $ref: "#/$defs/TaskRejected" } } } },
    { if: { properties: { type: { const: "task.progress" } } }, then: { properties: { params: { $ref: "#/$defs/TaskProgress" } } } },
    { if: { properties: { type: { const: "task.completed" } } }, then: { properties: { params: { $ref: "#/$defs/TaskCompleted" } } } },
    { if: { properties: { type: { const: "task.cancel" } } }, then: { properties: { params: { $ref: "#/$defs/TaskCancel" } } } },
    { if: { properties: { type: { const: "task.status" } } }, then: { properties: { params: { $ref: "#/$defs/TaskStatus" } } } },
    { if: { properties: { type: { const: "error" } } }, then: { required: ["in_reply_to"], properties: { params: { $ref: "#/$defs/ApplicationError" } } } },
  ],
  $defs: {
    TaskSubmit: {
      type: "object",
      additionalProperties: false,
      required: ["task_id", "capability", "capability_version", "capability_contract_digest", "input", "deadline"],
      properties: {
        task_id: { $ref: "common.json#/$defs/UuidV7" },
        capability: { $ref: "common.json#/$defs/CapabilityId" },
        capability_version: { $ref: "common.json#/$defs/Semver" },
        capability_contract_digest: { $ref: "common.json#/$defs/Digest" },
        input: { $ref: "common.json#/$defs/JsonValue" },
        deadline: { $ref: "common.json#/$defs/DateTimeMs" },
      },
    },
    TaskAccepted: {
      allOf: [
        { $ref: "common.json#/$defs/CapabilityTuple" },
        {
          type: "object",
          additionalProperties: false,
          required: ["task_id", "event_seq", "accepted_at"],
          properties: {
            task_id: { $ref: "common.json#/$defs/UuidV7" },
            event_seq: { const: 1 },
            accepted_at: { $ref: "common.json#/$defs/DateTimeMs" },
            capability: { $ref: "common.json#/$defs/CapabilityId" },
            capability_version: { $ref: "common.json#/$defs/Semver" },
            capability_contract_digest: { $ref: "common.json#/$defs/Digest" },
          },
        },
      ],
    },
    TaskRejected: {
      allOf: [
        { $ref: "common.json#/$defs/CapabilityTuple" },
        {
          type: "object",
          additionalProperties: false,
          required: ["task_id", "event_seq", "code", "message"],
          properties: {
            task_id: { $ref: "common.json#/$defs/UuidV7" },
            event_seq: { const: 1 },
            code: { $ref: "common.json#/$defs/ErrorCode" },
            message: { type: "string", maxLength: 512 },
            capability: { $ref: "common.json#/$defs/CapabilityId" },
            capability_version: { $ref: "common.json#/$defs/Semver" },
            capability_contract_digest: { $ref: "common.json#/$defs/Digest" },
          },
        },
      ],
    },
    TaskProgress: {
      allOf: [
        { $ref: "common.json#/$defs/CapabilityTuple" },
        {
          type: "object",
          additionalProperties: false,
          required: ["task_id", "event_seq", "progress"],
          properties: {
            task_id: { $ref: "common.json#/$defs/UuidV7" },
            event_seq: { type: "integer", minimum: 2, maximum: Number.MAX_SAFE_INTEGER },
            capability: { $ref: "common.json#/$defs/CapabilityId" },
            capability_version: { $ref: "common.json#/$defs/Semver" },
            capability_contract_digest: { $ref: "common.json#/$defs/Digest" },
            progress: { $ref: "#/$defs/Progress" },
          },
        },
      ],
    },
    TaskCompleted: {
      allOf: [
        { $ref: "common.json#/$defs/CapabilityTuple" },
        {
          type: "object",
          additionalProperties: false,
          required: ["task_id", "event_seq", "terminal"],
          properties: {
            task_id: { $ref: "common.json#/$defs/UuidV7" },
            event_seq: { type: "integer", minimum: 2, maximum: Number.MAX_SAFE_INTEGER },
            capability: { $ref: "common.json#/$defs/CapabilityId" },
            capability_version: { $ref: "common.json#/$defs/Semver" },
            capability_contract_digest: { $ref: "common.json#/$defs/Digest" },
            terminal: { $ref: "#/$defs/Terminal" },
          },
        },
      ],
    },
    TaskCancel: {
      type: "object",
      additionalProperties: false,
      required: ["task_id"],
      properties: {
        task_id: { $ref: "common.json#/$defs/UuidV7" },
        reason: { type: "string", maxLength: 512 },
      },
    },
    TaskStatus: {
      oneOf: [{ $ref: "#/$defs/TaskStatusQuery" }, { $ref: "#/$defs/TaskStatusSnapshot" }],
    },
    ApplicationError: { $ref: "common.json#/$defs/StructuredError" },
    Progress: {
      type: "object",
      additionalProperties: false,
      required: ["state"],
      properties: {
        state: { type: "string", enum: ["queued", "running", "waiting"] },
        current: { type: "integer", minimum: 0, maximum: Number.MAX_SAFE_INTEGER },
        total: { type: "integer", minimum: 1, maximum: Number.MAX_SAFE_INTEGER },
        status: { type: "string", maxLength: 1_024 },
      },
    },
    Terminal: {
      oneOf: [
        {
          type: "object",
          additionalProperties: false,
          required: ["outcome", "result", "completed_at"],
          properties: {
            outcome: { const: "succeeded" },
            result: { $ref: "common.json#/$defs/JsonValue" },
            completed_at: { $ref: "common.json#/$defs/DateTimeMs" },
          },
        },
        {
          type: "object",
          additionalProperties: false,
          required: ["outcome", "error", "completed_at"],
          properties: {
            outcome: { const: "failed" },
            error: { $ref: "common.json#/$defs/StructuredError" },
            completed_at: { $ref: "common.json#/$defs/DateTimeMs" },
          },
        },
        {
          type: "object",
          additionalProperties: false,
          required: ["outcome", "cancellation", "completed_at"],
          properties: {
            outcome: { const: "cancelled" },
            cancellation: { $ref: "common.json#/$defs/Cancellation" },
            completed_at: { $ref: "common.json#/$defs/DateTimeMs" },
          },
        },
      ],
    },
    TaskStatusQuery: {
      type: "object",
      additionalProperties: false,
      required: ["kind", "task_id"],
      properties: {
        kind: { const: "query" },
        task_id: { $ref: "common.json#/$defs/UuidV7" },
      },
    },
    TaskStatusSnapshot: {
      type: "object",
      additionalProperties: false,
      required: ["kind", "task_id", "state", "event_seq", "observed_at"],
      properties: {
        kind: { const: "snapshot" },
        task_id: { $ref: "common.json#/$defs/UuidV7" },
        state: { type: "string", enum: ["accepted", "queued", "running", "waiting", "succeeded", "failed", "cancelled", "rejected", "recovery_required"] },
        event_seq: { type: "integer", minimum: 1, maximum: Number.MAX_SAFE_INTEGER },
        observed_at: { $ref: "common.json#/$defs/DateTimeMs" },
        terminal: { $ref: "#/$defs/Terminal" },
      },
    },
  },
} as const;

export const V2_ENVELOPE_SCHEMA = V2_APPLICATION_ENVELOPE_SCHEMA;
export const v2ApplicationEnvelopeSchema = V2_APPLICATION_ENVELOPE_SCHEMA;
export const v2EnvelopeSchema = V2_APPLICATION_ENVELOPE_SCHEMA;

/** Remote/relay sessions require serialized mesh scope in both addresses. */
export const V2_REMOTE_ADDRESSES_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://polymesh.dev/schemas/v2/remote-addresses.json",
  $defs: {
    RemoteSourceAddress: {
      type: "object",
      additionalProperties: false,
      required: ["mesh_id", "agent_id", "instance_id"],
      properties: {
        mesh_id: { $ref: "common.json#/$defs/MeshId" },
        agent_id: { $ref: "common.json#/$defs/AgentId" },
        instance_id: { $ref: "common.json#/$defs/InstanceId" },
      },
    },
    RemoteTargetAddress: {
      type: "object",
      additionalProperties: false,
      required: ["mesh_id", "agent_id"],
      properties: {
        mesh_id: { $ref: "common.json#/$defs/MeshId" },
        agent_id: { $ref: "common.json#/$defs/AgentId" },
        instance_id: { $ref: "common.json#/$defs/InstanceId" },
      },
    },
  },
} as const;

/** Draft 2020-12 schema for the signed v0.2 mesh-scoped Agent Card. */
export const V2_AGENT_CARD_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://polymesh.dev/schemas/v2/card.json",
  title: "PolyMesh v2 signed Agent Card",
  type: "object",
  additionalProperties: false,
  required: [
    "card_version", "mesh_id", "agent_id", "instance_id", "issued_at", "expires_at",
    "revision", "identity", "capabilities", "signature",
  ],
  properties: {
    card_version: { const: V2_CARD_VERSION },
    mesh_id: { $ref: "common.json#/$defs/MeshId" },
    agent_id: { $ref: "common.json#/$defs/AgentId" },
    instance_id: { $ref: "common.json#/$defs/InstanceId" },
    display_name: { type: "string", minLength: 1, maxLength: 128 },
    issued_at: { $ref: "common.json#/$defs/DateTimeMs" },
    expires_at: { $ref: "common.json#/$defs/DateTimeMs" },
    revision: { type: "integer", minimum: 1, maximum: Number.MAX_SAFE_INTEGER },
    identity: { $ref: "#/$defs/Identity" },
    endpoints: { type: "array", maxItems: MAX_ENDPOINTS_PER_CARD, uniqueItems: true, items: { $ref: "#/$defs/Endpoint" } },
    capabilities: { type: "array", minItems: 1, maxItems: MAX_CAPABILITIES_PER_CARD, items: { $ref: "#/$defs/Capability" } },
    limits: { $ref: "#/$defs/AdvertisedLimits" },
    metadata: { $ref: "#/$defs/CardMetadata" },
    signature: { $ref: "common.json#/$defs/Signature" },
  },
  $defs: {
    Identity: {
      type: "object",
      additionalProperties: false,
      required: ["alg", "key_id", "public_key"],
      properties: {
        alg: { const: IDENTITY_ALGORITHM },
        key_id: { $ref: "common.json#/$defs/Digest" },
        public_key: { type: "string", pattern: V2_SID_PATTERN },
      },
    },
    Endpoint: {
      type: "object",
      additionalProperties: false,
      required: ["transport", "url", "scope"],
      properties: {
        transport: { type: "string", enum: ["unix", "wss", "remote-relay"] },
        url: { type: "string", format: "uri", maxLength: 2_048 },
        scope: { type: "string", enum: ["loopback", "lan", "remote"] },
        security: { type: "string", enum: ["local-unix", "enrolled-wss", "remote-relay"] },
      },
    },
    Capability: {
      type: "object",
      additionalProperties: false,
      required: [
        "id", "version", "contract_digest", "input_schema", "result_schema", "idempotency",
        "side_effects", "approval", "cancellation", "timeout_ceiling_seconds",
      ],
      properties: {
        id: { $ref: "common.json#/$defs/CapabilityId" },
        version: { $ref: "common.json#/$defs/Semver" },
        contract_digest: { $ref: "common.json#/$defs/Digest" },
        description: { type: "string", maxLength: 2_048 },
        input_schema: { $ref: "common.json#/$defs/JsonObject" },
        result_schema: { $ref: "common.json#/$defs/JsonObject" },
        idempotency: { type: "string", enum: ["pure", "idempotent", "sensitive"] },
        side_effects: { type: "string", enum: ["none", "read", "write", "network", "approval", "execution"] },
        approval: { type: "string", enum: ["never", "always", "threshold"] },
        cancellation: { type: "string", enum: ["none", "best_effort", "supported"] },
        timeout_ceiling_seconds: { type: "integer", minimum: 1, maximum: 86_400 },
      },
    },
    AdvertisedLimits: {
      type: "object",
      additionalProperties: false,
      properties: {
        max_task_timeout_ms: { type: "integer", minimum: 1, maximum: 86_400_000 },
        max_tasks_per_principal: { type: "integer", minimum: 1, maximum: 100_000 },
        max_input_bytes: { type: "integer", minimum: 1, maximum: MAX_FRAME_BYTES },
        max_result_bytes: { type: "integer", minimum: 1, maximum: MAX_FRAME_BYTES },
      },
    },
    CardMetadata: {
      type: "object",
      additionalProperties: false,
      properties: {
        description: { type: "string", maxLength: 2_048 },
        tags: { type: "array", maxItems: 32, uniqueItems: true, items: { type: "string", minLength: 1, maxLength: 64 } },
        icon: { type: "string", format: "uri", maxLength: 2_048 },
      },
    },
  },
} as const;

export const v2CommonSchema = V2_COMMON_SCHEMA;
export const v2RemoteAddressesSchema = V2_REMOTE_ADDRESSES_SCHEMA;
export const v2AgentCardSchema = V2_AGENT_CARD_SCHEMA;

/**
 * Draft 2020-12 schema for v0.2 handshake and non-compression control
 * records.  Session state still determines whether a structurally valid
 * record is allowed at a particular point in the handshake.
 */
export const V2_HANDSHAKE_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://polymesh.dev/schemas/v2/control.json",
  title: "PolyMesh v2 handshake and transport-control records",
  oneOf: [
    { $ref: "#/$defs/HelloInitiator" },
    { $ref: "#/$defs/HelloResponder" },
    { $ref: "#/$defs/Auth" },
    { $ref: "#/$defs/Card" },
    { $ref: "#/$defs/Ready" },
    { $ref: "#/$defs/CardUpdate" },
    { $ref: "#/$defs/DeliveryReceipt" },
    { $ref: "#/$defs/DeliveryResume" },
    { $ref: "#/$defs/DeliveryResumeAck" },
    { $ref: "#/$defs/Ping" },
    { $ref: "#/$defs/Pong" },
    { $ref: "#/$defs/SessionError" },
  ],
  $defs: {
    ReceiveLimits: {
      type: "object",
      additionalProperties: false,
      required: ["max_wire_bytes", "max_json_bytes", "max_uncompressed_bytes", "max_expansion_ratio"],
      properties: {
        max_wire_bytes: { type: "integer", minimum: 4_096, maximum: MAX_FRAME_BYTES },
        max_json_bytes: { type: "integer", minimum: 4_096, maximum: MAX_FRAME_BYTES },
        max_uncompressed_bytes: { type: "integer", minimum: 4_096, maximum: MAX_FRAME_BYTES },
        max_expansion_ratio: { type: "integer", minimum: 1, maximum: 64 },
      },
    },
    Extensions: {
      type: "array",
      maxItems: 8,
      uniqueItems: true,
      items: { type: "string", enum: ["compression/zstd"] },
    },
    Authentication: {
      type: "object",
      additionalProperties: false,
      required: ["method", "principal_id", "credential_id", "auth_epoch", "channel_binding"],
      properties: {
        method: { type: "string", enum: ["local-unix", "mtls-enrolled", "oauth-dpop", "oauth-mtls", "deckagent-bound"] },
        principal_id: { $ref: "common.json#/$defs/OpaqueId" },
        credential_id: { $ref: "common.json#/$defs/OpaqueId" },
        key_id: { $ref: "common.json#/$defs/Digest" },
        auth_epoch: { $ref: "common.json#/$defs/UInt64" },
        channel_binding: { $ref: "common.json#/$defs/Digest" },
      },
    },
    Session: {
      type: "object",
      properties: {
        v: { const: V2_HANDSHAKE_VERSION },
        sid: { $ref: "common.json#/$defs/Digest" },
        mesh_id: { $ref: "common.json#/$defs/MeshId" },
      },
    },
    Role: {
      type: "object",
      properties: { role: { type: "string", enum: ["initiator", "responder"] } },
    },
    HelloInitiator: {
      allOf: [
        {
          type: "object",
          required: [
            "type", "v", "profile", "role", "agent_id", "instance_id", "nonce",
            "transport_profile", "receive_limits", "extensions",
          ],
          properties: {
            type: { const: "hello" },
            v: { const: V2_HANDSHAKE_VERSION },
            profile: { const: V2_PROTOCOL_VERSION },
            role: { const: "initiator" },
            agent_id: { $ref: "common.json#/$defs/AgentId" },
            instance_id: { $ref: "common.json#/$defs/InstanceId" },
            mesh_id: { $ref: "common.json#/$defs/MeshId" },
            nonce: { $ref: "common.json#/$defs/Nonce" },
            transport_profile: { type: "string", enum: ["local-unix/1", "loopback-wss/1", "enrolled-wss/1", "remote-relay/1", "deckagent-carrier/1"] },
            receive_limits: { $ref: "#/$defs/ReceiveLimits" },
            extensions: { $ref: "#/$defs/Extensions" },
          },
        },
      ],
      unevaluatedProperties: false,
    },
    HelloResponder: {
      allOf: [
        {
          type: "object",
          required: [
            "type", "v", "profile", "role", "agent_id", "instance_id", "nonce", "echo", "sid",
            "transport_profile", "receive_limits", "extensions",
          ],
          properties: {
            type: { const: "hello" },
            v: { const: V2_HANDSHAKE_VERSION },
            profile: { const: V2_PROTOCOL_VERSION },
            role: { const: "responder" },
            agent_id: { $ref: "common.json#/$defs/AgentId" },
            instance_id: { $ref: "common.json#/$defs/InstanceId" },
            mesh_id: { $ref: "common.json#/$defs/MeshId" },
            nonce: { $ref: "common.json#/$defs/Nonce" },
            echo: { $ref: "common.json#/$defs/Nonce" },
            sid: { $ref: "common.json#/$defs/Digest" },
            transport_profile: { type: "string", enum: ["local-unix/1", "loopback-wss/1", "enrolled-wss/1", "remote-relay/1", "deckagent-carrier/1"] },
            receive_limits: { $ref: "#/$defs/ReceiveLimits" },
            extensions: { $ref: "#/$defs/Extensions" },
          },
        },
      ],
      unevaluatedProperties: false,
    },
    Auth: {
      allOf: [
        { $ref: "#/$defs/Session" },
        { $ref: "#/$defs/Role" },
        {
          type: "object",
          required: ["type", "v", "sid", "role", "mesh_id", "transcript_hash", "authentication"],
          properties: {
            type: { const: "auth" },
            transcript_hash: { $ref: "common.json#/$defs/Digest" },
            authentication: { $ref: "#/$defs/Authentication" },
            proof: { type: "string", minLength: 43, maxLength: 4_096, pattern: "^[A-Za-z0-9_-]+$" },
          },
        },
      ],
      unevaluatedProperties: false,
    },
    Card: {
      allOf: [
        { $ref: "#/$defs/Session" },
        { $ref: "#/$defs/Role" },
        {
          type: "object",
          required: ["type", "v", "sid", "role", "mesh_id", "card_digest", "card"],
          properties: {
            type: { const: "card" },
            card_digest: { $ref: "common.json#/$defs/Digest" },
            card: { $ref: "card.json" },
          },
        },
      ],
      unevaluatedProperties: false,
    },
    Ready: {
      allOf: [
        { $ref: "#/$defs/Session" },
        { $ref: "#/$defs/Role" },
        {
          type: "object",
          required: [
            "type", "v", "sid", "role", "mesh_id", "transcript_hash", "auth_digest",
            "self_card_digest", "peer_card_digest", "receive_limits", "extensions",
          ],
          properties: {
            type: { const: "ready" },
            transcript_hash: { $ref: "common.json#/$defs/Digest" },
            auth_digest: { $ref: "common.json#/$defs/Digest" },
            self_card_digest: { $ref: "common.json#/$defs/Digest" },
            peer_card_digest: { $ref: "common.json#/$defs/Digest" },
            receive_limits: { $ref: "#/$defs/ReceiveLimits" },
            extensions: { $ref: "#/$defs/Extensions" },
          },
        },
      ],
      unevaluatedProperties: false,
    },
    CardUpdate: {
      allOf: [
        { $ref: "#/$defs/Session" },
        { $ref: "#/$defs/Role" },
        {
          type: "object",
          required: ["type", "v", "sid", "role", "mesh_id", "previous_card_digest", "card_digest", "card"],
          properties: {
            type: { const: "card.update" },
            previous_card_digest: { $ref: "common.json#/$defs/Digest" },
            card_digest: { $ref: "common.json#/$defs/Digest" },
            card: { $ref: "card.json" },
          },
        },
      ],
      unevaluatedProperties: false,
    },
    DeliveryReceipt: {
      allOf: [
        { $ref: "#/$defs/Session" },
        {
          type: "object",
          required: ["type", "v", "sid", "mesh_id", "delivery_id", "message_id", "record_digest", "semantic_digest", "state"],
          properties: {
            type: { const: "delivery.receipt" },
            delivery_id: { $ref: "common.json#/$defs/UuidV7" },
            message_id: { $ref: "common.json#/$defs/UuidV7" },
            record_digest: { $ref: "common.json#/$defs/Digest" },
            semantic_digest: { $ref: "common.json#/$defs/Digest" },
            state: { type: "string", enum: ["stored", "duplicate", "rejected"] },
            code: { $ref: "common.json#/$defs/ErrorCode" },
          },
          allOf: [
            {
              if: { properties: { state: { const: "rejected" } } },
              then: { required: ["code"] },
              else: { not: { required: ["code"] } },
            },
          ],
        },
      ],
      unevaluatedProperties: false,
    },
    ResumeEntry: {
      type: "object",
      additionalProperties: false,
      required: ["partition_id", "fence", "received_through"],
      properties: {
        partition_id: { $ref: "common.json#/$defs/OpaqueId" },
        fence: { $ref: "common.json#/$defs/UInt64" },
        received_through: { $ref: "common.json#/$defs/UInt64" },
      },
    },
    DeliveryResume: {
      allOf: [
        { $ref: "#/$defs/Session" },
        {
          type: "object",
          required: ["type", "v", "sid", "mesh_id", "partitions"],
          properties: {
            type: { const: "delivery.resume" },
            partitions: { type: "array", minItems: 1, maxItems: 128, items: { $ref: "#/$defs/ResumeEntry" } },
          },
        },
      ],
      unevaluatedProperties: false,
    },
    ResumeAckEntry: {
      type: "object",
      additionalProperties: false,
      required: ["partition_id", "fence", "state"],
      properties: {
        partition_id: { $ref: "common.json#/$defs/OpaqueId" },
        fence: { $ref: "common.json#/$defs/UInt64" },
        state: { type: "string", enum: ["available", "unavailable", "stale_fence"] },
        replay_from: { $ref: "common.json#/$defs/UInt64" },
        available_through: { $ref: "common.json#/$defs/UInt64" },
        code: { $ref: "common.json#/$defs/ErrorCode" },
      },
    },
    DeliveryResumeAck: {
      allOf: [
        { $ref: "#/$defs/Session" },
        {
          type: "object",
          required: ["type", "v", "sid", "mesh_id", "partitions"],
          properties: {
            type: { const: "delivery.resume.ack" },
            partitions: { type: "array", minItems: 1, maxItems: 128, items: { $ref: "#/$defs/ResumeAckEntry" } },
          },
        },
      ],
      unevaluatedProperties: false,
    },
    Ping: {
      allOf: [
        { $ref: "#/$defs/Session" },
        {
          type: "object",
          required: ["type", "v", "sid", "mesh_id", "n"],
          properties: { type: { const: "ping" }, n: { $ref: "common.json#/$defs/UInt64" } },
        },
      ],
      unevaluatedProperties: false,
    },
    Pong: {
      allOf: [
        { $ref: "#/$defs/Session" },
        {
          type: "object",
          required: ["type", "v", "sid", "mesh_id", "n"],
          properties: { type: { const: "pong" }, n: { $ref: "common.json#/$defs/UInt64" } },
        },
      ],
      unevaluatedProperties: false,
    },
    SessionError: {
      allOf: [
        { $ref: "#/$defs/Session" },
        {
          type: "object",
          required: ["type", "v", "sid", "mesh_id", "code", "message", "retryable"],
          properties: {
            type: { const: "session.error" },
            in_reply_to: { $ref: "common.json#/$defs/UuidV7" },
            code: { $ref: "common.json#/$defs/ErrorCode" },
            message: { type: "string", minLength: 1, maxLength: 512 },
            retryable: { type: "boolean" },
            retry_after_ms: { type: ["integer", "null"], minimum: 0, maximum: 86_400_000 },
            details: { $ref: "common.json#/$defs/JsonObject" },
          },
        },
      ],
      unevaluatedProperties: false,
    },
  },
} as const;

/** Standalone receipt schema for transports which dispatch control records by type. */
export const V2_DELIVERY_RECEIPT_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://polymesh.dev/schemas/v2/delivery-receipt.json",
  $ref: "control.json#/$defs/DeliveryReceipt",
} as const;

export const V2_CONTROL_SCHEMA = V2_HANDSHAKE_SCHEMA;
export const V2_CONTROL_RECORD_SCHEMA = V2_HANDSHAKE_SCHEMA;
export const V2_HANDSHAKE_RECORD_SCHEMA = V2_HANDSHAKE_SCHEMA;
export const v2HandshakeSchema = V2_HANDSHAKE_SCHEMA;
export const v2ControlSchema = V2_HANDSHAKE_SCHEMA;
export const v2DeliveryReceiptSchema = V2_DELIVERY_RECEIPT_SCHEMA;

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
    provenance: {
      type: "object",
      required: [
        "version", "broker", "source_principal", "source", "target",
        "source_session_id", "target_session_id", "envelope_digest",
        "issued_at", "expires_at", "signature",
      ],
      properties: {
        version: { const: ROUTED_PROVENANCE_VERSION },
        broker: { type: "object" },
        source_principal: { type: "object" },
        source: { type: "object" },
        target: { type: "object" },
        source_session_id: { type: "string" },
        target_session_id: { type: "string" },
        envelope_digest: { type: "string" },
        issued_at: { type: "string", format: "date-time" },
        expires_at: { type: "string", format: "date-time" },
        signature: { type: "string" },
      },
      additionalProperties: false,
    },
    params: { type: "object" },
  },
  additionalProperties: false,
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
    identity: {
      type: "object",
      required: ["alg", "key_id", "public_key"],
      properties: {
        alg: { const: IDENTITY_ALGORITHM },
        key_id: { type: "string" },
        public_key: { type: "string" },
      },
      additionalProperties: false,
    },
    signature: { type: "string" },
  },
  additionalProperties: false,
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

/**
 * A broker-local acknowledgement for a validated inbound envelope. Receipts
 * are control records: they are never routed, acknowledged, or allowed to
 * change task state. `in_reply_to` is required to equal
 * `received_message_id` so a recipient can correlate it without inspecting
 * arbitrary diagnostic fields.
 */
export type ReceiptDisposition = "accepted" | "duplicate" | "rejected";

export interface ReceiptParams extends JsonObject {
  received_message_id: string;
  semantic_digest: string;
  disposition: ReceiptDisposition;
}

export interface TaskSubmitParams extends JsonObject {
  task_id: string;
  method: string;
  capability_version: string;
  capability_contract_digest: string;
  params: JsonObject;
  deadline: string;
}

export interface TaskAcceptedParams extends CapabilityContractTuple {
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

export interface TaskCompletedParams extends CapabilityContractTuple {
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
  /** Present only for the fail-closed enrolled-key secure profile. */
  security_profile?: typeof SECURE_IDENTITY_PROFILE;
} | {
  type: "hello";
  v: typeof HANDSHAKE_VERSION;
  role: "responder";
  agent_id: string;
  instance_id: string;
  nonce: string;
  echo: string;
  sid: string;
  /** Present only for the fail-closed enrolled-key secure profile. */
  security_profile?: typeof SECURE_IDENTITY_PROFILE;
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

/** Proof of the private key bound to a signed Card and local enrollment. */
export interface AuthFrame {
  type: "auth";
  sid: string;
  agent_id: string;
  key_id: string;
  signature: string;
}

export type HandshakeFrame = HelloFrame | CardFrame | AuthFrame | ReadyFrame;

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
// Namespaces are canonical lowercase DNS-like labels. The final operation
// label may contain an internal hyphen (for example `org.example.file-read`)
// but may not begin or end with one.
const CAPABILITY_ID_RE = /^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)*\.[a-z](?:[a-z0-9-]*[a-z0-9])?$/;
const SEMVER_RE = /^\d+\.\d+\.\d+$/;
const RFC3339_MILLIS_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

let lastUuidTimestamp = -1;
let lastUuidRandom = 0n;
const MAX_UUID_RANDOM = (1n << 74n) - 1n;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function hasRequiredKeys(value: Record<string, unknown>, required: readonly string[]): boolean {
  return required.every((key) => Object.hasOwn(value, key));
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return hasRequiredKeys(value, keys) && hasOnlyKeys(value, keys);
}

function serializedJsonBytes(value: unknown): number | undefined {
  if (!isJsonValue(value)) return undefined;
  try {
    const serialized = JSON.stringify(value);
    return typeof serialized === "string" ? Buffer.byteLength(serialized, "utf8") : undefined;
  } catch {
    return undefined;
  }
}

function isBoundedString(value: unknown, maximum = MAX_JSON_STRING_BYTES): value is string {
  return typeof value === "string" && Buffer.byteLength(value, "utf8") <= maximum;
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

export interface JsonParseLimits {
  maxBytes: number;
  maxDepth: number;
  maxNodes: number;
  maxObjectMembers: number;
  maxArrayItems: number;
  maxStringBytes: number;
}

export type JsonParseResult<T = JsonValue> =
  | { ok: true; value: T }
  | { ok: false; code: "MALFORMED_JSON" | "DUPLICATE_MEMBER" | "RESOURCE_EXHAUSTED"; error: string };

const DEFAULT_JSON_PARSE_LIMITS: JsonParseLimits = Object.freeze({
  maxBytes: MAX_FRAME_BYTES,
  maxDepth: MAX_JSON_DEPTH,
  maxNodes: MAX_JSON_NODES,
  maxObjectMembers: MAX_JSON_OBJECT_MEMBERS,
  maxArrayItems: MAX_JSON_ARRAY_ITEMS,
  maxStringBytes: MAX_JSON_STRING_BYTES,
});

function jsonParseLimits(overrides: Partial<JsonParseLimits> = {}): JsonParseLimits {
  const limits = { ...DEFAULT_JSON_PARSE_LIMITS, ...overrides };
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value <= 0) throw new RangeError(`${name} must be a positive safe integer`);
  }
  return limits;
}

function jsonParseError(
  code: "MALFORMED_JSON" | "DUPLICATE_MEMBER" | "RESOURCE_EXHAUSTED",
  message: string,
): ProtocolError {
  return new ProtocolError(code, message, code === "RESOURCE_EXHAUSTED" ? "resource" : "parse");
}

/**
 * Strict, bounded JSON parser for all untrusted protocol input.  `JSON.parse`
 * has two undesirable properties for a wire protocol: duplicate members are
 * silently last-wins and it has no structural resource budget.  This parser
 * rejects duplicate member names before application objects exist and uses
 * null-prototype objects to avoid prototype-pollution side effects.
 */
class StrictJsonParser {
  private index = 0;
  private nodes = 0;

  constructor(private readonly text: string, private readonly limits: JsonParseLimits) {}

  parse(): JsonValue {
    this.skipWhitespace();
    const value = this.parseValue(1);
    this.skipWhitespace();
    if (this.index !== this.text.length) this.fail("Unexpected data after JSON value");
    return value;
  }

  private parseValue(depth: number): JsonValue {
    if (depth > this.limits.maxDepth) this.exhaust("JSON nesting depth exceeds the configured limit");
    this.consumeNode();
    this.skipWhitespace();
    const character = this.text[this.index];
    if (character === "{") return this.parseObject(depth);
    if (character === "[") return this.parseArray(depth);
    if (character === '"') return this.parseString();
    if (character === "t") return this.parseLiteral("true", true);
    if (character === "f") return this.parseLiteral("false", false);
    if (character === "n") return this.parseLiteral("null", null);
    if (character === "-" || (character !== undefined && character >= "0" && character <= "9")) return this.parseNumber();
    this.fail("Expected a JSON value");
  }

  private parseObject(depth: number): JsonObject {
    this.expect("{");
    this.skipWhitespace();
    const result = Object.create(null) as JsonObject;
    const members = new Set<string>();
    if (this.consume("}")) return result;
    let count = 0;
    while (true) {
      if (++count > this.limits.maxObjectMembers) this.exhaust("JSON object has too many members");
      this.skipWhitespace();
      if (this.text[this.index] !== '"') this.fail("Object member name must be a string");
      const key = this.parseString();
      if (members.has(key)) {
        throw jsonParseError("DUPLICATE_MEMBER", `Duplicate JSON member '${key}'`);
      }
      members.add(key);
      this.skipWhitespace();
      this.expect(":");
      const value = this.parseValue(depth + 1);
      Object.defineProperty(result, key, {
        value,
        enumerable: true,
        configurable: true,
        writable: true,
      });
      this.skipWhitespace();
      if (this.consume("}")) return result;
      this.expect(",");
    }
  }

  private parseArray(depth: number): JsonValue[] {
    this.expect("[");
    this.skipWhitespace();
    const result: JsonValue[] = [];
    if (this.consume("]")) return result;
    while (true) {
      if (result.length >= this.limits.maxArrayItems) this.exhaust("JSON array has too many items");
      result.push(this.parseValue(depth + 1));
      this.skipWhitespace();
      if (this.consume("]")) return result;
      this.expect(",");
    }
  }

  private parseString(): string {
    this.expect('"');
    let result = "";
    while (this.index < this.text.length) {
      const character = this.text[this.index++]!;
      if (character === '"') {
        if (!validUnicodeScalarSequence(result)) this.fail("JSON string contains an unpaired surrogate");
        if (Buffer.byteLength(result, "utf8") > this.limits.maxStringBytes) this.exhaust("JSON string exceeds the configured limit");
        return result;
      }
      if (character === "\\") {
        const escape = this.text[this.index++];
        switch (escape) {
          case '"': result += '"'; break;
          case "\\": result += "\\"; break;
          case "/": result += "/"; break;
          case "b": result += "\b"; break;
          case "f": result += "\f"; break;
          case "n": result += "\n"; break;
          case "r": result += "\r"; break;
          case "t": result += "\t"; break;
          case "u": {
            const hex = this.text.slice(this.index, this.index + 4);
            if (!/^[0-9A-Fa-f]{4}$/.test(hex)) this.fail("Invalid Unicode escape");
            result += String.fromCharCode(Number.parseInt(hex, 16));
            this.index += 4;
            break;
          }
          default: this.fail("Invalid JSON string escape");
        }
        continue;
      }
      if (character.charCodeAt(0) < 0x20) this.fail("Control character in JSON string");
      result += character;
    }
    this.fail("Unterminated JSON string");
  }

  private parseLiteral<T extends JsonPrimitive>(literal: string, value: T): T {
    if (this.text.slice(this.index, this.index + literal.length) !== literal) this.fail(`Expected ${literal}`);
    this.index += literal.length;
    return value;
  }

  private parseNumber(): number {
    const start = this.index;
    this.consume("-");
    const first = this.text[this.index];
    if (first === "0") this.index += 1;
    else if (first !== undefined && first >= "1" && first <= "9") {
      this.index += 1;
      while (isDigit(this.text[this.index])) this.index += 1;
    } else this.fail("Invalid JSON number");
    if (this.consume(".")) {
      if (!isDigit(this.text[this.index])) this.fail("Invalid JSON number fraction");
      while (isDigit(this.text[this.index])) this.index += 1;
    }
    if (this.text[this.index] === "e" || this.text[this.index] === "E") {
      this.index += 1;
      if (this.text[this.index] === "+" || this.text[this.index] === "-") this.index += 1;
      if (!isDigit(this.text[this.index])) this.fail("Invalid JSON number exponent");
      while (isDigit(this.text[this.index])) this.index += 1;
    }
    const value = Number(this.text.slice(start, this.index));
    if (!Number.isFinite(value)) this.fail("JSON number is not finite");
    return value;
  }

  private skipWhitespace(): void {
    while (this.text[this.index] === " " || this.text[this.index] === "\n" || this.text[this.index] === "\r" || this.text[this.index] === "\t") this.index += 1;
  }

  private expect(character: string): void {
    if (!this.consume(character)) this.fail(`Expected '${character}'`);
  }

  private consume(character: string): boolean {
    if (this.text[this.index] !== character) return false;
    this.index += 1;
    return true;
  }

  private consumeNode(): void {
    this.nodes += 1;
    if (this.nodes > this.limits.maxNodes) this.exhaust("JSON node count exceeds the configured limit");
  }

  private fail(message: string): never {
    throw jsonParseError("MALFORMED_JSON", `${message} at byte offset ${this.index}`);
  }

  private exhaust(message: string): never {
    throw jsonParseError("RESOURCE_EXHAUSTED", message);
  }
}

function isDigit(character: string | undefined): boolean {
  return character !== undefined && character >= "0" && character <= "9";
}

function validUnicodeScalarSequence(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0xd800 || code > 0xdfff) continue;
    if (code > 0xdbff || index + 1 >= value.length) return false;
    const low = value.charCodeAt(++index);
    if (low < 0xdc00 || low > 0xdfff) return false;
  }
  return true;
}

/** Parse a strict UTF-8 JSON value with duplicate-key and resource checks. */
export function parseStrictJson(input: string | Uint8Array, overrides: Partial<JsonParseLimits> = {}): JsonParseResult {
  let text: string;
  let bytes: number;
  try {
    if (typeof input === "string") {
      text = input;
      bytes = Buffer.byteLength(text, "utf8");
    } else {
      bytes = input.byteLength;
      text = new TextDecoder("utf-8", { fatal: true }).decode(input);
    }
  } catch {
    return { ok: false, code: "MALFORMED_JSON", error: "Input is not valid UTF-8 JSON" };
  }
  let limits: JsonParseLimits;
  try {
    limits = jsonParseLimits(overrides);
  } catch (error) {
    return { ok: false, code: "RESOURCE_EXHAUSTED", error: error instanceof Error ? error.message : "Invalid JSON limits" };
  }
  if (bytes > limits.maxBytes) return { ok: false, code: "RESOURCE_EXHAUSTED", error: "JSON input exceeds the configured byte limit" };
  try {
    return { ok: true, value: new StrictJsonParser(text, limits).parse() };
  } catch (error) {
    if (error instanceof ProtocolError && (error.code === "MALFORMED_JSON" || error.code === "DUPLICATE_MEMBER" || error.code === "RESOURCE_EXHAUSTED")) {
      return { ok: false, code: error.code, error: error.message };
    }
    return { ok: false, code: "MALFORMED_JSON", error: "Invalid JSON" };
  }
}

export const parseBoundedJson = parseStrictJson;

/** True when value can be represented in a JSON text without lossy values. */
export function isJsonValue(value: unknown, seen = new WeakSet<object>()): value is JsonValue {
  let nodes = 0;
  const visit = (entry: unknown, depth: number): entry is JsonValue => {
    if (++nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH) return false;
    if (entry === null || typeof entry === "boolean") return true;
    if (typeof entry === "string") return validUnicodeScalarSequence(entry) && Buffer.byteLength(entry, "utf8") <= MAX_JSON_STRING_BYTES;
    if (typeof entry === "number") return Number.isFinite(entry);
    if (typeof entry !== "object" || seen.has(entry)) return false;
    seen.add(entry);
    try {
      if (Array.isArray(entry)) {
        return entry.length <= MAX_JSON_ARRAY_ITEMS && entry.every((child) => visit(child, depth + 1));
      }
      const entries = Object.values(entry);
      return entries.length <= MAX_JSON_OBJECT_MEMBERS && entries.every((child) => visit(child, depth + 1));
    } finally {
      seen.delete(entry);
    }
  };
  return visit(value, 1);
}

export function isUuidV7(value: unknown): value is string {
  return typeof value === "string" && UUID_V7_RE.test(value);
}

export function isAgentId(value: unknown): value is string {
  return typeof value === "string" && value.length <= 255 && AGENT_ID_RE.test(value);
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

function v2ChannelBindingBytes(value: string | Uint8Array): Buffer {
  if (typeof value === "string") {
    if (!isBase64Url(value, V2_SID_BYTES)) {
      throw new ProtocolError("MALFORMED_CHANNEL_BINDING", "v0.2 channel binding must be a 32-byte base64url value", "parse");
    }
    return Buffer.from(value, "base64url");
  }
  const bytes = Buffer.from(value);
  if (bytes.byteLength !== V2_SID_BYTES) {
    throw new ProtocolError("MALFORMED_CHANNEL_BINDING", "v0.2 channel binding must contain exactly 32 bytes", "parse");
  }
  return bytes;
}

function v2NonceBytes(value: string | Uint8Array): Buffer {
  const bytes = nonceBytes(value);
  if (bytes.byteLength !== V2_SID_BYTES) {
    throw new ProtocolError("MALFORMED_NONCE", "v0.2 session nonces must contain exactly 32 bytes", "parse");
  }
  return bytes;
}

/**
 * Derive the v0.2 session correlation value from both hello nonces and the
 * authenticated channel binding.  Unlike the legacy v0.1 SID this is bound
 * to the selected profile and cannot be replayed onto another TLS/carrier
 * session.  It is correlation material, not a credential.
 */
export function deriveV2SessionId(
  initiatorNonce: string | Uint8Array,
  responderNonce: string | Uint8Array,
  channelBindingHash: string | Uint8Array,
): V2SessionId {
  return createHash("sha256")
    .update(V2_SID_DOMAIN, "utf8")
    .update(v2NonceBytes(initiatorNonce))
    .update(v2NonceBytes(responderNonce))
    .update(V2_PROTOCOL_VERSION, "utf8")
    .update(v2ChannelBindingBytes(channelBindingHash))
    .digest("base64url");
}

/** RFC 8785-style canonical JSON suitable for protocol fingerprints and cards. */
export function canonicalize(value: JsonValue): string {
  if (!isJsonValue(value)) {
    throw new TypeError("Canonical JSON exceeds protocol structural limits or contains a non-JSON value");
  }
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

/**
 * Canonical, security-relevant portion of a capability advertisement.
 *
 * Optional capability fields are normalized to their protocol defaults. This
 * prevents an otherwise equivalent card that spells out a default from
 * producing a different pinned contract, while still covering every field
 * that changes input, output, side-effect, approval, cancellation, or timing
 * semantics.
 */
export function capabilityContractPayload(capability: Capability): JsonObject {
  const valid = validateCapability(capability);
  if (valid.ok === false) throw new TypeError(`Invalid capability contract: ${valid.error}`);
  const normalized = valid.value;
  return {
    id: normalized.id,
    version: normalized.version,
    input_schema: normalized.input_schema ?? null,
    result_schema: normalized.result_schema ?? null,
    idempotency: normalized.idempotency ?? "idempotent",
    side_effects: normalized.side_effects ?? "none",
    approval: normalized.approval ?? "never",
    cancellation: normalized.cancellation ?? "none",
    timeout_ceiling_seconds: normalized.timeout_ceiling_seconds ?? 300,
  };
}

/**
 * SHA-256 of the JCS-style canonical capability contract. Task owners pin
 * this value at submission and executors echo it once they have admitted the
 * exact advertised contract.
 */
export function capabilityContractDigest(capability: Capability): string {
  return sha256(capabilityContractPayload(capability));
}

/** Construct the exact contract tuple carried in task lifecycle records. */
export function capabilityContractTuple(capability: Capability): CapabilityContractTuple {
  const payload = capabilityContractPayload(capability);
  return {
    capability_id: payload.id as string,
    capability_version: payload.version as string,
    capability_contract_digest: sha256(payload),
  };
}

/** Structural guard for the closed wire representation of a contract tuple. */
export function isCapabilityContractTuple(value: unknown): value is CapabilityContractTuple {
  return isRecord(value) &&
    hasRequiredKeys(value, ["capability_id", "capability_version", "capability_contract_digest"]) &&
    hasOnlyKeys(value, ["capability_id", "capability_version", "capability_contract_digest"]) &&
    typeof value.capability_id === "string" && CAPABILITY_ID_RE.test(value.capability_id) &&
    typeof value.capability_version === "string" && SEMVER_RE.test(value.capability_version) &&
    typeof value.capability_contract_digest === "string" && /^[0-9a-f]{64}$/i.test(value.capability_contract_digest);
}

/** Compare a wire tuple with one locally validated advertised capability. */
export function matchesCapabilityContract(tuple: CapabilityContractTuple, capability: Capability): boolean {
  const expected = capabilityContractTuple(capability);
  return tuple.capability_id === expected.capability_id &&
    tuple.capability_version === expected.capability_version &&
    tuple.capability_contract_digest === expected.capability_contract_digest;
}

/**
 * Digest the stable semantics of an envelope for replay receipts. Transport
 * message IDs and diagnostic timestamps deliberately do not change the
 * digest; every other present envelope member remains covered, including
 * future authenticated envelope attachments.
 */
export function envelopeSemanticDigest(envelope: Envelope): string {
  const { message_id: _messageId, timestamp: _timestamp, ...semantic } = envelope;
  return sha256(semantic as unknown as JsonObject);
}

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const CARD_SIGNATURE_DOMAIN = Buffer.from("PMX-CARD/0.1\0", "utf8");
const AUTH_SIGNATURE_DOMAIN = Buffer.from("PMX-AUTH/0.1\0", "utf8");
const ROUTED_PROVENANCE_SIGNATURE_DOMAIN = Buffer.from("PMX-ROUTED-PROVENANCE/1\0", "utf8");

function rawEd25519PublicKey(value: KeyObject): Buffer {
  const key = value.type === "private" ? createPublicKey(value) : value;
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
    throw new TypeError("An Ed25519 public key is required");
  }
  const der = key.export({ type: "spki", format: "der" });
  const encoded = Buffer.from(der);
  if (
    encoded.byteLength !== ED25519_SPKI_PREFIX.byteLength + ED25519_PUBLIC_KEY_BYTES ||
    !encoded.subarray(0, ED25519_SPKI_PREFIX.byteLength).equals(ED25519_SPKI_PREFIX)
  ) {
    throw new TypeError("Ed25519 public key has an unexpected SPKI representation");
  }
  return encoded.subarray(ED25519_SPKI_PREFIX.byteLength);
}

function publicKeyFromRawEd25519(value: string | Uint8Array): KeyObject {
  const raw = typeof value === "string"
    ? (isBase64Url(value, ED25519_PUBLIC_KEY_BYTES) ? Buffer.from(value, "base64url") : undefined)
    : Buffer.from(value);
  if (!raw || raw.byteLength !== ED25519_PUBLIC_KEY_BYTES) {
    throw new TypeError("An Ed25519 public key must be 32 raw bytes");
  }
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}

function privateEd25519Key(value: Ed25519PrivateKey): KeyObject {
  const key = value instanceof KeyObject ? value : createPrivateKey(value);
  if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") {
    throw new TypeError("An Ed25519 private key is required");
  }
  return key;
}

function sameAgentRef(left: AgentRef, right: AgentRef): boolean {
  return left.agent_id === right.agent_id && left.instance_id === right.instance_id;
}

function isAgentRefShape(value: unknown): value is AgentRef {
  return isRecord(value) && hasRequiredKeys(value, ["agent_id"]) && hasOnlyKeys(value, ["agent_id", "instance_id"]) &&
    isAgentId(value.agent_id) && (value.instance_id === undefined || isInstanceId(value.instance_id));
}

function isAgentIdentityShape(value: unknown): value is AgentIdentity {
  return isRecord(value) && hasRequiredKeys(value, ["agent_id", "instance_id"]) && hasOnlyKeys(value, ["agent_id", "instance_id"]) &&
    isAgentId(value.agent_id) && isInstanceId(value.instance_id);
}

/** Validate the closed, bounded wire shape of a routed-provenance attachment. */
export function validateRoutedProvenance(value: unknown): ValidationResult<RoutedProvenance> {
  if (!isRecord(value)) return validationFailure("Routed provenance must be an object");
  const fields = [
    "version", "broker", "source_principal", "source", "target",
    "source_session_id", "target_session_id", "envelope_digest",
    "issued_at", "expires_at", "signature",
  ];
  if (!hasRequiredKeys(value, fields) || !hasOnlyKeys(value, fields) || value.version !== ROUTED_PROVENANCE_VERSION) {
    return validationFailure("Routed provenance has unknown, missing, or unsupported fields");
  }
  if (!isRecord(value.broker) || !hasRequiredKeys(value.broker, ["agent_id", "instance_id", "key_id"]) ||
    !hasOnlyKeys(value.broker, ["agent_id", "instance_id", "key_id"]) || !isAgentId(value.broker.agent_id) ||
    !isInstanceId(value.broker.instance_id) || !isBase64Url(value.broker.key_id, ED25519_PUBLIC_KEY_BYTES)) {
    return validationFailure("Routed provenance broker identity is invalid");
  }
  if (!isRecord(value.source_principal) || !hasRequiredKeys(value.source_principal, ["principal_id", "agent_id", "key_id"]) ||
    !hasOnlyKeys(value.source_principal, ["principal_id", "agent_id", "key_id"]) ||
    !isAgentId(value.source_principal.agent_id) || !isBase64Url(value.source_principal.key_id, ED25519_PUBLIC_KEY_BYTES) ||
    value.source_principal.principal_id !== `key:${value.source_principal.key_id}`) {
    return validationFailure("Routed provenance source principal is invalid");
  }
  if (!isAgentIdentityShape(value.source) || !isAgentRefShape(value.target) ||
    value.source.agent_id !== value.source_principal.agent_id ||
    !isBase64Url(value.source_session_id, 32) || !isBase64Url(value.target_session_id, 32) ||
    typeof value.envelope_digest !== "string" || !/^[0-9a-f]{64}$/.test(value.envelope_digest) ||
    !isTimestamp(value.issued_at) || !isTimestamp(value.expires_at) ||
    !isBase64Url(value.signature, ED25519_SIGNATURE_BYTES)) {
    return validationFailure("Routed provenance binding fields are invalid");
  }
  const issuedAt = Date.parse(value.issued_at);
  const expiresAt = Date.parse(value.expires_at);
  if (expiresAt <= issuedAt || expiresAt - issuedAt > MAX_ROUTED_PROVENANCE_LIFETIME_MS) {
    return validationFailure("Routed provenance lifetime is invalid");
  }
  return { ok: true, value: value as unknown as RoutedProvenance };
}

export function isRoutedProvenance(value: unknown): value is RoutedProvenance {
  return validateRoutedProvenance(value).ok;
}

/**
 * Hash the record that a broker actually routed.  The attachment itself is
 * removed to avoid a circular signature, while the receipt semantic digest
 * keeps every other security-relevant envelope field bound.
 */
export function routedEnvelopeDigest(envelope: Envelope): string {
  const { provenance: _provenance, ...unattested } = envelope;
  return envelopeSemanticDigest(unattested as Envelope);
}

function routedProvenanceSigningPayload(provenance: Omit<RoutedProvenance, "signature">): Buffer {
  return Buffer.concat([
    ROUTED_PROVENANCE_SIGNATURE_DOMAIN,
    Buffer.from(canonicalize(provenance as unknown as JsonObject), "utf8"),
  ]);
}

/**
 * Create an Ed25519 broker attestation after the router has authenticated the
 * source session and selected a target session. Callers cannot attach one to
 * an already attested record or substitute a source principal by name.
 */
export function createRoutedProvenance(options: CreateRoutedProvenanceOptions): RoutedProvenance {
  if (options.envelope.provenance !== undefined) throw new TypeError("A routed envelope cannot carry sender-supplied provenance");
  if (!isAgentId(options.broker.agent_id) || !isInstanceId(options.broker.instance_id) || !isBase64Url(options.broker.key_id, ED25519_PUBLIC_KEY_BYTES) ||
    !isAgentIdentityShape(options.envelope.source) || !isAgentRefShape(options.envelope.target) ||
    !isBase64Url(options.sourceSessionId, 32) || !isBase64Url(options.targetSessionId, 32) ||
    options.sourcePrincipal.auth_strength !== "enrolled-key" ||
    options.sourcePrincipal.principal_id !== `key:${options.sourcePrincipal.key_id}` ||
    options.sourcePrincipal.agent_id !== options.envelope.source.agent_id ||
    !isBase64Url(options.sourcePrincipal.key_id, ED25519_PUBLIC_KEY_BYTES) ||
    !isTimestamp(options.expiresAt)) {
    throw new TypeError("Invalid routed provenance inputs");
  }
  const issuedAt = options.issuedAt ?? new Date().toISOString();
  if (!isTimestamp(issuedAt)) throw new TypeError("Routed provenance issuedAt must be RFC 3339 UTC milliseconds");
  const issuedMs = Date.parse(issuedAt);
  const expiresMs = Date.parse(options.expiresAt);
  if (expiresMs <= issuedMs || expiresMs - issuedMs > MAX_ROUTED_PROVENANCE_LIFETIME_MS) {
    throw new RangeError("Routed provenance expiry must be after issuance and no more than one minute later");
  }
  const signingIdentity = createCardIdentity(privateEd25519Key(options.privateKey));
  if (signingIdentity.key_id !== options.broker.key_id) {
    throw new TypeError("Routed provenance broker key does not match the signing key");
  }
  const unsigned: Omit<RoutedProvenance, "signature"> = {
    version: ROUTED_PROVENANCE_VERSION,
    broker: {
      agent_id: options.broker.agent_id,
      instance_id: options.broker.instance_id,
      key_id: options.broker.key_id,
    },
    source_principal: {
      principal_id: options.sourcePrincipal.principal_id,
      agent_id: options.sourcePrincipal.agent_id,
      key_id: options.sourcePrincipal.key_id,
    },
    source: {
      agent_id: options.envelope.source.agent_id,
      instance_id: options.envelope.source.instance_id,
    },
    target: options.envelope.target.instance_id === undefined
      ? { agent_id: options.envelope.target.agent_id }
      : { agent_id: options.envelope.target.agent_id, instance_id: options.envelope.target.instance_id },
    source_session_id: options.sourceSessionId,
    target_session_id: options.targetSessionId,
    envelope_digest: routedEnvelopeDigest(options.envelope),
    issued_at: issuedAt,
    expires_at: options.expiresAt,
  };
  return {
    ...unsigned,
    signature: ed25519Sign(null, routedProvenanceSigningPayload(unsigned), privateEd25519Key(options.privateKey)).toString("base64url"),
  };
}

/**
 * Verify a broker-signed routed record against the broker Card/enrollment
 * principal that the recipient established in its own secure handshake.
 */
export function verifyRoutedProvenance(envelope: Envelope, options: VerifyRoutedProvenanceOptions): boolean {
  const parsed = validateRoutedProvenance(envelope.provenance);
  if (parsed.ok === false || !isAgentIdentityShape(options.brokerIdentity) ||
    !isBase64Url(options.targetSessionId, 32) || options.brokerPrincipal.auth_strength !== "enrolled-key") {
    return false;
  }
  const provenance = parsed.value;
  const now = options.now ?? Date.now();
  if (!Number.isFinite(now) || Date.parse(provenance.issued_at) > now || Date.parse(provenance.expires_at) <= now) return false;
  if (provenance.broker.agent_id !== options.brokerPrincipal.agent_id ||
    provenance.broker.agent_id !== options.brokerIdentity.agent_id ||
    provenance.broker.instance_id !== options.brokerIdentity.instance_id ||
    provenance.broker.key_id !== options.brokerPrincipal.key_id ||
    options.brokerPrincipal.principal_id !== `key:${options.brokerPrincipal.key_id}` ||
    provenance.target_session_id !== options.targetSessionId ||
    provenance.source_principal.principal_id !== `key:${provenance.source_principal.key_id}` ||
    provenance.source_principal.agent_id !== envelope.source.agent_id ||
    !sameAgentRef(provenance.source, envelope.source) || !sameAgentRef(provenance.target, envelope.target) ||
    provenance.envelope_digest !== routedEnvelopeDigest(envelope)) {
    return false;
  }
  try {
    const identity = createCardIdentity(options.brokerPrincipal.public_key);
    if (identity.key_id !== options.brokerPrincipal.key_id) return false;
    const { signature: _signature, ...unsigned } = provenance;
    void _signature;
    return ed25519Verify(
      null,
      routedProvenanceSigningPayload(unsigned),
      publicKeyFromRawEd25519(options.brokerPrincipal.public_key),
      Buffer.from(provenance.signature, "base64url"),
    );
  } catch {
    return false;
  }
}

/** Create the public Card identity associated with an Ed25519 public key. */
export function createCardIdentity(publicKey: KeyObject | Uint8Array | string): CardIdentity {
  const raw = publicKey instanceof KeyObject
    ? rawEd25519PublicKey(publicKey)
    : typeof publicKey === "string"
      ? (isBase64Url(publicKey, ED25519_PUBLIC_KEY_BYTES) ? Buffer.from(publicKey, "base64url") : Buffer.alloc(0))
      : Buffer.from(publicKey);
  if (raw.byteLength !== ED25519_PUBLIC_KEY_BYTES) {
    throw new TypeError("An Ed25519 public key must be 32 raw bytes");
  }
  const public_key = raw.toString("base64url");
  if (!isBase64Url(public_key, ED25519_PUBLIC_KEY_BYTES)) {
    throw new TypeError("Ed25519 public key must use canonical base64url encoding");
  }
  return {
    alg: IDENTITY_ALGORITHM,
    key_id: createHash("sha256").update(raw).digest("base64url"),
    public_key,
  };
}

/** Derive a Card identity from the public half of an Ed25519 private key. */
export function createCardIdentityFromPrivateKey(privateKey: Ed25519PrivateKey): CardIdentity {
  return createCardIdentity(privateEd25519Key(privateKey));
}

export function isCardIdentity(value: unknown): value is CardIdentity {
  if (!isRecord(value) || !hasRequiredKeys(value, ["alg", "key_id", "public_key"]) || !hasOnlyKeys(value, ["alg", "key_id", "public_key"])) return false;
  if (value.alg !== IDENTITY_ALGORITHM || !isBase64Url(value.public_key, ED25519_PUBLIC_KEY_BYTES) || !isBase64Url(value.key_id, 32)) return false;
  const expected = createHash("sha256").update(Buffer.from(value.public_key, "base64url")).digest("base64url");
  return value.key_id === expected;
}

/** Canonical, domain-separated bytes signed for an Agent Card. */
export function cardSigningPayload(card: AgentCard): Buffer {
  const { signature: _signature, ...unsigned } = card;
  void _signature;
  return Buffer.concat([CARD_SIGNATURE_DOMAIN, Buffer.from(canonicalize(unsigned as unknown as JsonValue), "utf8")]);
}

/** Sign a Card after binding it to the supplied Ed25519 private key. */
export function signAgentCard(card: AgentCard, privateKey: Ed25519PrivateKey): AgentCard {
  const key = privateEd25519Key(privateKey);
  const identity = createCardIdentity(key);
  if (card.identity !== undefined && (
    card.identity.alg !== identity.alg ||
    card.identity.key_id !== identity.key_id ||
    card.identity.public_key !== identity.public_key
  )) {
    throw new TypeError("Card identity does not match the signing key");
  }
  const unsigned: AgentCard = { ...card, identity };
  delete unsigned.signature;
  const signature = ed25519Sign(null, cardSigningPayload(unsigned), key).toString("base64url");
  return { ...unsigned, signature };
}

/** Verify a Card's self-signature, without treating it as enrollment. */
export function verifyAgentCardSignature(card: AgentCard): boolean {
  if (!isCardIdentity(card.identity) || !isBase64Url(card.signature, ED25519_SIGNATURE_BYTES)) return false;
  try {
    return ed25519Verify(
      null,
      cardSigningPayload(card),
      publicKeyFromRawEd25519(card.identity.public_key),
      Buffer.from(card.signature, "base64url"),
    );
  } catch {
    return false;
  }
}

function normalizeEnrollment(value: Enrollment): Enrollment {
  if (!isAgentId(value.agent_id) || !isCardIdentity({
    alg: IDENTITY_ALGORITHM,
    key_id: value.key_id,
    public_key: value.public_key,
  })) {
    throw new TypeError("Enrollment must contain a valid agent ID and Ed25519 key binding");
  }
  if (value.enabled !== undefined && typeof value.enabled !== "boolean") throw new TypeError("Enrollment enabled must be boolean");
  if (value.expires_at !== undefined && !isTimestamp(value.expires_at)) throw new TypeError("Enrollment expiry must be RFC 3339 UTC");
  return Object.freeze({
    agent_id: value.agent_id,
    key_id: value.key_id,
    public_key: value.public_key,
    ...(value.enabled === undefined ? {} : { enabled: value.enabled }),
    ...(value.expires_at === undefined ? {} : { expires_at: value.expires_at }),
  });
}

/**
 * A small, immutable-key enrollment map.  Production callers can rebuild it
 * from their durable enrollment store after an administrative change; this
 * reference type deliberately does not learn identity material from peers.
 */
export class EnrollmentStore {
  private readonly records = new Map<string, Enrollment>();

  constructor(enrollments: readonly Enrollment[] = []) {
    for (const enrollment of enrollments) this.enroll(enrollment);
  }

  enroll(value: Enrollment): Enrollment {
    const enrollment = normalizeEnrollment(value);
    const key = this.key(enrollment.agent_id, enrollment.key_id);
    const prior = this.records.get(key);
    if (prior && (prior.public_key !== enrollment.public_key || prior.agent_id !== enrollment.agent_id)) {
      throw new TypeError("Enrollment key collision");
    }
    this.records.set(key, enrollment);
    return enrollment;
  }

  resolve(agentId: string, keyId: string, now = Date.now()): Enrollment | undefined {
    const enrollment = this.records.get(this.key(agentId, keyId));
    if (!enrollment || enrollment.enabled === false) return undefined;
    if (enrollment.expires_at !== undefined && Date.parse(enrollment.expires_at) <= now) return undefined;
    return enrollment;
  }

  verifyCard(card: AgentCard, now = Date.now()): VerifiedPrincipal | undefined {
    if (!card.identity || !verifyAgentCardSignature(card)) return undefined;
    const enrollment = this.resolve(card.agent_id, card.identity.key_id, now);
    if (!enrollment || enrollment.public_key !== card.identity.public_key) return undefined;
    return {
      principal_id: `key:${enrollment.key_id}`,
      agent_id: enrollment.agent_id,
      key_id: enrollment.key_id,
      public_key: enrollment.public_key,
      auth_strength: "enrolled-key",
    };
  }

  private key(agentId: string, keyId: string): string {
    return `${agentId}\0${keyId}`;
  }
}

export function verifyEnrolledCard(card: AgentCard, enrollments: EnrollmentStore, now = Date.now()): VerifiedPrincipal | undefined {
  return enrollments.verifyCard(card, now);
}

export interface AuthTranscriptInput {
  initiator_hello: HelloFrame;
  responder_hello: HelloFrame;
  initiator_card_digest: string;
  responder_card_digest: string;
  /** Base64url TLS exporter material, never a session ID or token. */
  tls_channel_binding: string;
}

/**
 * Construct the exact authenticated transcript used by both peers.  It binds
 * roles, nonces, profile selection, cards, and the TLS channel so a proof
 * from one connection cannot be replayed in another.
 */
export function authTranscript(input: AuthTranscriptInput): Buffer {
  const initiator = input.initiator_hello;
  const responder = input.responder_hello;
  if (
    initiator.role !== "initiator" || responder.role !== "responder" ||
    initiator.security_profile !== SECURE_IDENTITY_PROFILE ||
    responder.security_profile !== SECURE_IDENTITY_PROFILE ||
    !isNonce(initiator.nonce) || !isNonce(responder.nonce) ||
    responder.echo !== initiator.nonce ||
    !isBase64Url(responder.sid, 32) ||
    !/^[0-9a-f]{64}$/i.test(input.initiator_card_digest) ||
    !/^[0-9a-f]{64}$/i.test(input.responder_card_digest) ||
    !isBase64Url(input.tls_channel_binding, 32)
  ) {
    throw new TypeError("Invalid secure handshake transcript");
  }
  return Buffer.concat([
    AUTH_SIGNATURE_DOMAIN,
    Buffer.from(canonicalize({
      protocol: PROTOCOL_VERSION,
      handshake_version: HANDSHAKE_VERSION,
      security_profile: SECURE_IDENTITY_PROFILE,
      initiator_hello: initiator as unknown as JsonObject,
      responder_hello: responder as unknown as JsonObject,
      initiator_card_digest: input.initiator_card_digest,
      responder_card_digest: input.responder_card_digest,
      tls_channel_binding: input.tls_channel_binding,
    }), "utf8"),
  ]);
}

export function createAuthProof(
  identity: CardIdentity,
  agentId: string,
  sid: string,
  transcript: Uint8Array,
  privateKey: Ed25519PrivateKey,
): AuthFrame {
  if (!isCardIdentity(identity) || !isAgentId(agentId) || !isBase64Url(sid, 32)) throw new TypeError("Invalid authenticated handshake identity");
  const key = privateEd25519Key(privateKey);
  const expected = createCardIdentity(key);
  if (expected.key_id !== identity.key_id || expected.public_key !== identity.public_key) {
    throw new TypeError("Handshake identity does not match proof key");
  }
  return {
    type: "auth",
    sid,
    agent_id: agentId,
    key_id: identity.key_id,
    signature: ed25519Sign(null, Buffer.from(transcript), key).toString("base64url"),
  };
}

/** Verify proof possession and return only a locally enrolled principal. */
export function verifyAuthProof(
  proof: AuthFrame,
  transcript: Uint8Array,
  enrollments: EnrollmentStore,
  now = Date.now(),
): VerifiedPrincipal | undefined {
  const enrollment = enrollments.resolve(proof.agent_id, proof.key_id, now);
  if (!enrollment || !isBase64Url(proof.signature, ED25519_SIGNATURE_BYTES)) return undefined;
  try {
    const valid = ed25519Verify(
      null,
      Buffer.from(transcript),
      publicKeyFromRawEd25519(enrollment.public_key),
      Buffer.from(proof.signature, "base64url"),
    );
    return valid
      ? {
        principal_id: `key:${enrollment.key_id}`,
        agent_id: enrollment.agent_id,
        key_id: enrollment.key_id,
        public_key: enrollment.public_key,
        auth_strength: "enrolled-key",
      }
      : undefined;
  } catch {
    return undefined;
  }
}

/** SHA-256 hex digest of the RFC-8785-style canonical Agent Card JSON. */
export function cardDigest(card: AgentCard): string {
  return sha256(card as unknown as JsonObject);
}

export const digestCard = cardDigest;
export const canonicalCardDigest = cardDigest;

/**
 * The dependency-free reference implementation deliberately supports a small,
 * closed schema profile.  It must reject rather than ignore any JSON Schema
 * assertion outside this profile; callers needing complete Draft 2020-12
 * semantics should compile schemas with a hardened full validator before
 * placing them in an Agent Card.
 */
export const RESTRICTED_SCHEMA_PROFILE = "polymesh.restricted-json-schema/1" as const;

const RESTRICTED_SCHEMA_TYPES = new Set(["object", "array", "string", "number", "integer", "boolean", "null"]);
const RESTRICTED_SCHEMA_FIELDS = new Set([
  "$schema",
  "type",
  "const",
  "enum",
  "anyOf",
  "oneOf",
  "allOf",
  "properties",
  "required",
  "additionalProperties",
  "items",
  "minLength",
  "maxLength",
  "minimum",
  "maximum",
  "minItems",
  "maxItems",
]);

interface SchemaBudget {
  nodes: number;
}

/** Validate the explicit, non-executable reference schema profile. */
export function validateRestrictedSchema(value: unknown): ValidationResult<JsonObject> {
  const budget: SchemaBudget = { nodes: 0 };
  const check = (schema: unknown, depth: number): string | undefined => {
    if (++budget.nodes > 4_096 || depth > 32) return "Schema exceeds structural limits";
    if (!isRecord(schema) || !isJsonValue(schema)) return "Schema must be a JSON object";
    if (!Object.keys(schema).every((key) => RESTRICTED_SCHEMA_FIELDS.has(key))) return "Schema contains an unsupported keyword";
    if (schema.$schema !== undefined && schema.$schema !== RESTRICTED_SCHEMA_PROFILE) return "Schema declares an unsupported profile";
    if (schema.type !== undefined) {
      const types = Array.isArray(schema.type) ? schema.type : [schema.type];
      if (types.length === 0 || types.length > RESTRICTED_SCHEMA_TYPES.size || types.some((type) => typeof type !== "string" || !RESTRICTED_SCHEMA_TYPES.has(type)) || new Set(types).size !== types.length) {
        return "Schema type is invalid";
      }
    }
    if (schema.const !== undefined && !isJsonValue(schema.const)) return "Schema const is invalid";
    if (schema.enum !== undefined && (!Array.isArray(schema.enum) || schema.enum.length === 0 || schema.enum.length > 64 || schema.enum.some((entry) => !isJsonValue(entry)))) return "Schema enum is invalid";
    for (const composition of ["anyOf", "oneOf", "allOf"] as const) {
      const branches = schema[composition];
      if (branches === undefined) continue;
      if (!Array.isArray(branches) || branches.length === 0 || branches.length > 32) return `Schema ${composition} is invalid`;
      for (const branch of branches) {
        const error = check(branch, depth + 1);
        if (error) return error;
      }
    }
    if (schema.properties !== undefined) {
      if (!isRecord(schema.properties) || Object.keys(schema.properties).length > 1_024) return "Schema properties is invalid";
      for (const child of Object.values(schema.properties)) {
        const error = check(child, depth + 1);
        if (error) return error;
      }
    }
    if (schema.required !== undefined && (!Array.isArray(schema.required) || schema.required.length > 1_024 || schema.required.some((name) => typeof name !== "string" || !isBoundedString(name, 255)) || new Set(schema.required).size !== schema.required.length)) {
      return "Schema required is invalid";
    }
    if (schema.additionalProperties !== undefined && typeof schema.additionalProperties !== "boolean") return "Schema additionalProperties is invalid";
    if (schema.items !== undefined) {
      const error = check(schema.items, depth + 1);
      if (error) return error;
    }
    for (const keyword of ["minLength", "maxLength", "minItems", "maxItems"] as const) {
      if (schema[keyword] !== undefined && !isFiniteInteger(schema[keyword], 0)) return `Schema ${keyword} is invalid`;
    }
    const minLength = schema.minLength;
    const maxLength = schema.maxLength;
    if (typeof minLength === "number" && typeof maxLength === "number" && minLength > maxLength) return "Schema string bounds are invalid";
    const minItems = schema.minItems;
    const maxItems = schema.maxItems;
    if (typeof minItems === "number" && typeof maxItems === "number" && minItems > maxItems) return "Schema array bounds are invalid";
    for (const keyword of ["minimum", "maximum"] as const) {
      if (schema[keyword] !== undefined && (typeof schema[keyword] !== "number" || !Number.isFinite(schema[keyword]))) return `Schema ${keyword} is invalid`;
    }
    const minimum = schema.minimum;
    const maximum = schema.maximum;
    if (typeof minimum === "number" && typeof maximum === "number" && minimum > maximum) return "Schema numeric bounds are invalid";
    return undefined;
  };
  const error = check(value, 1);
  return error === undefined ? { ok: true, value: value as JsonObject } : validationFailure(error);
}

export function validateCapability(value: unknown): ValidationResult<Capability> {
  if (!isRecord(value)) return validationFailure("Capability must be an object");
  const allowed = ["id", "version", "description", "input_schema", "result_schema", "idempotency", "side_effects", "approval", "cancellation", "timeout_ceiling_seconds"];
  if (!hasRequiredKeys(value, ["id", "version"]) || !hasOnlyKeys(value, allowed)) return validationFailure("Capability has unknown or missing fields");
  if (!hasString(value, "id") || !CAPABILITY_ID_RE.test(value.id) || value.id.length > 255) return validationFailure("Capability id is invalid");
  if (!hasString(value, "version") || !SEMVER_RE.test(value.version) || value.version.length > 32) return validationFailure("Capability version is invalid");
  if (value.description !== undefined && !isBoundedString(value.description)) return validationFailure("Capability description must be a bounded string");
  for (const field of ["input_schema", "result_schema"] as const) {
    const schema = value[field];
    if (schema === undefined) continue;
    if (!isRecord(schema) || !isJsonValue(schema) || (serializedJsonBytes(schema) ?? Number.POSITIVE_INFINITY) > MAX_SCHEMA_BYTES_PER_CAPABILITY) {
      return validationFailure(`Capability ${field} must be a bounded JSON object`);
    }
    const schemaValidation = validateRestrictedSchema(schema);
    if (schemaValidation.ok === false) return validationFailure(`Capability ${field} is not in the restricted secure schema profile: ${schemaValidation.error}`);
  }
  if (value.idempotency !== undefined && !["pure", "idempotent", "sensitive"].includes(String(value.idempotency))) return validationFailure("Capability idempotency is invalid");
  if (value.side_effects !== undefined && !["none", "read", "write", "network", "approval"].includes(String(value.side_effects))) return validationFailure("Capability side_effects is invalid");
  if (value.approval !== undefined && !["never", "always", "threshold"].includes(String(value.approval))) return validationFailure("Capability approval is invalid");
  if (value.cancellation !== undefined && !["none", "best_effort", "supported"].includes(String(value.cancellation))) return validationFailure("Capability cancellation is invalid");
  if (value.timeout_ceiling_seconds !== undefined && !isFiniteInteger(value.timeout_ceiling_seconds, 1)) return validationFailure("Capability timeout_ceiling_seconds is invalid");
  return { ok: true, value: value as unknown as Capability };
}

export function validateAgentCard(value: unknown, now = Date.now()): ValidationResult<AgentCard> {
  if (!isRecord(value)) return validationFailure("Card must be an object");
  const allowed = ["card_version", "agent_id", "instance_id", "display_name", "issued_at", "expires_at", "revision", "endpoints", "capabilities", "limits", "metadata", "identity", "signature"];
  const required = ["card_version", "agent_id", "instance_id", "issued_at", "expires_at", "revision", "capabilities"];
  if (!hasRequiredKeys(value, required) || !hasOnlyKeys(value, allowed)) return validationFailure("Card has unknown or missing fields");
  if (!isJsonValue(value) || (serializedJsonBytes(value) ?? Number.POSITIVE_INFINITY) > MAX_CARD_BYTES) return validationFailure("Card exceeds JSON resource limits");
  if (value.card_version !== CARD_VERSION) return validationFailure(`Card version must be ${CARD_VERSION}`);
  if (!isAgentId(value.agent_id)) return validationFailure("Card agent_id is invalid");
  if (!isInstanceId(value.instance_id)) return validationFailure("Card instance_id is invalid");
  if (!isTimestamp(value.issued_at) || !isTimestamp(value.expires_at)) return validationFailure("Card timestamps are invalid");
  if (Date.parse(value.expires_at) <= Date.parse(value.issued_at)) return validationFailure("Card expires_at must be after issued_at");
  if (!isFiniteInteger(value.revision, 1)) return validationFailure("Card revision is invalid");
  if (!Array.isArray(value.capabilities) || value.capabilities.length === 0 || value.capabilities.length > MAX_CAPABILITIES_PER_CARD) return validationFailure("Card capabilities must be non-empty and bounded");
  const capabilityIds = new Set<string>();
  for (const capability of value.capabilities) {
    const result = validateCapability(capability);
    if (result.ok === false) return validationFailure(result.error);
    if (capabilityIds.has(result.value.id)) return validationFailure(`Card contains duplicate capability ${result.value.id}`);
    capabilityIds.add(result.value.id);
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
  if (value.display_name !== undefined && !isBoundedString(value.display_name)) return validationFailure("Card display_name must be a bounded string");
  if (value.endpoints !== undefined) {
    if (!Array.isArray(value.endpoints) || value.endpoints.length > MAX_ENDPOINTS_PER_CARD) return validationFailure("Card endpoints must be a bounded array");
    for (const endpoint of value.endpoints) {
      if (!isRecord(endpoint) || !hasRequiredKeys(endpoint, ["transport", "url", "scope"]) || !hasOnlyKeys(endpoint, ["transport", "url", "scope", "security"]) || !["websocket", "unix"].includes(String(endpoint.transport)) || !isBoundedString(endpoint.url, 2_048) || !["loopback", "lan", "remote"].includes(String(endpoint.scope))) {
        return validationFailure("Card endpoint is invalid");
      }
      try {
        const url = new URL(endpoint.url);
        if (url.username || url.password || url.hash || url.search) return validationFailure("Card endpoint contains forbidden URL components");
        if (endpoint.transport === "websocket") {
          if (!url.hostname || !["ws:", "wss:"].includes(url.protocol)) return validationFailure("Card WebSocket endpoint is invalid");
          if (endpoint.scope === "loopback" && url.protocol !== "ws:" && url.protocol !== "wss:") return validationFailure("Card loopback endpoint is invalid");
          if (endpoint.scope !== "loopback" && url.protocol !== "wss:") return validationFailure("LAN and remote WebSocket endpoints require WSS");
        } else if (url.protocol !== "unix:" || url.hostname || !url.pathname.startsWith("/") || url.pathname.split("/").includes("..")) {
          return validationFailure("Card Unix endpoint is invalid");
        }
      } catch {
        return validationFailure("Card endpoint URL is invalid");
      }
      if (endpoint.security !== undefined && !["none", "token", "mutual"].includes(String(endpoint.security))) return validationFailure("Card endpoint security is invalid");
    }
  }
  if (value.limits !== undefined && (!isRecord(value.limits) || !hasOnlyKeys(value.limits, ["max_task_timeout_ms", "max_tasks_per_principal", "max_input_bytes", "max_result_bytes"]) || !Object.values(value.limits).every((limit) => isFiniteInteger(limit, 0)))) return validationFailure("Card limits are invalid");
  if (value.metadata !== undefined && (!isRecord(value.metadata) || !isJsonValue(value.metadata))) return validationFailure("Card metadata is invalid");
  if ((value.identity === undefined) !== (value.signature === undefined)) return validationFailure("Card identity and signature must be present together");
  if (value.identity !== undefined) {
    if (!isCardIdentity(value.identity) || !isBase64Url(value.signature, ED25519_SIGNATURE_BYTES)) return validationFailure("Card identity or signature is invalid");
    if (!verifyAgentCardSignature(value as unknown as AgentCard)) return validationFailure("Card signature is invalid");
  }
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
  const suppliedIds = new Set<string>();
  for (const capability of supplied) {
    if (suppliedIds.has(capability.id)) throw new TypeError(`Duplicate capability ${capability.id}`);
    suppliedIds.add(capability.id);
  }
  const capabilities = options.include_standard_capabilities === false
    ? supplied
    : [...STANDARD_CAPABILITIES, ...supplied.filter((candidate) => !STANDARD_CAPABILITIES.some((base) => base.id === candidate.id))];
  const card: AgentCard = {
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
    ...(options.identity === undefined ? {} : { identity: options.identity }),
    ...(options.signature === undefined ? {} : { signature: options.signature }),
  };
  const validated = validateAgentCard(card);
  if (validated.ok === false) throw new TypeError(`Cannot create invalid Agent Card: ${validated.error}`);
  return validated.value;
}

function validateTerminal(terminal: JsonObject): string | undefined {
  if (!hasRequiredKeys(terminal, ["outcome", "completed_at"]) || !hasOnlyKeys(terminal, ["outcome", "completed_at", "result", "error", "cancellation"])) {
    return "Terminal record has unknown or missing fields";
  }
  if (!isTimestamp(terminal.completed_at)) return "Terminal completion timestamp is invalid";
  if (terminal.outcome === "succeeded") {
    if (!Object.hasOwn(terminal, "result") || Object.hasOwn(terminal, "error") || Object.hasOwn(terminal, "cancellation") || !isJsonValue(terminal.result)) {
      return "Succeeded terminal must contain only a JSON result";
    }
    return undefined;
  }
  if (terminal.outcome === "failed") {
    if (!isRecord(terminal.error) || Object.hasOwn(terminal, "result") || Object.hasOwn(terminal, "cancellation") || !hasRequiredKeys(terminal.error, ["code", "message"]) || !hasOnlyKeys(terminal.error, ["code", "message", "details"]) || !isBoundedString(terminal.error.code, 128) || !isBoundedString(terminal.error.message, 8_192) || (terminal.error.details !== undefined && !isRecord(terminal.error.details))) {
      return "Failed terminal must contain only a structured error";
    }
    return undefined;
  }
  if (terminal.outcome === "cancelled") {
    if (!isRecord(terminal.cancellation) || Object.hasOwn(terminal, "result") || Object.hasOwn(terminal, "error") || !hasRequiredKeys(terminal.cancellation, ["code"]) || !hasOnlyKeys(terminal.cancellation, ["code", "message"]) || !isBoundedString(terminal.cancellation.code, 128) || (terminal.cancellation.message !== undefined && !isBoundedString(terminal.cancellation.message, 8_192))) {
      return "Cancelled terminal must contain only structured cancellation details";
    }
    return undefined;
  }
  return "Terminal outcome is invalid";
}

function validateParams(type: MessageType, params: JsonObject): string | undefined {
  const taskId = params.task_id;
  const eventSeq = params.event_seq;
  switch (type) {
    case "card":
      if (!hasRequiredKeys(params, ["card", "digest"]) || !hasOnlyKeys(params, ["card", "digest"]) || !isAgentCard(params.card) || typeof params.digest !== "string" || !/^[0-9a-f]{64}$/i.test(params.digest) || cardDigest(params.card) !== params.digest) return "Invalid card params";
      return undefined;
    case "task.submit":
      if (!hasRequiredKeys(params, ["task_id", "method", "capability_version", "capability_contract_digest", "params", "deadline"]) || !hasOnlyKeys(params, ["task_id", "method", "capability_version", "capability_contract_digest", "params", "deadline"]) || !isUuidV7(taskId) || !isBoundedString(params.method, 255) || !CAPABILITY_ID_RE.test(params.method) || !isBoundedString(params.capability_version, 32) || !SEMVER_RE.test(params.capability_version) || typeof params.capability_contract_digest !== "string" || !/^[0-9a-f]{64}$/i.test(params.capability_contract_digest) || !isRecord(params.params) || !isJsonValue(params.params) || !isTimestamp(params.deadline)) return "Invalid task.submit params";
      return undefined;
    case "task.accepted":
      if (!hasRequiredKeys(params, ["task_id", "event_seq", "accepted_at", "capability_id", "capability_version", "capability_contract_digest"]) || !hasOnlyKeys(params, ["task_id", "event_seq", "accepted_at", "capability_id", "capability_version", "capability_contract_digest"]) || !isUuidV7(taskId) || eventSeq !== 1 || !isTimestamp(params.accepted_at) || !isCapabilityContractTuple({
        capability_id: params.capability_id,
        capability_version: params.capability_version,
        capability_contract_digest: params.capability_contract_digest,
      })) return "Invalid task.accepted params";
      return undefined;
    case "task.rejected":
      if (!hasRequiredKeys(params, ["task_id", "event_seq", "code", "message"]) || !hasOnlyKeys(params, ["task_id", "event_seq", "code", "message"]) || !isUuidV7(taskId) || eventSeq !== 1 || !isBoundedString(params.code, 128) || !isBoundedString(params.message, 8_192)) return "Invalid task.rejected params";
      return undefined;
    case "task.progress":
      if (!hasRequiredKeys(params, ["task_id", "event_seq", "progress"]) || !hasOnlyKeys(params, ["task_id", "event_seq", "progress"]) || !isUuidV7(taskId) || !isFiniteInteger(eventSeq, 2) || !isRecord(params.progress) || !isJsonValue(params.progress)) return "Invalid task.progress params";
      return undefined;
    case "task.completed":
      if (!hasRequiredKeys(params, ["task_id", "event_seq", "terminal", "capability_id", "capability_version", "capability_contract_digest"]) || !hasOnlyKeys(params, ["task_id", "event_seq", "terminal", "capability_id", "capability_version", "capability_contract_digest"]) || !isUuidV7(taskId) || !isFiniteInteger(eventSeq, 2) || !isRecord(params.terminal) || !isCapabilityContractTuple({
        capability_id: params.capability_id,
        capability_version: params.capability_version,
        capability_contract_digest: params.capability_contract_digest,
      })) return "Invalid task.completed params";
      return validateTerminal(params.terminal);
    case "task.cancel":
      if (!hasRequiredKeys(params, ["task_id"]) || !hasOnlyKeys(params, ["task_id", "reason"]) || !isUuidV7(taskId) || (params.reason !== undefined && !isBoundedString(params.reason, 8_192))) return "Invalid task.cancel params";
      return undefined;
    case "task.status":
      if (params.kind === "query" && hasRequiredKeys(params, ["kind", "task_id"]) && hasOnlyKeys(params, ["kind", "task_id"]) && isUuidV7(taskId)) return undefined;
      if (params.kind === "snapshot" && hasRequiredKeys(params, ["kind", "task_id", "observed_at"]) && hasOnlyKeys(params, ["kind", "task_id", "observed_at", "state", "event_seq", "terminal", "progress"]) && isUuidV7(taskId) && isTimestamp(params.observed_at)) return undefined;
      return "Invalid task.status params";
    case "ping":
    case "pong":
      return hasRequiredKeys(params, ["n"]) && hasOnlyKeys(params, ["n"]) && isFiniteInteger(params.n, 0) ? undefined : `Invalid ${type} params`;
    case "receipt":
      return hasRequiredKeys(params, ["received_message_id", "semantic_digest", "disposition"]) &&
        hasOnlyKeys(params, ["received_message_id", "semantic_digest", "disposition"]) &&
        isUuidV7(params.received_message_id) &&
        typeof params.semantic_digest === "string" && /^[0-9a-f]{64}$/i.test(params.semantic_digest) &&
        (params.disposition === "accepted" || params.disposition === "duplicate" || params.disposition === "rejected")
        ? undefined
        : "Invalid receipt params";
    case "error":
      if (!hasRequiredKeys(params, ["category", "code", "message", "retryable", "retry_after_ms"]) || !hasOnlyKeys(params, ["category", "code", "message", "retryable", "retry_after_ms", "details"]) || !ERROR_CATEGORY_SET.has(String(params.category)) || !isBoundedString(params.code, 128) || !isBoundedString(params.message, 8_192) || typeof params.retryable !== "boolean" || !(params.retry_after_ms === null || isFiniteInteger(params.retry_after_ms, 0)) || (params.details !== undefined && (!isRecord(params.details) || !isJsonValue(params.details)))) return "Invalid error params";
      return undefined;
  }
}

/** Validate a complete, application-level v0.1 envelope. */
export function validateEnvelope(value: unknown): ValidationResult<Envelope> {
  if (!isRecord(value)) return validationFailure("Envelope must be an object");
  const envelopeFields = ["protocol", "type", "message_id", "timestamp", "source", "target", "delivery", "in_reply_to", "provenance", "params"];
  const requiredFields = ["protocol", "type", "message_id", "timestamp", "source", "target", "delivery", "params"];
  if (!hasRequiredKeys(value, requiredFields) || !hasOnlyKeys(value, envelopeFields)) return validationFailure("Envelope has unknown or missing fields");
  if (value.protocol !== PROTOCOL_VERSION) return validationFailure(`Unsupported protocol: ${String(value.protocol)}`);
  if (typeof value.type !== "string" || !MESSAGE_TYPE_SET.has(value.type)) return validationFailure("Envelope type is invalid");
  if (!isUuidV7(value.message_id)) return validationFailure("Envelope message_id must be UUIDv7");
  if (!isTimestamp(value.timestamp)) return validationFailure("Envelope timestamp is invalid");
  if (!isRecord(value.source) || !hasRequiredKeys(value.source, ["agent_id", "instance_id"]) || !hasOnlyKeys(value.source, ["agent_id", "instance_id"]) || !isAgentId(value.source.agent_id) || !isInstanceId(value.source.instance_id)) return validationFailure("Envelope source is invalid");
  if (!isRecord(value.target) || !hasRequiredKeys(value.target, ["agent_id"]) || !hasOnlyKeys(value.target, ["agent_id", "instance_id"]) || !isAgentId(value.target.agent_id) || (value.target.instance_id !== undefined && !isInstanceId(value.target.instance_id))) return validationFailure("Envelope target is invalid");
  if (!isRecord(value.delivery) || !hasRequiredKeys(value.delivery, ["mode", "idempotency_key", "deadline"]) || !hasOnlyKeys(value.delivery, ["mode", "idempotency_key", "deadline"]) || value.delivery.mode !== "at_least_once" || !isBoundedString(value.delivery.idempotency_key, MAX_IDEMPOTENCY_KEY_BYTES) || value.delivery.idempotency_key.length === 0 || !isTimestamp(value.delivery.deadline)) return validationFailure("Envelope delivery is invalid");
  if (value.in_reply_to !== undefined && !isUuidV7(value.in_reply_to)) return validationFailure("Envelope in_reply_to is invalid");
  if (value.provenance !== undefined) {
    const provenance = validateRoutedProvenance(value.provenance);
    if (provenance.ok === false) return validationFailure(provenance.error);
  }
  if (!isRecord(value.params) || !isJsonValue(value.params)) return validationFailure("Envelope params must be a JSON object");
  const parameterError = validateParams(value.type as MessageType, value.params as JsonObject);
  if (parameterError) return validationFailure(parameterError);
  if (value.type === "task.submit" && (value.params as JsonObject).deadline !== value.delivery.deadline) {
    return validationFailure("task.submit params.deadline must exactly match delivery.deadline");
  }
  if (value.type === "receipt") {
    const receipt = value.params as ReceiptParams;
    if (value.in_reply_to !== receipt.received_message_id) {
      return validationFailure("receipt in_reply_to must exactly match received_message_id");
    }
  }
  return { ok: true, value: value as unknown as Envelope };
}

export function isEnvelope(value: unknown): value is Envelope {
  return validateEnvelope(value).ok;
}

export interface V2ApplicationEnvelopeValidationOptions {
  /** Require serialized mesh scope and bind both addresses to this session mesh. */
  meshId?: V2MeshId;
  /** Reject the local-only paired mesh omission. */
  requireMesh?: boolean;
}

/**
 * Strict, closed validation for one `polymesh.0.2` application envelope.
 * This is deliberately not a v0.1 adapter: v2 keeps delivery_id inside the
 * delivery object, has no raw-card/receipt/ping application messages, and
 * binds paired address mesh omissions only in the local-only profile.
 */
export function validateV2ApplicationEnvelope(
  value: unknown,
  options: V2ApplicationEnvelopeValidationOptions = {},
): ValidationResult<V2ApplicationEnvelope> {
  if (!isRecord(value)) return validationFailure("v0.2 envelope must be an object");
  const fields = ["protocol", "type", "message_id", "timestamp", "source", "target", "delivery", "in_reply_to", "params"];
  const required = ["protocol", "type", "message_id", "timestamp", "source", "target", "delivery", "params"];
  if (!hasRequiredKeys(value, required) || !hasOnlyKeys(value, fields) || value.protocol !== V2_PROTOCOL_VERSION ||
    typeof value.type !== "string" || !V2_APPLICATION_MESSAGE_TYPES.includes(value.type as V2ApplicationMessageType) ||
    !isUuidV7(value.message_id) || !isTimestamp(value.timestamp) ||
    !isV2SourceAddress(value.source) || !isV2TargetAddress(value.target) || !isV2Delivery(value.delivery) ||
    (value.in_reply_to !== undefined && !isUuidV7(value.in_reply_to)) || !isRecord(value.params) || !isJsonValue(value.params)) {
    return validationFailure("v0.2 envelope has an invalid, unknown, or missing field");
  }
  const source = value.source as Record<string, unknown>;
  const target = value.target as Record<string, unknown>;
  const sourceMesh = source.mesh_id;
  const targetMesh = target.mesh_id;
  if ((sourceMesh === undefined) !== (targetMesh === undefined) ||
    (sourceMesh !== undefined && sourceMesh !== targetMesh) ||
    (options.requireMesh === true && sourceMesh === undefined) ||
    (options.meshId !== undefined && (sourceMesh !== options.meshId || targetMesh !== options.meshId))) {
    return validationFailure("v0.2 envelope mesh scope does not match the session");
  }
  const parameterError = validateV2ApplicationParams(value.type as V2ApplicationMessageType, value.params as JsonObject);
  if (parameterError !== undefined) return validationFailure(parameterError);
  if (value.type === "task.submit" && (value.params as JsonObject).deadline !== (value.delivery as JsonObject).deadline) {
    return validationFailure("v0.2 task.submit params.deadline must exactly match delivery.deadline");
  }
  return { ok: true, value: value as unknown as V2ApplicationEnvelope };
}

export function isV2ApplicationEnvelope(
  value: unknown,
  options?: V2ApplicationEnvelopeValidationOptions,
): value is V2ApplicationEnvelope {
  return validateV2ApplicationEnvelope(value, options).ok;
}

function isV2AgentId(value: unknown): value is string {
  return typeof value === "string" && value.length >= 1 && value.length <= 128 &&
    /^(?:[a-z]|[a-z][a-z0-9._-]*[a-z0-9])$/.test(value) && !value.includes("..") && !value.includes("*");
}

function isV2CapabilityId(value: unknown): value is string {
  return typeof value === "string" && value.length >= 3 && value.length <= 192 &&
    /^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9-]*)+$/.test(value);
}

function isV2Semver(value: unknown): value is string {
  return typeof value === "string" && /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/.test(value);
}

function isV2Digest(value: unknown): value is string {
  return typeof value === "string" && isBase64Url(value, V2_SID_BYTES);
}

function isV2SourceAddress(value: unknown): boolean {
  return isRecord(value) && hasOnlyKeys(value, ["mesh_id", "agent_id", "instance_id"]) &&
    hasRequiredKeys(value, ["agent_id", "instance_id"]) && isV2AgentId(value.agent_id) && isInstanceId(value.instance_id) &&
    (value.mesh_id === undefined || isV2MeshId(value.mesh_id));
}

function isV2TargetAddress(value: unknown): boolean {
  return isRecord(value) && hasOnlyKeys(value, ["mesh_id", "agent_id", "instance_id"]) &&
    hasRequiredKeys(value, ["agent_id"]) && isV2AgentId(value.agent_id) &&
    (value.instance_id === undefined || isInstanceId(value.instance_id)) &&
    (value.mesh_id === undefined || isV2MeshId(value.mesh_id));
}

function isV2Delivery(value: unknown): boolean {
  return isRecord(value) && hasExactKeys(value, ["delivery_id", "mode", "idempotency_key", "deadline"]) &&
    isUuidV7(value.delivery_id) && value.mode === "at_least_once" && typeof value.idempotency_key === "string" &&
    value.idempotency_key.length >= 1 && value.idempotency_key.length <= MAX_IDEMPOTENCY_KEY_BYTES &&
    /^[A-Za-z0-9._~:-]+$/.test(value.idempotency_key) && isTimestamp(value.deadline);
}

function isV2CapabilityTuple(value: JsonObject): boolean {
  return isV2CapabilityId(value.capability) && isV2Semver(value.capability_version) && isV2Digest(value.capability_contract_digest);
}

function validateV2ApplicationParams(type: V2ApplicationMessageType, params: JsonObject): string | undefined {
  const taskId = params.task_id;
  if (type === "task.submit") {
    return hasExactKeys(params, ["task_id", "capability", "capability_version", "capability_contract_digest", "input", "deadline"]) &&
      isUuidV7(taskId) && isV2CapabilityTuple(params) && isJsonValue(params.input) && isTimestamp(params.deadline)
      ? undefined : "Invalid v0.2 task.submit params";
  }
  if (type === "task.accepted") {
    return hasExactKeys(params, ["task_id", "event_seq", "accepted_at", "capability", "capability_version", "capability_contract_digest"]) &&
      isUuidV7(taskId) && params.event_seq === 1 && isTimestamp(params.accepted_at) && isV2CapabilityTuple(params)
      ? undefined : "Invalid v0.2 task.accepted params";
  }
  if (type === "task.rejected") {
    return hasExactKeys(params, ["task_id", "event_seq", "code", "message", "capability", "capability_version", "capability_contract_digest"]) &&
      isUuidV7(taskId) && params.event_seq === 1 && isV2ErrorCode(params.code) && isBoundedString(params.message, 512) && isV2CapabilityTuple(params)
      ? undefined : "Invalid v0.2 task.rejected params";
  }
  if (type === "task.progress") {
    return hasExactKeys(params, ["task_id", "event_seq", "progress", "capability", "capability_version", "capability_contract_digest"]) &&
      isUuidV7(taskId) && isFiniteInteger(params.event_seq, 2) && isV2CapabilityTuple(params) && isV2Progress(params.progress)
      ? undefined : "Invalid v0.2 task.progress params";
  }
  if (type === "task.completed") {
    return hasExactKeys(params, ["task_id", "event_seq", "terminal", "capability", "capability_version", "capability_contract_digest"]) &&
      isUuidV7(taskId) && isFiniteInteger(params.event_seq, 2) && isV2CapabilityTuple(params) && isV2Terminal(params.terminal)
      ? undefined : "Invalid v0.2 task.completed params";
  }
  if (type === "task.cancel") {
    return hasOnlyKeys(params, ["task_id", "reason"]) && hasRequiredKeys(params, ["task_id"]) && isUuidV7(taskId) &&
      (params.reason === undefined || isBoundedString(params.reason, 512)) ? undefined : "Invalid v0.2 task.cancel params";
  }
  if (type === "task.status") {
    const query = hasExactKeys(params, ["kind", "task_id"]) && params.kind === "query" && isUuidV7(taskId);
    const snapshot = hasOnlyKeys(params, ["kind", "task_id", "state", "event_seq", "observed_at", "terminal"]) &&
      hasRequiredKeys(params, ["kind", "task_id", "state", "event_seq", "observed_at"]) && params.kind === "snapshot" && isUuidV7(taskId) &&
      typeof params.state === "string" && ["accepted", "queued", "running", "waiting", "succeeded", "failed", "cancelled", "rejected", "recovery_required"].includes(params.state) &&
      isFiniteInteger(params.event_seq, 1) && isTimestamp(params.observed_at) && (params.terminal === undefined || isV2Terminal(params.terminal));
    return query || snapshot ? undefined : "Invalid v0.2 task.status params";
  }
  return hasExactKeys(params, ["category", "code", "message", "retryable", "retry_after_ms", "details"]) && isV2StructuredError(params)
    ? undefined : "Invalid v0.2 error params";
}

function isV2ErrorCode(value: unknown): boolean {
  return typeof value === "string" && value.length >= 3 && value.length <= 128 && /^[A-Z][A-Z0-9_.]+$/.test(value);
}

function isV2StructuredError(value: unknown): boolean {
  return isRecord(value) && hasRequiredKeys(value, ["category", "code", "message", "retryable"]) &&
    hasOnlyKeys(value, ["category", "code", "message", "retryable", "retry_after_ms", "details"]) &&
    typeof value.category === "string" && ERROR_CATEGORY_SET.has(value.category) && isV2ErrorCode(value.code) &&
    isBoundedString(value.message, 512) && typeof value.retryable === "boolean" &&
    (value.retry_after_ms === undefined || value.retry_after_ms === null || isFiniteInteger(value.retry_after_ms, 0)) &&
    (value.details === undefined || (isRecord(value.details) && isJsonValue(value.details)));
}

function isV2Progress(value: unknown): boolean {
  return isRecord(value) && hasRequiredKeys(value, ["state"]) && hasOnlyKeys(value, ["state", "current", "total", "status"]) &&
    (value.state === "queued" || value.state === "running" || value.state === "waiting") &&
    (value.current === undefined || isFiniteInteger(value.current, 0)) &&
    (value.total === undefined || isFiniteInteger(value.total, 1)) &&
    (value.status === undefined || isBoundedString(value.status, 1_024));
}

function isV2Terminal(value: unknown): boolean {
  if (!isRecord(value) || !hasRequiredKeys(value, ["outcome", "completed_at"]) || !isTimestamp(value.completed_at)) return false;
  if (value.outcome === "succeeded") return hasExactKeys(value, ["outcome", "result", "completed_at"]) && isJsonValue(value.result);
  if (value.outcome === "failed") return hasExactKeys(value, ["outcome", "error", "completed_at"]) && isV2StructuredError(value.error);
  return value.outcome === "cancelled" && hasOnlyKeys(value, ["outcome", "cancellation", "completed_at"]) &&
    hasRequiredKeys(value, ["outcome", "cancellation", "completed_at"]) && isRecord(value.cancellation) &&
    hasRequiredKeys(value.cancellation, ["code"]) && hasOnlyKeys(value.cancellation, ["code", "message"]) &&
    isV2ErrorCode(value.cancellation.code) && (value.cancellation.message === undefined || isBoundedString(value.cancellation.message, 512));
}

export function validateHandshakeFrame(value: unknown): ValidationResult<HandshakeFrame> {
  if (!isRecord(value) || typeof value.type !== "string") return validationFailure("Handshake frame must be an object");
  if (value.type === "hello") {
    if (!hasRequiredKeys(value, ["type", "v", "role", "agent_id", "instance_id", "nonce"]) || value.v !== HANDSHAKE_VERSION || !["initiator", "responder"].includes(String(value.role)) || !isAgentId(value.agent_id) || !isInstanceId(value.instance_id) || !isNonce(value.nonce)) return validationFailure("Invalid hello frame");
    if (value.security_profile !== undefined && value.security_profile !== SECURE_IDENTITY_PROFILE) return validationFailure("Unsupported handshake security profile");
    if (value.role === "responder" && (!hasOnlyKeys(value, ["type", "v", "role", "agent_id", "instance_id", "nonce", "echo", "sid", "security_profile"]) || !isNonce(value.echo) || !isBase64Url(value.sid, 32))) return validationFailure("Invalid responder hello frame");
    if (value.role === "initiator" && !hasOnlyKeys(value, ["type", "v", "role", "agent_id", "instance_id", "nonce", "security_profile"])) return validationFailure("Initiator hello has unknown fields");
    return { ok: true, value: value as unknown as HelloFrame };
  }
  if (value.type === "card") {
    if (!hasRequiredKeys(value, ["type", "sid", "for_nonce", "digest", "card"]) || !hasOnlyKeys(value, ["type", "sid", "for_nonce", "digest", "card"]) || !isBase64Url(value.sid, 32) || !isNonce(value.for_nonce) || typeof value.digest !== "string" || !/^[0-9a-f]{64}$/i.test(value.digest)) return validationFailure("Invalid card frame");
    const card = validateAgentCard(value.card);
    if (card.ok === false || cardDigest(card.value) !== value.digest) return validationFailure(card.ok === false ? card.error : "Card digest does not match card contents");
    return { ok: true, value: value as unknown as CardFrame };
  }
  if (value.type === "auth") {
    if (!hasRequiredKeys(value, ["type", "sid", "agent_id", "key_id", "signature"]) || !hasOnlyKeys(value, ["type", "sid", "agent_id", "key_id", "signature"]) || !isBase64Url(value.sid, 32) || !isAgentId(value.agent_id) || !isBase64Url(value.key_id, 32) || !isBase64Url(value.signature, ED25519_SIGNATURE_BYTES)) {
      return validationFailure("Invalid authentication proof frame");
    }
    return { ok: true, value: value as unknown as AuthFrame };
  }
  if (value.type === "ready") {
    if (!hasRequiredKeys(value, ["type", "sid", "self_card", "peer_card"]) || !hasOnlyKeys(value, ["type", "sid", "self_card", "peer_card"]) || !isBase64Url(value.sid, 32) || typeof value.self_card !== "string" || !/^[0-9a-f]{64}$/i.test(value.self_card) || typeof value.peer_card !== "string" || !/^[0-9a-f]{64}$/i.test(value.peer_card)) return validationFailure("Invalid ready frame");
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
  if (!isAgentId(options.source.agent_id) || !isInstanceId(options.source.instance_id) || !isAgentId(options.target.agent_id) || (options.target.instance_id !== undefined && !isInstanceId(options.target.instance_id))) {
    throw new TypeError("Envelope source and target identities must be valid PolyMesh identities");
  }
  if (!isJsonValue((options.params ?? {}) as JsonObject)) throw new TypeError("Envelope params exceed protocol JSON limits");
  const messageId = options.message_id ?? uuidv7();
  const idempotencyKey = options.delivery?.idempotency_key ?? options.idempotency_key ?? options.idempotencyKey ?? `${options.type}:${messageId}`;
  // An application envelope always carries a deadline.  A one-minute default
  // preserves the strict v0.1 wire shape while keeping control messages easy
  // to construct through the small reference API.
  const deadline = options.delivery?.deadline ?? options.deadline ?? new Date(Date.now() + 60_000).toISOString();
  const timestamp = options.timestamp ?? new Date().toISOString();
  if (!isTimestamp(deadline) || !isTimestamp(timestamp)) throw new TypeError("Envelope timestamps must be RFC 3339 UTC milliseconds");
  if (Buffer.byteLength(idempotencyKey, "utf8") === 0 || Buffer.byteLength(idempotencyKey, "utf8") > MAX_IDEMPOTENCY_KEY_BYTES) {
    throw new RangeError("Envelope idempotency key is invalid");
  }
  if (options.type === "task.submit" && (options.params as JsonObject | undefined)?.deadline !== deadline) {
    throw new TypeError("task.submit params.deadline must exactly match delivery.deadline");
  }
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

/**
 * Validate and deterministically encode one v0.1 application or handshake
 * record.  Keeping this at the protocol boundary makes fixture consumers and
 * non-WebSocket transports use the same canonical bytes as the Python SDK.
 */
export function encodeRecordText(record: unknown): string {
  const envelope = validateEnvelope(record);
  if (envelope.ok) return canonicalize(envelope.value as unknown as JsonObject);
  const handshake = validateHandshakeFrame(record);
  if (handshake.ok) return canonicalize(handshake.value as unknown as JsonObject);
  throw new TypeError("Record must be a valid PolyMesh envelope or handshake frame");
}

/** UTF-8 bytes for a validated canonical v0.1 record. */
export function encodeRecord(record: unknown): Buffer {
  return Buffer.from(encodeRecordText(record), "utf8");
}

export function encodeUnixFrame(payload: string | JsonValue): Buffer {
  if (typeof payload === "string" && !validUnicodeScalarSequence(payload)) {
    throw new ProtocolError("MALFORMED_JSON", "Unix frame contains invalid UTF-8 string data", "parse");
  }
  if (typeof payload !== "string" && !isJsonValue(payload)) {
    throw new ProtocolError("MALFORMED_JSON", "Unix frame contains an out-of-budget JSON value", "parse");
  }
  const body = Buffer.from(typeof payload === "string" ? payload : JSON.stringify(payload), "utf8");
  if (body.byteLength + 4 > MAX_FRAME_BYTES) throw new ProtocolError("FRAME_TOO_LARGE", `Frame exceeds ${MAX_FRAME_BYTES} bytes including framing`, "resource");
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
  if (!Number.isSafeInteger(maxFrameBytes) || maxFrameBytes < 5 || maxFrameBytes > MAX_FRAME_BYTES) {
    throw new RangeError(`maxFrameBytes must be between 5 and ${MAX_FRAME_BYTES}`);
  }
  const frames: string[] = [];
  let offset = 0;
  while (offset + 4 <= buffer.length) {
    const length = buffer.readUInt32BE(offset);
    if (length + 4 > maxFrameBytes) throw new ProtocolError("FRAME_TOO_LARGE", `Frame exceeds ${maxFrameBytes} bytes including framing`, "resource");
    if (offset + 4 + length > buffer.length) break;
    try {
      frames.push(new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(offset + 4, offset + 4 + length)));
    } catch {
      throw new ProtocolError("MALFORMED_JSON", "Unix frame is not valid UTF-8", "parse");
    }
    offset += 4 + length;
  }
  if (buffer.length - offset > maxFrameBytes) throw new ProtocolError("FRAME_TOO_LARGE", "Unix frame remainder exceeds the configured limit", "resource");
  return { frames, remainder: buffer.subarray(offset) };
}

export const decodeUnixFrame = decodeUnixFrames;

export type WireData = string | Buffer | Uint8Array | JsonValue;
export type WireMessageListener = (data: string, isBinary: boolean) => void;
export type WireCloseListener = (code: number, reason: Buffer) => void;
export type WireErrorListener = (error: Error) => void;
export type WireOpenListener = () => void;

function validWireCloseCode(code: number): boolean {
  return (code >= 3000 && code <= 4999) ||
    [1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014].includes(code);
}

function safeWireCloseReason(reason: string): string {
  const sanitized = reason.replace(/[\u0000-\u001f\u007f]/g, "?");
  return Buffer.byteLength(sanitized, "utf8") <= 123 ? sanitized : "connection closed";
}

export interface WireMessageEvent {
  data: string;
}

/**
 * Public WebSocket-shaped transport surface used by brokers and clients.
 *
 * `WireTransport` used to be only the concrete in-memory implementation
 * below.  Keeping its public contract structural lets a real carrier (for
 * example the DeckAgent tunnel adapter) participate in the same APIs without
 * inheriting the in-memory peer and listener bookkeeping.
 */
export interface WireTransport {
  readonly CONNECTING: number;
  readonly OPEN: number;
  readonly CLOSING: number;
  readonly CLOSED: number;
  readyState: number;
  onmessage?: (event: WireMessageEvent) => void;
  onclose?: (event: { code: number; reason: string }) => void;
  onerror?: (event: { error: Error }) => void;
  readonly isOpen: boolean;
  /** @internal Connects the in-memory implementation to its peer. */
  connect(peer: WireTransport): void;
  on(event: "message", listener: WireMessageListener): this;
  on(event: "close", listener: WireCloseListener): this;
  on(event: "error", listener: WireErrorListener): this;
  on(event: "open", listener: WireOpenListener): this;
  once(event: "message", listener: WireMessageListener): this;
  once(event: "close", listener: WireCloseListener): this;
  once(event: "error", listener: WireErrorListener): this;
  once(event: "open", listener: WireOpenListener): this;
  off(event: "message", listener: WireMessageListener): this;
  off(event: "close", listener: WireCloseListener): this;
  off(event: "error", listener: WireErrorListener): this;
  off(event: "open", listener: WireOpenListener): this;
  addEventListener(event: "message", listener: (event: WireMessageEvent) => void): void;
  addEventListener(event: "close", listener: (event: { code: number; reason: string }) => void): void;
  addEventListener(event: "error", listener: (event: { error: Error }) => void): void;
  send(data: WireData, callback?: (error?: Error) => void): void;
  close(code?: number, reason?: string): void;
  terminate(): void;
}

/**
 * A small in-memory, WebSocket-shaped transport used by integration tests and
 * by embedders that want to exercise routing without opening a port.
 */
class InMemoryWireTransport implements WireTransport {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;

  readonly CONNECTING = InMemoryWireTransport.CONNECTING;
  readonly OPEN = InMemoryWireTransport.OPEN;
  readonly CLOSING = InMemoryWireTransport.CLOSING;
  readonly CLOSED = InMemoryWireTransport.CLOSED;
  readyState = InMemoryWireTransport.OPEN;
  onmessage?: (event: WireMessageEvent) => void;
  onclose?: (event: { code: number; reason: string }) => void;
  onerror?: (event: { error: Error }) => void;

  private peer?: InMemoryWireTransport;
  private readonly messageListeners = new Set<WireMessageListener>();
  private readonly closeListeners = new Set<WireCloseListener>();
  private readonly errorListeners = new Set<WireErrorListener>();
  private readonly openListeners = new Set<WireOpenListener>();

  /** @internal */
  connect(peer: WireTransport): void {
    // This hook belongs to the in-memory test double. A production transport
    // can satisfy the public WireTransport interface without exposing the
    // in-memory receiver that makes a pair possible.
    if (!(peer instanceof InMemoryWireTransport)) {
      throw new TypeError("In-memory wires can only connect to another in-memory wire");
    }
    this.peer = peer;
  }

  get isOpen(): boolean {
    return this.readyState === InMemoryWireTransport.OPEN;
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
    // Match native WebSocket wire constraints even in tests.  In particular,
    // 1005, 1006, and 1015 are local-only sentinels and cannot be transmitted.
    this.finishClose(validWireCloseCode(code) ? code : 1000, safeWireCloseReason(reason), true);
  }

  terminate(): void {
    // 1006 is a local API sentinel, never a valid WebSocket wire close code.
    // The in-memory transport has no separate TCP reset primitive, so model a
    // forceful teardown with a valid generic close event instead.
    this.close(1000, "terminated");
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
    if (this.readyState === InMemoryWireTransport.CLOSED) return;
    this.readyState = InMemoryWireTransport.CLOSED;
    const reasonBuffer = Buffer.from(reason);
    for (const listener of this.closeListeners) listener(code, reasonBuffer);
    this.onclose?.({ code, reason });
    if (closePeer && this.peer) this.peer.finishClose(code, reason, false);
  }
}

/** Concrete in-memory implementation of the structural WireTransport API. */
export const WireTransport = InMemoryWireTransport;

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
  const pair = [a, b] as unknown as WirePair;
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

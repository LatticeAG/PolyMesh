/**
 * Opt-in PolyMesh 0.2 wire-profile primitives.
 *
 * The v0.1 envelope remains intentionally unchanged for local development.
 * These types give a durable relay an explicit profile boundary instead of
 * letting it silently add mesh identity or delivery semantics to an existing
 * v0.1 session.
 */

import {
  ED25519_PUBLIC_KEY_BYTES,
  ED25519_SIGNATURE_BYTES,
  IDENTITY_ALGORITHM,
  PROTOCOL_VERSION,
  SECURE_IDENTITY_PROFILE,
  canonicalize,
  createCardIdentityFromPrivateKey,
  isAgentId,
  isBase64Url,
  isInstanceId,
  isNonce,
  isUuidV7,
  sha256,
  validateEnvelope,
  type AuthFrame,
  type Delivery,
  type Ed25519PrivateKey,
  type EnrollmentStore,
  type Envelope,
  type HelloFrame,
  type JsonObject,
  type MessageType,
  type ValidationResult,
  type VerifiedPrincipal,
} from "./protocol.js";
import {
  KeyObject,
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as ed25519Sign,
  verify as ed25519Verify,
} from "node:crypto";
import {
  isCompressionAlgorithm,
  isCompressionNegotiation,
  isCompressionRecordType,
  negotiateCompression,
  validateCompressionFrame,
  validateCompressionRecordBinding,
  type CompressionAlgorithm,
  type CompressionFrameMetadata,
  type CompressionLimits,
  type CompressionNegotiation,
  type CompressionOffer,
  type CompressionRecordBindingResult,
  type CompressionRecordType,
} from "./compression.js";

export const V2_PROTOCOL_VERSION = "polymesh.0.2" as const;
export const V2_HANDSHAKE_VERSION = "0.2" as const;
export const V2_SUBPROTOCOL = V2_PROTOCOL_VERSION;
/** Separate TLS exporter label prevents cross-profile proof reuse. */
export const V2_TLS_EXPORTER_LABEL = "EXPORTER-PolyMesh/0.2" as const;

/** Mesh IDs are authenticated routing scopes, not sender-selected aliases. */
export interface MeshAgentRef {
  mesh_id: string;
  agent_id: string;
  instance_id?: string;
}

export interface MeshAgentIdentity extends MeshAgentRef {
  instance_id: string;
}

export interface V2Envelope<
  T extends MessageType = MessageType,
  P extends JsonObject = JsonObject,
> {
  protocol: typeof V2_PROTOCOL_VERSION;
  type: T;
  message_id: string;
  timestamp: string;
  source: MeshAgentIdentity;
  target: MeshAgentRef;
  delivery: Delivery;
  /**
   * Relay-assigned delivery correlation.  It is absent from sender ingress
   * and added exactly once to the immutable record written to the target
   * outbox.  A receiver echoes it in `delivery.receipt` after committing its
   * own inbox/idempotency state.
   *
   * This is deliberately not part of the v0.1-compatible semantic payload:
   * redelivery of the same logical envelope can have transport correlation
   * without changing idempotency semantics.  Brokers must reject this field
   * when it is supplied on an ingress envelope.
   */
  delivery_id?: string;
  in_reply_to?: string;
  params: P;
}

/** A v0.2 envelope as accepted from a sender before relay delivery metadata. */
export type V2IngressEnvelope<
  T extends MessageType = MessageType,
  P extends JsonObject = JsonObject,
> = Omit<V2Envelope<T, P>, "delivery_id"> & { delivery_id?: never };

/** A relay-to-target v0.2 envelope with immutable delivery correlation. */
export type V2DeliveredEnvelope<
  T extends MessageType = MessageType,
  P extends JsonObject = JsonObject,
> = Omit<V2Envelope<T, P>, "delivery_id"> & { delivery_id: string };

/**
 * A transport receipt confirms that the receiver committed delivery state.
 * It never has task-state authority and is intentionally non-recursive.
 */
export interface DeliveryReceiptRecord {
  type: "delivery.receipt";
  v: typeof V2_HANDSHAKE_VERSION;
  delivery_id: string;
  message_id: string;
  state: "stored";
}

/**
 * Compression capabilities exchanged only after the v0.2 READY boundary.
 * This is a control record, not an application envelope, and is deliberately
 * excluded from the compression record vocabulary so negotiation itself can
 * never be recursively compressed.
 */
export interface V2CompressionOfferRecord extends CompressionOffer {
  type: "compression.offer";
  v: typeof V2_HANDSHAKE_VERSION;
}

/** The single codec/limit set selected from two post-READY offers. */
export interface V2CompressionSelectedRecord extends CompressionNegotiation {
  type: "compression.selected";
  v: typeof V2_HANDSHAKE_VERSION;
}

/**
 * One independently compressed zstd record.  There is no dictionary, stream
 * ID, or context field: every wrapper is intentionally self-contained, which
 * prevents implicit cross-message compression state.
 */
export interface V2CompressionFrame {
  type: "compression.frame";
  v: typeof V2_HANDSHAKE_VERSION;
  algorithm: "zstd";
  record_type: CompressionRecordType;
  compressed_bytes: number;
  uncompressed_bytes: number;
  /** Canonical, unpadded base64url of exactly `compressed_bytes` bytes. */
  payload: string;
}

export type V2CompressionControlRecord = V2CompressionOfferRecord | V2CompressionSelectedRecord;

/** Explicit phase state supplied by the session state machine. */
export interface V2CompressionControlValidationOptions {
  /** True only after this session completed its authenticated READY exchange. */
  ready: boolean;
}

/** A selected state may optionally be bound to the locally computed outcome. */
export interface V2CompressionSelectedValidationOptions extends V2CompressionControlValidationOptions {
  /** The exact result of `negotiateCompression(localOffer, peerOffer, { ready: true })`. */
  expected?: CompressionNegotiation;
}

/** A compressed wrapper is valid only against the active negotiated state. */
export interface V2CompressionFrameValidationOptions extends V2CompressionControlValidationOptions {
  negotiation: CompressionNegotiation;
}

export type V2CompressionValidationCode =
  | "COMPRESSION_NEGOTIATION_BEFORE_READY"
  | "COMPRESSION_OFFER_INVALID"
  | "COMPRESSION_SELECTED_INVALID"
  | "COMPRESSION_SELECTED_MISMATCH"
  | "COMPRESSION_FRAME_INVALID"
  | "COMPRESSION_METADATA_INVALID"
  | "COMPRESSION_FORBIDDEN_RECORD"
  | "COMPRESSION_NOT_NEGOTIATED"
  | "COMPRESSION_LIMIT_EXCEEDED"
  | "COMPRESSION_EXPANSION_LIMIT";

export type V2CompressionValidationResult<T> =
  | { ok: true; value: T }
  | { ok: false; code: V2CompressionValidationCode; error: string };

export interface V2HelloFrame {
  type: "hello";
  v: typeof V2_HANDSHAKE_VERSION;
  role: "initiator" | "responder";
  agent_id: string;
  instance_id: string;
  nonce: string;
  mesh_id?: string;
  echo?: string;
  sid?: string;
  security_profile?: typeof SECURE_IDENTITY_PROFILE;
}

const MESH_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$/;

export function isMeshId(value: unknown): value is string {
  return typeof value === "string" && MESH_ID_RE.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function hasRequiredKeys(value: Record<string, unknown>, required: readonly string[]): boolean {
  return required.every((key) => Object.hasOwn(value, key));
}

function validationFailure<T = never>(error: string): ValidationResult<T> {
  return { ok: false, error };
}

function compressionFailure<T = never>(
  code: V2CompressionValidationCode,
  error: string,
): V2CompressionValidationResult<T> {
  return { ok: false, code, error };
}

function compressionReady(options: V2CompressionControlValidationOptions | undefined): boolean {
  return options?.ready === true;
}

function strictCompressionLimits(value: unknown): value is CompressionLimits {
  return isRecord(value) &&
    hasRequiredKeys(value, ["maxCompressedBytes", "maxUncompressedBytes", "maxExpansionRatio"]) &&
    hasOnlyKeys(value, ["maxCompressedBytes", "maxUncompressedBytes", "maxExpansionRatio"]) &&
    isPositiveSafeInteger(value.maxCompressedBytes) &&
    isPositiveSafeInteger(value.maxUncompressedBytes) &&
    typeof value.maxExpansionRatio === "number" && Number.isFinite(value.maxExpansionRatio) && value.maxExpansionRatio >= 1;
}

function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function strictCompressionOfferRecord(value: unknown): value is V2CompressionOfferRecord {
  if (!isRecord(value) || value.type !== "compression.offer" || value.v !== V2_HANDSHAKE_VERSION ||
    !hasRequiredKeys(value, ["type", "v", "algorithms"]) ||
    !hasOnlyKeys(value, ["type", "v", "algorithms", "limits"]) ||
    !Array.isArray(value.algorithms) || value.algorithms.length === 0 ||
    value.algorithms.some((algorithm) => !isCompressionAlgorithm(algorithm))) {
    return false;
  }
  const algorithms = value.algorithms as CompressionAlgorithm[];
  if (new Set(algorithms).size !== algorithms.length || !algorithms.includes("none")) return false;
  const hasZstd = algorithms.includes("zstd");
  if (hasZstd !== Object.hasOwn(value, "limits")) return false;
  if (hasZstd && !strictCompressionLimits(value.limits)) return false;
  // Reuse the compression module's semantic offer validation rather than
  // copying its negotiation rules into the v2 wire profile.
  const offer: CompressionOffer = hasZstd
    ? { algorithms, limits: value.limits as CompressionLimits }
    : { algorithms };
  return negotiateCompression(offer, offer, { ready: true }).ok;
}

function strictCompressionSelectedRecord(value: unknown): value is V2CompressionSelectedRecord {
  if (!isRecord(value) || value.type !== "compression.selected" || value.v !== V2_HANDSHAKE_VERSION ||
    !hasRequiredKeys(value, ["type", "v", "algorithm"]) ||
    !hasOnlyKeys(value, ["type", "v", "algorithm", "limits"]) ||
    !isCompressionAlgorithm(value.algorithm)) {
    return false;
  }
  const hasZstd = value.algorithm === "zstd";
  if (hasZstd !== Object.hasOwn(value, "limits")) return false;
  const negotiation: CompressionNegotiation = hasZstd
    ? { algorithm: "zstd", limits: value.limits as CompressionLimits }
    : { algorithm: "none" };
  return (!hasZstd || strictCompressionLimits(value.limits)) && isCompressionNegotiation(negotiation);
}

function sameCompressionNegotiation(left: CompressionNegotiation, right: CompressionNegotiation): boolean {
  if (!isCompressionNegotiation(left) || !isCompressionNegotiation(right) || left.algorithm !== right.algorithm) return false;
  if (left.algorithm === "none") return true;
  return left.limits!.maxCompressedBytes === right.limits!.maxCompressedBytes &&
    left.limits!.maxUncompressedBytes === right.limits!.maxUncompressedBytes &&
    left.limits!.maxExpansionRatio === right.limits!.maxExpansionRatio;
}

/**
 * Validate a strict post-READY compression capability offer. A caller must
 * pass session state explicitly so a valid record cannot accidentally be
 * accepted during hello/card/auth/ready.
 */
export function validateV2CompressionOffer(
  value: unknown,
  options: V2CompressionControlValidationOptions,
): V2CompressionValidationResult<V2CompressionOfferRecord> {
  if (!compressionReady(options)) {
    return compressionFailure("COMPRESSION_NEGOTIATION_BEFORE_READY", "Compression negotiation is allowed only after READY");
  }
  if (!strictCompressionOfferRecord(value)) {
    return compressionFailure("COMPRESSION_OFFER_INVALID", "Compression offer has an invalid or unsupported wire shape");
  }
  return { ok: true, value };
}

/** Phase-aware type guard for a v0.2 compression offer. */
export function isV2CompressionOffer(
  value: unknown,
  options: V2CompressionControlValidationOptions,
): value is V2CompressionOfferRecord {
  return validateV2CompressionOffer(value, options).ok;
}

/**
 * Validate a strict post-READY selection. When `expected` is supplied, the
 * peer's control record must exactly equal the locally negotiated outcome;
 * this prevents a peer from widening limits or selecting a codec on its own.
 */
export function validateV2CompressionSelected(
  value: unknown,
  options: V2CompressionSelectedValidationOptions,
): V2CompressionValidationResult<V2CompressionSelectedRecord> {
  if (!compressionReady(options)) {
    return compressionFailure("COMPRESSION_NEGOTIATION_BEFORE_READY", "Compression selection is allowed only after READY");
  }
  if (!strictCompressionSelectedRecord(value)) {
    return compressionFailure("COMPRESSION_SELECTED_INVALID", "Compression selection has an invalid or unsupported wire shape");
  }
  if (options.expected !== undefined && !sameCompressionNegotiation(value, options.expected)) {
    return compressionFailure("COMPRESSION_SELECTED_MISMATCH", "Compression selection differs from the locally negotiated outcome");
  }
  return { ok: true, value };
}

/** Phase-aware type guard for a v0.2 compression selection. */
export function isV2CompressionSelected(
  value: unknown,
  options: V2CompressionSelectedValidationOptions,
): value is V2CompressionSelectedRecord {
  return validateV2CompressionSelected(value, options).ok;
}

/** Build the closed control record from an already validated negotiation result. */
export function createV2CompressionSelected(
  negotiation: CompressionNegotiation,
): V2CompressionSelectedRecord {
  if (!isCompressionNegotiation(negotiation)) throw new TypeError("Compression negotiation is invalid");
  return Object.freeze({
    type: "compression.selected",
    v: V2_HANDSHAKE_VERSION,
    algorithm: negotiation.algorithm,
    ...(negotiation.limits === undefined ? {} : { limits: Object.freeze({ ...negotiation.limits }) }),
  }) as V2CompressionSelectedRecord;
}

/** Convert snake_case v2 wrapper metadata into the shared compression shape. */
export function v2CompressionFrameMetadata(frame: V2CompressionFrame): CompressionFrameMetadata {
  return {
    algorithm: frame.algorithm,
    recordType: frame.record_type,
    compressedBytes: frame.compressed_bytes,
    uncompressedBytes: frame.uncompressed_bytes,
  };
}

/**
 * Validate a zstd wrapper before handing `payload` to a codec.  This does not
 * decompress anything; adapters must still call `validateDecompressedOutput`
 * with actual codec output and `validateV2CompressionRecordBinding` after
 * strict JSON parsing.
 */
export function validateV2CompressionFrame(
  value: unknown,
  options: V2CompressionFrameValidationOptions,
): V2CompressionValidationResult<V2CompressionFrame> {
  if (!compressionReady(options)) {
    return compressionFailure("COMPRESSION_NEGOTIATION_BEFORE_READY", "Compressed frames are allowed only after READY");
  }
  if (!isRecord(value) || value.type !== "compression.frame" || value.v !== V2_HANDSHAKE_VERSION ||
    !hasRequiredKeys(value, ["type", "v", "algorithm", "record_type", "compressed_bytes", "uncompressed_bytes", "payload"]) ||
    !hasOnlyKeys(value, ["type", "v", "algorithm", "record_type", "compressed_bytes", "uncompressed_bytes", "payload"]) ||
    value.algorithm !== "zstd" || !isCompressionRecordType(value.record_type) ||
    !isPositiveSafeInteger(value.compressed_bytes) || !isPositiveSafeInteger(value.uncompressed_bytes) ||
    !isBase64Url(value.payload)) {
    return compressionFailure("COMPRESSION_FRAME_INVALID", "Compressed frame has an invalid or unsupported wire shape");
  }
  const frame = value as unknown as V2CompressionFrame;
  const metadata = v2CompressionFrameMetadata(frame);
  const metadataValidation = validateCompressionFrame(options.negotiation, metadata);
  if (!metadataValidation.ok) {
    return compressionFailure(metadataValidation.code, "Compressed frame violates the active compression negotiation");
  }
  // `isBase64Url` establishes canonical encoding. Check decoded bytes too so
  // metadata cannot understate the cost or create a decoder length mismatch.
  if (Buffer.from(frame.payload, "base64url").byteLength !== frame.compressed_bytes) {
    return compressionFailure("COMPRESSION_FRAME_INVALID", "Compressed frame payload length does not match compressed_bytes");
  }
  return { ok: true, value: frame };
}

/** Phase-aware type guard for one bounded, negotiated zstd wrapper. */
export function isV2CompressionFrame(
  value: unknown,
  options: V2CompressionFrameValidationOptions,
): value is V2CompressionFrame {
  return validateV2CompressionFrame(value, options).ok;
}

/** Bind a decoded record's type to the wrapper metadata before routing it. */
export function validateV2CompressionRecordBinding(
  frame: V2CompressionFrame,
  decodedRecord: unknown,
): CompressionRecordBindingResult {
  return validateCompressionRecordBinding(v2CompressionFrameMetadata(frame), decodedRecord);
}

/**
 * Validate the versioned hello independently from v0.1.  A v2 session never
 * accepts a v0.1 hello, even though the card/auth/ready record shapes remain
 * deliberately compatible across the two profiles.
 */
export function validateV2HelloFrame(value: unknown): ValidationResult<V2HelloFrame> {
  if (!isRecord(value) || value.type !== "hello" || value.v !== V2_HANDSHAKE_VERSION ||
    (value.role !== "initiator" && value.role !== "responder") || !isAgentId(value.agent_id) ||
    !isInstanceId(value.instance_id) || !isNonce(value.nonce) ||
    (value.mesh_id !== undefined && !isMeshId(value.mesh_id)) ||
    (value.security_profile !== undefined && value.security_profile !== SECURE_IDENTITY_PROFILE)) {
    return validationFailure("Invalid v0.2 hello frame");
  }
  if (value.role === "initiator") {
    if (!hasRequiredKeys(value, ["type", "v", "role", "agent_id", "instance_id", "nonce"]) ||
      !hasOnlyKeys(value, ["type", "v", "role", "agent_id", "instance_id", "nonce", "mesh_id", "security_profile"])) {
      return validationFailure("Invalid v0.2 initiator hello frame");
    }
  } else if (!hasRequiredKeys(value, ["type", "v", "role", "agent_id", "instance_id", "nonce", "echo", "sid"]) ||
    !hasOnlyKeys(value, ["type", "v", "role", "agent_id", "instance_id", "nonce", "echo", "sid", "mesh_id", "security_profile"]) ||
    !isNonce(value.echo) || !isBase64Url(value.sid, 32)) {
    return validationFailure("Invalid v0.2 responder hello frame");
  }
  return { ok: true, value: value as unknown as V2HelloFrame };
}

export function isV2HelloFrame(value: unknown): value is V2HelloFrame {
  return validateV2HelloFrame(value).ok;
}

/** Version-domain-separated v2 session ID; it cannot collide with a v0.1 SID. */
export function deriveV2SessionId(initiatorNonce: string, responderNonce: string): string {
  if (!isNonce(initiatorNonce) || !isNonce(responderNonce)) throw new TypeError("v0.2 session nonces must be 32-byte base64url values");
  return createHash("sha256")
    .update(`${V2_PROTOCOL_VERSION}\0`, "utf8")
    .update(Buffer.from(initiatorNonce, "base64url"))
    .update(Buffer.from(responderNonce, "base64url"))
    .digest("base64url");
}

/**
 * Validate a v2 application envelope without accepting a v1-shaped identity
 * by accident.  The v1 validator is reused only for the closed task/control
 * payload grammar after the authenticated mesh scope has been removed.
 */
export function validateV2Envelope(value: unknown): ValidationResult<V2Envelope> {
  if (!isRecord(value)) return validationFailure("v0.2 envelope must be an object");
  const fields = ["protocol", "type", "message_id", "timestamp", "source", "target", "delivery", "delivery_id", "in_reply_to", "params"];
  const required = ["protocol", "type", "message_id", "timestamp", "source", "target", "delivery", "params"];
  if (!hasRequiredKeys(value, required) || !hasOnlyKeys(value, fields) || value.protocol !== V2_PROTOCOL_VERSION ||
    !isRecord(value.source) || !isRecord(value.target) ||
    !hasRequiredKeys(value.source, ["mesh_id", "agent_id", "instance_id"]) ||
    !hasOnlyKeys(value.source, ["mesh_id", "agent_id", "instance_id"]) ||
    !hasRequiredKeys(value.target, ["mesh_id", "agent_id"]) ||
    !hasOnlyKeys(value.target, ["mesh_id", "agent_id", "instance_id"]) ||
    !isMeshId(value.source.mesh_id) || !isMeshId(value.target.mesh_id) ||
    !isAgentId(value.source.agent_id) || !isInstanceId(value.source.instance_id) ||
    !isAgentId(value.target.agent_id) ||
    (value.target.instance_id !== undefined && !isInstanceId(value.target.instance_id)) ||
    (value.delivery_id !== undefined && !isUuidV7(value.delivery_id))) {
    return validationFailure("v0.2 envelope mesh identities are invalid");
  }
  // The v0.1 validation view is deliberately stripped of relay-only metadata:
  // its closed envelope grammar cannot silently start accepting a v2 field.
  const { delivery_id: _deliveryId, ...withoutDeliveryMetadata } = value;
  void _deliveryId;
  const legacy = {
    ...withoutDeliveryMetadata,
    protocol: PROTOCOL_VERSION,
    source: { agent_id: value.source.agent_id, instance_id: value.source.instance_id },
    target: value.target.instance_id === undefined
      ? { agent_id: value.target.agent_id }
      : { agent_id: value.target.agent_id, instance_id: value.target.instance_id },
  };
  const checked = validateEnvelope(legacy);
  return checked.ok ? { ok: true, value: value as unknown as V2Envelope } : validationFailure(checked.error);
}

export function isV2Envelope(value: unknown): value is V2Envelope {
  return validateV2Envelope(value).ok;
}

/** True when a valid v0.2 envelope carries relay-controlled delivery metadata. */
export function hasV2DeliveryMetadata(value: V2Envelope): value is V2DeliveredEnvelope {
  return value.delivery_id !== undefined;
}

/** Distinguish sender ingress from a relay-to-target delivery at the API boundary. */
export function isV2IngressEnvelope(value: unknown): value is V2IngressEnvelope {
  const parsed = validateV2Envelope(value);
  return parsed.ok && !hasV2DeliveryMetadata(parsed.value);
}

/** Validate a relay-delivered envelope which a recipient may acknowledge. */
export function isV2DeliveredEnvelope(value: unknown): value is V2DeliveredEnvelope {
  const parsed = validateV2Envelope(value);
  return parsed.ok && hasV2DeliveryMetadata(parsed.value);
}

/**
 * Attach the one relay-generated correlation identifier a target needs to
 * issue a non-recursive durable receipt.  This fails rather than replacing an
 * existing value, so application ingress cannot be relabelled as another
 * delivery after it has entered relay-owned state.
 */
export function attachV2DeliveryMetadata<T extends MessageType, P extends JsonObject>(
  envelope: V2IngressEnvelope<T, P>,
  deliveryId: string,
): V2DeliveredEnvelope<T, P> {
  if (!isUuidV7(deliveryId)) throw new TypeError("v0.2 delivery_id must be UUIDv7");
  if (Object.hasOwn(envelope, "delivery_id")) {
    throw new TypeError("A sender ingress envelope cannot already carry relay delivery metadata");
  }
  return Object.freeze({ ...envelope, delivery_id: deliveryId }) as V2DeliveredEnvelope<T, P>;
}

/** Stable replay fingerprint for v2; delivery IDs and timestamps are transport metadata. */
export function v2EnvelopeSemanticDigest(envelope: V2Envelope): string {
  const { message_id: _messageId, timestamp: _timestamp, delivery_id: _deliveryId, ...semantic } = envelope;
  void _messageId;
  void _timestamp;
  void _deliveryId;
  return sha256(semantic as unknown as JsonObject);
}

/**
 * A short-lived internal compatibility view for task payload validation. It
 * is never emitted on a v2 session, which prevents a hidden v2-to-v1
 * downgrade at the wire boundary.
 */
export function v2EnvelopeAsLegacy(envelope: V2Envelope): Envelope {
  const { delivery_id: _deliveryId, ...withoutDeliveryMetadata } = envelope;
  void _deliveryId;
  return {
    ...withoutDeliveryMetadata,
    protocol: PROTOCOL_VERSION,
    source: { agent_id: envelope.source.agent_id, instance_id: envelope.source.instance_id },
    target: envelope.target.instance_id === undefined
      ? { agent_id: envelope.target.agent_id }
      : { agent_id: envelope.target.agent_id, instance_id: envelope.target.instance_id },
  } as Envelope;
}

const V2_AUTH_SIGNATURE_DOMAIN = Buffer.from("PMX-AUTH/0.2\0", "utf8");
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function v2PrivateKey(value: Ed25519PrivateKey): KeyObject {
  const key = value instanceof KeyObject ? value : createPrivateKey(value);
  if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") throw new TypeError("An Ed25519 private key is required");
  return key;
}

function v2PublicKey(value: string): KeyObject {
  if (!isBase64Url(value, ED25519_PUBLIC_KEY_BYTES)) throw new TypeError("Invalid Ed25519 public key");
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(value, "base64url")]),
    format: "der",
    type: "spki",
  });
}

export interface V2AuthTranscriptInput {
  initiator_hello: V2HelloFrame;
  responder_hello: V2HelloFrame;
  initiator_card_digest: string;
  responder_card_digest: string;
  tls_channel_binding: string;
}

/** TLS-bound, version-domain-separated auth transcript for the v2 profile. */
export function v2AuthTranscript(input: V2AuthTranscriptInput): Buffer {
  const initiator = input.initiator_hello;
  const responder = input.responder_hello;
  if (initiator.role !== "initiator" || responder.role !== "responder" || responder.echo !== initiator.nonce ||
    !isNonce(initiator.nonce) || !isNonce(responder.nonce) || !isBase64Url(responder.sid, 32) ||
    !/^[0-9a-f]{64}$/i.test(input.initiator_card_digest) || !/^[0-9a-f]{64}$/i.test(input.responder_card_digest) ||
    !isBase64Url(input.tls_channel_binding, 32)) {
    throw new TypeError("Invalid v0.2 secure handshake transcript");
  }
  return Buffer.concat([V2_AUTH_SIGNATURE_DOMAIN, Buffer.from(canonicalize({
    protocol: V2_PROTOCOL_VERSION,
    handshake_version: V2_HANDSHAKE_VERSION,
    initiator_hello: initiator as unknown as JsonObject,
    responder_hello: responder as unknown as JsonObject,
    initiator_card_digest: input.initiator_card_digest,
    responder_card_digest: input.responder_card_digest,
    tls_channel_binding: input.tls_channel_binding,
  }), "utf8")]);
}

export function createV2AuthProof(
  agentId: string,
  keyId: string,
  sid: string,
  transcript: Uint8Array,
  privateKey: Ed25519PrivateKey,
): AuthFrame {
  if (!isAgentId(agentId) || !isBase64Url(keyId, ED25519_PUBLIC_KEY_BYTES) || !isBase64Url(sid, 32)) {
    throw new TypeError("Invalid v0.2 authenticated handshake identity");
  }
  const key = v2PrivateKey(privateKey);
  if (createCardIdentityFromPrivateKey(key).key_id !== keyId) throw new TypeError("v0.2 handshake signing key does not match key ID");
  return {
    type: "auth",
    sid,
    agent_id: agentId,
    key_id: keyId,
    signature: ed25519Sign(null, Buffer.from(transcript), key).toString("base64url"),
  };
}

/** Verify only an enrolled v2 principal; Card claims never become enrollment. */
export function verifyV2AuthProof(
  proof: AuthFrame,
  transcript: Uint8Array,
  enrollments: EnrollmentStore,
  now = Date.now(),
): VerifiedPrincipal | undefined {
  const enrollment = enrollments.resolve(proof.agent_id, proof.key_id, now);
  if (!enrollment || !isBase64Url(proof.signature, ED25519_SIGNATURE_BYTES)) return undefined;
  try {
    if (!ed25519Verify(null, Buffer.from(transcript), v2PublicKey(enrollment.public_key), Buffer.from(proof.signature, "base64url"))) return undefined;
    return {
      principal_id: `key:${enrollment.key_id}`,
      agent_id: enrollment.agent_id,
      key_id: enrollment.key_id,
      public_key: enrollment.public_key,
      auth_strength: "enrolled-key",
    };
  } catch {
    return undefined;
  }
}

export function isDeliveryReceiptRecord(value: unknown): value is DeliveryReceiptRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return Object.keys(record).length === 5 &&
    record.type === "delivery.receipt" &&
    record.v === V2_HANDSHAKE_VERSION &&
    record.state === "stored" &&
    typeof record.delivery_id === "string" && record.delivery_id.length > 0 &&
    typeof record.message_id === "string" && record.message_id.length > 0;
}

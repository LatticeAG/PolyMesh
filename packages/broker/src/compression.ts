/**
 * PolyMesh v0.2 compression negotiation and safety policy.
 *
 * Compression is deliberately modelled as a small, authenticated transport
 * protocol rather than as a WebSocket extension.  In particular, selecting a
 * codec never makes a control record compressible and never gives compressed
 * bytes any authority that the decoded application envelope did not have.
 */

import { validateV2ApplicationEnvelope } from "./protocol.js";
import type { RateLimitCharge } from "./rate-limit.js";

/** The only algorithms in the v0.2 base profile. */
export const COMPRESSION_ALGORITHMS = ["none", "zstd"] as const;
export type CompressionAlgorithm = (typeof COMPRESSION_ALGORITHMS)[number];

/** Fixed values used by the v0.2 compression records. */
export const V2_COMPRESSION_VERSION = "0.2" as const;
export const V2_COMPRESSION_EPOCH = "1" as const;
export const V2_COMPRESSION_CONTENT_TYPE = "application/polymesh-envelope+json" as const;
export const MAX_COMPRESSION_BYTES = 1_048_576;
export const MAX_COMPRESSION_EXPANSION_RATIO = 64;

/**
 * Historical v2 code called the first record an "offer".  The Ultra task
 * names it `compression.proposal`; both closed spellings are represented so
 * adapters can make an explicit compatibility choice instead of silently
 * rewriting a wire record.  New state machines emit `compression.proposal`
 * by default.  `compression.offer` remains available for the earlier v2
 * adapter while it is migrated to the full record shape.
 */
export const COMPRESSION_PROPOSAL_RECORD_TYPES = [
  "compression.proposal",
  "compression.offer",
] as const;
export type CompressionProposalRecordType = (typeof COMPRESSION_PROPOSAL_RECORD_TYPES)[number];

export const COMPRESSION_ACCEPT_RECORD_TYPE = "compression.accept" as const;
export const COMPRESSION_READY_RECORD_TYPE = "compression.ready" as const;
export const COMPRESSION_ZSTD_RECORD_TYPE = "compression.zstd" as const;

const COMPRESSION_SET = new Set<string>(COMPRESSION_ALGORITHMS);
const COMPRESSION_PROPOSAL_TYPE_SET = new Set<string>(COMPRESSION_PROPOSAL_RECORD_TYPES);

/**
 * Closed record vocabulary retained for the legacy metadata helpers below.
 * `compressionAllowedForRecord` is intentionally stricter: only v2
 * application envelopes are compressible.
 */
export const COMPRESSION_RECORD_TYPES = [
  "hello",
  "card",
  "auth",
  "ready",
  "receipt",
  "delivery.receipt",
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

export type CompressionRecordType = (typeof COMPRESSION_RECORD_TYPES)[number];
const COMPRESSION_RECORD_TYPE_SET = new Set<string>(COMPRESSION_RECORD_TYPES);

/** The complete v0.2 application-envelope type set. */
export const COMPRESSIBLE_APPLICATION_RECORD_TYPES = [
  "task.submit",
  "task.accepted",
  "task.rejected",
  "task.progress",
  "task.completed",
  "task.cancel",
  "task.status",
  "error",
] as const;
export type CompressibleApplicationRecordType = (typeof COMPRESSIBLE_APPLICATION_RECORD_TYPES)[number];
const COMPRESSIBLE_APPLICATION_RECORD_TYPE_SET = new Set<string>(COMPRESSIBLE_APPLICATION_RECORD_TYPES);

/**
 * Legacy camel-case bounds used by the broker's pre-Ultra compression API.
 * The wire records below use `CompressionZstdLimits` and snake-case members.
 */
export interface CompressionLimits {
  maxCompressedBytes: number;
  maxUncompressedBytes: number;
  maxExpansionRatio: number;
}

/** Authenticated READY receive limits relevant to a compression session. */
export interface CompressionReceiveLimits extends CompressionLimits {
  /** Maximum serialized wrapper bytes accepted by this peer. */
  maxWireBytes?: number;
  /** Maximum decoded JSON record bytes accepted by this peer. */
  maxJsonBytes?: number;
}

export const DEFAULT_COMPRESSION_LIMITS: Readonly<CompressionLimits> = Object.freeze({
  maxCompressedBytes: MAX_COMPRESSION_BYTES,
  maxUncompressedBytes: MAX_COMPRESSION_BYTES,
  maxExpansionRatio: 32,
});

/** Exact snake-case limits carried in a v0.2 compression control record. */
export interface CompressionZstdLimits {
  max_compressed_bytes: number;
  max_uncompressed_bytes: number;
  max_expansion_ratio: number;
}

/** Capabilities used by the legacy, symmetric negotiation helper. */
export interface CompressionOffer {
  /** `none` is mandatory in the old helper; zstd requires `limits`. */
  algorithms: readonly CompressionAlgorithm[];
  /** Required when zstd is advertised. */
  limits?: CompressionLimits;
}

export interface CompressionNegotiationOptions {
  /** Must be true only after the ordinary protocol READY exchange completed. */
  ready: boolean;
  /** Lets a deployment retain `none` even when both peers support zstd. */
  allowZstd?: boolean;
  /** Initiator's authenticated `ready.receive_limits`, when available. */
  localReceiveLimits?: CompressionLimits;
  /** Responder's authenticated `ready.receive_limits`, when available. */
  remoteReceiveLimits?: CompressionLimits;
  /** Responder local policy ceiling, when the local caller is the responder. */
  localPolicyLimits?: CompressionLimits;
}

export interface CompressionNegotiation {
  algorithm: CompressionAlgorithm;
  /** Present only for zstd; `none` carries no cross-message state. */
  limits?: CompressionLimits;
}

export type CompressionNegotiationResult =
  | { ok: true; value: CompressionNegotiation }
  | {
    ok: false;
    code: "COMPRESSION_NEGOTIATION_BEFORE_READY" | "COMPRESSION_OFFER_INVALID" | "COMPRESSION_NO_COMMON_ALGORITHM";
  };

/**
 * The full post-READY wire proposal.  `compression.offer` has the identical
 * structure and exists only as an explicitly named compatibility variant.
 */
export interface CompressionProposalRecord {
  type: CompressionProposalRecordType;
  v: typeof V2_COMPRESSION_VERSION;
  sid: string;
  mesh_id: string;
  proposal_id: string;
  algorithms: readonly ["zstd"];
  zstd: CompressionZstdLimits;
}

export interface CompressionOfferRecord extends Omit<CompressionProposalRecord, "type"> {
  type: "compression.offer";
}

export interface CompressionAcceptRecord {
  type: typeof COMPRESSION_ACCEPT_RECORD_TYPE;
  v: typeof V2_COMPRESSION_VERSION;
  sid: string;
  mesh_id: string;
  proposal_id: string;
  algorithm: CompressionAlgorithm;
  /** Required exactly when `algorithm` is zstd. */
  zstd?: CompressionZstdLimits;
}

export interface CompressionReadyRecord {
  type: typeof COMPRESSION_READY_RECORD_TYPE;
  v: typeof V2_COMPRESSION_VERSION;
  sid: string;
  mesh_id: string;
  proposal_id: string;
  algorithm: "zstd";
  epoch: typeof V2_COMPRESSION_EPOCH;
}

/**
 * One independent zstd frame containing exactly one UTF-8 application
 * envelope.  The wrapper deliberately has no record type, dictionary, stream
 * identifier, or cross-record context: the decoded object must be classified
 * and fully validated before it can be routed.
 */
export interface CompressionZstdWrapper {
  type: typeof COMPRESSION_ZSTD_RECORD_TYPE;
  v: typeof V2_COMPRESSION_VERSION;
  sid: string;
  mesh_id: string;
  epoch: typeof V2_COMPRESSION_EPOCH;
  content_type: typeof V2_COMPRESSION_CONTENT_TYPE;
  uncompressed_bytes: number;
  compressed_bytes: number;
  payload: string;
}

export type CompressionControlRecord =
  | CompressionProposalRecord
  | CompressionAcceptRecord
  | CompressionReadyRecord;
export type CompressionWireRecord = CompressionControlRecord | CompressionZstdWrapper;

/**
 * Wire validation is deliberately separate from state validation.  A record
 * can be well-formed yet invalid for a session role, phase, SID, or mesh.
 */
export type CompressionWireValidationCode =
  | "COMPRESSION_RECORD_INVALID"
  | "COMPRESSION_PROPOSAL_INVALID"
  | "COMPRESSION_ACCEPT_INVALID"
  | "COMPRESSION_READY_INVALID"
  | "COMPRESSION_ZSTD_INVALID"
  | "COMPRESSION_NOT_NEGOTIATED"
  | "COMPRESSION_NEGOTIATION_BEFORE_READY"
  | "COMPRESSION_LIMIT_EXCEEDED"
  | "COMPRESSION_EXPANSION_LIMIT"
  | "COMPRESSION_OUTPUT_SIZE_MISMATCH"
  | "COMPRESSION_INNER_RECORD_INVALID";

export type CompressionWireValidationResult<T> =
  | { ok: true; value: T }
  | { ok: false; code: CompressionWireValidationCode; error: string };

export interface CompressionRecordSession {
  sid: string;
  meshId: string;
}

export interface CompressionZstdWrapperValidationOptions extends CompressionRecordSession {
  /** The final post-ready negotiation, which must select zstd. */
  negotiation: CompressionNegotiation;
  /** True only after both `compression.ready` records have validated. */
  active?: boolean;
  /** Exact serialized wrapper length, supplied by the framing layer when known. */
  wireBytes?: number;
  maxWireBytes?: number;
}

/** Map camel-case local policy limits to the closed wire representation. */
export function compressionLimitsToWire(value: CompressionLimits): CompressionZstdLimits {
  if (!validCompressionLimits(value)) throw new TypeError("Compression limits are invalid");
  return Object.freeze({
    max_compressed_bytes: value.maxCompressedBytes,
    max_uncompressed_bytes: value.maxUncompressedBytes,
    max_expansion_ratio: value.maxExpansionRatio,
  });
}

/** Parse the exact closed wire representation into local policy limits. */
export function compressionLimitsFromWire(value: unknown): CompressionLimits | undefined {
  if (!validWireCompressionLimits(value)) return undefined;
  return Object.freeze({
    maxCompressedBytes: value.max_compressed_bytes,
    maxUncompressedBytes: value.max_uncompressed_bytes,
    maxExpansionRatio: value.max_expansion_ratio,
  });
}

/** Validate one bounded, canonical v0.2 mesh identifier. */
export function isCompressionMeshId(value: unknown): value is string {
  return typeof value === "string" && /^msh_[0-9A-HJKMNP-TV-Z]{26}$/.test(value);
}

/** Validate the 32-byte base64url `sid` used by the v0.2 handshake. */
export function isCompressionSessionId(value: unknown): value is string {
  return isCanonicalBase64Url(value, 32);
}

export function isCompressionProposalRecordType(value: unknown): value is CompressionProposalRecordType {
  return typeof value === "string" && COMPRESSION_PROPOSAL_TYPE_SET.has(value);
}

export function isCompressionAlgorithm(value: unknown): value is CompressionAlgorithm {
  return typeof value === "string" && COMPRESSION_SET.has(value);
}

/** True only for the legacy closed record vocabulary. */
export function isCompressionRecordType(value: unknown): value is CompressionRecordType {
  return typeof value === "string" && COMPRESSION_RECORD_TYPE_SET.has(value);
}

/** True only for a v0.2 application-envelope type eligible for zstd. */
export function isCompressibleApplicationRecordType(value: unknown): value is CompressibleApplicationRecordType {
  return typeof value === "string" && COMPRESSIBLE_APPLICATION_RECORD_TYPE_SET.has(value);
}

/** Runtime guard for a negotiated compression state received from an adapter. */
export function isCompressionNegotiation(value: unknown): value is CompressionNegotiation {
  if (!isRecord(value) || !isCompressionAlgorithm(value.algorithm)) return false;
  if (value.algorithm === "none") return value.limits === undefined;
  return validCompressionLimits(value.limits);
}

/**
 * Negotiate only after READY. `none` is a safe fallback; zstd is selected
 * only when both sides explicitly offered it.  Additional optional limits let
 * the legacy helper model the v0.2 rule that an accept is the component-wise
 * minimum of proposal, both READY receive limits, and responder policy.
 */
export function negotiateCompression(
  local: CompressionOffer,
  remote: CompressionOffer,
  options: CompressionNegotiationOptions,
): CompressionNegotiationResult {
  if (options.ready !== true) return { ok: false, code: "COMPRESSION_NEGOTIATION_BEFORE_READY" };
  const localValidation = validateCompressionOffer(local);
  const remoteValidation = validateCompressionOffer(remote);
  if (!localValidation.ok || !remoteValidation.ok ||
    !optionalLimitsAreValid(options.localReceiveLimits, options.remoteReceiveLimits, options.localPolicyLimits)) {
    return { ok: false, code: "COMPRESSION_OFFER_INVALID" };
  }

  const zstdAllowed = options.allowZstd !== false &&
    local.algorithms.includes("zstd") && remote.algorithms.includes("zstd");
  if (zstdAllowed) {
    const limits = intersectCompressionLimits([
      local.limits!,
      remote.limits!,
      ...(options.localReceiveLimits === undefined ? [] : [options.localReceiveLimits]),
      ...(options.remoteReceiveLimits === undefined ? [] : [options.remoteReceiveLimits]),
      ...(options.localPolicyLimits === undefined ? [] : [options.localPolicyLimits]),
    ]);
    return { ok: true, value: { algorithm: "zstd", limits } };
  }
  if (local.algorithms.includes("none") && remote.algorithms.includes("none")) {
    return { ok: true, value: { algorithm: "none" } };
  }
  return { ok: false, code: "COMPRESSION_NO_COMMON_ALGORITHM" };
}

/**
 * Build the full closed proposal record.  `wireType` is explicit so the old
 * `compression.offer` spelling cannot appear by accidental object spread.
 */
export function createCompressionProposal(
  session: CompressionRecordSession,
  proposalId: string,
  zstd: CompressionZstdLimits | CompressionLimits,
  wireType: CompressionProposalRecordType = "compression.proposal",
): CompressionProposalRecord {
  if (!isCompressionSessionId(session.sid) || !isCompressionMeshId(session.meshId) || !isUuidV7(proposalId) ||
    !isCompressionProposalRecordType(wireType)) {
    throw new TypeError("Compression proposal session or identifier is invalid");
  }
  const wireLimits = toWireLimits(zstd);
  if (!wireLimits) throw new TypeError("Compression proposal zstd limits are invalid");
  return Object.freeze({
    type: wireType,
    v: V2_COMPRESSION_VERSION,
    sid: session.sid,
    mesh_id: session.meshId,
    proposal_id: proposalId,
    algorithms: Object.freeze(["zstd"]) as readonly ["zstd"],
    zstd: wireLimits,
  });
}

export function createCompressionAccept(
  session: CompressionRecordSession,
  proposalId: string,
  negotiation: CompressionNegotiation,
): CompressionAcceptRecord {
  if (!isCompressionSessionId(session.sid) || !isCompressionMeshId(session.meshId) || !isUuidV7(proposalId) ||
    !isCompressionNegotiation(negotiation)) {
    throw new TypeError("Compression acceptance inputs are invalid");
  }
  return Object.freeze({
    type: COMPRESSION_ACCEPT_RECORD_TYPE,
    v: V2_COMPRESSION_VERSION,
    sid: session.sid,
    mesh_id: session.meshId,
    proposal_id: proposalId,
    algorithm: negotiation.algorithm,
    ...(negotiation.algorithm === "zstd" ? { zstd: compressionLimitsToWire(negotiation.limits!) } : {}),
  }) as CompressionAcceptRecord;
}

export function createCompressionReady(
  session: CompressionRecordSession,
  proposalId: string,
): CompressionReadyRecord {
  if (!isCompressionSessionId(session.sid) || !isCompressionMeshId(session.meshId) || !isUuidV7(proposalId)) {
    throw new TypeError("Compression ready inputs are invalid");
  }
  return Object.freeze({
    type: COMPRESSION_READY_RECORD_TYPE,
    v: V2_COMPRESSION_VERSION,
    sid: session.sid,
    mesh_id: session.meshId,
    proposal_id: proposalId,
    algorithm: "zstd",
    epoch: V2_COMPRESSION_EPOCH,
  });
}

/** Build a wrapper after the sender has produced one independent zstd frame. */
export function createCompressionZstdWrapper(
  session: CompressionRecordSession,
  payload: Uint8Array,
  uncompressedBytes: number,
): CompressionZstdWrapper {
  if (!isCompressionSessionId(session.sid) || !isCompressionMeshId(session.meshId) ||
    !isPositiveByteCount(uncompressedBytes) || payload.byteLength === 0 || payload.byteLength > MAX_COMPRESSION_BYTES) {
    throw new TypeError("Compression zstd wrapper inputs are invalid");
  }
  return Object.freeze({
    type: COMPRESSION_ZSTD_RECORD_TYPE,
    v: V2_COMPRESSION_VERSION,
    sid: session.sid,
    mesh_id: session.meshId,
    epoch: V2_COMPRESSION_EPOCH,
    content_type: V2_COMPRESSION_CONTENT_TYPE,
    uncompressed_bytes: uncompressedBytes,
    compressed_bytes: payload.byteLength,
    payload: Buffer.from(payload).toString("base64url"),
  });
}

/** Strict shape validation only; phase, role, and SID/mesh binding are state work. */
export function validateCompressionProposalRecord(value: unknown): CompressionWireValidationResult<CompressionProposalRecord> {
  if (!isRecord(value) || !isCompressionProposalRecordType(value.type) || value.v !== V2_COMPRESSION_VERSION ||
    !hasExactKeys(value, ["type", "v", "sid", "mesh_id", "proposal_id", "algorithms", "zstd"]) ||
    !isCompressionSessionId(value.sid) || !isCompressionMeshId(value.mesh_id) || !isUuidV7(value.proposal_id) ||
    !Array.isArray(value.algorithms) || value.algorithms.length !== 1 || value.algorithms[0] !== "zstd" ||
    !validWireCompressionLimits(value.zstd)) {
    return wireFailure("COMPRESSION_PROPOSAL_INVALID", "Compression proposal has an invalid or unsupported wire shape");
  }
  return { ok: true, value: value as unknown as CompressionProposalRecord };
}

export const validateCompressionProposal = validateCompressionProposalRecord;

export function isCompressionProposalRecord(value: unknown): value is CompressionProposalRecord {
  return validateCompressionProposalRecord(value).ok;
}

export function validateCompressionAcceptRecord(value: unknown): CompressionWireValidationResult<CompressionAcceptRecord> {
  if (!isRecord(value) || value.type !== COMPRESSION_ACCEPT_RECORD_TYPE || value.v !== V2_COMPRESSION_VERSION ||
    !hasOnlyKeys(value, ["type", "v", "sid", "mesh_id", "proposal_id", "algorithm", "zstd"]) ||
    !hasRequiredKeys(value, ["type", "v", "sid", "mesh_id", "proposal_id", "algorithm"]) ||
    !isCompressionSessionId(value.sid) || !isCompressionMeshId(value.mesh_id) || !isUuidV7(value.proposal_id) ||
    !isCompressionAlgorithm(value.algorithm)) {
    return wireFailure("COMPRESSION_ACCEPT_INVALID", "Compression acceptance has an invalid or unsupported wire shape");
  }
  if (value.algorithm === "zstd") {
    if (!validWireCompressionLimits(value.zstd)) {
      return wireFailure("COMPRESSION_ACCEPT_INVALID", "A zstd acceptance requires bounded zstd limits");
    }
  } else if (Object.hasOwn(value, "zstd")) {
    return wireFailure("COMPRESSION_ACCEPT_INVALID", "A none acceptance must not carry zstd limits");
  }
  return { ok: true, value: value as unknown as CompressionAcceptRecord };
}

export const validateCompressionAccept = validateCompressionAcceptRecord;

export function isCompressionAcceptRecord(value: unknown): value is CompressionAcceptRecord {
  return validateCompressionAcceptRecord(value).ok;
}

export function validateCompressionReadyRecord(value: unknown): CompressionWireValidationResult<CompressionReadyRecord> {
  if (!isRecord(value) || value.type !== COMPRESSION_READY_RECORD_TYPE || value.v !== V2_COMPRESSION_VERSION ||
    !hasExactKeys(value, ["type", "v", "sid", "mesh_id", "proposal_id", "algorithm", "epoch"]) ||
    !isCompressionSessionId(value.sid) || !isCompressionMeshId(value.mesh_id) || !isUuidV7(value.proposal_id) ||
    value.algorithm !== "zstd" || value.epoch !== V2_COMPRESSION_EPOCH) {
    return wireFailure("COMPRESSION_READY_INVALID", "Compression ready has an invalid or unsupported wire shape");
  }
  return { ok: true, value: value as unknown as CompressionReadyRecord };
}

export const validateCompressionReady = validateCompressionReadyRecord;

export function isCompressionReadyRecord(value: unknown): value is CompressionReadyRecord {
  return validateCompressionReadyRecord(value).ok;
}

/**
 * Validate all wrapper fields that can be checked before zstd decoding.
 * Decoded bytes and inner-envelope class are deliberately validated by
 * `validateCompressionZstdDecodedEnvelope` after bounded codec output.
 */
export function validateCompressionZstdWrapper(
  value: unknown,
  options: CompressionZstdWrapperValidationOptions,
): CompressionWireValidationResult<CompressionZstdWrapper> {
  if (options.active !== true) {
    return wireFailure("COMPRESSION_NEGOTIATION_BEFORE_READY", "A zstd wrapper is forbidden before both compression ready records validate");
  }
  if (!isCompressionNegotiation(options.negotiation) || options.negotiation.algorithm !== "zstd" || !options.negotiation.limits) {
    return wireFailure("COMPRESSION_NOT_NEGOTIATED", "zstd has not been negotiated for this session");
  }
  if (!isCompressionSessionId(options.sid) || !isCompressionMeshId(options.meshId)) {
    return wireFailure("COMPRESSION_RECORD_INVALID", "Compression wrapper validation context is invalid");
  }
  if (!isRecord(value) || value.type !== COMPRESSION_ZSTD_RECORD_TYPE || value.v !== V2_COMPRESSION_VERSION ||
    !hasExactKeys(value, [
      "type", "v", "sid", "mesh_id", "epoch", "content_type",
      "uncompressed_bytes", "compressed_bytes", "payload",
    ]) ||
    value.sid !== options.sid || value.mesh_id !== options.meshId || value.epoch !== V2_COMPRESSION_EPOCH ||
    value.content_type !== V2_COMPRESSION_CONTENT_TYPE || !isPositiveByteCount(value.uncompressed_bytes) ||
    !isPositiveByteCount(value.compressed_bytes) || !isCanonicalBase64Url(value.payload)) {
    return wireFailure("COMPRESSION_ZSTD_INVALID", "Compression zstd wrapper has an invalid or mismatched wire shape");
  }
  const wrapper = value as unknown as CompressionZstdWrapper;
  if (Buffer.from(wrapper.payload, "base64url").byteLength !== wrapper.compressed_bytes) {
    return wireFailure("COMPRESSION_ZSTD_INVALID", "Compression zstd payload length does not match compressed_bytes");
  }
  const wireBytes = options.wireBytes ?? serializedBytes(value);
  const maxWireBytes = options.maxWireBytes ?? MAX_COMPRESSION_BYTES;
  if (!isPositiveByteCount(maxWireBytes) || wireBytes === undefined || wireBytes > maxWireBytes) {
    return wireFailure("COMPRESSION_LIMIT_EXCEEDED", "Compression wrapper exceeds the negotiated wire-byte limit");
  }
  const limits = options.negotiation.limits;
  if (wrapper.compressed_bytes > limits.maxCompressedBytes || wrapper.uncompressed_bytes > limits.maxUncompressedBytes) {
    return wireFailure("COMPRESSION_LIMIT_EXCEEDED", "Compression wrapper exceeds negotiated zstd limits");
  }
  if (wrapper.uncompressed_bytes / Math.max(1, wrapper.compressed_bytes) > limits.maxExpansionRatio) {
    return wireFailure("COMPRESSION_EXPANSION_LIMIT", "Compression wrapper exceeds the negotiated expansion ratio");
  }
  return { ok: true, value: wrapper };
}

export const validateZstdWrapper = validateCompressionZstdWrapper;

export function isCompressionZstdWrapper(
  value: unknown,
  options: CompressionZstdWrapperValidationOptions,
): value is CompressionZstdWrapper {
  return validateCompressionZstdWrapper(value, options).ok;
}

/**
 * Bind the result of a bounded zstd decode to its wrapper.  This does not
 * replace the ordinary application-envelope schema validator; it guarantees
 * that a decoded value satisfies the full strict v2 application-envelope
 * grammar. A control record or partial object cannot pass the compression
 * boundary as an inner application value.
 */
export function validateCompressionZstdDecodedEnvelope(
  wrapper: CompressionZstdWrapper,
  decodedRecord: unknown,
  actualUncompressedBytes: number,
  negotiation: CompressionNegotiation,
): CompressionWireValidationResult<CompressibleApplicationRecordType> {
  if (!isCompressionNegotiation(negotiation) || negotiation.algorithm !== "zstd" || !negotiation.limits ||
    !isPositiveByteCount(actualUncompressedBytes)) {
    return wireFailure("COMPRESSION_RECORD_INVALID", "Compression decoded-envelope inputs are invalid");
  }
  const limits = negotiation.limits;
  if (actualUncompressedBytes > limits.maxUncompressedBytes) {
    return wireFailure("COMPRESSION_LIMIT_EXCEEDED", "Decoded zstd output exceeds its negotiated byte limit");
  }
  if (actualUncompressedBytes !== wrapper.uncompressed_bytes) {
    return wireFailure("COMPRESSION_OUTPUT_SIZE_MISMATCH", "Decoded zstd output does not equal uncompressed_bytes");
  }
  if (actualUncompressedBytes / Math.max(1, wrapper.compressed_bytes) > limits.maxExpansionRatio) {
    return wireFailure("COMPRESSION_EXPANSION_LIMIT", "Decoded zstd output exceeds its negotiated expansion ratio");
  }
  const envelope = validateV2ApplicationEnvelope(decodedRecord, {
    meshId: wrapper.mesh_id,
    requireMesh: true,
  });
  if (!envelope.ok || !isCompressibleApplicationRecordType(envelope.value.type)) {
    return wireFailure("COMPRESSION_INNER_RECORD_INVALID", "A zstd wrapper may contain only one v0.2 application envelope");
  }
  return { ok: true, value: envelope.value.type };
}

export const validateZstdDecodedEnvelope = validateCompressionZstdDecodedEnvelope;

/** Validate and classify every full Ultra compression wire record. */
export function validateCompressionWireRecord(
  value: unknown,
  wrapperOptions?: CompressionZstdWrapperValidationOptions,
): CompressionWireValidationResult<CompressionWireRecord> {
  if (!isRecord(value) || typeof value.type !== "string") {
    return wireFailure("COMPRESSION_RECORD_INVALID", "Compression record must be an object with a type");
  }
  if (isCompressionProposalRecordType(value.type)) return validateCompressionProposalRecord(value);
  if (value.type === COMPRESSION_ACCEPT_RECORD_TYPE) return validateCompressionAcceptRecord(value);
  if (value.type === COMPRESSION_READY_RECORD_TYPE) return validateCompressionReadyRecord(value);
  if (value.type === COMPRESSION_ZSTD_RECORD_TYPE) {
    return wrapperOptions === undefined
      ? wireFailure("COMPRESSION_NEGOTIATION_BEFORE_READY", "A zstd wrapper requires active session negotiation context")
      : validateCompressionZstdWrapper(value, wrapperOptions);
  }
  return wireFailure("COMPRESSION_RECORD_INVALID", "Unknown compression record type");
}

/**
 * JSON Schema documents are exported for callers using a hardened full Draft
 * 2020-12 implementation. Runtime validators above additionally enforce
 * canonical base64url bytes, size arithmetic, state, and decoded-record
 * classification, which JSON Schema cannot establish alone.
 */
export const COMPRESSION_PROPOSAL_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://polymesh.dev/schemas/v2/compression-proposal.json",
  type: "object",
  additionalProperties: false,
  required: ["type", "v", "sid", "mesh_id", "proposal_id", "algorithms", "zstd"],
  properties: {
    type: { const: "compression.proposal" },
    v: { const: V2_COMPRESSION_VERSION },
    sid: { type: "string", pattern: "^[A-Za-z0-9_-]{43}$", maxLength: 43 },
    mesh_id: { type: "string", pattern: "^msh_[0-9A-HJKMNP-TV-Z]{26}$", maxLength: 30 },
    proposal_id: { type: "string", pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" },
    algorithms: { type: "array", minItems: 1, maxItems: 1, uniqueItems: true, items: { const: "zstd" } },
    zstd: { $ref: "#/$defs/ZstdLimits" },
  },
  $defs: {
    ZstdLimits: {
      type: "object",
      additionalProperties: false,
      required: ["max_compressed_bytes", "max_uncompressed_bytes", "max_expansion_ratio"],
      properties: {
        max_compressed_bytes: { type: "integer", minimum: 1, maximum: MAX_COMPRESSION_BYTES },
        max_uncompressed_bytes: { type: "integer", minimum: 1, maximum: MAX_COMPRESSION_BYTES },
        max_expansion_ratio: { type: "integer", minimum: 1, maximum: MAX_COMPRESSION_EXPANSION_RATIO },
      },
    },
  },
} as const;

/** Explicit compatibility schema for the spelling used by the earlier draft. */
export const COMPRESSION_OFFER_SCHEMA = {
  ...COMPRESSION_PROPOSAL_SCHEMA,
  $id: "https://polymesh.dev/schemas/v2/compression-offer.json",
  properties: {
    ...COMPRESSION_PROPOSAL_SCHEMA.properties,
    type: { const: "compression.offer" },
  },
} as const;

export const COMPRESSION_ACCEPT_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://polymesh.dev/schemas/v2/compression-accept.json",
  type: "object",
  additionalProperties: false,
  required: ["type", "v", "sid", "mesh_id", "proposal_id", "algorithm"],
  properties: {
    type: { const: COMPRESSION_ACCEPT_RECORD_TYPE },
    v: { const: V2_COMPRESSION_VERSION },
    sid: { type: "string", pattern: "^[A-Za-z0-9_-]{43}$", maxLength: 43 },
    mesh_id: { type: "string", pattern: "^msh_[0-9A-HJKMNP-TV-Z]{26}$", maxLength: 30 },
    proposal_id: { type: "string", pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" },
    algorithm: { enum: COMPRESSION_ALGORITHMS },
    zstd: { $ref: "#/$defs/ZstdLimits" },
  },
  allOf: [{
    if: { properties: { algorithm: { const: "zstd" } } },
    then: { required: ["zstd"] },
    else: { not: { required: ["zstd"] } },
  }],
  $defs: COMPRESSION_PROPOSAL_SCHEMA.$defs,
} as const;

export const COMPRESSION_READY_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://polymesh.dev/schemas/v2/compression-ready.json",
  type: "object",
  additionalProperties: false,
  required: ["type", "v", "sid", "mesh_id", "proposal_id", "algorithm", "epoch"],
  properties: {
    type: { const: COMPRESSION_READY_RECORD_TYPE },
    v: { const: V2_COMPRESSION_VERSION },
    sid: { type: "string", pattern: "^[A-Za-z0-9_-]{43}$", maxLength: 43 },
    mesh_id: { type: "string", pattern: "^msh_[0-9A-HJKMNP-TV-Z]{26}$", maxLength: 30 },
    proposal_id: { type: "string", pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" },
    algorithm: { const: "zstd" },
    epoch: { const: V2_COMPRESSION_EPOCH },
  },
} as const;

export const COMPRESSION_ZSTD_WRAPPER_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://polymesh.dev/schemas/v2/compression-zstd.json",
  type: "object",
  additionalProperties: false,
  required: [
    "type", "v", "sid", "mesh_id", "epoch", "content_type",
    "uncompressed_bytes", "compressed_bytes", "payload",
  ],
  properties: {
    type: { const: COMPRESSION_ZSTD_RECORD_TYPE },
    v: { const: V2_COMPRESSION_VERSION },
    sid: { type: "string", pattern: "^[A-Za-z0-9_-]{43}$", maxLength: 43 },
    mesh_id: { type: "string", pattern: "^msh_[0-9A-HJKMNP-TV-Z]{26}$", maxLength: 30 },
    epoch: { const: V2_COMPRESSION_EPOCH },
    content_type: { const: V2_COMPRESSION_CONTENT_TYPE },
    uncompressed_bytes: { type: "integer", minimum: 1, maximum: MAX_COMPRESSION_BYTES },
    compressed_bytes: { type: "integer", minimum: 1, maximum: MAX_COMPRESSION_BYTES },
    payload: { type: "string", minLength: 2, maxLength: 1_398_102, pattern: "^[A-Za-z0-9_-]+$" },
  },
} as const;

/** One convenience document covering every v0.2 compression record class. */
export const V2_COMPRESSION_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://polymesh.dev/schemas/v2/compression.json",
  title: "PolyMesh v2 zstd compression records",
  oneOf: [
    COMPRESSION_PROPOSAL_SCHEMA,
    COMPRESSION_OFFER_SCHEMA,
    COMPRESSION_ACCEPT_SCHEMA,
    COMPRESSION_READY_SCHEMA,
    COMPRESSION_ZSTD_WRAPPER_SCHEMA,
  ],
} as const;
export const COMPRESSION_SCHEMA = V2_COMPRESSION_SCHEMA;
export const COMPRESSION_ZSTD_SCHEMA = COMPRESSION_ZSTD_WRAPPER_SCHEMA;
export const V2_COMPRESSION_PROPOSAL_SCHEMA = COMPRESSION_PROPOSAL_SCHEMA;
export const V2_COMPRESSION_OFFER_SCHEMA = COMPRESSION_OFFER_SCHEMA;
export const V2_COMPRESSION_ACCEPT_SCHEMA = COMPRESSION_ACCEPT_SCHEMA;
export const V2_COMPRESSION_READY_SCHEMA = COMPRESSION_READY_SCHEMA;
export const V2_COMPRESSION_ZSTD_WRAPPER_SCHEMA = COMPRESSION_ZSTD_WRAPPER_SCHEMA;
export const compressionProposalSchema = COMPRESSION_PROPOSAL_SCHEMA;
export const compressionOfferSchema = COMPRESSION_OFFER_SCHEMA;
export const compressionAcceptSchema = COMPRESSION_ACCEPT_SCHEMA;
export const compressionReadySchema = COMPRESSION_READY_SCHEMA;
export const compressionZstdWrapperSchema = COMPRESSION_ZSTD_WRAPPER_SCHEMA;

/**
 * State machines start before the ordinary hello/card/auth/ready handshake,
 * then become eligible for a single post-ready compression negotiation.
 */
export const CompressionNegotiationState = Object.freeze({
  HELLO: "hello",
  ACTIVE_PLAIN: "active_plain",
  PROPOSAL_SENT: "proposal_sent",
  PROPOSAL_RECEIVED: "proposal_received",
  ACCEPT_SENT: "accept_sent",
  ACCEPT_RECEIVED: "accept_received",
  READY_SENT: "ready_sent",
  READY_RECEIVED: "ready_received",
  ACTIVE_COMPRESSED: "active_compressed",
  CLOSED: "closed",
} as const);
export type CompressionNegotiationState = (typeof CompressionNegotiationState)[keyof typeof CompressionNegotiationState];

/**
 * Declarative transition map for observability and conformance tests.  The
 * state-machine methods below additionally bind each action to a session role
 * and record contents; this map intentionally describes only legal topology.
 */
export const COMPRESSION_NEGOTIATION_TRANSITIONS = Object.freeze({
  [CompressionNegotiationState.HELLO]: Object.freeze({
    handshake_ready: CompressionNegotiationState.ACTIVE_PLAIN,
    close: CompressionNegotiationState.CLOSED,
  }),
  [CompressionNegotiationState.ACTIVE_PLAIN]: Object.freeze({
    proposal_sent: CompressionNegotiationState.PROPOSAL_SENT,
    proposal_received: CompressionNegotiationState.PROPOSAL_RECEIVED,
    close: CompressionNegotiationState.CLOSED,
  }),
  [CompressionNegotiationState.PROPOSAL_SENT]: Object.freeze({
    accept_none: CompressionNegotiationState.ACTIVE_PLAIN,
    accept_zstd: CompressionNegotiationState.ACCEPT_RECEIVED,
    close: CompressionNegotiationState.CLOSED,
  }),
  [CompressionNegotiationState.PROPOSAL_RECEIVED]: Object.freeze({
    accept_none: CompressionNegotiationState.ACTIVE_PLAIN,
    accept_zstd: CompressionNegotiationState.ACCEPT_SENT,
    close: CompressionNegotiationState.CLOSED,
  }),
  [CompressionNegotiationState.ACCEPT_RECEIVED]: Object.freeze({
    ready_sent: CompressionNegotiationState.READY_SENT,
    close: CompressionNegotiationState.CLOSED,
  }),
  [CompressionNegotiationState.ACCEPT_SENT]: Object.freeze({
    ready_received: CompressionNegotiationState.READY_RECEIVED,
    close: CompressionNegotiationState.CLOSED,
  }),
  [CompressionNegotiationState.READY_SENT]: Object.freeze({
    ready_received: CompressionNegotiationState.ACTIVE_COMPRESSED,
    close: CompressionNegotiationState.CLOSED,
  }),
  [CompressionNegotiationState.READY_RECEIVED]: Object.freeze({
    ready_sent: CompressionNegotiationState.ACTIVE_COMPRESSED,
    close: CompressionNegotiationState.CLOSED,
  }),
  [CompressionNegotiationState.ACTIVE_COMPRESSED]: Object.freeze({
    close: CompressionNegotiationState.CLOSED,
  }),
  [CompressionNegotiationState.CLOSED]: Object.freeze({}),
} as const);

export type CompressionNegotiationRole = "initiator" | "responder";

export interface CompressionNegotiationStateMachineOptions extends CompressionRecordSession {
  role: CompressionNegotiationRole;
  /** Local authenticated `ready.receive_limits`. */
  localReceiveLimits: CompressionReceiveLimits;
  /** Peer authenticated `ready.receive_limits`. */
  peerReceiveLimits: CompressionReceiveLimits;
  /** Responder's local policy ceiling. Defaults to local receive limits. */
  localPolicyLimits?: CompressionLimits;
  /** Optional known responder policy used by the initiator for exact checking. */
  peerPolicyLimits?: CompressionLimits;
  allowZstd?: boolean;
  /** Explicitly opt into the legacy `compression.offer` wire spelling. */
  proposalWireType?: CompressionProposalRecordType;
}

export interface CompressionNegotiationSnapshot {
  state: CompressionNegotiationState;
  role: CompressionNegotiationRole;
  sid: string;
  meshId: string;
  proposal?: CompressionProposalRecord;
  accept?: CompressionAcceptRecord;
  negotiation?: CompressionNegotiation;
}

export type CompressionStateTransitionCode =
  | "COMPRESSION_INVALID_TRANSITION"
  | "COMPRESSION_ROLE_VIOLATION"
  | "COMPRESSION_SESSION_MISMATCH"
  | "COMPRESSION_MESH_MISMATCH"
  | "COMPRESSION_NEGOTIATION_MISMATCH"
  | CompressionWireValidationCode;

export type CompressionStateTransitionResult<T = undefined> =
  | { ok: true; state: CompressionNegotiationState; value: T; negotiation?: CompressionNegotiation }
  | { ok: false; state: CompressionNegotiationState; code: CompressionStateTransitionCode; error: string };

/**
 * Role-aware one-shot negotiation state machine. It does not perform I/O or
 * zstd decoding; callers send the returned record and pass received records
 * back into the matching method. A new transport connection creates a new
 * instance, so an epoch or proposal is never inherited across reconnects.
 */
export class CompressionNegotiationStateMachine {
  private stateValue: CompressionNegotiationState = CompressionNegotiationState.HELLO;
  private proposal?: CompressionProposalRecord;
  private accept?: CompressionAcceptRecord;
  private negotiationValue?: CompressionNegotiation;
  private proposalConsumed = false;

  readonly role: CompressionNegotiationRole;
  readonly sid: string;
  readonly meshId: string;
  private readonly localReceiveLimits: CompressionLimits;
  private readonly peerReceiveLimits: CompressionLimits;
  private readonly localMaxWireBytes: number;
  private readonly localMaxJsonBytes: number;
  private readonly localPolicyLimits: CompressionLimits;
  private readonly peerPolicyLimits?: CompressionLimits;
  private readonly allowZstd: boolean;
  private readonly proposalWireType: CompressionProposalRecordType;

  constructor(options: CompressionNegotiationStateMachineOptions) {
    if ((options.role !== "initiator" && options.role !== "responder") ||
      !isCompressionSessionId(options.sid) || !isCompressionMeshId(options.meshId) ||
      !validReceiveCompressionLimits(options.localReceiveLimits) || !validReceiveCompressionLimits(options.peerReceiveLimits) ||
      (options.localPolicyLimits !== undefined && !validCompressionLimits(options.localPolicyLimits)) ||
      (options.peerPolicyLimits !== undefined && !validCompressionLimits(options.peerPolicyLimits)) ||
      (options.proposalWireType !== undefined && !isCompressionProposalRecordType(options.proposalWireType))) {
      throw new TypeError("Compression negotiation state machine options are invalid");
    }
    this.role = options.role;
    this.sid = options.sid;
    this.meshId = options.meshId;
    this.localReceiveLimits = normalizeReceiveCompressionLimits(options.localReceiveLimits);
    this.peerReceiveLimits = normalizeReceiveCompressionLimits(options.peerReceiveLimits);
    this.localMaxWireBytes = receiveWireLimit(options.localReceiveLimits);
    this.localMaxJsonBytes = receiveJsonLimit(options.localReceiveLimits);
    this.localPolicyLimits = freezeLimits(options.localPolicyLimits ?? options.localReceiveLimits);
    this.peerPolicyLimits = options.peerPolicyLimits === undefined ? undefined : freezeLimits(options.peerPolicyLimits);
    this.allowZstd = options.allowZstd !== false;
    this.proposalWireType = options.proposalWireType ?? "compression.proposal";
  }

  get state(): CompressionNegotiationState {
    return this.stateValue;
  }

  get negotiation(): CompressionNegotiation | undefined {
    return this.negotiationValue === undefined ? undefined : cloneNegotiation(this.negotiationValue);
  }

  get activeCompression(): boolean {
    return this.stateValue === CompressionNegotiationState.ACTIVE_COMPRESSED;
  }

  get canSendUncompressedEnvelope(): boolean {
    return this.stateValue === CompressionNegotiationState.ACTIVE_PLAIN || this.stateValue === CompressionNegotiationState.ACTIVE_COMPRESSED;
  }

  snapshot(): CompressionNegotiationSnapshot {
    return {
      state: this.stateValue,
      role: this.role,
      sid: this.sid,
      meshId: this.meshId,
      ...(this.proposal === undefined ? {} : { proposal: this.proposal }),
      ...(this.accept === undefined ? {} : { accept: this.accept }),
      ...(this.negotiationValue === undefined ? {} : { negotiation: cloneNegotiation(this.negotiationValue) }),
    };
  }

  /** Complete the ordinary hello/auth/card/ready handshake. */
  markHandshakeReady(): CompressionStateTransitionResult<undefined> {
    if (this.stateValue !== CompressionNegotiationState.HELLO) {
      return this.failure("COMPRESSION_INVALID_TRANSITION", "The ordinary handshake was already completed or the session is closed");
    }
    this.stateValue = CompressionNegotiationState.ACTIVE_PLAIN;
    return this.success(undefined);
  }

  /** Alias that reads naturally in transport state-machine code. */
  onHandshakeReady(): CompressionStateTransitionResult<undefined> {
    return this.markHandshakeReady();
  }

  /** Only the transport initiator can issue the one permitted proposal. */
  createProposal(proposalId: string, zstd: CompressionZstdLimits | CompressionLimits): CompressionStateTransitionResult<CompressionProposalRecord> {
    if (this.role !== "initiator") return this.failure("COMPRESSION_ROLE_VIOLATION", "Only the transport initiator may propose compression");
    if (this.stateValue !== CompressionNegotiationState.ACTIVE_PLAIN || this.proposalConsumed) {
      return this.failure("COMPRESSION_INVALID_TRANSITION", "Compression may be proposed once from ACTIVE_PLAIN");
    }
    let proposal: CompressionProposalRecord;
    try {
      proposal = createCompressionProposal(this, proposalId, zstd, this.proposalWireType);
    } catch {
      return this.failure("COMPRESSION_PROPOSAL_INVALID", "Compression proposal inputs are invalid");
    }
    this.proposal = proposal;
    this.proposalConsumed = true;
    this.stateValue = CompressionNegotiationState.PROPOSAL_SENT;
    return this.success(proposal);
  }

  /** Receive the initiator's post-ready proposal at the responder. */
  receiveProposal(value: unknown): CompressionStateTransitionResult<CompressionProposalRecord> {
    if (this.role !== "responder") return this.failClosed("COMPRESSION_ROLE_VIOLATION", "Only the transport responder may receive a compression proposal");
    if (this.stateValue !== CompressionNegotiationState.ACTIVE_PLAIN || this.proposalConsumed) {
      return this.failClosed("COMPRESSION_INVALID_TRANSITION", "Compression proposal is unexpected in the current session state");
    }
    const validated = validateCompressionProposalRecord(value);
    if (!validated.ok) return this.failClosed(validated.code, validated.error);
    const binding = this.validateRecordBinding(validated.value);
    if (!binding.ok) return this.failClosed(binding.code, binding.error);
    this.proposal = validated.value;
    this.proposalConsumed = true;
    this.stateValue = CompressionNegotiationState.PROPOSAL_RECEIVED;
    return this.success(validated.value);
  }

  /**
   * Respond to a proposal. `none` immediately restores ACTIVE_PLAIN; a zstd
   * selection waits for both compression.ready records before activation.
   */
  createAccept(): CompressionStateTransitionResult<CompressionAcceptRecord> {
    if (this.role !== "responder") return this.failure("COMPRESSION_ROLE_VIOLATION", "Only the transport responder may accept compression");
    if (this.stateValue !== CompressionNegotiationState.PROPOSAL_RECEIVED || !this.proposal) {
      return this.failure("COMPRESSION_INVALID_TRANSITION", "Compression acceptance requires a received proposal");
    }
    const selection = selectCompressionForProposal(this.proposal, {
      initiatorReceiveLimits: this.peerReceiveLimits,
      responderReceiveLimits: this.localReceiveLimits,
      responderPolicyLimits: this.localPolicyLimits,
      allowZstd: this.allowZstd,
    });
    if (!selection.ok) return this.failure(selection.code, selection.error);
    const accept = createCompressionAccept(this, this.proposal.proposal_id, selection.value);
    this.accept = accept;
    this.negotiationValue = cloneNegotiation(selection.value);
    this.stateValue = selection.value.algorithm === "none"
      ? CompressionNegotiationState.ACTIVE_PLAIN
      : CompressionNegotiationState.ACCEPT_SENT;
    return this.success(accept);
  }

  /** Receive and verify the responder's selected limits at the initiator. */
  receiveAccept(value: unknown): CompressionStateTransitionResult<CompressionAcceptRecord> {
    if (this.role !== "initiator") return this.failClosed("COMPRESSION_ROLE_VIOLATION", "Only the transport initiator may receive a compression acceptance");
    if (this.stateValue !== CompressionNegotiationState.PROPOSAL_SENT || !this.proposal) {
      return this.failClosed("COMPRESSION_INVALID_TRANSITION", "Compression acceptance requires a sent proposal");
    }
    const validated = validateCompressionAcceptRecord(value);
    if (!validated.ok) return this.failClosed(validated.code, validated.error);
    const binding = this.validateRecordBinding(validated.value);
    if (!binding.ok) return this.failClosed(binding.code, binding.error);
    if (validated.value.proposal_id !== this.proposal.proposal_id) {
      return this.failClosed("COMPRESSION_NEGOTIATION_MISMATCH", "Compression acceptance names a different proposal");
    }
    const selection = validateAcceptedSelection(this.proposal, validated.value, {
      initiatorReceiveLimits: this.localReceiveLimits,
      responderReceiveLimits: this.peerReceiveLimits,
      responderPolicyLimits: this.peerPolicyLimits,
    });
    if (!selection.ok) return this.failClosed(selection.code, selection.error);
    this.accept = validated.value;
    this.negotiationValue = cloneNegotiation(selection.value);
    this.stateValue = selection.value.algorithm === "none"
      ? CompressionNegotiationState.ACTIVE_PLAIN
      : CompressionNegotiationState.ACCEPT_RECEIVED;
    return this.success(validated.value);
  }

  /** Send this side's zstd barrier once a zstd accept is known. */
  createReady(): CompressionStateTransitionResult<CompressionReadyRecord> {
    const expectedState = this.role === "initiator"
      ? CompressionNegotiationState.ACCEPT_RECEIVED
      : CompressionNegotiationState.READY_RECEIVED;
    if (this.stateValue !== expectedState || !this.proposal || this.negotiationValue?.algorithm !== "zstd") {
      return this.failure("COMPRESSION_INVALID_TRANSITION", "Compression ready requires an accepted zstd negotiation");
    }
    const ready = createCompressionReady(this, this.proposal.proposal_id);
    this.stateValue = this.role === "initiator"
      ? CompressionNegotiationState.READY_SENT
      : CompressionNegotiationState.ACTIVE_COMPRESSED;
    return this.success(ready);
  }

  /** Receive the peer's zstd barrier. The responder must then echo its own. */
  receiveReady(value: unknown): CompressionStateTransitionResult<CompressionReadyRecord> {
    const expectedState = this.role === "initiator"
      ? CompressionNegotiationState.READY_SENT
      : CompressionNegotiationState.ACCEPT_SENT;
    if (this.stateValue !== expectedState || !this.proposal || this.negotiationValue?.algorithm !== "zstd") {
      return this.failClosed("COMPRESSION_INVALID_TRANSITION", "Compression ready is unexpected in the current negotiation state");
    }
    const validated = validateCompressionReadyRecord(value);
    if (!validated.ok) return this.failClosed(validated.code, validated.error);
    const binding = this.validateRecordBinding(validated.value);
    if (!binding.ok) return this.failClosed(binding.code, binding.error);
    if (validated.value.proposal_id !== this.proposal.proposal_id) {
      return this.failClosed("COMPRESSION_NEGOTIATION_MISMATCH", "Compression ready names a different proposal");
    }
    this.stateValue = this.role === "initiator"
      ? CompressionNegotiationState.ACTIVE_COMPRESSED
      : CompressionNegotiationState.READY_RECEIVED;
    return this.success(validated.value);
  }

  /** Validate an incoming wrapper against the exact active session state. */
  validateZstdWrapper(value: unknown, options: Omit<CompressionZstdWrapperValidationOptions, "sid" | "meshId" | "negotiation" | "active"> = {}): CompressionWireValidationResult<CompressionZstdWrapper> {
    const result = validateCompressionZstdWrapper(value, {
      ...options,
      sid: this.sid,
      meshId: this.meshId,
      negotiation: this.negotiationValue ?? { algorithm: "none" },
      active: this.stateValue === CompressionNegotiationState.ACTIVE_COMPRESSED,
      maxWireBytes: options.maxWireBytes ?? this.localMaxWireBytes,
    });
    if (!result.ok && this.stateValue === CompressionNegotiationState.ACTIVE_COMPRESSED) this.close();
    return result;
  }

  /** Decode binding is also terminal for an authenticated active session. */
  validateZstdDecodedEnvelope(
    wrapper: CompressionZstdWrapper,
    decodedRecord: unknown,
    actualUncompressedBytes: number,
  ): CompressionWireValidationResult<CompressibleApplicationRecordType> {
    if (actualUncompressedBytes > this.localMaxJsonBytes) {
      if (this.stateValue === CompressionNegotiationState.ACTIVE_COMPRESSED) this.close();
      return wireFailure("COMPRESSION_LIMIT_EXCEEDED", "Decoded zstd output exceeds the local JSON receive limit");
    }
    const result = validateCompressionZstdDecodedEnvelope(
      wrapper,
      decodedRecord,
      actualUncompressedBytes,
      this.negotiationValue ?? { algorithm: "none" },
    );
    if (!result.ok && this.stateValue === CompressionNegotiationState.ACTIVE_COMPRESSED) this.close();
    return result;
  }

  /** Close is terminal; a reconnect must instantiate a fresh state machine. */
  close(): void {
    this.stateValue = CompressionNegotiationState.CLOSED;
  }

  /** Dispatch a received control record without making callers switch on type. */
  receive(value: unknown): CompressionStateTransitionResult<CompressionControlRecord> {
    if (!isRecord(value) || typeof value.type !== "string") {
      return this.failClosed("COMPRESSION_RECORD_INVALID", "Compression control record must have a type");
    }
    if (isCompressionProposalRecordType(value.type)) return this.receiveProposal(value);
    if (value.type === COMPRESSION_ACCEPT_RECORD_TYPE) return this.receiveAccept(value);
    if (value.type === COMPRESSION_READY_RECORD_TYPE) return this.receiveReady(value);
    return this.failClosed("COMPRESSION_RECORD_INVALID", "Unexpected compression record type");
  }

  private validateRecordBinding(record: Pick<CompressionProposalRecord, "sid" | "mesh_id">): CompressionStateTransitionResult<never> | { ok: true } {
    if (record.sid !== this.sid) return this.failure("COMPRESSION_SESSION_MISMATCH", "Compression record sid does not match this session");
    if (record.mesh_id !== this.meshId) return this.failure("COMPRESSION_MESH_MISMATCH", "Compression record mesh_id does not match this session");
    return { ok: true };
  }

  private success<T>(value: T): CompressionStateTransitionResult<T> {
    return {
      ok: true,
      state: this.stateValue,
      value,
      ...(this.negotiationValue === undefined ? {} : { negotiation: cloneNegotiation(this.negotiationValue) }),
    };
  }

  private failure(code: CompressionStateTransitionCode, error: string): CompressionStateTransitionResult<never> {
    return { ok: false, state: this.stateValue, code, error };
  }

  private failClosed(code: CompressionStateTransitionCode, error: string): CompressionStateTransitionResult<never> {
    this.close();
    return { ok: false, state: this.stateValue, code, error };
  }
}

/** Shorter alias for integrations that use `Machine` naming. */
export const CompressionNegotiationMachine = CompressionNegotiationStateMachine;

export interface CompressionProposalSelectionOptions {
  initiatorReceiveLimits: CompressionLimits;
  responderReceiveLimits: CompressionLimits;
  responderPolicyLimits: CompressionLimits;
  allowZstd?: boolean;
}

/** The initiator may not know the responder's private policy ceiling. */
export interface CompressionAcceptedSelectionOptions {
  initiatorReceiveLimits: CompressionLimits;
  responderReceiveLimits: CompressionLimits;
  responderPolicyLimits?: CompressionLimits;
}

export type CompressionProposalSelectionResult =
  | { ok: true; value: CompressionNegotiation }
  | { ok: false; code: "COMPRESSION_PROPOSAL_INVALID" | "COMPRESSION_NEGOTIATION_MISMATCH"; error: string };

/** Compute the responder-owned selection mandated by the v0.2 profile. */
export function selectCompressionForProposal(
  proposal: CompressionProposalRecord,
  options: CompressionProposalSelectionOptions,
): CompressionProposalSelectionResult {
  const validProposal = validateCompressionProposalRecord(proposal);
  if (!validProposal.ok || !validCompressionLimits(options.initiatorReceiveLimits) ||
    !validCompressionLimits(options.responderReceiveLimits) || !validCompressionLimits(options.responderPolicyLimits)) {
    return { ok: false, code: "COMPRESSION_PROPOSAL_INVALID", error: "Compression proposal or negotiated limits are invalid" };
  }
  if (options.allowZstd === false) return { ok: true, value: { algorithm: "none" } };
  const proposed = compressionLimitsFromWire(proposal.zstd)!;
  return {
    ok: true,
    value: {
      algorithm: "zstd",
      limits: intersectCompressionLimits([
        proposed,
        options.initiatorReceiveLimits,
        options.responderReceiveLimits,
        options.responderPolicyLimits,
      ]),
    },
  };
}

/** Verify that an accept cannot select an unoffered codec or widen any limit. */
export function validateAcceptedSelection(
  proposal: CompressionProposalRecord,
  accept: CompressionAcceptRecord,
  options: CompressionAcceptedSelectionOptions,
): CompressionProposalSelectionResult {
  const validProposal = validateCompressionProposalRecord(proposal);
  const validAccept = validateCompressionAcceptRecord(accept);
  if (!validProposal.ok || !validAccept.ok || accept.proposal_id !== proposal.proposal_id ||
    !validCompressionLimits(options.initiatorReceiveLimits) || !validCompressionLimits(options.responderReceiveLimits) ||
    (options.responderPolicyLimits !== undefined && !validCompressionLimits(options.responderPolicyLimits))) {
    return { ok: false, code: "COMPRESSION_NEGOTIATION_MISMATCH", error: "Compression acceptance does not bind to the proposal" };
  }
  if (accept.algorithm === "none") return { ok: true, value: { algorithm: "none" } };
  if (!accept.zstd) {
    return { ok: false, code: "COMPRESSION_NEGOTIATION_MISMATCH", error: "zstd acceptance has no limits" };
  }
  const acceptedLimits = compressionLimitsFromWire(accept.zstd);
  const proposalLimits = compressionLimitsFromWire(proposal.zstd);
  if (!acceptedLimits || !proposalLimits) {
    return { ok: false, code: "COMPRESSION_NEGOTIATION_MISMATCH", error: "Compression acceptance limits are invalid" };
  }
  const knownCeiling = intersectCompressionLimits([
    proposalLimits,
    options.initiatorReceiveLimits,
    options.responderReceiveLimits,
    ...(options.responderPolicyLimits === undefined ? [] : [options.responderPolicyLimits]),
  ]);
  // If policy is not visible to the initiator, a strictly lower selected
  // limit remains valid; it is a responder policy restriction, never a
  // widening. If it is visible, equality proves the exact minimum rule.
  const exactPolicyKnown = options.responderPolicyLimits !== undefined;
  const matches = exactPolicyKnown
    ? sameCompressionLimits(acceptedLimits, knownCeiling)
    : doesNotExceedCompressionLimits(acceptedLimits, knownCeiling);
  if (!matches) {
    return { ok: false, code: "COMPRESSION_NEGOTIATION_MISMATCH", error: "Compression acceptance widens or mismatches negotiated limits" };
  }
  return { ok: true, value: { algorithm: "zstd", limits: freezeLimits(acceptedLimits) } };
}

/** Records which must never appear inside a zstd wrapper. */
export const UNCOMPRESSIBLE_RECORD_TYPES: ReadonlySet<CompressionRecordType> = new Set(
  COMPRESSION_RECORD_TYPES.filter((type) => !COMPRESSIBLE_APPLICATION_RECORD_TYPE_SET.has(type)),
);

/** Only complete v0.2 application envelopes are eligible for zstd. */
export function compressionAllowedForRecord(recordType: string): boolean {
  return isCompressibleApplicationRecordType(recordType);
}

/** Legacy metadata shape retained for current transport adapters. */
export interface CompressionFrameMetadata {
  algorithm: CompressionAlgorithm;
  /** A closed record type; zstd accepts only an application-envelope type. */
  recordType: string;
  compressedBytes: number;
  /** Required for zstd so limits can be checked before decompression. */
  uncompressedBytes?: number;
}

export type CompressionFrameValidationResult =
  | { ok: true; uncompressedBytes: number }
  | {
    ok: false;
    code:
      | "COMPRESSION_FORBIDDEN_RECORD"
      | "COMPRESSION_NOT_NEGOTIATED"
      | "COMPRESSION_METADATA_INVALID"
      | "COMPRESSION_LIMIT_EXCEEDED"
      | "COMPRESSION_EXPANSION_LIMIT";
  };

export type DecompressedOutputValidationResult =
  | { ok: true; uncompressedBytes: number }
  | {
    ok: false;
    code:
      | "COMPRESSION_FORBIDDEN_RECORD"
      | "COMPRESSION_NOT_NEGOTIATED"
      | "COMPRESSION_METADATA_INVALID"
      | "COMPRESSION_LIMIT_EXCEEDED"
      | "COMPRESSION_EXPANSION_LIMIT"
      | "COMPRESSION_OUTPUT_SIZE_MISMATCH";
  };

export type CompressionRecordBindingResult =
  | { ok: true; recordType: CompressionRecordType }
  | {
    ok: false;
    code:
      | "COMPRESSION_METADATA_INVALID"
      | "COMPRESSION_FORBIDDEN_RECORD"
      | "COMPRESSION_RECORD_TYPE_MISMATCH";
  };

/**
 * Validate declared legacy metadata before decompression.  The codec must
 * still call `validateDecompressedOutput` with actual output length.
 */
export function validateCompressionFrame(
  negotiation: CompressionNegotiation,
  frame: CompressionFrameMetadata,
): CompressionFrameValidationResult {
  if (!isCompressionNegotiation(negotiation) || !isCompressionAlgorithm(frame.algorithm) || !isCompressionRecordType(frame.recordType) ||
    !isFiniteByteCount(frame.compressedBytes)) {
    return { ok: false, code: "COMPRESSION_METADATA_INVALID" };
  }
  if (!compressionAllowedForRecord(frame.recordType) && frame.algorithm !== "none") {
    return { ok: false, code: "COMPRESSION_FORBIDDEN_RECORD" };
  }
  if (frame.algorithm !== negotiation.algorithm) return { ok: false, code: "COMPRESSION_NOT_NEGOTIATED" };

  if (frame.algorithm === "none") {
    if (frame.uncompressedBytes !== undefined && (!isFiniteByteCount(frame.uncompressedBytes) || frame.uncompressedBytes !== frame.compressedBytes)) {
      return { ok: false, code: "COMPRESSION_METADATA_INVALID" };
    }
    return { ok: true, uncompressedBytes: frame.compressedBytes };
  }

  const limits = negotiation.limits;
  if (!limits || !isPositiveByteCount(frame.compressedBytes) || !isPositiveByteCount(frame.uncompressedBytes)) {
    return { ok: false, code: "COMPRESSION_METADATA_INVALID" };
  }
  if (frame.compressedBytes > limits.maxCompressedBytes || frame.uncompressedBytes > limits.maxUncompressedBytes) {
    return { ok: false, code: "COMPRESSION_LIMIT_EXCEEDED" };
  }
  if (frame.uncompressedBytes / Math.max(1, frame.compressedBytes) > limits.maxExpansionRatio) {
    return { ok: false, code: "COMPRESSION_EXPANSION_LIMIT" };
  }
  return { ok: true, uncompressedBytes: frame.uncompressedBytes };
}

/** Bind legacy metadata to a decoded record before normal routing validation. */
export function validateCompressionRecordBinding(
  frame: CompressionFrameMetadata,
  decodedRecord: unknown,
): CompressionRecordBindingResult {
  if (!isCompressionAlgorithm(frame.algorithm) || !isCompressionRecordType(frame.recordType)) {
    return { ok: false, code: "COMPRESSION_METADATA_INVALID" };
  }
  if (!compressionAllowedForRecord(frame.recordType) && frame.algorithm !== "none") {
    return { ok: false, code: "COMPRESSION_FORBIDDEN_RECORD" };
  }
  if (!isRecord(decodedRecord) || decodedRecord.type !== frame.recordType) {
    return { ok: false, code: "COMPRESSION_RECORD_TYPE_MISMATCH" };
  }
  return { ok: true, recordType: frame.recordType };
}

/** Validate actual codec output after pre-decompression metadata admission. */
export function validateDecompressedOutput(
  negotiation: CompressionNegotiation,
  frame: CompressionFrameMetadata,
  actualBytes: number,
): DecompressedOutputValidationResult {
  const declared = validateCompressionFrame(negotiation, frame);
  if (!declared.ok) return declared;
  if (!isFiniteByteCount(actualBytes)) return { ok: false, code: "COMPRESSION_METADATA_INVALID" };

  if (frame.algorithm === "none") {
    return actualBytes === declared.uncompressedBytes
      ? { ok: true, uncompressedBytes: actualBytes }
      : { ok: false, code: "COMPRESSION_OUTPUT_SIZE_MISMATCH" };
  }

  const limits = negotiation.limits;
  if (!limits) return { ok: false, code: "COMPRESSION_METADATA_INVALID" };
  if (actualBytes > limits.maxUncompressedBytes) return { ok: false, code: "COMPRESSION_LIMIT_EXCEEDED" };
  if (frame.compressedBytes === 0 && actualBytes > 0) return { ok: false, code: "COMPRESSION_EXPANSION_LIMIT" };
  if (frame.compressedBytes > 0 && actualBytes / frame.compressedBytes > limits.maxExpansionRatio) {
    return { ok: false, code: "COMPRESSION_EXPANSION_LIMIT" };
  }
  return actualBytes === declared.uncompressedBytes
    ? { ok: true, uncompressedBytes: actualBytes }
    : { ok: false, code: "COMPRESSION_OUTPUT_SIZE_MISMATCH" };
}

export function assertDecompressedSize(
  negotiation: CompressionNegotiation,
  frame: CompressionFrameMetadata,
  actualBytes: number,
): boolean {
  return validateDecompressedOutput(negotiation, frame, actualBytes).ok;
}

/** Rate-limit compressed input by both wire and declared decoded byte size. */
export function compressionRateLimitCharges(frame: CompressionFrameMetadata): readonly RateLimitCharge[] {
  if (!isCompressionAlgorithm(frame.algorithm) || !isCompressionRecordType(frame.recordType) ||
    !isFiniteByteCount(frame.compressedBytes)) {
    throw new TypeError("Compression frame metadata is invalid");
  }
  if (!compressionAllowedForRecord(frame.recordType) && frame.algorithm !== "none") {
    throw new TypeError("Compression is forbidden for this record type");
  }
  if (frame.algorithm === "none") return [{ operation: "uncompressed_bytes", cost: frame.compressedBytes }];
  if (!isPositiveByteCount(frame.compressedBytes) || !isPositiveByteCount(frame.uncompressedBytes)) {
    throw new TypeError("A zstd frame requires positive compressed and uncompressed byte counts");
  }
  return [
    { operation: "compressed_bytes", cost: frame.compressedBytes },
    { operation: "uncompressed_bytes", cost: frame.uncompressedBytes },
  ];
}

function validateCompressionOffer(offer: CompressionOffer): { ok: true } | { ok: false } {
  if (!offer || typeof offer !== "object" || !Array.isArray(offer.algorithms) || offer.algorithms.length === 0) return { ok: false };
  const unique = new Set<string>();
  for (const algorithm of offer.algorithms) {
    if (!isCompressionAlgorithm(algorithm) || unique.has(algorithm)) return { ok: false };
    unique.add(algorithm);
  }
  if (!unique.has("none")) return { ok: false };
  if (unique.has("zstd") !== (offer.limits !== undefined)) return { ok: false };
  if (unique.has("zstd") && !validCompressionLimits(offer.limits)) return { ok: false };
  return { ok: true };
}

function validCompressionLimits(value: unknown): value is CompressionLimits {
  return isRecord(value) &&
    isPositiveByteCount(value.maxCompressedBytes) && value.maxCompressedBytes <= MAX_COMPRESSION_BYTES &&
    isPositiveByteCount(value.maxUncompressedBytes) && value.maxUncompressedBytes <= MAX_COMPRESSION_BYTES &&
    isPositiveSafeInteger(value.maxExpansionRatio) && value.maxExpansionRatio <= MAX_COMPRESSION_EXPANSION_RATIO;
}

function validReceiveCompressionLimits(value: unknown): value is CompressionReceiveLimits {
  return validCompressionLimits(value) && isRecord(value) &&
    (value.maxWireBytes === undefined || (isPositiveByteCount(value.maxWireBytes) && value.maxWireBytes <= MAX_COMPRESSION_BYTES)) &&
    (value.maxJsonBytes === undefined || (isPositiveByteCount(value.maxJsonBytes) && value.maxJsonBytes <= MAX_COMPRESSION_BYTES));
}

function receiveWireLimit(value: CompressionReceiveLimits): number {
  return value.maxWireBytes ?? MAX_COMPRESSION_BYTES;
}

function receiveJsonLimit(value: CompressionReceiveLimits): number {
  return value.maxJsonBytes ?? MAX_COMPRESSION_BYTES;
}

/** A READY max_json_bytes is an additional ceiling on decoded envelope bytes. */
function normalizeReceiveCompressionLimits(value: CompressionReceiveLimits): CompressionLimits {
  return freezeLimits({
    maxCompressedBytes: value.maxCompressedBytes,
    maxUncompressedBytes: Math.min(value.maxUncompressedBytes, receiveJsonLimit(value)),
    maxExpansionRatio: value.maxExpansionRatio,
  });
}

function validWireCompressionLimits(value: unknown): value is CompressionZstdLimits {
  return isRecord(value) &&
    isPositiveByteCount(value.max_compressed_bytes) && value.max_compressed_bytes <= MAX_COMPRESSION_BYTES &&
    isPositiveByteCount(value.max_uncompressed_bytes) && value.max_uncompressed_bytes <= MAX_COMPRESSION_BYTES &&
    isPositiveSafeInteger(value.max_expansion_ratio) && value.max_expansion_ratio <= MAX_COMPRESSION_EXPANSION_RATIO;
}

function toWireLimits(value: CompressionZstdLimits | CompressionLimits): CompressionZstdLimits | undefined {
  if (validWireCompressionLimits(value)) return Object.freeze({ ...value });
  return validCompressionLimits(value) ? compressionLimitsToWire(value) : undefined;
}

function optionalLimitsAreValid(...limits: Array<CompressionLimits | undefined>): boolean {
  return limits.every((limits) => limits === undefined || validCompressionLimits(limits));
}

function intersectCompressionLimits(limits: readonly CompressionLimits[]): CompressionLimits {
  if (limits.length === 0 || limits.some((limit) => !validCompressionLimits(limit))) {
    throw new TypeError("Compression limit intersection requires valid limits");
  }
  return Object.freeze({
    maxCompressedBytes: Math.min(...limits.map((limit) => limit.maxCompressedBytes)),
    maxUncompressedBytes: Math.min(...limits.map((limit) => limit.maxUncompressedBytes)),
    maxExpansionRatio: Math.min(...limits.map((limit) => limit.maxExpansionRatio)),
  });
}

function sameCompressionLimits(left: CompressionLimits, right: CompressionLimits): boolean {
  return left.maxCompressedBytes === right.maxCompressedBytes &&
    left.maxUncompressedBytes === right.maxUncompressedBytes &&
    left.maxExpansionRatio === right.maxExpansionRatio;
}

function doesNotExceedCompressionLimits(value: CompressionLimits, ceiling: CompressionLimits): boolean {
  return value.maxCompressedBytes <= ceiling.maxCompressedBytes &&
    value.maxUncompressedBytes <= ceiling.maxUncompressedBytes &&
    value.maxExpansionRatio <= ceiling.maxExpansionRatio;
}

function freezeLimits(value: CompressionLimits): CompressionLimits {
  return Object.freeze({ ...value });
}

function cloneNegotiation(value: CompressionNegotiation): CompressionNegotiation {
  return value.algorithm === "none"
    ? Object.freeze({ algorithm: "none" as const })
    : Object.freeze({ algorithm: "zstd" as const, limits: freezeLimits(value.limits!) });
}

function wireFailure<T = never>(code: CompressionWireValidationCode, error: string): CompressionWireValidationResult<T> {
  return { ok: false, code, error };
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

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).length === keys.length && hasRequiredKeys(value, keys) && hasOnlyKeys(value, keys);
}

function isFiniteByteCount(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isPositiveByteCount(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 1;
}

function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 1;
}

function isUuidV7(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
}

function isCanonicalBase64Url(value: unknown, bytes?: number): value is string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) return false;
  try {
    const decoded = Buffer.from(value, "base64url");
    return decoded.byteLength > 0 && (bytes === undefined || decoded.byteLength === bytes) && decoded.toString("base64url") === value;
  } catch {
    return false;
  }
}

function serializedBytes(value: unknown): number | undefined {
  try {
    const encoded = JSON.stringify(value);
    return typeof encoded === "string" ? Buffer.byteLength(encoded, "utf8") : undefined;
  } catch {
    return undefined;
  }
}

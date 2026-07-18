/**
 * v0.2 compression negotiation and safety policy.
 *
 * This is intentionally a protocol model only. The broker's Node transport
 * adapter may invoke the runtime zstd codec, but it must enforce this module's
 * negotiated metadata before decompression and bind the decoded record before
 * routing it.
 */

import type { RateLimitCharge } from "./rate-limit.js";

export const COMPRESSION_ALGORITHMS = ["none", "zstd"] as const;
export type CompressionAlgorithm = (typeof COMPRESSION_ALGORITHMS)[number];

/**
 * Closed record vocabulary for compression metadata.  The metadata is a
 * transport assertion, so it must be tied to a known protocol record rather
 * than allowing an arbitrary label such as `"task.submit"` for an auth
 * record.  New wire extensions must be deliberately added here alongside
 * their parser and compression policy.
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

export const DEFAULT_COMPRESSION_LIMITS: Readonly<CompressionLimits> = Object.freeze({
  maxCompressedBytes: 1_048_576,
  maxUncompressedBytes: 1_048_576,
  maxExpansionRatio: 16,
});

/** Bounds negotiated before any compressed data is accepted. */
export interface CompressionLimits {
  maxCompressedBytes: number;
  maxUncompressedBytes: number;
  maxExpansionRatio: number;
}

/** Capabilities sent only after both peers have exchanged READY. */
export interface CompressionOffer {
  /** `none` is mandatory; zstd is optional and requires limits. */
  algorithms: readonly CompressionAlgorithm[];
  /** Required when zstd is advertised. */
  limits?: CompressionLimits;
}

export interface CompressionNegotiationOptions {
  /** Must be true only after the protocol READY exchange has completed. */
  ready: boolean;
  /** Lets a deployment retain `none` even when both sides support zstd. */
  allowZstd?: boolean;
}

export interface CompressionNegotiation {
  algorithm: CompressionAlgorithm;
  /** Present only for zstd; `none` carries no implicit cross-message state. */
  limits?: CompressionLimits;
}

export type CompressionNegotiationResult =
  | { ok: true; value: CompressionNegotiation }
  | {
    ok: false;
    code: "COMPRESSION_NEGOTIATION_BEFORE_READY" | "COMPRESSION_OFFER_INVALID" | "COMPRESSION_NO_COMMON_ALGORITHM";
  };

/** Record types that must never be sent as compressed payloads. */
export const UNCOMPRESSIBLE_RECORD_TYPES: ReadonlySet<CompressionRecordType> = new Set([
  "hello",
  "card",
  "auth",
  "ready",
  "receipt",
  "delivery.receipt",
]);

export interface CompressionFrameMetadata {
  algorithm: CompressionAlgorithm;
  /** A closed transport/control record type, never application-supplied free text. */
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

/**
 * Result of comparing codec output with the metadata that was accepted before
 * decompression.  A declared byte count is only an admission hint; the codec
 * output remains untrusted until this comparison succeeds.
 */
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

/** Result of binding accepted compression metadata to a decoded record. */
export type CompressionRecordBindingResult =
  | { ok: true; recordType: CompressionRecordType }
  | {
    ok: false;
    code:
      | "COMPRESSION_METADATA_INVALID"
      | "COMPRESSION_FORBIDDEN_RECORD"
      | "COMPRESSION_RECORD_TYPE_MISMATCH";
  };

const COMPRESSION_SET = new Set<string>(COMPRESSION_ALGORITHMS);
const COMPRESSION_RECORD_TYPE_SET = new Set<string>(COMPRESSION_RECORD_TYPES);

export function isCompressionAlgorithm(value: unknown): value is CompressionAlgorithm {
  return typeof value === "string" && COMPRESSION_SET.has(value);
}

/** True only for the closed record vocabulary carried by compression metadata. */
export function isCompressionRecordType(value: unknown): value is CompressionRecordType {
  return typeof value === "string" && COMPRESSION_RECORD_TYPE_SET.has(value);
}

/** Runtime guard for a negotiated compression state received from an adapter. */
export function isCompressionNegotiation(value: unknown): value is CompressionNegotiation {
  if (!isRecord(value) || !isCompressionAlgorithm(value.algorithm)) return false;
  if (value.algorithm === "none") return value.limits === undefined;
  return validCompressionLimits(value.limits);
}

/**
 * Negotiate only after READY.  `none` is the safe fallback; zstd is selected
 * only when both peers explicitly offered it and the caller allows it.
 */
export function negotiateCompression(
  local: CompressionOffer,
  remote: CompressionOffer,
  options: CompressionNegotiationOptions,
): CompressionNegotiationResult {
  if (options.ready !== true) return { ok: false, code: "COMPRESSION_NEGOTIATION_BEFORE_READY" };
  const localValidation = validateCompressionOffer(local);
  const remoteValidation = validateCompressionOffer(remote);
  if (!localValidation.ok || !remoteValidation.ok) return { ok: false, code: "COMPRESSION_OFFER_INVALID" };

  const zstdAllowed = options.allowZstd !== false &&
    local.algorithms.includes("zstd") && remote.algorithms.includes("zstd");
  if (zstdAllowed) {
    const localLimits = local.limits!;
    const remoteLimits = remote.limits!;
    return {
      ok: true,
      value: {
        algorithm: "zstd",
        limits: Object.freeze({
          maxCompressedBytes: Math.min(localLimits.maxCompressedBytes, remoteLimits.maxCompressedBytes),
          maxUncompressedBytes: Math.min(localLimits.maxUncompressedBytes, remoteLimits.maxUncompressedBytes),
          maxExpansionRatio: Math.min(localLimits.maxExpansionRatio, remoteLimits.maxExpansionRatio),
        }),
      },
    };
  }
  if (local.algorithms.includes("none") && remote.algorithms.includes("none")) {
    return { ok: true, value: { algorithm: "none" } };
  }
  return { ok: false, code: "COMPRESSION_NO_COMMON_ALGORITHM" };
}

/** Auth, handshake, and receipt records always stay uncompressed. */
export function compressionAllowedForRecord(recordType: string): boolean {
  return isCompressionRecordType(recordType) && !UNCOMPRESSIBLE_RECORD_TYPES.has(recordType);
}

/**
 * Validate declared metadata before decompression.  The codec must then call
 * assertDecompressedSize with the actual output length; declared lengths are
 * untrusted and cannot by themselves prevent a decompression bomb.
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
  if (!limits || !isFiniteByteCount(frame.uncompressedBytes)) return { ok: false, code: "COMPRESSION_METADATA_INVALID" };
  if (frame.compressedBytes > limits.maxCompressedBytes || frame.uncompressedBytes > limits.maxUncompressedBytes) {
    return { ok: false, code: "COMPRESSION_LIMIT_EXCEEDED" };
  }
  if (frame.compressedBytes === 0 && frame.uncompressedBytes > 0) return { ok: false, code: "COMPRESSION_EXPANSION_LIMIT" };
  if (frame.compressedBytes > 0 && frame.uncompressedBytes / frame.compressedBytes > limits.maxExpansionRatio) {
    return { ok: false, code: "COMPRESSION_EXPANSION_LIMIT" };
  }
  return { ok: true, uncompressedBytes: frame.uncompressedBytes };
}

/**
 * Bind compression metadata to the decoded (but not yet application-accepted)
 * protocol record. Call this after decompression and strict JSON parsing, and
 * before routing or authorizing it. This check complements, rather than
 * replaces, the normal closed schema validation of that record.
 */
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

/**
 * Validate actual codec output after a frame passed its pre-decompression
 * metadata checks. This must be called before parsing, routing, or charging
 * a decompressed record. In particular, a codec output of a safe size but a
 * different size than the sender declared is still rejected: charging or
 * parsing it would let a sender evade the declared-byte contract.
 */
export function validateDecompressedOutput(
  negotiation: CompressionNegotiation,
  frame: CompressionFrameMetadata,
  actualBytes: number,
): DecompressedOutputValidationResult {
  const declared = validateCompressionFrame(negotiation, frame);
  if (!declared.ok) return declared;
  if (!isFiniteByteCount(actualBytes)) {
    return { ok: false, code: "COMPRESSION_METADATA_INVALID" };
  }

  if (frame.algorithm === "none") {
    return actualBytes === declared.uncompressedBytes
      ? { ok: true, uncompressedBytes: actualBytes }
      : { ok: false, code: "COMPRESSION_OUTPUT_SIZE_MISMATCH" };
  }

  const limits = negotiation.limits;
  // `validateCompressionFrame` established these facts for zstd, but repeat
  // the actual-output checks here so this function remains safe on its own.
  if (!limits) return { ok: false, code: "COMPRESSION_METADATA_INVALID" };
  if (actualBytes > limits.maxUncompressedBytes) {
    return { ok: false, code: "COMPRESSION_LIMIT_EXCEEDED" };
  }
  if (frame.compressedBytes === 0 && actualBytes > 0) {
    return { ok: false, code: "COMPRESSION_EXPANSION_LIMIT" };
  }
  if (frame.compressedBytes > 0 && actualBytes / frame.compressedBytes > limits.maxExpansionRatio) {
    return { ok: false, code: "COMPRESSION_EXPANSION_LIMIT" };
  }
  return actualBytes === declared.uncompressedBytes
    ? { ok: true, uncompressedBytes: actualBytes }
    : { ok: false, code: "COMPRESSION_OUTPUT_SIZE_MISMATCH" };
}

/**
 * Boolean convenience form of `validateDecompressedOutput`. Frame metadata is
 * intentionally required: checking only a negotiated ceiling cannot prove
 * that the codec output matches the declared uncompressed byte count.
 */
export function assertDecompressedSize(
  negotiation: CompressionNegotiation,
  frame: CompressionFrameMetadata,
  actualBytes: number,
): boolean {
  return validateDecompressedOutput(negotiation, frame, actualBytes).ok;
}

/**
 * Charges needed to rate-limit a compressed record by both wire bytes and
 * declared/decompressed bytes.  Add envelope_count separately when relevant.
 */
export function compressionRateLimitCharges(frame: CompressionFrameMetadata): readonly RateLimitCharge[] {
  if (!isCompressionAlgorithm(frame.algorithm) || !isCompressionRecordType(frame.recordType) ||
    !isFiniteByteCount(frame.compressedBytes)) {
    throw new TypeError("Compression frame metadata is invalid");
  }
  if (!compressionAllowedForRecord(frame.recordType) && frame.algorithm !== "none") {
    throw new TypeError("Compression is forbidden for this record type");
  }
  if (frame.algorithm === "none") {
    return [{ operation: "uncompressed_bytes", cost: frame.compressedBytes }];
  }
  if (!isFiniteByteCount(frame.uncompressedBytes)) {
    throw new TypeError("A zstd frame requires uncompressedBytes for rate limiting");
  }
  return [
    { operation: "compressed_bytes", cost: frame.compressedBytes },
    { operation: "uncompressed_bytes", cost: frame.uncompressedBytes },
  ];
}

function validateCompressionOffer(offer: CompressionOffer): { ok: true } | { ok: false } {
  if (!offer || typeof offer !== "object" || !Array.isArray(offer.algorithms) || offer.algorithms.length === 0) {
    return { ok: false };
  }
  const unique = new Set<string>();
  for (const algorithm of offer.algorithms) {
    if (!isCompressionAlgorithm(algorithm) || unique.has(algorithm)) return { ok: false };
    unique.add(algorithm);
  }
  // `none` is required so a peer can safely fall back when a codec is
  // unavailable or a security policy declines compression.
  if (!unique.has("none")) return { ok: false };
  if (unique.has("zstd") && !validCompressionLimits(offer.limits)) return { ok: false };
  return { ok: true };
}

function validCompressionLimits(value: unknown): value is CompressionLimits {
  return isRecord(value) &&
    isFiniteByteCount(value.maxCompressedBytes) && value.maxCompressedBytes > 0 &&
    isFiniteByteCount(value.maxUncompressedBytes) && value.maxUncompressedBytes > 0 &&
    typeof value.maxExpansionRatio === "number" && Number.isFinite(value.maxExpansionRatio) && value.maxExpansionRatio >= 1;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isFiniteByteCount(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

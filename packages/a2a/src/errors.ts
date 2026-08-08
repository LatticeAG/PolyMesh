/**
 * A2A ↔ PolyMesh error mapping (PM-V6-SPEC §A.9.2.1, §A.11.1–§A.11.4).
 *
 * The adapter MUST surface PolyMesh codes to the routing engine, never raw
 * HTTP status codes or A2A/JSON-RPC codes.
 */
import type { A2AErrorObject, OutboundErrorSummary } from "./types.js";

export interface ErrorTableRow {
  /** Retryable default per §A.11.1. `"conditional"` collapses to false here. */
  retryable: boolean;
  /** A2A task-level `error.code` string. */
  a2aCode: string;
  /** JSON-RPC `error.code`. */
  jsonRpcCode: number;
  /** Normative message token. */
  message: string;
}

/**
 * §A.11.1 master table, byte-identical PolyMesh codes.
 *
 * `CANCELLED` is adapter-local (caller abort) and is not part of the wire
 * table; it is included so cancellation can flow through the same error type.
 */
export const A2A_ERROR_TABLE: Readonly<Record<string, ErrorTableRow>> = Object.freeze({
  UNSUPPORTED_CAPABILITY: { retryable: false, a2aCode: "UNSUPPORTED_CAPABILITY", jsonRpcCode: -32601, message: "Method not found / skill unsupported" },
  UNSUPPORTED_METHOD: { retryable: false, a2aCode: "UNSUPPORTED_METHOD", jsonRpcCode: -32601, message: "Method not found" },
  AUTHORIZATION_DENIED: { retryable: false, a2aCode: "AUTHORIZATION_DENIED", jsonRpcCode: -32001, message: "Authorization denied" },
  AUTHENTICATION_FAILED: { retryable: false, a2aCode: "AUTHENTICATION_FAILED", jsonRpcCode: -32001, message: "Authentication failed" },
  RATE_LIMITED: { retryable: true, a2aCode: "RATE_LIMITED", jsonRpcCode: -32002, message: "Rate limited" },
  OVERLOADED: { retryable: true, a2aCode: "OVERLOADED", jsonRpcCode: -32002, message: "Overloaded" },
  QUOTA_EXCEEDED: { retryable: true, a2aCode: "QUOTA_EXCEEDED", jsonRpcCode: -32002, message: "Quota exceeded" },
  MALFORMED: { retryable: false, a2aCode: "MALFORMED", jsonRpcCode: -32600, message: "Invalid request" },
  MALFORMED_JSON: { retryable: false, a2aCode: "MALFORMED", jsonRpcCode: -32600, message: "Invalid request" },
  MALFORMED_FRAME: { retryable: false, a2aCode: "MALFORMED", jsonRpcCode: -32600, message: "Invalid request" },
  INTERNAL: { retryable: false, a2aCode: "INTERNAL", jsonRpcCode: -32603, message: "Internal error" },
  INTERNAL_ERROR: { retryable: false, a2aCode: "INTERNAL", jsonRpcCode: -32603, message: "Internal error" },
  TASK_NOT_FOUND: { retryable: false, a2aCode: "TASK_NOT_FOUND", jsonRpcCode: -32004, message: "Task not found" },
  "PMX.TASK.NOT_FOUND": { retryable: false, a2aCode: "TASK_NOT_FOUND", jsonRpcCode: -32004, message: "Task not found" },
  DEADLINE: { retryable: false, a2aCode: "DEADLINE", jsonRpcCode: -32005, message: "Deadline exceeded" },
  "PMX.TASK.DEADLINE_EXCEEDED": { retryable: false, a2aCode: "DEADLINE", jsonRpcCode: -32005, message: "Deadline exceeded" },
  IDEMPOTENCY_CONFLICT: { retryable: false, a2aCode: "IDEMPOTENCY_CONFLICT", jsonRpcCode: -32006, message: "Idempotency conflict" },
  "PMX.DELIVERY.IDEMPOTENCY_CONFLICT": { retryable: false, a2aCode: "IDEMPOTENCY_CONFLICT", jsonRpcCode: -32006, message: "Idempotency conflict" },
  MESSAGE_ID_CONFLICT: { retryable: false, a2aCode: "IDEMPOTENCY_CONFLICT", jsonRpcCode: -32006, message: "Idempotency conflict" },
  "PMX.DELIVERY.MESSAGE_ID_CONFLICT": { retryable: false, a2aCode: "IDEMPOTENCY_CONFLICT", jsonRpcCode: -32006, message: "Idempotency conflict" },
  UNKNOWN_TARGET: { retryable: false, a2aCode: "UNKNOWN_TARGET", jsonRpcCode: -32007, message: "Unknown target" },
  TARGET_UNAVAILABLE: { retryable: true, a2aCode: "TARGET_UNAVAILABLE", jsonRpcCode: -32008, message: "Target unavailable" },
  EXECUTION_FAILED: { retryable: false, a2aCode: "EXECUTION_FAILED", jsonRpcCode: -32009, message: "Execution failed" },
  DEPENDENCY_FAILED: { retryable: false, a2aCode: "DEPENDENCY_FAILED", jsonRpcCode: -32009, message: "Dependency failed" },
  RESULT_TOO_LARGE: { retryable: false, a2aCode: "RESULT_TOO_LARGE", jsonRpcCode: -32010, message: "Result too large" },
  CANCEL_NOT_SUPPORTED: { retryable: false, a2aCode: "CANCEL_NOT_SUPPORTED", jsonRpcCode: -32011, message: "Cancel not supported" },
  "PMX.TASK.CONFLICT": { retryable: false, a2aCode: "TASK_CONFLICT", jsonRpcCode: -32012, message: "Task conflict" },
  SOURCE_IDENTITY_MISMATCH: { retryable: false, a2aCode: "AUTHORIZATION_DENIED", jsonRpcCode: -32001, message: "Authorization denied" },
  UNSUPPORTED_PROTOCOL_VERSION: { retryable: false, a2aCode: "UNSUPPORTED_PROTOCOL_VERSION", jsonRpcCode: -32600, message: "Invalid request" },
  SCHEMA_VALIDATION_FAILED: { retryable: false, a2aCode: "MALFORMED", jsonRpcCode: -32600, message: "Invalid request" },
  A2A_BRIDGE_UNBOUND: { retryable: false, a2aCode: "BRIDGE_UNBOUND", jsonRpcCode: -32603, message: "A2A outbound bridge unbound" },
  BRIDGE_UNBOUND: { retryable: false, a2aCode: "BRIDGE_UNBOUND", jsonRpcCode: -32603, message: "A2A outbound bridge unbound" },
  // Adapter-local lifecycle signal for caller-initiated abort (§A.10.2).
  CANCELLED: { retryable: false, a2aCode: "CANCELLED", jsonRpcCode: -32603, message: "Cancelled" },
});

const FALLBACK_ROW: ErrorTableRow = A2A_ERROR_TABLE.INTERNAL!;

/** Base class for adapter-surfaced errors. */
export class A2AError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "A2AError";
  }
}

/**
 * Error carrying the PolyMesh code plus its §A.11.1 wire projection.
 * `retryable` feeds §B.7.3 re-route classification in the routing engine.
 */
export class A2ADialectError extends A2AError {
  readonly code: string;
  readonly jsonRpcCode: number;
  readonly a2aCode: string;
  readonly retryable: boolean;
  readonly httpStatus?: number;
  readonly data?: unknown;
  override readonly cause?: unknown;

  constructor(
    code: string,
    message?: string,
    options?: {
      retryable?: boolean;
      httpStatus?: number;
      data?: unknown;
      cause?: unknown;
      jsonRpcCode?: number;
    },
  ) {
    const row = A2A_ERROR_TABLE[code] ?? FALLBACK_ROW;
    super(message ?? row.message);
    this.name = "A2ADialectError";
    this.code = code;
    this.jsonRpcCode = options?.jsonRpcCode ?? row.jsonRpcCode;
    this.a2aCode = row.a2aCode;
    this.retryable = options?.retryable ?? row.retryable;
    this.httpStatus = options?.httpStatus;
    this.data = options?.data;
    if (options?.cause !== undefined) this.cause = options.cause;
  }

  toSummary(): OutboundErrorSummary {
    return {
      code: this.code,
      message: this.message,
      jsonrpc_code: this.jsonRpcCode,
      retryable: this.retryable,
      ...(this.data !== undefined ? { data: this.data } : {}),
    };
  }

  toJSON(): Record<string, unknown> {
    return {
      code: this.code,
      message: this.message,
      jsonrpc_code: this.jsonRpcCode,
      a2a_code: this.a2aCode,
      retryable: this.retryable,
      ...(this.httpStatus !== undefined ? { http_status: this.httpStatus } : {}),
    };
  }
}

/** Retryable default for a PolyMesh code (§A.11.1). */
export function isRetryableCode(code: string): boolean {
  return (A2A_ERROR_TABLE[code] ?? FALLBACK_ROW).retryable;
}

/** JSON-RPC code for a PolyMesh code (§A.11.1). */
export function jsonRpcCodeFor(code: string): number {
  return (A2A_ERROR_TABLE[code] ?? FALLBACK_ROW).jsonRpcCode;
}

/** A2A task-level `error.code` for a PolyMesh code (§A.11.1). */
export function a2aCodeFor(code: string): string {
  return (A2A_ERROR_TABLE[code] ?? FALLBACK_ROW).a2aCode;
}

/**
 * Classify an HTTP-level outbound failure with no usable JSON-RPC body
 * (§A.9.2.1).
 */
export function mapHttpStatusToPolyMesh(status: number): A2ADialectError {
  if (status === 408 || status === 429) {
    return new A2ADialectError("RATE_LIMITED", `A2A remote returned HTTP ${status}`, {
      httpStatus: status,
    });
  }
  if (status >= 500) {
    return new A2ADialectError("TARGET_UNAVAILABLE", `A2A remote returned HTTP ${status}`, {
      httpStatus: status,
    });
  }
  if (status === 401 || status === 403) {
    return new A2ADialectError("AUTHENTICATION_FAILED", `A2A remote returned HTTP ${status}`, {
      httpStatus: status,
    });
  }
  if (status === 404) {
    return new A2ADialectError("UNKNOWN_TARGET", `A2A remote returned HTTP ${status}`, {
      httpStatus: status,
    });
  }
  return new A2ADialectError("MALFORMED", `A2A remote returned HTTP ${status}`, {
    httpStatus: status,
  });
}

const CONNECTION_ERROR_PATTERN =
  /econnrefused|econnreset|enotfound|eai_again|ehostunreach|enetunreach|epipe|etimedout|socket hang up|connect(ion)?\s*(refused|reset)|fetch failed|network|timeout|timed out/i;

/**
 * Connection refused / reset / timeout before a response → `TARGET_UNAVAILABLE`
 * retryable (§A.9.2.1).
 */
export function mapTransportErrorToPolyMesh(error: unknown): A2ADialectError {
  if (error instanceof A2ADialectError) return error;
  const code = extractCode(error);
  const message = extractMessage(error);
  if (CONNECTION_ERROR_PATTERN.test(`${code} ${message}`)) {
    return new A2ADialectError("TARGET_UNAVAILABLE", message || "A2A transport failure", {
      cause: error,
    });
  }
  return new A2ADialectError("INTERNAL", message || "A2A adapter failure", { cause: error });
}

/**
 * Map a JSON-RPC error body to a PolyMesh code (§A.11.1). `data.polymesh_code`
 * wins when it names a known code (§A.11.4); otherwise the numeric code plus
 * the normative message token disambiguates.
 */
export function mapJsonRpcErrorToPolyMesh(error: {
  code?: number;
  message?: string;
  data?: unknown;
}): A2ADialectError {
  const data = error.data;
  const declared =
    data && typeof data === "object" && typeof (data as { polymesh_code?: unknown }).polymesh_code === "string"
      ? (data as { polymesh_code: string }).polymesh_code
      : undefined;

  if (declared && A2A_ERROR_TABLE[declared]) {
    return new A2ADialectError(declared, error.message ?? A2A_ERROR_TABLE[declared]!.message, {
      data,
      jsonRpcCode: typeof error.code === "number" ? error.code : undefined,
    });
  }

  const message = error.message ?? "";
  const code = typeof error.code === "number" ? error.code : -32603;
  const polymeshCode = polyMeshCodeForJsonRpc(code, message);
  return new A2ADialectError(polymeshCode, message || A2A_ERROR_TABLE[polymeshCode]!.message, {
    data,
    jsonRpcCode: code,
  });
}

function polyMeshCodeForJsonRpc(code: number, message: string): string {
  switch (code) {
    case -32700:
      return "MALFORMED_JSON";
    case -32600:
      return "MALFORMED";
    case -32601:
      return /skill/i.test(message) ? "UNSUPPORTED_CAPABILITY" : "UNSUPPORTED_METHOD";
    case -32602:
      return "MALFORMED";
    case -32001:
      return /authentication/i.test(message) ? "AUTHENTICATION_FAILED" : "AUTHORIZATION_DENIED";
    case -32002:
      if (/quota/i.test(message)) return "QUOTA_EXCEEDED";
      if (/overload/i.test(message)) return "OVERLOADED";
      return "RATE_LIMITED";
    case -32004:
      return "TASK_NOT_FOUND";
    case -32005:
      return "DEADLINE";
    case -32006:
      return "IDEMPOTENCY_CONFLICT";
    case -32007:
      return "UNKNOWN_TARGET";
    case -32008:
      return "TARGET_UNAVAILABLE";
    case -32009:
      return /dependency/i.test(message) ? "DEPENDENCY_FAILED" : "EXECUTION_FAILED";
    case -32010:
      return "RESULT_TOO_LARGE";
    case -32011:
      return "CANCEL_NOT_SUPPORTED";
    case -32012:
      return "PMX.TASK.CONFLICT";
    default:
      return "INTERNAL";
  }
}

/** Map an A2A task-level `status.error` object to a PolyMesh error (§A.11.3). */
export function mapA2ATaskErrorToPolyMesh(error: A2AErrorObject | undefined): A2ADialectError {
  if (!error) return new A2ADialectError("EXECUTION_FAILED", "Remote A2A task failed");
  const code = A2A_ERROR_TABLE[error.code] ? error.code : reverseA2ACode(error.code);
  return new A2ADialectError(code, error.message ?? A2A_ERROR_TABLE[code]!.message, {
    data: error.data,
  });
}

function reverseA2ACode(a2aCode: string): string {
  for (const [polymeshCode, row] of Object.entries(A2A_ERROR_TABLE)) {
    if (row.a2aCode === a2aCode) return polymeshCode;
  }
  return "EXECUTION_FAILED";
}

function extractCode(error: unknown): string {
  if (error && typeof error === "object") {
    const obj = error as Record<string, unknown>;
    if (typeof obj.code === "string") return obj.code;
    const cause = obj.cause as Record<string, unknown> | undefined;
    if (cause && typeof cause.code === "string") return cause.code;
  }
  return "";
}

function extractMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  if (error && typeof error === "object") {
    const message = (error as { message?: unknown }).message;
    if (typeof message === "string") return message;
  }
  return String(error ?? "");
}

/** Aliases matching earlier M2 call sites / tests. */
export const ERROR_TABLE = A2A_ERROR_TABLE;
export const mapJsonRpcErrorToPolymesh = mapJsonRpcErrorToPolyMesh;
export const mapHttpTransportError = (
  status: number | undefined,
  cause?: unknown,
  _bodyIsJsonRpc = false,
): A2ADialectError => {
  if (status !== undefined) return mapHttpStatusToPolyMesh(status);
  return mapTransportErrorToPolyMesh(cause);
};
export function lookupErrorMapping(code: string): ErrorTableRow & { polymeshCode: string } {
  const row = A2A_ERROR_TABLE[code] ?? FALLBACK_ROW;
  return { ...row, polymeshCode: code };
}

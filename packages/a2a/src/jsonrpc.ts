/**
 * JSON-RPC 2.0 request/response framing for the A2A dialect (§A.7.1).
 */
import { A2ADialectError, mapJsonRpcErrorToPolyMesh } from "./errors.js";

export const JSONRPC_VERSION = "2.0";

export type JsonRpcId = string | number;

export interface JsonRpcRequest<P = unknown> {
  jsonrpc: typeof JSONRPC_VERSION;
  id: JsonRpcId;
  method: string;
  params: P;
}

export interface JsonRpcErrorBody {
  code: number;
  message: string;
  data?: unknown;
}

export interface JsonRpcResponse<R = unknown> {
  jsonrpc: typeof JSONRPC_VERSION;
  id: JsonRpcId | null;
  result?: R;
  error?: JsonRpcErrorBody;
}

export function buildJsonRpcRequest<P>(
  method: string,
  params: P,
  id: JsonRpcId,
): JsonRpcRequest<P> {
  return { jsonrpc: JSONRPC_VERSION, id, method, params };
}

export function buildJsonRpcResult<R>(id: JsonRpcId | null, result: R): JsonRpcResponse<R> {
  return { jsonrpc: JSONRPC_VERSION, id, result };
}

export function buildJsonRpcError(
  id: JsonRpcId | null,
  code: number,
  message: string,
  data?: unknown,
): JsonRpcResponse<never> {
  return {
    jsonrpc: JSONRPC_VERSION,
    id,
    error: { code, message, ...(data !== undefined ? { data } : {}) },
  };
}

export function isJsonRpcResponse(value: unknown): value is JsonRpcResponse {
  return (
    !!value &&
    typeof value === "object" &&
    (value as { jsonrpc?: unknown }).jsonrpc === JSONRPC_VERSION
  );
}

/**
 * Unwrap a JSON-RPC response body, converting an `error` member into an
 * {@link A2ADialectError} via the §A.11.1 table.
 */
export function unwrapJsonRpcResult<R>(body: unknown): R {
  if (!isJsonRpcResponse(body)) {
    throw new A2ADialectError("MALFORMED", "A2A response is not a JSON-RPC 2.0 envelope", {
      data: body,
    });
  }
  if (body.error) throw mapJsonRpcErrorToPolyMesh(body.error);
  if (body.result === undefined) {
    throw new A2ADialectError("MALFORMED", "A2A JSON-RPC response has neither result nor error");
  }
  return body.result as R;
}

export function parseJsonRpcBody(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch (cause) {
    throw new A2ADialectError("MALFORMED_JSON", "A2A response body is not valid JSON", {
      jsonRpcCode: -32700,
      cause,
    });
  }
}

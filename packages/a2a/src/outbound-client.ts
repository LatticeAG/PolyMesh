/**
 * Outbound HTTP JSON-RPC client (§A.9 / §A.7).
 */

import { A2AAuthBoundary } from "./auth-boundary.js";
import type { A2AAdapterConfig } from "./config.js";
import {
  A2ADialectError,
  mapHttpStatusToPolyMesh,
  mapTransportErrorToPolyMesh,
} from "./errors.js";
import { buildJsonRpcRequest, parseJsonRpcBody, unwrapJsonRpcResult } from "./jsonrpc.js";
import type { A2ATask } from "./types.js";

export interface OutboundClientOptions {
  config: A2AAdapterConfig;
  auth: A2AAuthBoundary;
  fetchImpl?: typeof fetch;
  onRequest?: (info: { url: string; headers: Record<string, string>; body: string }) => void;
}

let rpcSeq = 0;

export class OutboundClient {
  private readonly auth: A2AAuthBoundary;
  private readonly fetchImpl: typeof fetch;
  private readonly onRequest?: OutboundClientOptions["onRequest"];

  constructor(options: OutboundClientOptions) {
    this.auth = options.auth;
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
    this.onRequest = options.onRequest;
  }

  async tasksSend(
    a2aUrl: string,
    params: Record<string, unknown>,
    signal?: AbortSignal,
  ): Promise<A2ATask> {
    return this.call(a2aUrl, "tasks/send", params, signal);
  }

  async tasksGet(a2aUrl: string, id: string, signal?: AbortSignal): Promise<A2ATask> {
    return this.call(a2aUrl, "tasks/get", { id }, signal);
  }

  async tasksCancel(a2aUrl: string, id: string, signal?: AbortSignal): Promise<A2ATask> {
    return this.call(a2aUrl, "tasks/cancel", { id }, signal);
  }

  private async call(
    a2aUrl: string,
    method: string,
    params: unknown,
    signal?: AbortSignal,
  ): Promise<A2ATask> {
    const headers = this.auth.outboundHeaders(a2aUrl);
    this.auth.assertNoMeshCredentials(headers);
    const req = buildJsonRpcRequest(method, params, `pm-a2a-${++rpcSeq}`);
    const body = JSON.stringify(req);
    this.onRequest?.({ url: a2aUrl, headers: { ...headers }, body });

    let response: Response;
    try {
      response = await this.fetchImpl(a2aUrl, {
        method: "POST",
        headers,
        body,
        signal,
      });
    } catch (err) {
      if (signal?.aborted) {
        throw new A2ADialectError("CANCELLED", "outbound request aborted");
      }
      throw mapTransportErrorToPolyMesh(err);
    }

    const text = await response.text();
    if (!response.ok) {
      try {
        const parsed = parseJsonRpcBody(text);
        return unwrapJsonRpcResult<A2ATask>(parsed);
      } catch {
        throw mapHttpStatusToPolyMesh(response.status);
      }
    }

    const parsed = parseJsonRpcBody(text);
    return unwrapJsonRpcResult<A2ATask>(parsed);
  }
}

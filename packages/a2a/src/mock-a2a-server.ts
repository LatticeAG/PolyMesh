/**
 * In-memory mock A2A JSON-RPC server for outbound conformance tests (§E.1.2).
 *
 * Supports `tasks/send`, `tasks/get`, and `tasks/cancel` over HTTP POST, and
 * records every request so tests can assert on wire contents.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { AddressInfo } from "node:net";

import { buildJsonRpcError, buildJsonRpcResult, JSONRPC_VERSION } from "./jsonrpc.js";
import type { A2ATask, TasksSendParams } from "./types.js";

export interface MockA2AFailure {
  /** Respond with this HTTP status and no usable JSON-RPC body. */
  http_status?: number;
  /** Respond 200 with this JSON-RPC error body. */
  jsonrpc?: { code: number; message: string; data?: unknown };
}

export interface MockA2AServerOptions {
  /** Artificial per-request latency in ms. */
  latency_ms?: number;
  /** Alias for {@link MockA2AServerOptions.latency_ms}. */
  delay_ms?: number;
  /** Fail every `tasks/send` with this shape. */
  fail_on_send?: MockA2AFailure;
  /** Return `working` for the first N `tasks/get` calls, then complete. */
  drop_n_polls?: number;
  /** Reject every call with JSON-RPC `-32001` / `AUTHENTICATION_FAILED`. */
  auth_reject?: boolean;
  /** Require this exact Authorization header value. */
  require_authorization?: string;
  /** Reply `-32011` / `CANCEL_NOT_SUPPORTED` to `tasks/cancel`. */
  cancel_unsupported?: boolean;
  /** JSON body attached to the completion artifact. */
  result?: unknown;
  /** Path the JSON-RPC endpoint is served from. */
  path?: string;
}

export interface CapturedRequest {
  method: string;
  params: unknown;
  headers: Record<string, string>;
  raw_body: string;
  received_at: number;
}

export interface MockA2AServer {
  url: string;
  origin: string;
  port: number;
  requests: CapturedRequest[];
  sendCount: number;
  getCount: number;
  cancelCount: number;
  tasks: Map<string, A2ATask>;
  pollCountByTask: Map<string, number>;
  setOptions(patch: Partial<MockA2AServerOptions>): void;
  close(): Promise<void>;
  raw: Server;
}

export async function createMockA2AServer(
  options: MockA2AServerOptions = {},
): Promise<MockA2AServer> {
  let opts: MockA2AServerOptions = { path: "/a2a", ...options };
  const requests: CapturedRequest[] = [];
  const tasks = new Map<string, A2ATask>();
  const pollCountByTask = new Map<string, number>();
  const counters = { send: 0, get: 0, cancel: 0 };

  const server = createServer((req, res) => {
    void handle(req, res);
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const rawBody = await readBody(req);
    const latency = opts.latency_ms ?? opts.delay_ms ?? 0;
    if (latency > 0) await sleep(latency);

    if (req.method !== "POST") {
      respond(res, 405, { error: "method not allowed" });
      return;
    }

    let parsed: { id?: unknown; method?: string; params?: unknown };
    try {
      parsed = JSON.parse(rawBody) as typeof parsed;
    } catch {
      respond(res, 200, buildJsonRpcError(null, -32700, "Parse error"));
      return;
    }

    const id = (parsed.id as string | number | null) ?? null;
    const method = parsed.method ?? "";
    requests.push({
      method,
      params: parsed.params,
      headers: normalizeHeaders(req),
      raw_body: rawBody,
      received_at: Date.now(),
    });

    if (opts.auth_reject) {
      respond(
        res,
        200,
        buildJsonRpcError(id, -32001, "Authentication failed", {
          polymesh_code: "AUTHENTICATION_FAILED",
        }),
      );
      return;
    }
    if (
      opts.require_authorization !== undefined &&
      req.headers.authorization !== opts.require_authorization
    ) {
      respond(
        res,
        200,
        buildJsonRpcError(id, -32001, "Authentication failed", {
          polymesh_code: "AUTHENTICATION_FAILED",
        }),
      );
      return;
    }

    switch (method) {
      case "tasks/send":
        counters.send += 1;
        handleSend(res, id, parsed.params as TasksSendParams);
        return;
      case "tasks/get":
        counters.get += 1;
        handleGet(res, id, (parsed.params as { id: string })?.id);
        return;
      case "tasks/cancel":
        counters.cancel += 1;
        handleCancel(res, id, (parsed.params as { id: string })?.id);
        return;
      default:
        respond(res, 200, buildJsonRpcError(id, -32601, "Method not found"));
    }
  }

  function handleSend(res: ServerResponse, id: string | number | null, params: TasksSendParams): void {
    const failure = opts.fail_on_send;
    if (failure?.http_status) {
      respond(res, failure.http_status, { error: `mock failure ${failure.http_status}` });
      return;
    }
    if (failure?.jsonrpc) {
      respond(
        res,
        200,
        buildJsonRpcError(id, failure.jsonrpc.code, failure.jsonrpc.message, failure.jsonrpc.data),
      );
      return;
    }

    const taskId = params?.id ?? `mock-${counters.send}`;
    const existing = tasks.get(taskId);
    if (existing) {
      respond(res, 200, buildJsonRpcResult(id, existing));
      return;
    }
    const task: A2ATask = {
      id: taskId,
      status: { state: "submitted", timestamp: new Date().toISOString() },
      metadata: { ...(params?.metadata ?? {}) },
    };
    tasks.set(taskId, task);
    pollCountByTask.set(taskId, 0);
    respond(res, 200, buildJsonRpcResult(id, task));
  }

  function handleGet(res: ServerResponse, id: string | number | null, taskId: string): void {
    const task = tasks.get(taskId);
    if (!task) {
      respond(
        res,
        200,
        buildJsonRpcError(id, -32004, "Task not found", { polymesh_code: "TASK_NOT_FOUND" }),
      );
      return;
    }
    if (isTerminal(task)) {
      respond(res, 200, buildJsonRpcResult(id, task));
      return;
    }

    const polls = (pollCountByTask.get(taskId) ?? 0) + 1;
    pollCountByTask.set(taskId, polls);
    const drop = opts.drop_n_polls ?? 0;
    if (polls <= drop) {
      task.status = {
        state: "working",
        progress: Math.min(0.99, polls / (drop + 1)),
        timestamp: new Date().toISOString(),
      };
    } else {
      task.status = { state: "completed", progress: 1, timestamp: new Date().toISOString() };
      task.artifacts = [
        {
          name: "result",
          parts: [{ type: "data", data: opts.result ?? { ok: true, task_id: taskId } }],
        },
      ];
    }
    respond(res, 200, buildJsonRpcResult(id, task));
  }

  function handleCancel(res: ServerResponse, id: string | number | null, taskId: string): void {
    if (opts.cancel_unsupported) {
      respond(
        res,
        200,
        buildJsonRpcError(id, -32011, "Cancel not supported", {
          polymesh_code: "CANCEL_NOT_SUPPORTED",
        }),
      );
      return;
    }
    const task = tasks.get(taskId);
    if (!task) {
      respond(
        res,
        200,
        buildJsonRpcError(id, -32004, "Task not found", { polymesh_code: "TASK_NOT_FOUND" }),
      );
      return;
    }
    if (!isTerminal(task)) {
      task.status = { state: "canceled", timestamp: new Date().toISOString() };
    }
    respond(res, 200, buildJsonRpcResult(id, task));
  }

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  const origin = `http://127.0.0.1:${address.port}`;

  return {
    url: `${origin}${opts.path ?? "/a2a"}`,
    origin,
    port: address.port,
    requests,
    tasks,
    pollCountByTask,
    get sendCount() {
      return counters.send;
    },
    get getCount() {
      return counters.get;
    },
    get cancelCount() {
      return counters.cancel;
    },
    setOptions(patch) {
      opts = { ...opts, ...patch };
    },
    async close() {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
    raw: server,
  };
}

function isTerminal(task: A2ATask): boolean {
  return (
    task.status.state === "completed" ||
    task.status.state === "failed" ||
    task.status.state === "canceled"
  );
}

function respond(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function normalizeHeaders(req: IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    out[key.toLowerCase()] = Array.isArray(value) ? value.join(",") : value;
  }
  return out;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export { JSONRPC_VERSION };

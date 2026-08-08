/**
 * In-memory mock A2A JSON-RPC HTTP server for outbound tests (§E.4.4).
 */

import http from "node:http";
import { uuidv7 } from "@latticeag/polymesh-broker";

import type { A2ATask, A2ATaskState } from "./types.js";

export interface MockA2AServerOptions {
  host?: string;
  port?: number;
  delayMs?: number;
  failOnSend?: boolean | { code: number; message: string; data?: Record<string, unknown> };
  dropNPolls?: number;
  authReject?: boolean;
  requireAuthHeader?: string;
  /** HTTP status to return without JSON-RPC body. */
  httpErrorStatus?: number;
  completeResult?: unknown;
  latencyGetMs?: number;
}

export interface MockA2AServer {
  url: string;
  port: number;
  close(): Promise<void>;
  requests: Array<{ method: string; headers: http.IncomingHttpHeaders; body: unknown }>;
  tasks: Map<string, A2ATask & { polls: number }>;
  setOptions(patch: Partial<MockA2AServerOptions>): void;
}

export async function createMockA2AServer(options: MockA2AServerOptions = {}): Promise<MockA2AServer> {
  const state: MockA2AServerOptions = { ...options };
  const tasks = new Map<string, A2ATask & { polls: number }>();
  const requests: MockA2AServer["requests"] = [];

  const server = http.createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    const raw = Buffer.concat(chunks).toString("utf8");
    let body: unknown = null;
    try {
      body = raw ? JSON.parse(raw) : null;
    } catch {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: { code: -32700, message: "Parse error" },
        }),
      );
      return;
    }

    requests.push({ method: req.method ?? "POST", headers: req.headers, body });

    if (state.httpErrorStatus) {
      res.writeHead(state.httpErrorStatus, { "content-type": "text/plain" });
      res.end(`HTTP ${state.httpErrorStatus}`);
      return;
    }

    if (state.authReject) {
      const auth = req.headers.authorization ?? "";
      const needed = state.requireAuthHeader;
      if (!needed || auth !== needed) {
        res.writeHead(401, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            jsonrpc: "2.0",
            id: (body as { id?: unknown })?.id ?? null,
            error: {
              code: -32001,
              message: "Authentication failed",
              data: { polymesh_code: "AUTHENTICATION_FAILED" },
            },
          }),
        );
        return;
      }
    }

    const rpc = body as { id?: string | number; method?: string; params?: Record<string, unknown> };
    const reply = (result: unknown) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: rpc.id ?? null, result }));
    };
    const fail = (code: number, message: string, data?: Record<string, unknown>) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: rpc.id ?? null, error: { code, message, data } }));
    };

    if (state.delayMs) await sleep(state.delayMs);

    if (rpc.method === "tasks/send") {
      if (state.failOnSend) {
        if (typeof state.failOnSend === "object") {
          fail(state.failOnSend.code, state.failOnSend.message, state.failOnSend.data);
        } else {
          fail(-32008, "Target unavailable", { polymesh_code: "TARGET_UNAVAILABLE" });
        }
        return;
      }
      const id = typeof rpc.params?.id === "string" ? rpc.params.id : uuidv7();
      const task: A2ATask & { polls: number } = {
        id,
        status: { state: "submitted" },
        metadata: { ...(rpc.params?.metadata as object) },
        polls: 0,
      };
      tasks.set(id, task);
      // Advance to working immediately so first poll can complete after dropN.
      task.status.state = "working";
      reply(task);
      return;
    }

    if (rpc.method === "tasks/get") {
      if (state.latencyGetMs) await sleep(state.latencyGetMs);
      const id = String(rpc.params?.id ?? "");
      const task = tasks.get(id);
      if (!task) {
        fail(-32004, "Task not found", { polymesh_code: "TASK_NOT_FOUND" });
        return;
      }
      task.polls += 1;
      const dropN = state.dropNPolls ?? 0;
      if (task.status.state !== "completed" && task.status.state !== "failed" && task.status.state !== "canceled") {
        if (task.polls > dropN) {
          task.status = { state: "completed", progress: 1 };
          task.artifacts = [
            {
              name: "result",
              parts: [{ type: "data", data: state.completeResult ?? { ok: true } }],
            },
          ];
        } else {
          task.status = { state: "working", progress: Math.min(0.9, task.polls * 0.1) };
        }
      }
      reply({
        id: task.id,
        status: task.status,
        artifacts: task.artifacts,
        metadata: task.metadata,
      });
      return;
    }

    if (rpc.method === "tasks/cancel") {
      const id = String(rpc.params?.id ?? "");
      const task = tasks.get(id);
      if (!task) {
        fail(-32004, "Task not found", { polymesh_code: "TASK_NOT_FOUND" });
        return;
      }
      task.status = { state: "canceled" };
      reply(task);
      return;
    }

    fail(-32601, "Method not found");
  });

  const host = options.host ?? "127.0.0.1";
  const port = await listen(server, host, options.port ?? 0);
  const url = `http://${host}:${port}/a2a`;

  return {
    url,
    port,
    tasks,
    requests,
    setOptions(patch) {
      Object.assign(state, patch);
    },
    async close() {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
    },
  };
}

function listen(server: http.Server, host: string, port: number): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      const addr = server.address();
      if (addr && typeof addr === "object") resolve(addr.port);
      else reject(new Error("no address"));
    });
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** Force a task into a specific state (monotonic tests). */
export function forceMockTaskState(
  server: MockA2AServer,
  id: string,
  state: A2ATaskState,
): void {
  const task = server.tasks.get(id);
  if (!task) return;
  task.status = { state };
  if (state === "completed") {
    task.artifacts = [{ name: "result", parts: [{ type: "data", data: { forced: true } }] }];
  }
}

import { afterEach, describe, expect, it } from "vitest";

import {
  GatewayTransport,
  GatewayTransportError,
  gatewayHttpBase,
  gatewayWsUrl,
  PolyMeshClient,
  type GatewayFetch,
  type GatewayTransportOptions,
  type GatewayWsSocket,
} from "@latticeag/polymesh-client";

const GATEWAY_URL = "https://gateway.test.example";
const API_KEY = "pmgk_test_key";
const MESH_ID = "msh_test_mesh_001";
const INVITE = "ABC-INVITE";
/** Keep under setTimeout's 32-bit ms limit while staying past skew. */
const FAR_FUTURE = new Date(Date.now() + 60 * 60 * 1000).toISOString();

const transports: GatewayTransport[] = [];
const clients: PolyMeshClient[] = [];

afterEach(async () => {
  while (transports.length > 0) {
    const t = transports.pop()!;
    await t.close().catch(() => undefined);
  }
  while (clients.length > 0) {
    const c = clients.pop()!;
    await c.gateway?.close().catch(() => undefined);
  }
});

function b64url(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

function makeFakeJwt(claims: Record<string, unknown> = { sub: "alice@latticeag" }): string {
  const header = b64url(JSON.stringify({ alg: "none", typ: "JWT" }));
  const payload = b64url(JSON.stringify(claims));
  return `${header}.${payload}.sig`;
}

class MockGatewaySocket implements GatewayWsSocket {
  static OPEN = 1;
  static CONNECTING = 0;
  static CLOSED = 3;

  readyState = MockGatewaySocket.CONNECTING;
  sent: string[] = [];
  readonly url: string;
  private listeners = new Map<string, Set<(...args: unknown[]) => void>>();

  constructor(url = "") {
    this.url = url;
  }

  on(event: string, listener: (...args: unknown[]) => void): this {
    let set = this.listeners.get(event);
    if (!set) {
      set = new Set();
      this.listeners.set(event, set);
    }
    set.add(listener);
    return this;
  }

  once(event: string, listener: (...args: unknown[]) => void): this {
    const wrap = (...args: unknown[]) => {
      this.off(event, wrap);
      listener(...args);
    };
    return this.on(event, wrap);
  }

  off(event: string, listener: (...args: unknown[]) => void): this {
    this.listeners.get(event)?.delete(listener);
    return this;
  }

  removeListener(event: string, listener: (...args: unknown[]) => void): this {
    return this.off(event, listener);
  }

  send(data: string, callback?: (error?: Error) => void): void {
    this.sent.push(data);
    callback?.();
  }

  close(code = 1000, reason = ""): void {
    if (this.readyState === MockGatewaySocket.CLOSED) return;
    this.readyState = MockGatewaySocket.CLOSED;
    this.emit("close", code, reason);
  }

  open(): void {
    this.readyState = MockGatewaySocket.OPEN;
    this.emit("open");
  }

  serverSend(obj: unknown): void {
    this.emit("message", JSON.stringify(obj));
  }

  emit(event: string, ...args: unknown[]): void {
    const snapshot = [...(this.listeners.get(event) ?? [])];
    for (const listener of snapshot) listener(...args);
  }

  parsedSent(): Array<Record<string, unknown>> {
    return this.sent.map((raw) => JSON.parse(raw) as Record<string, unknown>);
  }
}

type FetchHandler = (
  input: string,
  init?: Parameters<GatewayFetch>[1],
) => Promise<{
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
  text(): Promise<string>;
}> | {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
  text(): Promise<string>;
} | undefined;

function jsonResponse(status: number, body: unknown) {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      return typeof body === "string" ? JSON.parse(body) : body;
    },
    async text() {
      return text;
    },
  };
}

function onceEvent<T = unknown>(
  target: { once(event: string, listener: (payload: T) => void): unknown; on?(event: string, listener: (payload: T) => void): unknown; off?(event: string, listener: (payload: T) => void): unknown },
  event: string,
  predicate?: (payload: T) => boolean,
): Promise<T> {
  return new Promise((resolve) => {
    if (!predicate) {
      target.once(event, (payload: T) => resolve(payload));
      return;
    }
    const listener = (payload: T) => {
      if (!predicate(payload)) return;
      target.off?.(event, listener);
      resolve(payload);
    };
    target.on?.(event, listener);
  });
}

function onceTransportError(
  transport: GatewayTransport,
  code?: string,
): Promise<GatewayTransportError> {
  return onceEvent<GatewayTransportError>(
    transport,
    "error",
    (payload) =>
      payload instanceof GatewayTransportError &&
      (code === undefined || payload.code === code),
  );
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(
  predicate: () => boolean,
  timeoutMs = 2_000,
  intervalMs = 5,
): Promise<void> {
  const start = Date.now();
  while (!predicate()) {
    if (Date.now() - start > timeoutMs) throw new Error("waitFor timed out");
    await sleep(intervalMs);
  }
}

interface HarnessOptions {
  authStatus?: number;
  authBody?: unknown;
  joinStatus?: number;
  joinBody?: unknown;
  agentsBody?: unknown;
  agentsStatus?: number;
  autoJoin?: boolean;
  autoDiscover?: boolean;
  requestTimeoutMs?: number;
  tokenRefreshSkewMs?: number;
  reconnect?: GatewayTransportOptions["reconnect"];
  tokenClaims?: Record<string, unknown>;
  fetchOverride?: FetchHandler;
}

function createHarness(opts: HarnessOptions = {}) {
  const sockets: MockGatewaySocket[] = [];
  let authCalls = 0;
  let joinCalls = 0;
  let agentsCalls = 0;

  const token = makeFakeJwt(opts.tokenClaims ?? { sub: "alice@latticeag" });

  const fetchImpl: GatewayFetch = async (input, init) => {
    const overridden = opts.fetchOverride?.(input, init);
    if (overridden !== undefined) return await overridden;

    const url = String(input);
    if (url.includes("/api/v1/auth/token") && init?.method === "POST") {
      authCalls += 1;
      const status = opts.authStatus ?? 200;
      if (status !== 200) {
        return jsonResponse(status, opts.authBody ?? { error: "auth failed" });
      }
      return jsonResponse(200, opts.authBody ?? { token, expires_at: FAR_FUTURE });
    }

    if (url.includes("/join") && init?.method === "POST") {
      joinCalls += 1;
      const status = opts.joinStatus ?? 200;
      return jsonResponse(status, opts.joinBody ?? { ok: true });
    }

    if (url.includes("/agents") && (init?.method === "GET" || init?.method === undefined)) {
      agentsCalls += 1;
      const status = opts.agentsStatus ?? 200;
      return jsonResponse(
        status,
        opts.agentsBody ?? {
          agents: [
            {
              id: "bob@latticeag",
              display_name: "bob",
              capabilities: [{ name: "calendar.read" }],
            },
          ],
          page: 1,
          limit: 50,
          total: 1,
          has_more: false,
        },
      );
    }

    return jsonResponse(404, { error: `unexpected fetch ${init?.method ?? "GET"} ${url}` });
  };

  const createWebSocket = (url: string): GatewayWsSocket => {
    const socket = new MockGatewaySocket(url);
    sockets.push(socket);

    const originalSend = socket.send.bind(socket);
    socket.send = (data: string, callback?: (error?: Error) => void) => {
      originalSend(data, callback);
      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(data) as Record<string, unknown>;
      } catch {
        return;
      }
      if (opts.autoJoin !== false && msg.type === "mesh.join") {
        queueMicrotask(() => {
          if (socket.readyState === MockGatewaySocket.OPEN) {
            socket.serverSend({
              type: "mesh.joined",
              mesh_id: msg.mesh_id,
              members: [],
              agent_id: "alice@latticeag",
            });
          }
        });
      }
      if (opts.autoDiscover && msg.type === "discovery.request") {
        queueMicrotask(() => {
          if (socket.readyState === MockGatewaySocket.OPEN) {
            socket.serverSend({
              type: "discovery.response",
              agents: [
                {
                  id: "bob@latticeag",
                  display_name: "bob",
                  capabilities: [{ name: "calendar.read" }],
                },
              ],
              page: typeof msg.page === "number" ? msg.page : 1,
              limit: typeof msg.limit === "number" ? msg.limit : 50,
              total: 1,
              has_more: false,
            });
          }
        });
      }
    };

    queueMicrotask(() => socket.open());
    return socket;
  };

  const transport = new GatewayTransport({
    apiKey: API_KEY,
    gatewayUrl: GATEWAY_URL,
    fetch: fetchImpl,
    createWebSocket,
    requestTimeoutMs: opts.requestTimeoutMs ?? 400,
    tokenRefreshSkewMs: opts.tokenRefreshSkewMs ?? 60_000,
    reconnect: opts.reconnect ?? {
      enabled: true,
      initialDelayMs: 10,
      maxDelayMs: 50,
      jitter: 0,
      maxAttempts: 3,
    },
  });
  transports.push(transport);

  return {
    transport,
    sockets,
    fetchImpl,
    createWebSocket,
    get authCalls() {
      return authCalls;
    },
    get joinCalls() {
      return joinCalls;
    },
    get agentsCalls() {
      return agentsCalls;
    },
    get socket() {
      return sockets[sockets.length - 1]!;
    },
  };
}

describe("GatewayTransport (PM-V5-SPEC §9.1)", () => {
  it("1. happy path: connect + join + submit + task.completed", async () => {
    const h = createHarness();
    const completed = onceEvent(h.transport, "task.completed");

    await h.transport.connectGateway();
    expect(h.transport.connected).toBe(true);
    expect(h.transport.currentAgentId).toBe("alice@latticeag");
    expect(h.sockets).toHaveLength(1);

    const joined = await h.transport.joinMesh(MESH_ID, {
      inviteCode: INVITE,
      capabilities: [{ name: "echo" }],
      displayName: "alice",
    });
    expect(joined.mesh_id).toBe(MESH_ID);
    expect(h.joinCalls).toBe(1);

    const taskId = await h.transport.submitTask("bob@latticeag", "echo", { ping: true }, { taskId: "task_happy_1" });
    expect(taskId).toBe("task_happy_1");
    expect(h.socket.parsedSent().some((m) => m.type === "task.submit" && m.task_id === taskId)).toBe(true);

    h.socket.serverSend({
      type: "task.completed",
      task_id: taskId,
      from: "bob@latticeag",
      result: { pong: true },
    });

    const done = await completed;
    expect(done).toMatchObject({ type: "task.completed", task_id: taskId });
  });

  it("2. auth 401 → AUTH_INVALID_KEY, no WS open", async () => {
    const h = createHarness({ authStatus: 401, authBody: { error: "bad key" } });

    await expect(h.transport.connectGateway()).rejects.toMatchObject({
      name: "GatewayTransportError",
      code: "AUTH_INVALID_KEY",
      status: 401,
    });
    expect(h.sockets).toHaveLength(0);
    expect(h.transport.connected).toBe(false);
  });

  it("3. auth 403 → AUTH_REVOKED", async () => {
    const h = createHarness({ authStatus: 403, authBody: { error: "revoked" } });

    await expect(h.transport.connectGateway()).rejects.toMatchObject({
      name: "GatewayTransportError",
      code: "AUTH_REVOKED",
      status: 403,
    });
    expect(h.sockets).toHaveLength(0);
  });

  it("4. reconnect after unexpected close → reconnecting then reconnected; mesh restored without invite", async () => {
    const h = createHarness({
      reconnect: { enabled: true, initialDelayMs: 10, maxDelayMs: 50, jitter: 0, maxAttempts: 3 },
    });

    const reconnecting = onceEvent<{ attempt: number; delayMs: number }>(h.transport, "reconnecting");
    const reconnected = onceEvent<{ mesh_id?: string }>(h.transport, "reconnected");

    await h.transport.connectGateway();
    await h.transport.joinMesh(MESH_ID, { inviteCode: INVITE, capabilities: [{ name: "echo" }] });
    expect(h.joinCalls).toBe(1);

    const firstSocket = h.socket;
    firstSocket.close(1006, "abnormal");

    const reconnectingPayload = await reconnecting;
    expect(reconnectingPayload.attempt).toBeGreaterThanOrEqual(1);

    await waitFor(() => h.sockets.length >= 2);
    await waitFor(() => h.socket.readyState === MockGatewaySocket.OPEN);

    const restoreJoin = await waitFor(() =>
      h.socket.parsedSent().some((m) => m.type === "mesh.join" && m.mesh_id === MESH_ID),
    ).then(() => h.socket.parsedSent().find((m) => m.type === "mesh.join" && m.mesh_id === MESH_ID)!);

    expect(restoreJoin.invite_code).toBeUndefined();
    expect(h.joinCalls).toBe(1);

    const payload = await reconnected;
    expect(payload.mesh_id).toBe(MESH_ID);
    expect(h.transport.connected).toBe(true);
    expect(h.transport.currentMeshId).toBe(MESH_ID);
  });

  it("5. duplicate task_id error frame → DUPLICATE_TASK_ID; connection remains", async () => {
    const h = createHarness();
    await h.transport.connectGateway();
    await h.transport.joinMesh(MESH_ID, { inviteCode: INVITE });

    // Wire frames emit `error` twice: typed channel payload, then GatewayTransportError.
    const errorP = onceTransportError(h.transport, "DUPLICATE_TASK_ID");
    await h.transport.submitTask("bob@latticeag", "echo", {}, { taskId: "dup_1" });
    h.socket.serverSend({
      type: "error",
      code: "DUPLICATE_TASK_ID",
      message: "task already exists",
      task_id: "dup_1",
    });

    const err = await errorP;
    expect(err).toBeInstanceOf(GatewayTransportError);
    expect(err.code).toBe("DUPLICATE_TASK_ID");
    expect(h.transport.connected).toBe(true);
    expect(h.socket.readyState).toBe(MockGatewaySocket.OPEN);
  });

  it("6. INVALID_CAPABILITY error surfaced", async () => {
    const h = createHarness();
    await h.transport.connectGateway();
    await h.transport.joinMesh(MESH_ID, { inviteCode: INVITE });

    const errorP = onceTransportError(h.transport, "INVALID_CAPABILITY");
    await h.transport.submitTask("bob@latticeag", "nope.capability", {}, { taskId: "cap_1" });
    h.socket.serverSend({
      type: "error",
      code: "INVALID_CAPABILITY",
      message: "unknown capability",
      task_id: "cap_1",
    });

    const err = await errorP;
    expect(err.code).toBe("INVALID_CAPABILITY");
    expect(h.transport.connected).toBe(true);
  });

  it("7. mesh not found (REST join 404) → MESH_NOT_FOUND", async () => {
    const h = createHarness({
      joinStatus: 404,
      joinBody: { code: "MESH_NOT_FOUND", message: "no such mesh" },
    });
    await h.transport.connectGateway();

    await expect(
      h.transport.joinMesh(MESH_ID, { inviteCode: INVITE }),
    ).rejects.toMatchObject({
      name: "GatewayTransportError",
      code: "MESH_NOT_FOUND",
      status: 404,
    });
  });

  it("8. leave during session; submit after leave throws NOT_CONNECTED or NOT_IN_MESH", async () => {
    const h = createHarness();
    await h.transport.connectGateway();
    await h.transport.joinMesh(MESH_ID, { inviteCode: INVITE });

    await h.transport.leaveMesh();
    expect(h.transport.currentMeshId).toBeUndefined();

    await expect(
      h.transport.submitTask("bob@latticeag", "echo", {}),
    ).rejects.toSatisfy((err: unknown) => {
      return (
        err instanceof GatewayTransportError &&
        (err.code === "NOT_CONNECTED" || err.code === "NOT_IN_MESH")
      );
    });
  });

  it("9. token.expiring triggers refresh → token.refreshed", async () => {
    const h = createHarness();
    await h.transport.connectGateway();
    expect(h.authCalls).toBe(1);

    const refreshed = onceEvent<{ token: string; expires_at: string }>(h.transport, "token.refreshed");
    h.socket.serverSend({ type: "token.expiring", expires_at: FAR_FUTURE });

    const auth = await refreshed;
    expect(auth.token).toBeTruthy();
    expect(auth.expires_at).toBeTruthy();
    expect(h.authCalls).toBe(2);
    expect(h.transport.currentToken).toBe(auth.token);
  });

  it("10. discoverAgents with capability filter returns GatewayDiscoverResult pagination fields", async () => {
    const h = createHarness({
      autoDiscover: true,
      agentsBody: {
        agents: [
          {
            id: "bob@latticeag",
            display_name: "bob",
            capabilities: [{ name: "calendar.read" }],
          },
        ],
        page: 2,
        limit: 10,
        total: 11,
        has_more: true,
      },
    });
    await h.transport.connectGateway();
    await h.transport.joinMesh(MESH_ID, { inviteCode: INVITE });

    const result = await h.transport.discoverAgents({
      capability: "calendar.*",
      page: 2,
      limit: 10,
    });

    expect(result.agents).toHaveLength(1);
    expect(result.agents[0]).toMatchObject({ id: "bob@latticeag" });
    expect(result).toMatchObject({
      page: expect.any(Number),
      limit: expect.any(Number),
      total: expect.any(Number),
      has_more: expect.any(Boolean),
    });
    expect(result.page).toBeGreaterThanOrEqual(1);
    expect(result.limit).toBeGreaterThanOrEqual(1);

    const request = h.socket.parsedSent().find((m) => m.type === "discovery.request");
    expect(request).toMatchObject({
      type: "discovery.request",
      capability: "calendar.*",
      page: 2,
      limit: 10,
    });
  });

  it("11. malformed WS frame → MALFORMED_FRAME on error event", async () => {
    const h = createHarness();
    await h.transport.connectGateway();

    const errorP = onceTransportError(h.transport, "MALFORMED_FRAME");
    h.socket.emit("message", "{not-json");

    const err = await errorP;
    expect(err).toBeInstanceOf(GatewayTransportError);
    expect(err.code).toBe("MALFORMED_FRAME");
    expect(h.transport.connected).toBe(true);
  });

  it("12. leaveMesh cleanup closes socket", async () => {
    const h = createHarness();
    await h.transport.connectGateway();
    await h.transport.joinMesh(MESH_ID, { inviteCode: INVITE });
    const sock = h.socket;

    const leaveWire = onceEvent(h.transport, "close").catch(() => undefined);
    await h.transport.leaveMesh();
    await leaveWire;

    expect(sock.readyState).toBe(MockGatewaySocket.CLOSED);
    expect(sock.parsedSent().some((m) => m.type === "mesh.leave")).toBe(true);
    expect(h.transport.connected).toBe(false);
    expect(h.transport.currentMeshId).toBeUndefined();
  });

  it("gatewayHttpBase / gatewayWsUrl helpers normalize schemes and paths", () => {
    expect(gatewayHttpBase("wss://gw.example/api/v1/ws")).toBe("https://gw.example");
    expect(gatewayHttpBase("https://gw.example")).toBe("https://gw.example");
    expect(gatewayWsUrl("https://gw.example", "tok", "msh_1")).toContain("wss://gw.example/api/v1/ws");
    expect(gatewayWsUrl("https://gw.example", "tok", "msh_1")).toContain("token=tok");
    expect(gatewayWsUrl("https://gw.example", "tok", "msh_1")).toContain("mesh=msh_1");
  });

  it("PolyMeshClient transport:\"gateway\" smoke test wires GatewayTransport", async () => {
    const h = createHarness();
    const client = new PolyMeshClient({
      transport: "gateway",
      gatewayUrl: GATEWAY_URL,
      apiKey: API_KEY,
      gateway: {
        fetch: h.fetchImpl,
        createWebSocket: h.createWebSocket,
        requestTimeoutMs: 400,
        tokenRefreshSkewMs: 60_000,
        reconnect: { enabled: false },
      },
    });
    clients.push(client);

    expect(client.isGatewayTransport).toBe(true);
    expect(client.gateway).toBeInstanceOf(GatewayTransport);

    await client.connectGateway();
    expect(client.connected).toBe(true);
    await client.joinMesh(MESH_ID, { inviteCode: INVITE });
    const taskId = await client.submitTask("bob@latticeag", "echo", { ok: 1 });
    expect(typeof taskId).toBe("string");
    await client.leaveMesh();
  });
});

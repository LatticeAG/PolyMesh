import { afterEach, describe, expect, it, vi } from "vitest";

import { createEnvelope, randomInstanceId } from "@polymesh/broker";
import { DeckAgentCarrier } from "@polymesh/client";

type TunnelListener = (...args: unknown[]) => void;

/**
 * A deliberately small DeckAgent WebSocket double.  It only speaks the
 * newline-delimited tunnel wire format; no live Worker or network listener is
 * needed to exercise the carrier.
 */
class MockTunnelSocket {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;

  readonly CONNECTING = MockTunnelSocket.CONNECTING;
  readonly OPEN = MockTunnelSocket.OPEN;
  readonly CLOSING = MockTunnelSocket.CLOSING;
  readonly CLOSED = MockTunnelSocket.CLOSED;
  readyState = MockTunnelSocket.CONNECTING;
  readonly sent: string[] = [];

  private readonly listeners = new Map<string, Set<TunnelListener>>();

  on(event: string, listener: TunnelListener): this {
    const listeners = this.listeners.get(event) ?? new Set<TunnelListener>();
    listeners.add(listener);
    this.listeners.set(event, listeners);
    return this;
  }

  once(event: string, listener: TunnelListener): this {
    const wrapped: TunnelListener = (...args) => {
      this.off(event, wrapped);
      listener(...args);
    };
    return this.on(event, wrapped);
  }

  off(event: string, listener: TunnelListener): this {
    this.listeners.get(event)?.delete(listener);
    return this;
  }

  send(data: string | Buffer | Uint8Array, callback?: (error?: Error) => void): void {
    if (this.readyState !== MockTunnelSocket.OPEN) {
      const error = new Error("mock tunnel is closed");
      callback?.(error);
      throw error;
    }
    this.sent.push(typeof data === "string" ? data : Buffer.from(data).toString("utf8"));
    callback?.();
  }

  close(code = 1000, reason = ""): void {
    this.finishClose(code, reason);
  }

  terminate(): void {
    this.finishClose(1006, "terminated");
  }

  open(): void {
    if (this.readyState !== MockTunnelSocket.CONNECTING) return;
    this.readyState = MockTunnelSocket.OPEN;
    this.emit("open");
  }

  /** Send one complete newline-delimited server record, optionally fragmented. */
  serverSend(record: unknown, splitAt?: number): void {
    const line = `${JSON.stringify(record)}\n`;
    if (splitAt !== undefined && splitAt > 0 && splitAt < line.length) {
      this.emit("message", Buffer.from(line.slice(0, splitAt), "utf8"), false);
      this.emit("message", Buffer.from(line.slice(splitAt), "utf8"), false);
      return;
    }
    this.emit("message", Buffer.from(line, "utf8"), false);
  }

  serverClose(code = 1006, reason = "network lost"): void {
    this.finishClose(code, reason);
  }

  private finishClose(code: number, reason: string): void {
    if (this.readyState === MockTunnelSocket.CLOSED) return;
    this.readyState = MockTunnelSocket.CLOSED;
    this.emit("close", code, Buffer.from(reason, "utf8"));
  }

  private emit(event: string, ...args: unknown[]): void {
    for (const listener of this.listeners.get(event) ?? []) listener(...args);
  }
}

interface TunnelRig {
  sockets: MockTunnelSocket[];
  createWebSocket: () => MockTunnelSocket;
}

function createTunnelRig(): TunnelRig {
  const sockets: MockTunnelSocket[] = [];
  return {
    sockets,
    createWebSocket: () => {
      const socket = new MockTunnelSocket();
      sockets.push(socket);
      return socket;
    },
  };
}

const channel = {
  meshId: "msh_test",
  agentId: "com.example.deckagent",
  instanceId: randomInstanceId(),
};

function records(socket: MockTunnelSocket): Record<string, unknown>[] {
  return socket.sent
    .flatMap((line) => line.split("\n"))
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function frameOf(record: Record<string, unknown>): Record<string, unknown> {
  const args = record.args;
  if (!isRecord(args) || !isRecord(args.frame)) throw new Error("Tunnel record has no frame");
  return args.frame;
}

function reservedToolCalls(socket: MockTunnelSocket): Record<string, unknown>[] {
  return records(socket).filter((record) =>
    record.type === "execute_tool" && record.tool === "__polymesh_envelope__",
  );
}

function lastFrame(socket: MockTunnelSocket, type: string): Record<string, unknown> {
  const call = [...reservedToolCalls(socket)].reverse().find((record) => frameOf(record).type === type);
  if (!call) throw new Error(`No ${type} tunnel frame was sent`);
  return call;
}

function callForFrame(socket: MockTunnelSocket, type: string): Record<string, unknown> {
  const call = [...reservedToolCalls(socket)].reverse().find((record) => frameOf(record).type === type);
  if (!call) throw new Error(`No ${type} tool call was sent`);
  return call;
}

function numberField(value: Record<string, unknown>, name: string): number {
  const field = value[name];
  if (typeof field !== "number") throw new Error(`${name} is not a number`);
  return field;
}

function authOk(): Record<string, unknown> {
  return {
    type: "auth_ok",
    session_id: "tunnel-session",
    worker_version: "test",
    min_protocol_version: 1,
    server_time: Date.now(),
  };
}

function toolResult(id: string, result: Record<string, unknown>): Record<string, unknown> {
  return {
    type: "tool_result",
    id,
    result: {
      content: [{ type: "text", text: JSON.stringify(result) }],
    },
  };
}

function readyFrame(fence: number, receivedThrough = 0): Record<string, unknown> {
  return {
    type: "pm.tunnel.ready",
    mesh_id: channel.meshId,
    agent_id: channel.agentId,
    instance_id: channel.instanceId,
    fence,
    received_through: receivedThrough,
  };
}

function testEnvelope(n: number) {
  return createEnvelope({
    type: "ping",
    source: { agent_id: "com.example.sender", instance_id: randomInstanceId() },
    target: { agent_id: channel.agentId, instance_id: channel.instanceId },
    params: { n },
  });
}

async function flush(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
}

const carriers: DeckAgentCarrier[] = [];

afterEach(() => {
  for (const carrier of carriers.splice(0)) carrier.disconnect();
  vi.useRealTimers();
});

async function connectReady(options: Partial<ConstructorParameters<typeof DeckAgentCarrier>[0]> = {}) {
  const rig = createTunnelRig();
  const carrier = new DeckAgentCarrier({
    workerUrl: "wss://deck.example",
    deviceId: "poly-agent-1",
    token: "dm_test",
    channel,
    createWebSocket: rig.createWebSocket as never,
    reconnectInitialMs: 1,
    reconnectMaxMs: 8,
    ...options,
  });
  carriers.push(carrier);

  carrier.connect();
  const socket = rig.sockets[0];
  if (!socket) throw new Error("Carrier did not construct a tunnel WebSocket");
  socket.open();
  await flush();
  expect(records(socket)).toContainEqual(expect.objectContaining({
    type: "auth",
    device_id: "poly-agent-1",
    token: "dm_test",
    protocol_version: 1,
  }));
  socket.serverSend(authOk(), 7);
  await flush();
  expect(carrier.getState()).toBe("connected");

  const opening = carrier.openChannel();
  await flush();
  const openCall = callForFrame(socket, "pm.tunnel.open");
  const openFrame = frameOf(openCall);
  const fence = numberField(openFrame, "fence");
  socket.serverSend(toolResult(String(openCall.id), readyFrame(fence)));
  await Promise.resolve(opening);
  await flush();

  return { carrier, rig, socket, fence };
}

describe("DeckAgentCarrier", () => {
  it("starts from a normal WireTransport open listener without a carrier-specific connect call", async () => {
    const rig = createTunnelRig();
    const carrier = new DeckAgentCarrier({
      workerUrl: "wss://deck.example",
      deviceId: "poly-agent-1",
      token: "dm_test",
      channel,
      createWebSocket: rig.createWebSocket as never,
    });
    carriers.push(carrier);
    let opens = 0;
    carrier.once("open", () => { opens += 1; });

    await flush();
    const socket = rig.sockets[0];
    expect(socket).toBeDefined();
    socket!.open();
    socket!.serverSend(authOk());
    await flush();
    const openCall = callForFrame(socket!, "pm.tunnel.open");
    const fence = numberField(frameOf(openCall), "fence");
    socket!.serverSend(toolResult(String(openCall.id), readyFrame(fence)));
    await flush();

    expect(opens).toBe(1);
    expect(carrier.readyState).toBe(carrier.OPEN);
  });

  it("opens, becomes ready, and closes a virtual agent channel", async () => {
    const rig = createTunnelRig();
    const carrier = new DeckAgentCarrier({
      workerUrl: "wss://deck.example",
      deviceId: "poly-agent-1",
      token: "dm_test",
      channel,
      createWebSocket: rig.createWebSocket as never,
    });
    carriers.push(carrier);
    const opens: number[] = [];
    carrier.on("open", () => opens.push(Date.now()));

    carrier.connect();
    const socket = rig.sockets[0]!;
    socket.open();
    socket.serverSend(authOk());
    await flush();

    const opening = carrier.openChannel();
    const openCall = callForFrame(socket, "pm.tunnel.open");
    const openFrame = frameOf(openCall);
    const fence = numberField(openFrame, "fence");
    expect(openFrame).toMatchObject({
      mesh_id: channel.meshId,
      agent_id: channel.agentId,
      instance_id: channel.instanceId,
      received_through: 0,
    });

    socket.serverSend(toolResult(String(openCall.id), readyFrame(fence)));
    await Promise.resolve(opening);
    await flush();
    expect(carrier.readyState).toBe(carrier.OPEN);
    expect(opens).toHaveLength(1);
    expect(carrier.getChannel()).toMatchObject({ state: "ready", fence });

    carrier.closeChannel();
    expect(frameOf(lastFrame(socket, "pm.tunnel.close"))).toMatchObject({
      mesh_id: channel.meshId,
      agent_id: channel.agentId,
      instance_id: channel.instanceId,
      fence,
    });
    expect(carrier.readyState).toBe(carrier.CLOSED);
  });

  it("accepts a relay-initiated close for the current virtual channel", async () => {
    const { carrier, socket, fence } = await connectReady();
    const closes: Array<{ code: number; reason: string }> = [];
    carrier.on("close", (code, reason) => closes.push({ code, reason: reason.toString("utf8") }));

    socket.serverSend({
      type: "execute_tool",
      id: "relay-close",
      tool: "__polymesh_envelope__",
      args: {
        frame: {
          type: "pm.tunnel.close",
          mesh_id: channel.meshId,
          agent_id: channel.agentId,
          instance_id: channel.instanceId,
          fence,
          received_through: 0,
        },
      },
    });
    await flush();

    expect(carrier.getChannel()).toMatchObject({ state: "closed", fence });
    expect(carrier.readyState).toBe(carrier.CLOSED);
    expect(closes).toEqual([{ code: 1000, reason: "DeckAgent channel closed by relay" }]);
    expect(records(socket)).toContainEqual(expect.objectContaining({ type: "tool_result", id: "relay-close" }));
  });

  it("wraps outgoing envelopes and unwraps reserved inbound tool messages", async () => {
    const { carrier, socket, fence } = await connectReady();
    const outbound = testEnvelope(7);
    carrier.send(JSON.stringify(outbound));

    const outboundCall = callForFrame(socket, "pm.tunnel.envelope");
    expect(outboundCall).toMatchObject({
      type: "execute_tool",
      tool: "__polymesh_envelope__",
      args: expect.objectContaining({ envelope: outbound }),
    });
    expect(frameOf(outboundCall)).toMatchObject({ fence, received_through: 0 });

    const inbound = testEnvelope(8);
    const received: unknown[] = [];
    carrier.on("message", (data) => received.push(JSON.parse(String(data))));
    socket.serverSend({
      type: "execute_tool",
      id: "relay-inbound-1",
      tool: "__polymesh_envelope__",
      args: {
        envelope: inbound,
        frame: {
          type: "pm.tunnel.envelope",
          mesh_id: channel.meshId,
          agent_id: channel.agentId,
          instance_id: channel.instanceId,
          fence,
          sequence: 1,
          received_through: 0,
        },
      },
    });
    await flush();

    expect(received).toEqual([inbound]);
    expect(records(socket)).toContainEqual(expect.objectContaining({
      type: "tool_result",
      id: "relay-inbound-1",
    }));
  });

  it("replays only outbox records beyond received_through after reconnect", async () => {
    vi.useFakeTimers();
    const { carrier, rig, socket, fence } = await connectReady();
    const first = testEnvelope(1);
    const second = testEnvelope(2);
    carrier.send(JSON.stringify(first));
    carrier.send(JSON.stringify(second));
    const envelopeCalls = reservedToolCalls(socket).filter((call) => frameOf(call).type === "pm.tunnel.envelope");
    expect(envelopeCalls).toHaveLength(2);
    const firstCall = envelopeCalls[0]!;
    const firstSequence = numberField(frameOf(firstCall), "sequence");
    socket.serverSend(toolResult(String(firstCall.id), {
      type: "pm.tunnel.delivery.receipt",
      fence,
      received_through: firstSequence,
    }));
    await flush();

    socket.serverClose();
    await vi.advanceTimersByTimeAsync(1);
    await flush();
    const reconnect = rig.sockets[1];
    expect(reconnect).toBeDefined();
    reconnect!.open();
    reconnect!.serverSend(authOk());
    await flush();

    const reopen = callForFrame(reconnect!, "pm.tunnel.open");
    const reopenFrame = frameOf(reopen);
    const reconnectFence = numberField(reopenFrame, "fence");
    expect(reopenFrame.received_through).toBe(firstSequence);
    reconnect!.serverSend(toolResult(String(reopen.id), readyFrame(reconnectFence, firstSequence)));
    await flush();

    const replayed = reservedToolCalls(reconnect!).filter((call) => frameOf(call).type === "pm.tunnel.envelope");
    expect(replayed).toHaveLength(1);
    expect((replayed[0]!.args as Record<string, unknown>).envelope).toEqual(second);
    expect(frameOf(replayed[0]!)).toMatchObject({
      fence: reconnectFence,
      sequence: firstSequence + 1,
      received_through: firstSequence,
    });
  });

  it("retains an outbox record and recovers under a fresh fence after an invalid receipt", async () => {
    vi.useFakeTimers();
    const { carrier, rig, socket, fence } = await connectReady();
    const envelope = testEnvelope(9);
    carrier.send(JSON.stringify(envelope));
    const delivery = callForFrame(socket, "pm.tunnel.envelope");
    const sequence = numberField(frameOf(delivery), "sequence");

    socket.serverSend(toolResult(String(delivery.id), {
      type: "pm.tunnel.delivery.receipt",
      fence,
      received_through: sequence + 1,
    }));
    await flush();
    expect(carrier.getOutbox()).toEqual([{ sequence, envelope }]);

    await vi.advanceTimersByTimeAsync(1);
    await flush();
    const replacement = rig.sockets[1];
    expect(replacement).toBeDefined();
    replacement!.open();
    replacement!.serverSend(authOk());
    await flush();
    const reopen = callForFrame(replacement!, "pm.tunnel.open");
    const replacementFence = numberField(frameOf(reopen), "fence");
    replacement!.serverSend(toolResult(String(reopen.id), readyFrame(replacementFence)));
    await flush();

    const replay = callForFrame(replacement!, "pm.tunnel.envelope");
    expect((replay.args as Record<string, unknown>).envelope).toEqual(envelope);
    expect(frameOf(replay)).toMatchObject({ sequence, fence: replacementFence, received_through: 0 });
  });

  it("discards inbound envelopes fenced by a replaced channel lease", async () => {
    vi.useFakeTimers();
    const { carrier, rig, socket, fence: originalFence } = await connectReady();
    socket.serverClose();
    await vi.advanceTimersByTimeAsync(1);
    await flush();
    const replacement = rig.sockets[1]!;
    replacement.open();
    replacement.serverSend(authOk());
    await flush();
    const reopen = callForFrame(replacement, "pm.tunnel.open");
    const currentFence = numberField(frameOf(reopen), "fence");
    expect(currentFence).toBeGreaterThan(originalFence);
    replacement.serverSend(toolResult(String(reopen.id), readyFrame(currentFence)));
    await flush();

    const received: unknown[] = [];
    carrier.on("message", (data) => received.push(JSON.parse(String(data))));
    const stale = testEnvelope(3);
    replacement.serverSend({
      type: "execute_tool",
      id: "stale-fence",
      tool: "__polymesh_envelope__",
      args: {
        envelope: stale,
        frame: {
          type: "pm.tunnel.envelope",
          mesh_id: channel.meshId,
          agent_id: channel.agentId,
          instance_id: channel.instanceId,
          fence: originalFence,
          sequence: 1,
          received_through: 0,
        },
      },
    });
    await flush();
    expect(received).toEqual([]);

    const current = testEnvelope(4);
    replacement.serverSend({
      type: "execute_tool",
      id: "current-fence",
      tool: "__polymesh_envelope__",
      args: {
        envelope: current,
        frame: {
          type: "pm.tunnel.envelope",
          mesh_id: channel.meshId,
          agent_id: channel.agentId,
          instance_id: channel.instanceId,
          fence: currentFence,
          sequence: 1,
          received_through: 0,
        },
      },
    });
    await flush();
    expect(received).toEqual([current]);
  });

  it("reconnects after a missed heartbeat acknowledgement and recovers when acknowledgements resume", async () => {
    vi.useFakeTimers();
    const { carrier, rig, socket } = await connectReady();
    expect(records(socket)).toContainEqual(expect.objectContaining({ type: "heartbeat" }));

    // The default interval is 30s minus the 2s grace. A second heartbeat at
    // 28s must not reset the 45s watchdog for the still-unacknowledged first.
    await vi.advanceTimersByTimeAsync(28_000);
    expect(records(socket).filter((record) => record.type === "heartbeat")).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(17_000);
    await vi.advanceTimersByTimeAsync(1);
    await vi.advanceTimersByTimeAsync(1);
    await flush();
    const recovered = rig.sockets[1];
    expect(recovered).toBeDefined();
    recovered!.open();
    recovered!.serverSend(authOk());
    await flush();
    expect(carrier.getState()).toBe("connected");
    expect(records(recovered!)).toContainEqual(expect.objectContaining({ type: "heartbeat" }));

    recovered!.serverSend({ type: "heartbeat_ack" });
    await flush();
    await vi.advanceTimersByTimeAsync(45_000);
    expect(rig.sockets).toHaveLength(2);
  });
});

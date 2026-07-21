import { afterEach, describe, expect, it } from "vitest";
import WebSocket from "ws";

import {
  Broker,
  InMemoryDurableStore,
  V2_HANDSHAKE_VERSION,
  V2_PROTOCOL_VERSION,
  capabilityContractTuple,
  cardDigest,
  createAgentCard,
  createWirePair,
  deriveV2SessionId,
  generateRuntimeToken,
  randomNonce,
  uuidv7,
  type AgentCard,
  type Capability,
} from "@latticeag/polymesh-broker";

const brokers: Broker[] = [];

afterEach(async () => {
  await Promise.all(brokers.splice(0).map((broker) => broker.close()));
});

const echo: Capability = { id: "org.example.echo", version: "1.0.0" };

async function eventually<T>(read: () => T | undefined | Promise<T | undefined>, message: string): Promise<T> {
  const until = Date.now() + 1_000;
  while (Date.now() < until) {
    const value = await read();
    if (value !== undefined) return value;
    await new Promise<void>((resolve) => setTimeout(resolve, 1));
  }
  throw new Error(message);
}

function collect(wire: ReturnType<typeof createWirePair>[0]): unknown[] {
  const frames: unknown[] = [];
  wire.on("message", (data) => frames.push(JSON.parse(data)));
  return frames;
}

async function connectV2(
  wire: ReturnType<typeof createWirePair>[0],
  frames: unknown[],
  card: AgentCard,
  meshId: string,
): Promise<void> {
  const nonce = randomNonce();
  wire.send(JSON.stringify({
    type: "hello",
    v: V2_HANDSHAKE_VERSION,
    role: "initiator",
    agent_id: card.agent_id,
    instance_id: card.instance_id,
    nonce,
    mesh_id: meshId,
  }));
  const responder = await eventually(() => frames.find((frame): frame is Record<string, unknown> =>
    typeof frame === "object" && frame !== null && (frame as Record<string, unknown>).type === "hello" &&
    (frame as Record<string, unknown>).v === V2_HANDSHAKE_VERSION,
  ), "v0.2 responder hello was not received");
  const responderNonce = String(responder.nonce);
  const sid = deriveV2SessionId(nonce, responderNonce);
  expect(responder.sid).toBe(sid);
  expect(responder.mesh_id).toBe(meshId);
  wire.send(JSON.stringify({
    type: "card",
    sid,
    for_nonce: responderNonce,
    digest: cardDigest(card),
    card,
  }));
  const brokerCard = await eventually(() => frames.find((frame): frame is Record<string, unknown> =>
    typeof frame === "object" && frame !== null && (frame as Record<string, unknown>).type === "card",
  ), "broker Card was not received");
  wire.send(JSON.stringify({
    type: "ready",
    sid,
    self_card: cardDigest(card),
    peer_card: String(brokerCard.digest),
  }));
  await eventually(() => frames.find((frame): frame is Record<string, unknown> =>
    typeof frame === "object" && frame !== null && (frame as Record<string, unknown>).type === "ready",
  ), "v0.2 ready was not received");
}

describe("Broker polymesh.0.2 wire profile", () => {
  it("negotiates the explicit polymesh.0.2 WebSocket subprotocol", async () => {
    const token = generateRuntimeToken();
    const broker = new Broker({
      port: 0,
      host: "127.0.0.1",
      token,
      meshId: "msh-wire",
      multiInstanceRouting: true,
      allowInsecureLoopbackDevelopment: true,
      allowInsecureMultiInstanceDevelopment: true,
      durableStore: new InMemoryDurableStore(),
    });
    brokers.push(broker);
    await broker.start();
    const socket = new WebSocket(broker.url!, V2_PROTOCOL_VERSION, {
      headers: { "x-polymesh-token": token },
      perMessageDeflate: false,
    });
    try {
      await new Promise<void>((resolve, reject) => {
        socket.once("open", resolve);
        socket.once("error", reject);
      });
      expect(socket.protocol).toBe(V2_PROTOCOL_VERSION);
    } finally {
      socket.close();
    }
  });

  it("does not downgrade a v0.2-attached session to a v0.1 hello", async () => {
    const token = generateRuntimeToken();
    const broker = new Broker({
      token,
      meshId: "msh-wire",
      multiInstanceRouting: true,
      allowInsecureMultiInstanceDevelopment: true,
      durableStore: new InMemoryDurableStore(),
    });
    brokers.push(broker);
    const [clientWire, brokerWire] = createWirePair();
    const received = collect(clientWire);
    broker.attach(brokerWire, { token, profile: "v2" });
    const card = createAgentCard({ agent_id: "com.example.client" });
    clientWire.send(JSON.stringify({
      type: "hello",
      v: "0.1",
      role: "initiator",
      agent_id: card.agent_id,
      instance_id: card.instance_id,
      nonce: randomNonce(),
    }));
    await eventually(
      () => clientWire.readyState === clientWire.CLOSED ? true : undefined,
      "v0.1 hello did not close a v0.2 session",
    );
    // WireTransport may close before its queued diagnostic reaches the peer;
    // the important boundary is that it never reaches READY as v0.1.
    expect(received.some((frame) => (frame as { type?: unknown })?.type === "ready")).toBe(false);
  });

  it("persists normal v0.2 socket ingress before sending stored, then settles only a matching durable receipt", async () => {
    const token = generateRuntimeToken();
    const store = new InMemoryDurableStore();
    const broker = new Broker({
      token,
      meshId: "msh-wire",
      multiInstanceRouting: true,
      allowInsecureMultiInstanceDevelopment: true,
      durableStore: store,
      durableNodeId: "wire-test-node",
    });
    brokers.push(broker);
    const sourceCard = createAgentCard({ agent_id: "com.example.source" });
    const targetCard = createAgentCard({ agent_id: "com.example.target", capabilities: [echo] });
    const [sourceWire, brokerSourceWire] = createWirePair();
    const [targetWire, brokerTargetWire] = createWirePair();
    const sourceFrames = collect(sourceWire);
    const targetFrames = collect(targetWire);
    broker.attach(brokerSourceWire, { token, profile: "v2" });
    broker.attach(brokerTargetWire, { token, profile: "v2" });
    await Promise.all([
      connectV2(sourceWire, sourceFrames, sourceCard, "msh-wire"),
      connectV2(targetWire, targetFrames, targetCard, "msh-wire"),
    ]);

    const taskId = uuidv7();
    const deadline = new Date(Date.now() + 10_000).toISOString();
    const contract = capabilityContractTuple(echo);
    const messageId = uuidv7();
    sourceWire.send(JSON.stringify({
      protocol: V2_PROTOCOL_VERSION,
      type: "task.submit",
      message_id: messageId,
      timestamp: new Date().toISOString(),
      source: { mesh_id: "msh-wire", agent_id: sourceCard.agent_id, instance_id: sourceCard.instance_id },
      target: { mesh_id: "msh-wire", agent_id: targetCard.agent_id },
      delivery: { mode: "at_least_once", idempotency_key: "wire-submit", deadline },
      params: {
        task_id: taskId,
        method: echo.id,
        capability_version: contract.capability_version,
        capability_contract_digest: contract.capability_contract_digest,
        params: {},
        deadline,
      },
    }));
    const stored = await eventually(() => sourceFrames.find((frame): frame is {
      type: "delivery.receipt"; delivery_id: string; message_id: string; state: "stored";
    } => typeof frame === "object" && frame !== null && (frame as { type?: unknown }).type === "delivery.receipt",
    ), "v0.2 durable stored receipt was not received");
    expect(stored.message_id).toBe(messageId);
    const delivered = await eventually(() => targetFrames.find((frame): frame is Record<string, unknown> =>
      typeof frame === "object" && frame !== null && (frame as Record<string, unknown>).protocol === V2_PROTOCOL_VERSION &&
      (frame as Record<string, unknown>).type === "task.submit",
    ), "durable v0.2 outbox was not dispatched");
    expect((delivered.target as Record<string, unknown>).instance_id).toBe(targetCard.instance_id);
    // The target learns the broker-controlled delivery correlation from the
    // delivered record itself, not from the source-side stored receipt.
    expect(delivered.delivery_id).toBe(stored.delivery_id);
    const targetDeliveryId = delivered.delivery_id;
    if (typeof targetDeliveryId !== "string") throw new Error("v0.2 target delivery did not carry delivery_id");
    await expect(store.getOutbox(targetDeliveryId)).resolves.toMatchObject({ state: "SENT_AWAITING_RECEIPT" });

    targetWire.send(JSON.stringify({
      type: "delivery.receipt",
      v: V2_HANDSHAKE_VERSION,
      delivery_id: targetDeliveryId,
      message_id: messageId,
      state: "stored",
    }));
    await eventually(async () => {
      const outbox = await store.getOutbox(targetDeliveryId);
      return outbox?.state === "DELIVERED" ? outbox : undefined;
    }, "matching receipt did not settle durable outbox");
  });
});

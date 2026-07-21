import { afterEach, describe, expect, it } from "vitest";

import {
  Broker,
  createAgentCard,
  createEnvelope,
  createWirePair,
  envelopeSemanticDigest,
  generateRuntimeToken,
  randomInstanceId,
  uuidv7,
  validateEnvelope,
  type Envelope,
} from "@latticeag/polymesh-broker";
import { PolyMeshClient } from "@latticeag/polymesh-client";

const brokers: Broker[] = [];
const clients: PolyMeshClient[] = [];

afterEach(async () => {
  for (const client of clients.splice(0)) client.close();
  await Promise.all(brokers.splice(0).map((broker) => broker.close()));
});

function card(agentId: string) {
  return createAgentCard({ agent_id: agentId, instance_id: randomInstanceId() });
}

async function connectedClient() {
  const token = generateRuntimeToken();
  const broker = new Broker({ token });
  const client = new PolyMeshClient({ card: card("alice") });
  const [clientWire, brokerWire] = createWirePair();
  brokers.push(broker);
  clients.push(client);
  broker.attach(brokerWire, { token });
  await client.connectTransport(clientWire);
  return { broker, client, clientWire, brokerWire };
}

function waitFor(condition: () => boolean, timeoutMs = 250): Promise<void> {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const tick = () => {
      if (condition()) return resolve();
      if (Date.now() - started >= timeoutMs) return reject(new Error("condition was not met"));
      setTimeout(tick, 1);
    };
    tick();
  });
}

describe("secure receipt control records", () => {
  it("uses a closed, exactly correlated receipt shape", () => {
    const receivedMessageId = uuidv7();
    const receipt = createEnvelope({
      type: "receipt",
      source: { agent_id: "broker", instance_id: randomInstanceId() },
      target: { agent_id: "alice", instance_id: randomInstanceId() },
      in_reply_to: receivedMessageId,
      params: {
        received_message_id: receivedMessageId,
        semantic_digest: "a".repeat(64),
        disposition: "accepted",
      },
    });

    expect(validateEnvelope(receipt).ok).toBe(true);
    expect(validateEnvelope({
      ...receipt,
      in_reply_to: uuidv7(),
    }).ok).toBe(false);
    expect(validateEnvelope({
      ...receipt,
      params: { ...receipt.params, unexpected: true },
    }).ok).toBe(false);
  });

  it("issues an accepted then duplicate receipt from the broker replay ledger", async () => {
    const { broker, client, clientWire, brokerWire } = await connectedClient();
    const receipts: Envelope<"receipt">[] = [];
    const sent: Envelope[] = [];
    client.on("receipt", (receipt: Envelope<"receipt">) => receipts.push(receipt));
    brokerWire.on("message", (raw) => {
      const frame = JSON.parse(raw) as Envelope;
      if (frame.type === "ping") sent.push(frame);
    });

    const ping = createEnvelope({
      type: "ping",
      source: { agent_id: client.card.agent_id, instance_id: client.card.instance_id },
      target: { agent_id: broker.card.agent_id, instance_id: broker.card.instance_id },
      message_id: uuidv7(),
      delivery: { mode: "at_least_once", idempotency_key: "receipt-replay" },
      params: { n: 9 },
    });
    clientWire.send(JSON.stringify(ping));
    clientWire.send(JSON.stringify(ping));

    await waitFor(() => receipts.length === 2);
    expect(sent).toEqual([ping, ping]);
    expect(receipts.map((receipt) => receipt.params)).toEqual([
      {
        received_message_id: ping.message_id,
        semantic_digest: envelopeSemanticDigest(ping),
        disposition: "accepted",
      },
      {
        received_message_id: ping.message_id,
        semantic_digest: envelopeSemanticDigest(ping),
        disposition: "duplicate",
      },
    ]);
    expect(receipts.every((receipt) => receipt.in_reply_to === ping.message_id)).toBe(true);
  });

  it("does not route or acknowledge an inbound receipt", async () => {
    const { broker, client, clientWire } = await connectedClient();
    const receivedByClient: Envelope[] = [];
    clientWire.on("message", (raw) => {
      const frame = JSON.parse(raw) as Envelope;
      if (frame.type === "receipt") receivedByClient.push(frame);
    });
    const original = uuidv7();
    const incomingReceipt = createEnvelope({
      type: "receipt",
      source: { agent_id: client.card.agent_id, instance_id: client.card.instance_id },
      // A receipt cannot be used as a request to another registered peer.
      target: { agent_id: "some-other-agent", instance_id: randomInstanceId() },
      in_reply_to: original,
      params: {
        received_message_id: original,
        semantic_digest: "b".repeat(64),
        disposition: "accepted",
      },
    });

    clientWire.send(JSON.stringify(incomingReceipt));
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(receivedByClient).toEqual([]);
    expect(broker.listPeers()).toHaveLength(1);
  });
});

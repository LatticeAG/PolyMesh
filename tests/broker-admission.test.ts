import { afterEach, describe, expect, it } from "vitest";

import {
  Broker,
  createAgentCard,
  createEnvelope,
  createWirePair,
  generateRuntimeToken,
  randomInstanceId,
  uuidv7,
} from "@latticeag/polymesh-broker";
import { PolyMeshClient } from "@latticeag/polymesh-client";

const brokers: Broker[] = [];
const clients: PolyMeshClient[] = [];

afterEach(async () => {
  for (const client of clients.splice(0)) client.close();
  await Promise.all(brokers.splice(0).map((broker) => broker.close()));
});

function allow() {
  return { effect: "allow" as const, ruleId: "test", policyGeneration: 1, leaseId: "test-lease" };
}

function card(agentId: string, capabilities: string[] = []) {
  return createAgentCard({
    agent_id: agentId,
    instance_id: randomInstanceId(),
    capabilities: capabilities.map((id) => ({ id, version: "1.0.0" })),
  });
}

async function connectedPair(options: ConstructorParameters<typeof Broker>[0] = {}) {
  const token = options.token ?? generateRuntimeToken();
  const broker = new Broker({ ...options, token });
  brokers.push(broker);
  let release!: () => void;
  const blocked = new Promise<void>((resolve) => { release = resolve; });
  const alice = new PolyMeshClient({ card: card("alice") });
  const bob = new PolyMeshClient({
    card: card("bob", ["org.example.wait"]),
    handlers: { "org.example.wait": async () => { await blocked; return { done: true }; } },
    authorize: () => allow(),
  });
  clients.push(alice, bob);
  const [aliceWire, brokerAliceWire] = createWirePair();
  const [bobWire, brokerBobWire] = createWirePair();
  broker.attach(brokerAliceWire, { token });
  broker.attach(brokerBobWire, { token });
  await Promise.all([alice.connectTransport(aliceWire), bob.connectTransport(bobWire)]);
  return { broker, alice, bob, aliceWire, bobWire, release };
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

describe("broker admission and replay hardening", () => {
  it("rejects a second pending handshake before creating a tracked session", () => {
    const token = generateRuntimeToken();
    const broker = new Broker({ token, maxPendingHandshakes: 1, maxOpenSessions: 1 });
    brokers.push(broker);
    const [, firstBrokerWire] = createWirePair();
    const [, secondBrokerWire] = createWirePair();

    const first = broker.attach(firstBrokerWire, { token });
    const second = broker.attach(secondBrokerWire, { token });

    expect(first.phase).toBe("await_hello");
    expect(second.phase).toBe("closed");
    expect(broker.listPeers()).toEqual([]);
  });

  it("rejects new task routes when the bounded route reservation is full", async () => {
    const { alice, release } = await connectedPair({ maxPendingTaskRoutes: 1, maxPendingTaskRoutesPerSession: 1 });
    const first = alice.call("bob", "org.example.wait", {}, { taskId: uuidv7() });
    await new Promise((resolve) => setTimeout(resolve, 5));

    await expect(alice.call("bob", "org.example.wait", {}, { taskId: uuidv7() })).rejects.toMatchObject({
      code: "OVERLOADED",
      retryable: true,
    });

    release();
    await expect(first).resolves.toEqual({ done: true });
  });

  it("rejects changed semantics for a reused message id without forwarding it", async () => {
    const { alice, bob, aliceWire } = await connectedPair();
    const errors: Array<{ params?: { code?: string } }> = [];
    aliceWire.on("message", (raw) => {
      const frame = JSON.parse(raw) as { type?: string; params?: { code?: string } };
      if (frame.type === "error") errors.push(frame);
    });
    const messageId = uuidv7();
    const source = { agent_id: alice.card.agent_id, instance_id: alice.card.instance_id };
    const target = { agent_id: bob.card.agent_id, instance_id: bob.card.instance_id };
    const first = createEnvelope({
      type: "ping",
      source,
      target,
      message_id: messageId,
      delivery: { mode: "at_least_once", idempotency_key: "message-replay" },
      params: { n: 1 },
    });
    const changed = createEnvelope({
      type: "ping",
      source,
      target,
      message_id: messageId,
      delivery: { mode: "at_least_once", idempotency_key: "message-replay" },
      params: { n: 2 },
    });

    aliceWire.send(JSON.stringify(first));
    aliceWire.send(JSON.stringify(changed));
    await waitFor(() => errors.some((error) => error.params?.code === "PMX.DELIVERY.MESSAGE_ID_CONFLICT"));
  });

  it("fences out-of-sequence lifecycle events, non-owner cancellation, and uncorrelated errors", async () => {
    const { alice, bob, bobWire, release } = await connectedPair();
    const taskId = uuidv7();
    const errors: Array<{ params?: { code?: string } }> = [];
    bobWire.on("message", (raw) => {
      const frame = JSON.parse(raw) as { type?: string; params?: { code?: string } };
      if (frame.type === "error") errors.push(frame);
    });
    const call = alice.call("bob", "org.example.wait", {}, { taskId, timeoutMs: 1_000 });
    await new Promise((resolve) => setTimeout(resolve, 5));
    const source = { agent_id: bob.card.agent_id, instance_id: bob.card.instance_id };
    const owner = { agent_id: alice.card.agent_id, instance_id: alice.card.instance_id };
    const deadline = new Date(Date.now() + 1_000).toISOString();

    bobWire.send(JSON.stringify(createEnvelope({
      type: "task.progress",
      source,
      target: owner,
      delivery: { mode: "at_least_once", idempotency_key: `jump:${taskId}`, deadline },
      params: { task_id: taskId, event_seq: 99, progress: {} },
    })));
    bobWire.send(JSON.stringify(createEnvelope({
      type: "task.cancel",
      source,
      target: source,
      delivery: { mode: "at_least_once", idempotency_key: `cancel:${taskId}`, deadline },
      params: { task_id: taskId },
    })));
    bobWire.send(JSON.stringify(createEnvelope({
      type: "error",
      source,
      target: owner,
      delivery: { mode: "at_least_once", idempotency_key: "forged-error", deadline },
      in_reply_to: uuidv7(),
      params: { category: "task", code: "FORGED", message: "forged", retryable: false, retry_after_ms: null },
    })));

    await waitFor(() => ["PMX.TASK.INVALID_LIFECYCLE", "AUTHORIZATION_DENIED", "PMX.TASK.FORGED_ERROR"].every((code) =>
      errors.some((error) => error.params?.code === code)));
    release();
    await expect(call).resolves.toEqual({ done: true });
  });
});

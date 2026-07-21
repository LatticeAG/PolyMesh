import { afterEach, describe, expect, it } from "vitest";

import {
  Broker,
  DRAINING,
  InMemoryDurableStore,
  capabilityContractTuple,
  createAgentCard,
  createEnvelope,
  createWirePair,
  generateRuntimeToken,
  randomInstanceId,
  uuidv7,
  type Capability,
} from "@latticeag/polymesh-broker";
import { PolyMeshClient } from "@latticeag/polymesh-client";

const brokers: Broker[] = [];
const clients: PolyMeshClient[] = [];

const waitCapability: Capability = {
  id: "org.example.wait",
  version: "1.0.0",
  cancellation: "supported",
};
const echoCapability: Capability = { id: "org.example.echo", version: "1.0.0" };

function allow() {
  return { effect: "allow" as const, ruleId: "test", policyGeneration: 1, leaseId: "test-lease" };
}

afterEach(async () => {
  for (const client of clients.splice(0)) client.close();
  await Promise.all(brokers.splice(0).map((broker) => broker.close()));
});

describe("Broker v0.2 multi-instance routing", () => {
  it("commits durable registration and ingress route/outbox facts before returning a stored receipt", async () => {
    const token = generateRuntimeToken();
    const store = new InMemoryDurableStore();
    const broker = new Broker({
      token,
      meshId: "msh-durable",
      multiInstanceRouting: true,
      allowInsecureMultiInstanceDevelopment: true,
      durableStore: store,
      durableNodeId: "broker-test-node",
    });
    brokers.push(broker);
    const caller = new PolyMeshClient({ card: createAgentCard({ agent_id: "com.example.caller" }) });
    const executor = new PolyMeshClient({
      card: createAgentCard({ agent_id: "com.example.executor", capabilities: [echoCapability] }),
      handlers: { "org.example.echo": async () => ({}) },
      authorize: () => allow(),
    });
    clients.push(caller, executor);
    const [callerWire, brokerCallerWire] = createWirePair();
    const [executorWire, brokerExecutorWire] = createWirePair();
    broker.attach(brokerCallerWire, { token });
    broker.attach(brokerExecutorWire, { token });
    await Promise.all([caller.connectTransport(callerWire), executor.connectTransport(executorWire)]);

    const sourcePeer = broker.listPeers().find((peer) => peer.agentId === "com.example.caller");
    expect(sourcePeer).toBeDefined();
    if (!sourcePeer) throw new Error("caller did not register");
    const taskId = uuidv7();
    const deadline = new Date(Date.now() + 10_000).toISOString();
    const envelope = createEnvelope({
      type: "task.submit",
      source: { agent_id: caller.card.agent_id, instance_id: caller.card.instance_id },
      target: { agent_id: "com.example.executor" },
      delivery: { mode: "at_least_once", idempotency_key: "durable-submit", deadline },
      params: {
        task_id: taskId,
        method: echoCapability.id,
        capability_version: capabilityContractTuple(echoCapability).capability_version,
        capability_contract_digest: capabilityContractTuple(echoCapability).capability_contract_digest,
        params: {},
        deadline,
      },
    });
    const admitted = await broker.persistDurableIngress(sourcePeer, envelope);
    expect(admitted).toMatchObject({
      result: {
        disposition: "stored",
        route: { taskId, executorAgentId: "com.example.executor" },
        outbox: { state: "PENDING" },
      },
      receipt: { type: "delivery.receipt", state: "stored", message_id: envelope.message_id },
    });
    expect(await store.listInstances({ meshId: "msh-durable" })).toHaveLength(2);
    expect(await store.getRoute("msh-durable", taskId)).toMatchObject({ executorAgentId: "com.example.executor" });
    expect(await store.listDispatchableOutbox(Date.now())).toHaveLength(1);
    const deliveryId = admitted.receipt?.delivery_id;
    expect(deliveryId).toBeDefined();
    if (!deliveryId) throw new Error("durable ingress did not allocate a delivery id");
    await expect(broker.dispatchDurableOutbox({ leaseId: "dispatch-test", leaseMs: 1_000 })).resolves.toEqual({
      leased: 1,
      sent: 1,
      unavailable: 0,
      invalid: 0,
    });
    await expect(store.getOutbox(deliveryId)).resolves.toMatchObject({ state: "SENT_AWAITING_RECEIPT" });
    await expect(broker.acknowledgeDurableDelivery(deliveryId, "stored")).resolves.toMatchObject({
      state: "DELIVERED",
      receiptState: "stored",
    });

    const retry = createEnvelope({
      ...envelope,
      message_id: uuidv7(),
      timestamp: new Date().toISOString(),
    });
    await expect(broker.persistDurableIngress(sourcePeer, retry)).resolves.toMatchObject({
      result: { disposition: "duplicate" },
      receipt: { type: "delivery.receipt", state: "stored" },
    });
  });

  it("chooses one healthy instance, excludes it from new work after drain, and keeps cancellation pinned", async () => {
    const token = generateRuntimeToken();
    const broker = new Broker({
      token,
      meshId: "msh-test",
      multiInstanceRouting: true,
      allowInsecureMultiInstanceDevelopment: true,
    });
    brokers.push(broker);

    const caller = new PolyMeshClient({ card: createAgentCard({ agent_id: "com.example.caller" }) });
    const firstInstanceId = randomInstanceId();
    const secondInstanceId = randomInstanceId();
    const waitInvocations: string[] = [];
    const cancellations: string[] = [];
    let signalFirstInvocation!: (instanceId: string) => void;
    const firstInvocation = new Promise<string>((resolve) => { signalFirstInvocation = resolve; });

    const target = (instanceId: string) => new PolyMeshClient({
      card: createAgentCard({
        agent_id: "com.example.executor",
        instance_id: instanceId,
        capabilities: [waitCapability, echoCapability],
      }),
      authorize: () => allow(),
      handlers: {
        "org.example.wait": async (_input, context) => {
          waitInvocations.push(instanceId);
          signalFirstInvocation(instanceId);
          return new Promise((resolve) => {
            context.signal.addEventListener("abort", () => {
              cancellations.push(instanceId);
              resolve({ cancelled: true });
            }, { once: true });
          });
        },
        "org.example.echo": async () => ({ instance_id: instanceId }),
      },
    });
    const first = target(firstInstanceId);
    const second = target(secondInstanceId);
    clients.push(caller, first, second);

    const [callerWire, brokerCallerWire] = createWirePair();
    const [firstWire, brokerFirstWire] = createWirePair();
    const [secondWire, brokerSecondWire] = createWirePair();
    broker.attach(brokerCallerWire, { token });
    broker.attach(brokerFirstWire, { token });
    broker.attach(brokerSecondWire, { token });
    await Promise.all([
      caller.connectTransport(callerWire),
      first.connectTransport(firstWire),
      second.connectTransport(secondWire),
    ]);

    expect(broker.listRoutingInstances()).toHaveLength(3);

    const taskId = uuidv7();
    const blockedCall = caller.call("com.example.executor", waitCapability.id, {}, {
      taskId,
      capabilityContract: waitCapability,
    });
    const selectedInstanceId = await firstInvocation;
    expect(waitInvocations).toEqual([selectedInstanceId]);

    const selected = broker.listRoutingInstances().find((entry) => entry.instanceId === selectedInstanceId);
    expect(selected).toBeDefined();
    if (!selected) throw new Error("selected routing instance was not registered");
    if (selected.sessionFence === undefined) throw new Error("selected routing instance lacks a session fence");

    expect(broker.setInstanceHealth("com.example.executor", selectedInstanceId, DRAINING, {
      registrationFence: selected.registrationFence,
      sessionFence: selected.sessionFence,
      sessionId: selected.sessionId,
    })).toBe(true);
    // A stale mutator must not revive the drained replacement/session.
    expect(broker.setInstanceHealth("com.example.executor", selectedInstanceId, "HEALTHY", {
      registrationFence: selected.registrationFence - 1,
      sessionFence: selected.sessionFence,
      sessionId: selected.sessionId,
    })).toBe(false);

    await expect(caller.call("com.example.executor", echoCapability.id, {}, {
      capabilityContract: echoCapability,
    })).resolves.toEqual({
      instance_id: selectedInstanceId === firstInstanceId ? secondInstanceId : firstInstanceId,
    });

    caller.cancel(taskId);
    await expect(blockedCall).rejects.toMatchObject({ code: "TASK_CANCELLED" });
    expect(cancellations).toEqual([selectedInstanceId]);
  });
});

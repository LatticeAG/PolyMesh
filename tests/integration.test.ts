import { afterEach, describe, expect, it } from "vitest";

import { Broker, capabilityContractTuple, createAgentCard, createEnvelope, createWirePair, generateRuntimeToken, randomInstanceId, uuidv7 } from "@latticeag/polymesh-broker";
import { PolyMeshClient } from "@latticeag/polymesh-client";

const clients: PolyMeshClient[] = [];
const brokers: Broker[] = [];
const MEMORY_TOKEN = generateRuntimeToken();

function allow() {
  return { effect: "allow" as const, ruleId: "test", policyGeneration: 1, leaseId: "test-lease" };
}

afterEach(async () => {
  for (const client of clients.splice(0)) client.close();
  await Promise.all(brokers.splice(0).map((broker) => broker.close()));
});

function card(agentId: string, capability?: string | string[]) {
  return createAgentCard({
    agent_id: agentId,
    instance_id: randomInstanceId(),
    capabilities: (Array.isArray(capability) ? capability : capability ? [capability] : []).map((id) => ({ id, version: "1.0.0" })),
  });
}

function contractFor(cardValue: ReturnType<typeof createAgentCard>, capability: string) {
  const entry = cardValue.capabilities.find((candidate) => candidate.id === capability);
  if (!entry) throw new Error(`Missing test capability ${capability}`);
  return entry;
}

async function createMemoryClients() {
  const broker = new Broker({ token: MEMORY_TOKEN });
  brokers.push(broker);
  const alice = new PolyMeshClient({ card: card("alice") });
  const bob = new PolyMeshClient({
    card: card("bob", ["org.example.echo", "org.example.fail", "org.example.wait"]),
    handlers: {
      "org.example.echo": async (input, context) => {
        context.progress({ current: 1, total: 1, state: "running" });
        return { echoed: input };
      },
    },
    authorize: () => allow(),
  });
  clients.push(alice, bob);
  const [aliceWire, brokerAliceWire] = createWirePair();
  const [bobWire, brokerBobWire] = createWirePair();
  broker.attach(brokerAliceWire, { token: MEMORY_TOKEN });
  broker.attach(brokerBobWire, { token: MEMORY_TOKEN });
  await Promise.all([alice.connectTransport(aliceWire), bob.connectTransport(bobWire)]);
  return { broker, alice, bob, aliceWire, bobWire };
}

describe("in-memory broker/client integration", () => {
  it("exchanges cards, routes an echo task, and surfaces progress", async () => {
    const { broker, alice } = await createMemoryClients();
    const progress: string[] = [];

    await expect(
      alice.call("bob", "org.example.echo", { message: "hello" }, {
        onProgress: (event) => progress.push(String(event.state)),
      }),
    ).resolves.toEqual({ echoed: { message: "hello" } });

    expect(alice.connected).toBe(true);
    expect(alice.brokerIdentity?.agent_id).toBe("org.polymesh.broker");
    expect(broker.listPeers().map((peer) => peer.agentId).sort()).toEqual(["alice", "bob"]);
    expect(progress).toEqual(["running"]);
  });

  it("serves the broker's advertised standard capabilities directly", async () => {
    const { alice } = await createMemoryClients();

    await expect(alice.call("org.polymesh.broker", "org.polymesh.agent.ping", {})).resolves.toEqual({});
    await expect(alice.call("org.polymesh.broker", "org.polymesh.capabilities.list", {})).resolves.toEqual(
      expect.arrayContaining([expect.objectContaining({ id: "org.polymesh.agent.info" })]),
    );
  });

  it("returns deterministic task and routing errors", async () => {
    const { alice } = await createMemoryClients();

    await expect(alice.call("bob", "org.example.not-supported", {})).rejects.toMatchObject({
      code: "UNSUPPORTED_CAPABILITY",
    });
    await expect(alice.call("not-present", "org.example.echo", {})).rejects.toMatchObject({
      code: "UNKNOWN_TARGET",
      retryable: true,
    });

    const taskId = uuidv7();
    await expect(alice.call("bob", "org.example.echo", { value: 1 }, { taskId })).resolves.toEqual({ echoed: { value: 1 } });
    await expect(alice.call("bob", "org.example.echo", { value: 2 }, { taskId })).rejects.toMatchObject({
      code: "PMX.TASK.ID_CONFLICT",
    });
  });

  it("reports accepted handler failures and owner-side deadline timeouts", async () => {
    const { alice, bob } = await createMemoryClients();
    bob.setHandler("org.example.fail", () => {
      throw new Error("intentional failure");
    });
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => { release = resolve; });
    bob.setHandler("org.example.wait", async () => {
      await blocked;
      return {};
    });

    await expect(alice.call("bob", "org.example.fail", {})).rejects.toMatchObject({ code: "EXECUTION_FAILED" });
    await expect(alice.call("bob", "org.example.wait", {}, { timeoutMs: 10 })).rejects.toMatchObject({ code: "TIMEOUT", retryable: true });
    release();
  });

  it("deduplicates a stable submission replay and rejects idempotency-key conflicts", async () => {
    const { alice, bob } = await createMemoryClients();
    let starts = 0;
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => { release = resolve; });
    bob.setHandler("org.example.wait", async () => {
      starts += 1;
      await blocked;
      return { once: true };
    });
    const deadline = new Date(Date.now() + 1_000).toISOString();
    const taskId = uuidv7();
    const retry = { taskId, deadline, idempotencyKey: "stable-submit" };
    const first = alice.call("bob", "org.example.wait", {}, retry);
    await new Promise((resolve) => setTimeout(resolve, 5));
    const replay = alice.call("bob", "org.example.wait", {}, retry);
    await new Promise((resolve) => setTimeout(resolve, 5));
    expect(starts).toBe(1);
    release();
    await expect(first).resolves.toEqual({ once: true });
    await expect(replay).resolves.toEqual({ once: true });

    await expect(alice.call("bob", "org.example.wait", { changed: true }, {
      taskId: uuidv7(),
      deadline,
      idempotencyKey: "stable-submit",
    })).rejects.toMatchObject({ code: "PMX.DELIVERY.IDEMPOTENCY_CONFLICT" });
  });

  it("rejects a spoofed envelope source before it reaches the target", async () => {
    const { broker, bob, aliceWire } = await createMemoryClients();
    let invoked = false;
    bob.setHandler("org.example.echo", async () => {
      invoked = true;
      return {};
    });
    const errors: unknown[] = [];
    const echoContract = capabilityContractTuple(contractFor(bob.card, "org.example.echo"));
    aliceWire.on("message", (raw) => {
      const frame = JSON.parse(raw) as { type?: string; params?: { code?: string } };
      if (frame.type === "error") errors.push(frame);
    });

    aliceWire.send(JSON.stringify({
      protocol: "polymesh.0.1",
      type: "task.submit",
      message_id: "0197a1b0-0000-7000-8000-000000000001",
      timestamp: new Date().toISOString(),
      source: { agent_id: "mallory", instance_id: randomInstanceId() },
      target: { agent_id: "bob" },
      delivery: { mode: "at_least_once", idempotency_key: "spoof", deadline: new Date(Date.now() + 1_000).toISOString() },
      params: {
        task_id: "0197a1b0-0000-7000-8000-000000000002",
        method: "org.example.echo",
        capability_version: echoContract.capability_version,
        capability_contract_digest: echoContract.capability_contract_digest,
        params: {},
        deadline: new Date(Date.now() + 1_000).toISOString(),
      },
    }));

    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(invoked).toBe(false);
    expect(broker.listPeers()).toHaveLength(2);
    expect(errors).toContainEqual(expect.objectContaining({ params: expect.objectContaining({ code: "SOURCE_IDENTITY_MISMATCH" }) }));
  });

  it("fails a pending caller when the accepting target disconnects", async () => {
    let release!: () => void;
    const never = new Promise<void>((resolve) => { release = resolve; });
    const broker = new Broker({ token: MEMORY_TOKEN });
    brokers.push(broker);
    const alice = new PolyMeshClient({ card: card("alice") });
    const bob = new PolyMeshClient({
      card: card("bob", "org.example.wait"),
      handlers: { "org.example.wait": async () => { await never; return {}; } },
      authorize: () => allow(),
    });
    clients.push(alice, bob);
    const [aliceWire, brokerAliceWire] = createWirePair();
    const [bobWire, brokerBobWire] = createWirePair();
    broker.attach(brokerAliceWire, { token: MEMORY_TOKEN });
    broker.attach(brokerBobWire, { token: MEMORY_TOKEN });
    await Promise.all([alice.connectTransport(aliceWire), bob.connectTransport(bobWire)]);

    const call = alice.call("bob", "org.example.wait", {});
    await new Promise((resolve) => setTimeout(resolve, 10));
    bob.close();
    await expect(call).rejects.toMatchObject({ code: "TARGET_UNAVAILABLE", retryable: true });
    release();
  });

  it("rejects a forged lifecycle result that does not target the recorded owner", async () => {
    const { alice, bob, bobWire } = await createMemoryClients();
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => { release = resolve; });
    bob.setHandler("org.example.wait", async () => {
      await blocked;
      return {};
    });
    const taskId = uuidv7();
    const waitContract = capabilityContractTuple(contractFor(bob.card, "org.example.wait"));
    const brokerErrors: Array<{ params?: { code?: string } }> = [];
    bobWire.on("message", (raw) => {
      const frame = JSON.parse(raw) as { type?: string; params?: { code?: string } };
      if (frame.type === "error") brokerErrors.push(frame);
    });
    const call = alice.call("bob", "org.example.wait", {}, { taskId, timeoutMs: 1_000 });
    await new Promise((resolve) => setTimeout(resolve, 10));

    bobWire.send(JSON.stringify(createEnvelope({
      type: "task.completed",
      source: { agent_id: bob.card.agent_id, instance_id: bob.card.instance_id },
      target: { agent_id: "mallory" },
      delivery: { mode: "at_least_once", idempotency_key: `forged:${taskId}`, deadline: new Date(Date.now() + 1_000).toISOString() },
      params: {
        task_id: taskId,
        event_seq: 2,
        ...waitContract,
        terminal: { outcome: "succeeded", result: {}, completed_at: new Date().toISOString() },
      },
    })));

    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(brokerErrors).toContainEqual(expect.objectContaining({ params: expect.objectContaining({ code: "PMX.TASK.FORGED_RESULT" }) }));
    bob.close();
    await expect(call).rejects.toMatchObject({ code: "TARGET_UNAVAILABLE" });
    release();
  });

  it("enforces default-deny policy and validates capability input/result boundaries", async () => {
    const broker = new Broker({ token: MEMORY_TOKEN });
    brokers.push(broker);
    const alice = new PolyMeshClient({ card: card("alice") });
    const bob = new PolyMeshClient({
      card: createAgentCard({
        agent_id: "bob",
        capabilities: [
          {
            id: "org.example.typed",
            version: "1.0.0",
            input_schema: {
              type: "object",
              required: ["value"],
              properties: { value: { type: "string" } },
              additionalProperties: false,
            },
            result_schema: {
              type: "object",
              required: ["length"],
              properties: { length: { type: "integer" } },
              additionalProperties: false,
            },
          },
          { id: "org.example.denied", version: "1.0.0" },
          { id: "org.example.large", version: "1.0.0" },
        ],
      }),
      handlers: {
        "org.example.typed": ({ value }) => ({ length: String(value).length }),
        "org.example.denied": () => ({ shouldNotRun: true }),
        "org.example.large": () => "x".repeat(1_048_577),
      },
      authorize: (request) => request.capability !== "org.example.denied"
        ? allow()
        : { effect: "deny", code: "TEST_DENY" },
    });
    clients.push(alice, bob);
    const [aliceWire, brokerAliceWire] = createWirePair();
    const [bobWire, brokerBobWire] = createWirePair();
    broker.attach(brokerAliceWire, { token: MEMORY_TOKEN });
    broker.attach(brokerBobWire, { token: MEMORY_TOKEN });
    await Promise.all([alice.connectTransport(aliceWire), bob.connectTransport(bobWire)]);

    const typedContract = contractFor(bob.card, "org.example.typed");

    await expect(alice.call("bob", "org.example.typed", {}, { capabilityContract: typedContract })).rejects.toMatchObject({ code: "INVALID_INPUT" });
    await expect(alice.call("bob", "org.example.typed", { value: "ok" }, { capabilityContract: typedContract })).resolves.toEqual({ length: 2 });
    await expect(alice.call("bob", "org.example.denied", {})).rejects.toMatchObject({ code: "AUTHORIZATION_DENIED" });
    await expect(alice.call("bob", "org.example.large", {})).rejects.toMatchObject({ code: "RESULT_TOO_LARGE" });

    const charlie = new PolyMeshClient({
      card: createAgentCard({ agent_id: "charlie", capabilities: [{ id: "org.example.custom", version: "1.0.0" }] }),
      handlers: { "org.example.custom": () => ({ shouldNotRun: true }) },
      // No authorizer: non-standard capabilities are denied by default.
    });
    clients.push(charlie);
    const [charlieWire, brokerCharlieWire] = createWirePair();
    broker.attach(brokerCharlieWire, { token: MEMORY_TOKEN });
    await charlie.connectTransport(charlieWire);
    await expect(alice.call("charlie", "org.example.custom", {})).rejects.toMatchObject({ code: "AUTHORIZATION_DENIED" });
  });
});

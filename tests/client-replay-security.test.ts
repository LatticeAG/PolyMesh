import { afterEach, describe, expect, it } from "vitest";

import { Broker, createAgentCard, createWirePair, generateRuntimeToken, type Capability } from "@latticeag/polymesh-broker";
import {
  InMemoryPolicyStore,
  InMemoryReplayLedger,
  PolicyEngine,
  PolyMeshClient,
  type PolicySubject,
} from "@latticeag/polymesh-client";

const brokers: Broker[] = [];
const clients: PolyMeshClient[] = [];

const callerPrincipal = {
  principalId: "key:caller-key",
  keyId: "caller-key",
  agentId: "com.example.caller",
  authStrength: "enrolled-key" as const,
};

const subjects: PolicySubject[] = [
  { principalId: callerPrincipal.principalId, agentId: callerPrincipal.agentId, enabled: true, minimumAuthStrength: "enrolled-key" },
  { principalId: "key:target-key", agentId: "com.example.target", enabled: true },
];

afterEach(async () => {
  for (const client of clients.splice(0)) client.close();
  await Promise.all(brokers.splice(0).map((broker) => broker.close()));
});

function policyEngine() {
  return new PolicyEngine({
    store: new InMemoryPolicyStore(subjects, [{
      id: "allow-write",
      targetPrincipal: "key:target-key",
      callerPrincipal: callerPrincipal.principalId,
      capability: "org.example.write",
      effect: "allow",
    }]),
  });
}

async function connectTarget(replayLedger?: InMemoryReplayLedger) {
  const token = generateRuntimeToken();
  const broker = new Broker({ token });
  brokers.push(broker);
  const caller = new PolyMeshClient({ card: createAgentCard({ agent_id: "com.example.caller" }) });
  let invoked = 0;
  const target = new PolyMeshClient({
    card: createAgentCard({
      agent_id: "com.example.target",
      capabilities: [{
        id: "org.example.write",
        version: "1.0.0",
        side_effects: "write",
        idempotency: "sensitive",
      }],
    }),
    handlers: {
      "org.example.write": () => {
        invoked += 1;
        return { invocation: invoked };
      },
    },
    policyEngine: policyEngine(),
    policyTargetPrincipal: "key:target-key",
    resolveVerifiedPrincipal: () => callerPrincipal,
    ...(replayLedger === undefined ? {} : { replayLedger }),
  });
  clients.push(caller, target);
  const [callerWire, brokerCallerWire] = createWirePair();
  const [targetWire, brokerTargetWire] = createWirePair();
  broker.attach(brokerCallerWire, { token });
  broker.attach(brokerTargetWire, { token });
  await Promise.all([caller.connectTransport(callerWire), target.connectTransport(targetWire)]);
  return { caller, target, invoked: () => invoked };
}

function writeContract(target: PolyMeshClient): Capability {
  const capability = target.card.capabilities.find((entry) => entry.id === "org.example.write");
  if (!capability) throw new Error("Missing org.example.write test capability");
  return capability;
}

describe("client durable replay admission", () => {
  it("fails closed before a secure side-effecting handler when no durable ledger is configured", async () => {
    const { caller, target, invoked } = await connectTarget();

    await expect(caller.call("com.example.target", "org.example.write", {}, { capabilityContract: writeContract(target) })).rejects.toMatchObject({
      code: "REPLAY_PROTECTION_UNAVAILABLE",
    });
    expect(invoked()).toBe(0);
  });

  it("records durable admission before work and replays a canonical terminal artifact without re-executing", async () => {
    const ledger = new InMemoryReplayLedger({ durableForTesting: true });
    const { caller, target, invoked } = await connectTarget(ledger);
    const taskId = "019f74ac-0000-7000-8000-000000000001";
    const options = {
      taskId,
      idempotencyKey: "stable-write",
      deadline: new Date(Date.now() + 5_000).toISOString(),
      capabilityContract: writeContract(target),
    };

    await expect(caller.call("com.example.target", "org.example.write", {}, options)).resolves.toEqual({ invocation: 1 });
    await expect(caller.call("com.example.target", "org.example.write", {}, options)).resolves.toEqual({ invocation: 1 });

    expect(invoked()).toBe(1);
    expect(ledger.snapshot()).toEqual([
      expect.objectContaining({
        principal: expect.objectContaining({ principalId: callerPrincipal.principalId, keyId: callerPrincipal.keyId }),
        artifacts: expect.objectContaining({ terminal: true, events: expect.any(Array) }),
      }),
    ]);
  });
});

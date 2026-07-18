import { afterEach, describe, expect, it } from "vitest";
import { generateKeyPairSync } from "node:crypto";

import {
  Broker,
  capabilityContractDigest,
  capabilityContractTuple,
  createAgentCard,
  createCardIdentityFromPrivateKey,
  createEnvelope,
  createWirePair,
  generateRuntimeToken,
  randomInstanceId,
  uuidv7,
  validateEnvelope,
  type Capability,
  type Envelope,
} from "@polymesh/broker";
import { PolyMeshClient } from "@polymesh/client";

const brokers: Broker[] = [];
const clients: PolyMeshClient[] = [];

afterEach(async () => {
  for (const client of clients.splice(0)) client.close();
  await Promise.all(brokers.splice(0).map((broker) => broker.close()));
});

function allow() {
  return { effect: "allow" as const, ruleId: "contract-test", policyGeneration: 1, leaseId: "contract-test" };
}

function capability(card: ReturnType<typeof createAgentCard>, id: string): Capability {
  const entry = card.capabilities.find((candidate) => candidate.id === id);
  if (!entry) throw new Error(`Missing capability ${id}`);
  return entry;
}

async function connectedClients(targetCapability: Capability) {
  const token = generateRuntimeToken();
  const broker = new Broker({ token });
  const caller = new PolyMeshClient({ card: createAgentCard({ agent_id: "com.example.caller" }) });
  let invocations = 0;
  const target = new PolyMeshClient({
    card: createAgentCard({ agent_id: "com.example.target", capabilities: [targetCapability] }),
    handlers: {
      [targetCapability.id]: () => {
        invocations += 1;
        return { invocations };
      },
    },
    authorize: () => allow(),
  });
  brokers.push(broker);
  clients.push(caller, target);
  const [callerWire, brokerCallerWire] = createWirePair();
  const [targetWire, brokerTargetWire] = createWirePair();
  broker.attach(brokerCallerWire, { token });
  broker.attach(brokerTargetWire, { token });
  await Promise.all([caller.connectTransport(callerWire), target.connectTransport(targetWire)]);
  return { caller, target, invocations: () => invocations };
}

describe("capability contract pinning", () => {
  it("digests every security-relevant capability field with normalized defaults", () => {
    const base: Capability = { id: "org.example.read", version: "1.0.0" };
    const sameSemantics: Capability = {
      ...base,
      idempotency: "idempotent",
      side_effects: "none",
      approval: "never",
      cancellation: "none",
      timeout_ceiling_seconds: 300,
    };
    const changed: Capability = { ...base, side_effects: "network" };

    expect(capabilityContractDigest(base)).toBe(capabilityContractDigest(sameSemantics));
    expect(capabilityContractDigest(base)).not.toBe(capabilityContractDigest(changed));
  });

  it("requires a closed contract tuple on submissions and lifecycle replies", () => {
    const deadline = new Date(Date.now() + 60_000).toISOString();
    const contract = capabilityContractTuple({ id: "org.example.echo", version: "1.0.0" });
    const submit = createEnvelope({
      type: "task.submit",
      source: { agent_id: "com.example.caller", instance_id: randomInstanceId() },
      target: { agent_id: "com.example.target", instance_id: randomInstanceId() },
      delivery: { mode: "at_least_once", idempotency_key: "submit:contract", deadline },
      params: {
        task_id: uuidv7(),
        method: contract.capability_id,
        capability_version: contract.capability_version,
        capability_contract_digest: contract.capability_contract_digest,
        params: {},
        deadline,
      },
    });
    expect(validateEnvelope(submit).ok).toBe(true);
    expect(validateEnvelope({
      ...submit,
      params: (({ capability_contract_digest: _omitted, ...rest }) => rest)(submit.params),
    }).ok).toBe(false);
    expect(validateEnvelope({
      ...submit,
      params: { ...submit.params, unexpected: true },
    }).ok).toBe(false);

    const accepted = createEnvelope({
      type: "task.accepted",
      source: submit.target as { agent_id: string; instance_id: string },
      target: submit.source,
      in_reply_to: submit.message_id,
      delivery: { mode: "at_least_once", idempotency_key: "accepted:contract", deadline },
      params: { task_id: submit.params.task_id, event_seq: 1, accepted_at: new Date().toISOString(), ...contract },
    });
    expect(validateEnvelope(accepted).ok).toBe(true);
    expect(validateEnvelope({
      ...accepted,
      params: { ...accepted.params, capability_contract_digest: "0".repeat(64), extra: true },
    }).ok).toBe(false);
  });

  it("rejects a mismatched target contract before the handler is invoked", async () => {
    const advertised: Capability = {
      id: "org.example.write",
      version: "2.0.0",
      side_effects: "write",
    };
    const { caller, invocations } = await connectedClients(advertised);
    const stale: Capability = { id: advertised.id, version: "1.0.0" };

    await expect(caller.call("com.example.target", advertised.id, {}, {
      capabilityVersion: stale.version,
      capabilityContractDigest: capabilityContractDigest(stale),
    })).rejects.toMatchObject({ code: "CAPABILITY_CONTRACT_MISMATCH" });
    expect(invocations()).toBe(0);
  });

  it("echoes a pinned contract in accepted and completed records", async () => {
    const advertised: Capability = {
      id: "org.example.echo",
      version: "1.2.3",
      result_schema: {
        type: "object",
        required: ["invocations"],
        properties: { invocations: { type: "integer" } },
        additionalProperties: false,
      },
    };
    const { caller, target } = await connectedClients(advertised);
    const echoed: Envelope[] = [];
    caller.on("envelope", (envelope: Envelope) => {
      if (envelope.type === "task.accepted" || envelope.type === "task.completed") echoed.push(envelope);
    });
    const pinned = capability(target.card, advertised.id);

    await expect(caller.call("com.example.target", advertised.id, {}, { capabilityContract: pinned })).resolves.toEqual({ invocations: 1 });

    const expected = capabilityContractTuple(pinned);
    expect(echoed).toHaveLength(2);
    expect(echoed.map((envelope) => ({
      capability_id: (envelope.params as Record<string, unknown>).capability_id,
      capability_version: (envelope.params as Record<string, unknown>).capability_version,
      capability_contract_digest: (envelope.params as Record<string, unknown>).capability_contract_digest,
    }))).toEqual([expected, expected]);
  });

  it("does not synthesize an unverified routed contract in the enrolled profile", () => {
    const keys = generateKeyPairSync("ed25519");
    const identity = createCardIdentityFromPrivateKey(keys.privateKey);
    const client = new PolyMeshClient({
      card: createAgentCard({ agent_id: "com.example.secure-caller" }),
      identity: {
        privateKey: keys.privateKey,
        enrollments: [{
          agent_id: "com.example.secure-caller",
          key_id: identity.key_id,
          public_key: identity.public_key,
        }],
      },
    });
    const internal = client as unknown as {
      resolveCallCapabilityContract(target: string, method: string, options: Record<string, never>): unknown;
    };

    let failure: unknown;
    try {
      internal.resolveCallCapabilityContract("com.example.remote", "org.example.read", {});
    } catch (error) {
      failure = error;
    }
    expect(failure).toMatchObject({ code: "CAPABILITY_CONTRACT_REQUIRED" });
  });
});

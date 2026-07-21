import { generateKeyPairSync } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  Broker,
  EnrollmentStore,
  capabilityContractTuple,
  createAgentCard,
  createCardIdentityFromPrivateKey,
  createEnvelope,
  createRoutedProvenance,
  randomNonce,
  signAgentCard,
  validateEnvelope,
  verifyEnrolledCard,
  verifyRoutedProvenance,
  type AgentCard,
  type BrokerPeer,
  type Envelope,
} from "@latticeag/polymesh-broker";
import { PolyMeshClient } from "@latticeag/polymesh-client";

function signedCard(agentId: string): { card: AgentCard; privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"] } {
  const keys = generateKeyPairSync("ed25519");
  return {
    card: signAgentCard(createAgentCard({ agent_id: agentId }), keys.privateKey),
    privateKey: keys.privateKey,
  };
}

function enrolled(card: AgentCard) {
  const store = new EnrollmentStore([{
    agent_id: card.agent_id,
    key_id: card.identity!.key_id,
    public_key: card.identity!.public_key,
  }]);
  const principal = verifyEnrolledCard(card, store);
  if (!principal) throw new Error("test card must enroll");
  return principal;
}

const echoContract = capabilityContractTuple({ id: "org.example.echo", version: "1.0.0" });

describe("broker-signed routed provenance", () => {
  it("has the secure broker attach target-session-bound provenance while forwarding", () => {
    const brokerKeys = generateKeyPairSync("ed25519");
    const brokerIdentity = createCardIdentityFromPrivateKey(brokerKeys.privateKey);
    const broker = new Broker({
      agentId: "com.example.broker",
      identity: {
        privateKey: brokerKeys.privateKey,
        enrollments: [{
          agent_id: "com.example.broker",
          key_id: brokerIdentity.key_id,
          public_key: brokerIdentity.public_key,
        }],
      },
    });
    const source = signedCard("com.example.owner");
    const target = signedCard("com.example.executor");
    const sourcePrincipal = enrolled(source.card);
    const targetSessionId = randomNonce();
    const forwarded: string[] = [];
    const sourcePeer = {
      transport: { readyState: 1, send: () => undefined },
      phase: "active",
      authenticated: true,
      connectionId: "source-provenance-test",
      verifiedPrincipal: sourcePrincipal,
      agentId: source.card.agent_id,
      instanceId: source.card.instance_id,
      sessionId: randomNonce(),
      connectedAt: Date.now(),
    } as BrokerPeer;
    const targetPeer = {
      transport: {
        readyState: 1,
        send: (data: string) => {
          forwarded.push(data);
        },
      },
      phase: "active",
      authenticated: true,
      connectionId: "target-provenance-test",
      agentId: target.card.agent_id,
      instanceId: target.card.instance_id,
      sessionId: targetSessionId,
      connectedAt: Date.now(),
    } as BrokerPeer;
    const deadline = new Date(Date.now() + 45_000).toISOString();
    const envelope = createEnvelope({
      type: "task.submit",
      source: { agent_id: source.card.agent_id, instance_id: source.card.instance_id },
      target: { agent_id: target.card.agent_id, instance_id: target.card.instance_id },
      delivery: { mode: "at_least_once", idempotency_key: "submit:broker-forward", deadline },
      params: {
        task_id: "0197a1b0-0000-7000-8000-000000000007",
        method: "org.example.echo",
        capability_version: echoContract.capability_version,
        capability_contract_digest: echoContract.capability_contract_digest,
        params: {},
        deadline,
      },
    });

    const privateBroker = broker as unknown as {
      forwardEnvelope(source: BrokerPeer, target: BrokerPeer, envelope: Envelope): boolean;
    };
    expect(privateBroker.forwardEnvelope(sourcePeer, targetPeer, envelope)).toBe(true);
    expect(forwarded).toHaveLength(1);
    const routed = JSON.parse(forwarded[0]!) as Envelope;
    const brokerPrincipal = verifyEnrolledCard(broker.card, new EnrollmentStore([{
      agent_id: broker.card.agent_id,
      key_id: broker.card.identity!.key_id,
      public_key: broker.card.identity!.public_key,
    }]));
    expect(brokerPrincipal).toBeDefined();
    expect(routed.provenance?.target_session_id).toBe(targetSessionId);
    expect(verifyRoutedProvenance(routed, {
      brokerPrincipal: brokerPrincipal!,
      brokerIdentity: { agent_id: broker.card.agent_id, instance_id: broker.card.instance_id },
      targetSessionId,
    })).toBe(true);
  });

  it("binds an enrolled source, exact route, semantic record, and target session", () => {
    const broker = signedCard("com.example.broker");
    const source = signedCard("com.example.owner");
    const target = createAgentCard({ agent_id: "com.example.executor" });
    const brokerPrincipal = enrolled(broker.card);
    const sourcePrincipal = enrolled(source.card);
    const issuedAt = new Date("2026-07-18T12:00:00.000Z").toISOString();
    const expiresAt = new Date("2026-07-18T12:00:30.000Z").toISOString();
    const targetSessionId = randomNonce();
    const envelope = createEnvelope({
      type: "task.submit",
      source: { agent_id: source.card.agent_id, instance_id: source.card.instance_id },
      target: { agent_id: target.agent_id, instance_id: target.instance_id },
      delivery: {
        mode: "at_least_once",
        idempotency_key: "submit:provenance",
        deadline: "2026-07-18T12:05:00.000Z",
      },
      params: {
        task_id: "0197a1b0-0000-7000-8000-000000000001",
        method: "org.example.echo",
        capability_version: echoContract.capability_version,
        capability_contract_digest: echoContract.capability_contract_digest,
        params: { value: "original" },
        deadline: "2026-07-18T12:05:00.000Z",
      },
      timestamp: issuedAt,
      message_id: "0197a1b0-0000-7000-8000-000000000002",
    });
    const provenance = createRoutedProvenance({
      envelope,
      broker: {
        agent_id: broker.card.agent_id,
        instance_id: broker.card.instance_id,
        key_id: broker.card.identity!.key_id,
      },
      sourcePrincipal,
      sourceSessionId: randomNonce(),
      targetSessionId,
      issuedAt,
      expiresAt,
      privateKey: broker.privateKey,
    });
    const routed = { ...envelope, provenance } as Envelope;

    expect(validateEnvelope(routed)).toEqual({ ok: true, value: routed });
    expect(verifyRoutedProvenance(routed, {
      brokerPrincipal,
      brokerIdentity: { agent_id: broker.card.agent_id, instance_id: broker.card.instance_id },
      targetSessionId,
      now: Date.parse(issuedAt) + 1,
    })).toBe(true);

    const changedInput = {
      ...routed,
      params: { ...routed.params, params: { value: "tampered" } },
    } as Envelope;
    expect(validateEnvelope(changedInput).ok).toBe(true);
    expect(verifyRoutedProvenance(changedInput, {
      brokerPrincipal,
      brokerIdentity: { agent_id: broker.card.agent_id, instance_id: broker.card.instance_id },
      targetSessionId,
      now: Date.parse(issuedAt) + 1,
    })).toBe(false);

    expect(verifyRoutedProvenance(routed, {
      brokerPrincipal,
      brokerIdentity: { agent_id: broker.card.agent_id, instance_id: broker.card.instance_id },
      targetSessionId: randomNonce(),
      now: Date.parse(issuedAt) + 1,
    })).toBe(false);
  });

  it("rejects unclosed, malformed, expired, and signer-mismatched attestations", () => {
    const broker = signedCard("com.example.broker");
    const source = signedCard("com.example.owner");
    const target = createAgentCard({ agent_id: "com.example.executor" });
    const sourcePrincipal = enrolled(source.card);
    const issuedAt = new Date("2026-07-18T12:00:00.000Z").toISOString();
    const envelope = createEnvelope({
      type: "task.cancel",
      source: { agent_id: source.card.agent_id, instance_id: source.card.instance_id },
      target: { agent_id: target.agent_id, instance_id: target.instance_id },
      delivery: { mode: "at_least_once", idempotency_key: "cancel:provenance", deadline: "2026-07-18T12:05:00.000Z" },
      params: { task_id: "0197a1b0-0000-7000-8000-000000000003" },
      timestamp: issuedAt,
      message_id: "0197a1b0-0000-7000-8000-000000000004",
    });
    const attacker = signedCard("com.example.attacker");
    expect(() => createRoutedProvenance({
      envelope,
      broker: {
        agent_id: broker.card.agent_id,
        instance_id: broker.card.instance_id,
        key_id: broker.card.identity!.key_id,
      },
      sourcePrincipal,
      sourceSessionId: randomNonce(),
      targetSessionId: randomNonce(),
      issuedAt,
      expiresAt: "2026-07-18T12:00:30.000Z",
      privateKey: attacker.privateKey,
    })).toThrow(/broker key/i);

    const valid = createRoutedProvenance({
      envelope,
      broker: {
        agent_id: broker.card.agent_id,
        instance_id: broker.card.instance_id,
        key_id: broker.card.identity!.key_id,
      },
      sourcePrincipal,
      sourceSessionId: randomNonce(),
      targetSessionId: randomNonce(),
      issuedAt,
      expiresAt: "2026-07-18T12:00:30.000Z",
      privateKey: broker.privateKey,
    });
    expect(validateEnvelope({ ...envelope, provenance: { ...valid, extra: true } }).ok).toBe(false);
    expect(validateEnvelope({
      ...envelope,
      provenance: { ...valid, expires_at: "2026-07-18T12:00:00.000Z" },
    }).ok).toBe(false);
  });

  it("rejects a tampered secure routed submit before policy or handler state changes", () => {
    const broker = signedCard("com.example.broker");
    const source = signedCard("com.example.owner");
    const recipient = signedCard("com.example.executor");
    const sourcePrincipal = enrolled(source.card);
    const brokerPrincipal = enrolled(broker.card);
    const targetSessionId = randomNonce();
    const now = Date.now();
    const issuedAt = new Date(now).toISOString();
    const deadline = new Date(now + 55_000).toISOString();
    const client = new PolyMeshClient({
      card: recipient.card,
      identity: {
        privateKey: recipient.privateKey,
        enrollments: [
          {
            agent_id: recipient.card.agent_id,
            key_id: recipient.card.identity!.key_id,
            public_key: recipient.card.identity!.public_key,
          },
          {
            agent_id: broker.card.agent_id,
            key_id: broker.card.identity!.key_id,
            public_key: broker.card.identity!.public_key,
          },
        ],
      },
      handlers: {
        "org.example.echo": () => {
          throw new Error("must not run");
        },
      },
      authorize: () => ({ effect: "allow", ruleId: "test", policyGeneration: 1, leaseId: "test" }),
    });
    const envelope = createEnvelope({
      type: "task.submit",
      source: { agent_id: source.card.agent_id, instance_id: source.card.instance_id },
      target: { agent_id: recipient.card.agent_id, instance_id: recipient.card.instance_id },
      delivery: { mode: "at_least_once", idempotency_key: "submit:gated", deadline },
      params: {
        task_id: "0197a1b0-0000-7000-8000-000000000005",
        method: "org.example.echo",
        capability_version: echoContract.capability_version,
        capability_contract_digest: echoContract.capability_contract_digest,
        params: { value: "original" },
        deadline,
      },
      timestamp: issuedAt,
      message_id: "0197a1b0-0000-7000-8000-000000000006",
    });
    const provenance = createRoutedProvenance({
      envelope,
      broker: {
        agent_id: broker.card.agent_id,
        instance_id: broker.card.instance_id,
        key_id: broker.card.identity!.key_id,
      },
      sourcePrincipal,
      sourceSessionId: randomNonce(),
      targetSessionId,
      issuedAt,
      expiresAt: new Date(now + 30_000).toISOString(),
      privateKey: broker.privateKey,
    });
    const tampered = {
      ...envelope,
      provenance,
      params: { ...envelope.params, params: { value: "tampered" } },
    } as Envelope;
    const privateClient = client as unknown as {
      phase: string;
      peerCard?: AgentCard;
      peerIdentity?: { agent_id: string; instance_id: string };
      peerPrincipal?: unknown;
      sessionId?: string;
      lastValidInboundAt: number;
      receiveEnvelope(frame: unknown): void;
    };
    privateClient.phase = "active";
    privateClient.peerCard = broker.card;
    privateClient.peerIdentity = { agent_id: broker.card.agent_id, instance_id: broker.card.instance_id };
    privateClient.peerPrincipal = brokerPrincipal;
    privateClient.sessionId = targetSessionId;
    const errors: unknown[] = [];
    client.on("protocolError", (error) => errors.push(error));

    privateClient.receiveEnvelope(tampered);

    expect(privateClient.lastValidInboundAt).toBe(0);
    expect(errors).toContainEqual(expect.objectContaining({ code: "ROUTED_PROVENANCE_INVALID" }));
  });
});

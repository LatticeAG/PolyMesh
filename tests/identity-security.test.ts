import { generateKeyPairSync } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  EnrollmentStore,
  Broker,
  SECURE_IDENTITY_PROFILE,
  authTranscript,
  cardDigest,
  createAgentCard,
  createAuthProof,
  deriveSessionId,
  randomNonce,
  signAgentCard,
  validateAgentCard,
  verifyAuthProof,
  verifyEnrolledCard,
  type AgentCard,
  type HelloFrame,
} from "@polymesh/broker";
import { PolyMeshClient } from "@polymesh/client";

function signedCard(agentId: string) {
  const keys = generateKeyPairSync("ed25519");
  const card = signAgentCard(createAgentCard({ agent_id: agentId }), keys.privateKey);
  return { card, keys };
}

describe("enrolled identity security profile", () => {
  it("binds a signed card to an enrolled agent ID rather than a bearer token claim", () => {
    const { card, keys } = signedCard("com.example.deployer");
    const enrollment = new EnrollmentStore([{
      agent_id: card.agent_id,
      key_id: card.identity!.key_id,
      public_key: card.identity!.public_key,
    }]);

    expect(validateAgentCard(card)).toEqual({ ok: true, value: card });
    expect(verifyEnrolledCard(card, enrollment)).toMatchObject({
      agent_id: "com.example.deployer",
      key_id: card.identity!.key_id,
      auth_strength: "enrolled-key",
    });

    const claimedDifferentAgent = { ...card, agent_id: "com.example.admin" } as AgentCard;
    expect(validateAgentCard(claimedDifferentAgent).ok).toBe(false);
    expect(verifyEnrolledCard(claimedDifferentAgent, enrollment)).toBeUndefined();

    // The public key must be part of the enrollment; a same-name different
    // key is an identity collision rather than a replacement.
    const attacker = signedCard("com.example.deployer");
    expect(verifyEnrolledCard(attacker.card, enrollment)).toBeUndefined();
    void keys;
  });

  it("rejects incomplete or tampered card identity material", () => {
    const { card } = signedCard("com.example.worker");
    expect(validateAgentCard({ ...card, signature: undefined }).ok).toBe(false);
    expect(validateAgentCard({ ...card, identity: undefined }).ok).toBe(false);
    expect(validateAgentCard({ ...card, revision: card.revision + 1 }).ok).toBe(false);
  });

  it("binds proof possession to both cards, roles, nonces, and TLS exporter material", () => {
    const initiator = signedCard("com.example.initiator");
    const responder = signedCard("com.example.responder");
    const initiatorNonce = randomNonce();
    const responderNonce = randomNonce();
    const sid = deriveSessionId(initiatorNonce, responderNonce);
    const initiatorHello: HelloFrame = {
      type: "hello",
      v: "0.1",
      role: "initiator",
      agent_id: initiator.card.agent_id,
      instance_id: initiator.card.instance_id,
      nonce: initiatorNonce,
      security_profile: SECURE_IDENTITY_PROFILE,
    };
    const responderHello: HelloFrame = {
      type: "hello",
      v: "0.1",
      role: "responder",
      agent_id: responder.card.agent_id,
      instance_id: responder.card.instance_id,
      nonce: responderNonce,
      echo: initiatorNonce,
      sid,
      security_profile: SECURE_IDENTITY_PROFILE,
    };
    const binding = Buffer.alloc(32, 7).toString("base64url");
    const transcript = authTranscript({
      initiator_hello: initiatorHello,
      responder_hello: responderHello,
      initiator_card_digest: cardDigest(initiator.card),
      responder_card_digest: cardDigest(responder.card),
      tls_channel_binding: binding,
    });
    const proof = createAuthProof(
      initiator.card.identity!,
      initiator.card.agent_id,
      sid,
      transcript,
      initiator.keys.privateKey,
    );
    const enrollments = new EnrollmentStore([{
      agent_id: initiator.card.agent_id,
      key_id: initiator.card.identity!.key_id,
      public_key: initiator.card.identity!.public_key,
    }]);

    expect(verifyAuthProof(proof, transcript, enrollments)).toMatchObject({ agent_id: initiator.card.agent_id });
    const changedBinding = authTranscript({
      initiator_hello: initiatorHello,
      responder_hello: responderHello,
      initiator_card_digest: cardDigest(initiator.card),
      responder_card_digest: cardDigest(responder.card),
      tls_channel_binding: Buffer.alloc(32, 8).toString("base64url"),
    });
    expect(verifyAuthProof(proof, changedBinding, enrollments)).toBeUndefined();
  });

  it("fails closed when a WSS endpoint or TLS listener lacks enrolled identity configuration", async () => {
    const client = new PolyMeshClient({
      card: createAgentCard({ agent_id: "com.example.client" }),
      url: "wss://127.0.0.1:7443/polymesh",
    });
    await expect(client.connect()).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });

    const broker = new Broker({
      tls: { key: "not-used-before-validation", cert: "not-used-before-validation" },
    });
    await expect(broker.start()).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
  });
});

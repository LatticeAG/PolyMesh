import { describe, expect, it } from "vitest";

import {
  COMPRESSION_ACCEPT_SCHEMA,
  COMPRESSION_PROPOSAL_SCHEMA,
  COMPRESSION_READY_SCHEMA,
  COMPRESSION_ZSTD_WRAPPER_SCHEMA,
  CompressionNegotiationState,
  CompressionNegotiationStateMachine,
  createCompressionZstdWrapper,
  validateCompressionZstdDecodedEnvelope,
} from "../packages/broker/src/compression.js";
import { deriveV2SessionId, uuidv7 } from "../packages/broker/src/protocol.js";

const meshId = "msh_01J9YJP3QXA73AGWT2J71D8TQR";
const sid = deriveV2SessionId(
  Buffer.alloc(32, 0x11),
  Buffer.alloc(32, 0x22),
  Buffer.alloc(32, 0x33),
);

const initiatorReceiveLimits = {
  maxCompressedBytes: 700,
  maxUncompressedBytes: 2_500,
  maxExpansionRatio: 8,
} as const;
const responderReceiveLimits = {
  maxCompressedBytes: 800,
  maxUncompressedBytes: 3_000,
  maxExpansionRatio: 16,
} as const;
const responderPolicyLimits = {
  maxCompressedBytes: 600,
  maxUncompressedBytes: 2_000,
  maxExpansionRatio: 4,
} as const;
const proposedLimits = {
  max_compressed_bytes: 900,
  max_uncompressed_bytes: 4_000,
  max_expansion_ratio: 32,
} as const;

function applicationEnvelope() {
  const deadline = "2026-07-20T12:10:00.000Z";
  return {
    protocol: "polymesh.0.2",
    type: "task.submit",
    message_id: uuidv7(),
    timestamp: "2026-07-20T12:00:00.000Z",
    source: {
      mesh_id: meshId,
      agent_id: "org.example.owner",
      instance_id: "AAAAAAAAAAAAAAAAAAAAAA",
    },
    target: { mesh_id: meshId, agent_id: "org.example.executor" },
    delivery: {
      delivery_id: uuidv7(),
      mode: "at_least_once",
      idempotency_key: "submit:1",
      deadline,
    },
    params: {
      task_id: uuidv7(),
      capability: "org.example.echo",
      capability_version: "1.0.0",
      capability_contract_digest: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      input: { message: "hello" },
      deadline,
    },
  };
}

function machine(role: "initiator" | "responder", allowZstd = true): CompressionNegotiationStateMachine {
  return new CompressionNegotiationStateMachine({
    role,
    sid,
    meshId,
    localReceiveLimits: role === "initiator" ? initiatorReceiveLimits : responderReceiveLimits,
    peerReceiveLimits: role === "initiator" ? responderReceiveLimits : initiatorReceiveLimits,
    ...(role === "initiator"
      ? { peerPolicyLimits: responderPolicyLimits }
      : { localPolicyLimits: responderPolicyLimits }),
    allowZstd,
  });
}

describe("v2 compression negotiation protocol", () => {
  it("requires the ordinary ready boundary, then completes proposal → accept → ready → zstd", () => {
    const initiator = machine("initiator");
    const responder = machine("responder");
    const proposalId = uuidv7();

    expect(initiator.state).toBe(CompressionNegotiationState.HELLO);
    expect(initiator.createProposal(proposalId, proposedLimits)).toMatchObject({
      ok: false,
      code: "COMPRESSION_INVALID_TRANSITION",
    });
    expect(initiator.markHandshakeReady()).toMatchObject({
      ok: true,
      state: CompressionNegotiationState.ACTIVE_PLAIN,
    });
    expect(responder.markHandshakeReady()).toMatchObject({
      ok: true,
      state: CompressionNegotiationState.ACTIVE_PLAIN,
    });

    const proposalResult = initiator.createProposal(proposalId, proposedLimits);
    if (!proposalResult.ok) throw new Error(proposalResult.error);
    const proposal = proposalResult.value;
    expect(proposal).toMatchObject({
      type: "compression.proposal",
      v: "0.2",
      sid,
      mesh_id: meshId,
      proposal_id: proposalId,
      algorithms: ["zstd"],
      zstd: proposedLimits,
    });
    expect(initiator.state).toBe(CompressionNegotiationState.PROPOSAL_SENT);

    const receivedProposal = responder.receiveProposal(proposal);
    expect(receivedProposal).toMatchObject({ ok: true, state: CompressionNegotiationState.PROPOSAL_RECEIVED });
    const acceptResult = responder.createAccept();
    if (!acceptResult.ok) throw new Error(acceptResult.error);
    const accept = acceptResult.value;
    expect(accept).toMatchObject({
      type: "compression.accept",
      proposal_id: proposalId,
      algorithm: "zstd",
      zstd: {
        max_compressed_bytes: 600,
        max_uncompressed_bytes: 2_000,
        max_expansion_ratio: 4,
      },
    });
    expect(responder.state).toBe(CompressionNegotiationState.ACCEPT_SENT);

    expect(initiator.receiveAccept(accept)).toMatchObject({
      ok: true,
      state: CompressionNegotiationState.ACCEPT_RECEIVED,
      negotiation: {
        algorithm: "zstd",
        limits: {
          maxCompressedBytes: 600,
          maxUncompressedBytes: 2_000,
          maxExpansionRatio: 4,
        },
      },
    });
    const initiatorReady = initiator.createReady();
    if (!initiatorReady.ok) throw new Error(initiatorReady.error);
    expect(initiator.state).toBe(CompressionNegotiationState.READY_SENT);
    expect(responder.receiveReady(initiatorReady.value)).toMatchObject({
      ok: true,
      state: CompressionNegotiationState.READY_RECEIVED,
    });
    const responderReady = responder.createReady();
    if (!responderReady.ok) throw new Error(responderReady.error);
    expect(responder.state).toBe(CompressionNegotiationState.ACTIVE_COMPRESSED);
    expect(initiator.receiveReady(responderReady.value)).toMatchObject({
      ok: true,
      state: CompressionNegotiationState.ACTIVE_COMPRESSED,
    });
    expect(initiator.activeCompression).toBe(true);
    expect(initiator.canSendUncompressedEnvelope).toBe(true);

    const wrapper = createCompressionZstdWrapper({ sid, meshId }, Buffer.from("zstd-frame"), 24);
    expect(initiator.validateZstdWrapper(wrapper)).toMatchObject({ ok: true, value: wrapper });
    expect(validateCompressionZstdDecodedEnvelope(
      wrapper,
      applicationEnvelope(),
      24,
      initiator.negotiation!,
    )).toEqual({ ok: true, value: "task.submit" });
    expect(validateCompressionZstdDecodedEnvelope(
      wrapper,
      { protocol: "polymesh.0.2", type: "delivery.receipt" },
      24,
      initiator.negotiation!,
    )).toMatchObject({ ok: false, code: "COMPRESSION_INNER_RECORD_INVALID" });
  });

  it("rejects wrong-role, wrong-session, mismatched-proposal, and second-proposal transitions", () => {
    const initiator = machine("initiator");
    const responder = machine("responder");
    const proposalId = uuidv7();
    initiator.markHandshakeReady();
    responder.markHandshakeReady();

    expect(responder.createProposal(proposalId, proposedLimits)).toMatchObject({
      ok: false,
      code: "COMPRESSION_ROLE_VIOLATION",
    });
    const proposed = initiator.createProposal(proposalId, proposedLimits);
    if (!proposed.ok) throw new Error(proposed.error);
    expect(initiator.createProposal(uuidv7(), proposedLimits)).toMatchObject({
      ok: false,
      code: "COMPRESSION_INVALID_TRANSITION",
    });
    expect(responder.receiveProposal({ ...proposed.value, sid: deriveV2SessionId(
      Buffer.alloc(32, 0x44), Buffer.alloc(32, 0x55), Buffer.alloc(32, 0x66),
    ) })).toMatchObject({
      ok: false,
      code: "COMPRESSION_SESSION_MISMATCH",
      state: CompressionNegotiationState.CLOSED,
    });

    const freshResponder = machine("responder");
    freshResponder.markHandshakeReady();
    expect(freshResponder.receiveProposal(proposed.value)).toMatchObject({ ok: true });
    const accepted = freshResponder.createAccept();
    if (!accepted.ok) throw new Error(accepted.error);
    expect(initiator.receiveAccept({ ...accepted.value, proposal_id: uuidv7() })).toMatchObject({
      ok: false,
      code: "COMPRESSION_NEGOTIATION_MISMATCH",
      state: CompressionNegotiationState.CLOSED,
    });
  });

  it("keeps the session plain when the responder declines zstd and exports closed schemas", () => {
    const initiator = machine("initiator");
    const responder = machine("responder", false);
    initiator.markHandshakeReady();
    responder.markHandshakeReady();
    const proposal = initiator.createProposal(uuidv7(), proposedLimits);
    if (!proposal.ok) throw new Error(proposal.error);
    expect(responder.receiveProposal(proposal.value)).toMatchObject({ ok: true });
    const accepted = responder.createAccept();
    if (!accepted.ok) throw new Error(accepted.error);
    expect(accepted.value).toMatchObject({ type: "compression.accept", algorithm: "none" });
    expect(responder.state).toBe(CompressionNegotiationState.ACTIVE_PLAIN);
    expect(initiator.receiveAccept(accepted.value)).toMatchObject({
      ok: true,
      state: CompressionNegotiationState.ACTIVE_PLAIN,
      negotiation: { algorithm: "none" },
    });
    expect(initiator.createProposal(uuidv7(), proposedLimits)).toMatchObject({
      ok: false,
      code: "COMPRESSION_INVALID_TRANSITION",
    });

    for (const schema of [
      COMPRESSION_PROPOSAL_SCHEMA,
      COMPRESSION_ACCEPT_SCHEMA,
      COMPRESSION_READY_SCHEMA,
      COMPRESSION_ZSTD_WRAPPER_SCHEMA,
    ]) {
      expect(schema.additionalProperties).toBe(false);
      expect(schema.properties.v.const).toBe("0.2");
    }
  });
});

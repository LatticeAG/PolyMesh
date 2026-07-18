import { describe, expect, it } from "vitest";

import {
  HierarchicalRateLimiter,
  InMemoryAtomicTokenBucketStore,
  rateLimitBucketKey,
} from "../packages/broker/src/rate-limit.js";
import {
  assertDecompressedSize,
  negotiateCompression,
  validateCompressionFrame,
} from "../packages/broker/src/compression.js";
import {
  DRAINING,
  HEALTHY,
  SUSPECT,
  createRoutePin,
  resolvePinnedRoute,
  selectWeightedRendezvous,
  type RoutingInstance,
} from "../packages/broker/src/routing.js";
import {
  V2_HANDSHAKE_VERSION,
  V2_PROTOCOL_VERSION,
  attachV2DeliveryMetadata,
  createV2CompressionSelected,
  hasV2DeliveryMetadata,
  isV2CompressionFrame,
  isV2CompressionOffer,
  isV2CompressionSelected,
  isV2DeliveredEnvelope,
  isV2IngressEnvelope,
  validateV2CompressionFrame,
  validateV2CompressionOffer,
  validateV2CompressionRecordBinding,
  validateV2CompressionSelected,
  v2EnvelopeAsLegacy,
  v2EnvelopeSemanticDigest,
  validateV2Envelope,
} from "../packages/broker/src/v2.js";
import { randomInstanceId, uuidv7 } from "../packages/broker/src/protocol.js";

const now = 50_000;

function instance(overrides: Partial<RoutingInstance> = {}): RoutingInstance {
  return {
    meshId: "msh-test",
    agentId: "com.example.executor",
    instanceId: "executor-a",
    principalId: "principal-executor",
    sessionId: "session-a",
    registrationFence: 4,
    sessionFence: 9,
    health: HEALTHY,
    capacity: 2,
    currentInflight: 0,
    capacityWeight: 1,
    cardValid: true,
    leaseExpiresAt: now + 1_000,
    capabilities: ["org.example.work"],
    ...overrides,
  };
}

describe("v0.2 routing edge cases", () => {
  it("never falls back from an expired exact target and fails closed on a principal collision", () => {
    const expired = instance({ instanceId: "executor-expired", leaseExpiresAt: now });
    const healthySibling = instance({ instanceId: "executor-healthy", sessionId: "session-b" });
    const exact = selectWeightedRendezvous([expired, healthySibling], {
      meshId: "msh-test",
      targetAgentId: "com.example.executor",
      targetInstanceId: "executor-expired",
      routingKey: "task-exact",
      now,
    });
    expect(exact).toMatchObject({
      ok: false,
      code: "TARGET_UNAVAILABLE",
      retryable: true,
      reason: "LEASE_EXPIRED",
    });

    const collision = selectWeightedRendezvous([
      healthySibling,
      instance({ instanceId: "executor-other-principal", principalId: "principal-other", sessionId: "session-c" }),
    ], {
      meshId: "msh-test",
      targetAgentId: "com.example.executor",
      routingKey: "task-collision",
      now,
    });
    expect(collision).toEqual({ ok: false, code: "IDENTITY_COLLISION", retryable: false });
  });

  it("permits only a draining pinned instance to finish; suspect pinned work remains unavailable", () => {
    const original = instance();
    const pin = createRoutePin(original, { routeFence: 12 });

    expect(resolvePinnedRoute([instance({ health: DRAINING })], pin, { now })).toMatchObject({ ok: true });
    expect(resolvePinnedRoute([instance({ health: SUSPECT })], pin, { now })).toMatchObject({
      ok: false,
      code: "PMX.ROUTING.PINNED_INSTANCE_UNAVAILABLE",
      reason: "UNHEALTHY",
    });
  });
});

describe("v0.2 relay delivery metadata", () => {
  function ingressEnvelope() {
    const deadline = new Date(Date.now() + 60_000).toISOString();
    return {
      protocol: V2_PROTOCOL_VERSION,
      type: "ping",
      message_id: uuidv7(),
      timestamp: new Date().toISOString(),
      source: {
        mesh_id: "msh-test",
        agent_id: "com.example.source",
        instance_id: randomInstanceId(),
      },
      target: {
        mesh_id: "msh-test",
        agent_id: "com.example.target",
        instance_id: randomInstanceId(),
      },
      delivery: { mode: "at_least_once", idempotency_key: "v2-delivery-metadata", deadline },
      params: { n: 0 },
    };
  }

  it("keeps relay delivery IDs out of sender ingress and semantic idempotency", () => {
    const rawIngress = ingressEnvelope();
    const parsed = validateV2Envelope(rawIngress);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok || !isV2IngressEnvelope(parsed.value)) throw new Error("expected a valid v0.2 ingress envelope");
    const ingress = parsed.value;
    const semanticDigest = v2EnvelopeSemanticDigest(ingress);

    const deliveryId = uuidv7();
    const delivered = attachV2DeliveryMetadata(ingress, deliveryId);
    expect(delivered.delivery_id).toBe(deliveryId);
    expect(Object.isFrozen(delivered)).toBe(true);
    expect(validateV2Envelope(delivered).ok).toBe(true);
    expect(hasV2DeliveryMetadata(delivered)).toBe(true);
    expect(isV2DeliveredEnvelope(delivered)).toBe(true);
    expect(isV2IngressEnvelope(delivered)).toBe(false);
    expect(v2EnvelopeSemanticDigest(delivered)).toBe(semanticDigest);

    const legacy = v2EnvelopeAsLegacy(delivered);
    expect(Object.hasOwn(legacy, "delivery_id")).toBe(false);
    // The type only permits broker code to call the helper with ingress; use
    // an explicit adversarial cast to cover its runtime fail-closed check.
    expect(() => attachV2DeliveryMetadata(
      { ...ingress, delivery_id: uuidv7() } as unknown as typeof ingress,
      uuidv7(),
    )).toThrow("already carry relay delivery metadata");
  });

  it("rejects malformed relay metadata while keeping a valid forged field observable to ingress enforcement", () => {
    const rawIngress = ingressEnvelope();
    expect(validateV2Envelope({ ...rawIngress, delivery_id: "not-a-uuidv7" }).ok).toBe(false);

    const forged = { ...rawIngress, delivery_id: uuidv7() };
    expect(validateV2Envelope(forged).ok).toBe(true);
    expect(isV2IngressEnvelope(forged)).toBe(false);
    expect(isV2DeliveredEnvelope(forged)).toBe(true);
  });
});

describe("v0.2 hierarchical rate-limit atomicity", () => {
  it("does not debit any hierarchy scope when one compressed-work dimension is over quota", () => {
    const store = new InMemoryAtomicTokenBucketStore();
    const policies = {
      principalOperation: {
        compressed_bytes: { capacity: 10, refillPerMs: 0 },
        uncompressed_bytes: { capacity: 3, refillPerMs: 0 },
      },
      principalTarget: {
        compressed_bytes: { capacity: 10, refillPerMs: 0 },
        uncompressed_bytes: { capacity: 3, refillPerMs: 0 },
      },
      credential: {
        compressed_bytes: { capacity: 10, refillPerMs: 0 },
        uncompressed_bytes: { capacity: 3, refillPerMs: 0 },
      },
      connection: {
        compressed_bytes: { capacity: 10, refillPerMs: 0 },
        uncompressed_bytes: { capacity: 3, refillPerMs: 0 },
      },
    };
    const context = {
      meshId: "msh-test",
      principalId: "principal-caller",
      targetAgentId: "com.example.executor",
      credentialId: "credential-a",
      preAuthIp: "127.0.0.1",
      connectionId: "connection-a",
    };
    const limiter = new HierarchicalRateLimiter({ policies, store, clock: () => 0 });

    expect(limiter.admit(context, [
      { operation: "compressed_bytes", cost: 5 },
      { operation: "uncompressed_bytes", cost: 4 },
    ])).toMatchObject({ allowed: false, code: "RATE_LIMITED", retry_after_ms: null });

    for (const scope of ["principal_operation", "principal_target", "credential", "connection"] as const) {
      expect(store.get(rateLimitBucketKey(scope, context, "compressed_bytes"))).toBeUndefined();
    }

    const compressedOnly = new HierarchicalRateLimiter({
      policies: {
        principalOperation: { compressed_bytes: { capacity: 10, refillPerMs: 0 } },
        principalTarget: { compressed_bytes: { capacity: 10, refillPerMs: 0 } },
        credential: { compressed_bytes: { capacity: 10, refillPerMs: 0 } },
        connection: { compressed_bytes: { capacity: 10, refillPerMs: 0 } },
      },
      store,
      clock: () => 0,
    });
    expect(compressedOnly.consume(context, "compressed_bytes", 10).allowed).toBe(true);
  });
});

describe("v0.2 compression output bounds", () => {
  it("uses none when zstd is administratively disabled and checks the codec's actual output size", () => {
    const offer = {
      algorithms: ["none", "zstd"] as const,
      limits: { maxCompressedBytes: 100, maxUncompressedBytes: 64, maxExpansionRatio: 8 },
    };
    const fallback = negotiateCompression(offer, offer, { ready: true, allowZstd: false });
    expect(fallback).toEqual({ ok: true, value: { algorithm: "none" } });

    const negotiated = negotiateCompression(offer, offer, { ready: true });
    if (!negotiated.ok) throw new Error("expected zstd negotiation");
    expect(validateCompressionFrame(negotiated.value, {
      algorithm: "zstd",
      recordType: "task.submit",
      compressedBytes: 8,
      uncompressedBytes: 64,
    })).toEqual({ ok: true, uncompressedBytes: 64 });
    const frame = {
      algorithm: "zstd" as const,
      recordType: "task.submit",
      compressedBytes: 8,
      uncompressedBytes: 64,
    };
    expect(assertDecompressedSize(negotiated.value, frame, 64)).toBe(true);
    expect(assertDecompressedSize(negotiated.value, frame, 65)).toBe(false);
    expect(assertDecompressedSize(negotiated.value, { ...frame, uncompressedBytes: 63 }, 64)).toBe(false);
  });
});

describe("v0.2 compression wire controls", () => {
  const offer = {
    type: "compression.offer",
    v: V2_HANDSHAKE_VERSION,
    algorithms: ["none", "zstd"] as const,
    limits: { maxCompressedBytes: 64, maxUncompressedBytes: 256, maxExpansionRatio: 16 },
  };

  it("admits only strict post-READY offers and selections bound to local negotiation", () => {
    expect(validateV2CompressionOffer(offer, { ready: false })).toMatchObject({
      ok: false,
      code: "COMPRESSION_NEGOTIATION_BEFORE_READY",
    });
    expect(isV2CompressionOffer(offer, { ready: true })).toBe(true);
    expect(validateV2CompressionOffer({
      type: "compression.offer",
      v: V2_HANDSHAKE_VERSION,
      algorithms: ["none"],
      limits: offer.limits,
    }, { ready: true })).toMatchObject({ ok: false, code: "COMPRESSION_OFFER_INVALID" });

    const negotiated = negotiateCompression(offer, offer, { ready: true });
    if (!negotiated.ok) throw new Error("expected zstd negotiation");
    const selected = createV2CompressionSelected(negotiated.value);
    expect(Object.isFrozen(selected)).toBe(true);
    expect(validateV2CompressionSelected(selected, { ready: false, expected: negotiated.value })).toMatchObject({
      ok: false,
      code: "COMPRESSION_NEGOTIATION_BEFORE_READY",
    });
    expect(isV2CompressionSelected(selected, { ready: true, expected: negotiated.value })).toBe(true);
    expect(validateV2CompressionSelected({
      ...selected,
      limits: { ...selected.limits!, maxUncompressedBytes: 257 },
    }, { ready: true, expected: negotiated.value })).toMatchObject({
      ok: false,
      code: "COMPRESSION_SELECTED_MISMATCH",
    });
  });

  it("validates bounded base64url zstd wrappers against the selected state", () => {
    const negotiated = negotiateCompression(offer, offer, { ready: true });
    if (!negotiated.ok) throw new Error("expected zstd negotiation");
    const payloadBytes = Buffer.from("not-a-real-zstd-stream");
    const frame = {
      type: "compression.frame" as const,
      v: V2_HANDSHAKE_VERSION,
      algorithm: "zstd" as const,
      record_type: "task.submit" as const,
      compressed_bytes: payloadBytes.byteLength,
      uncompressed_bytes: payloadBytes.byteLength * 4,
      payload: payloadBytes.toString("base64url"),
    };

    expect(validateV2CompressionFrame(frame, { ready: false, negotiation: negotiated.value })).toMatchObject({
      ok: false,
      code: "COMPRESSION_NEGOTIATION_BEFORE_READY",
    });
    expect(isV2CompressionFrame(frame, { ready: true, negotiation: negotiated.value })).toBe(true);
    expect(validateV2CompressionFrame({
      ...frame,
      compressed_bytes: frame.compressed_bytes - 1,
    }, { ready: true, negotiation: negotiated.value })).toMatchObject({
      ok: false,
      code: "COMPRESSION_FRAME_INVALID",
    });
    expect(validateV2CompressionFrame({
      ...frame,
      record_type: "delivery.receipt",
    }, { ready: true, negotiation: negotiated.value })).toMatchObject({
      ok: false,
      code: "COMPRESSION_FORBIDDEN_RECORD",
    });
    expect(validateV2CompressionFrame(frame, {
      ready: true,
      negotiation: { algorithm: "none" },
    })).toMatchObject({ ok: false, code: "COMPRESSION_NOT_NEGOTIATED" });
    expect(validateV2CompressionRecordBinding(frame, { type: "task.submit" })).toEqual({
      ok: true,
      recordType: "task.submit",
    });
    expect(validateV2CompressionRecordBinding(frame, { type: "auth" })).toEqual({
      ok: false,
      code: "COMPRESSION_RECORD_TYPE_MISMATCH",
    });
  });
});

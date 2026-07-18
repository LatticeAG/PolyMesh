import { describe, expect, it } from "vitest";

import {
  DRAINING,
  HEALTHY,
  SUSPECT,
  createRoutePin,
  evaluateFencedInstanceUpdate,
  resolvePinnedRoute,
  selectWeightedRendezvous,
  shouldDiscardFencedUpdate,
  type RoutingInstance,
} from "../packages/broker/src/routing.js";

const now = 10_000;

function instance(overrides: Partial<RoutingInstance> = {}): RoutingInstance {
  return {
    meshId: "mesh-a",
    agentId: "executor",
    instanceId: "instance-a",
    principalId: "principal-executor",
    sessionId: "session-a",
    registrationFence: 1,
    sessionFence: 1,
    health: HEALTHY,
    capacity: 8,
    currentInflight: 0,
    capacityWeight: 1,
    cardValid: true,
    leaseExpiresAt: now + 1_000,
    capabilities: ["org.example.work"],
    ...overrides,
  };
}

describe("v0.2 routing primitives", () => {
  it("uses deterministic weighted rendezvous selection and excludes non-healthy candidates", () => {
    const first = instance({ instanceId: "instance-a" });
    const second = instance({ instanceId: "instance-b", sessionId: "session-b", registrationFence: 2, sessionFence: 2 });
    const unavailable = instance({
      instanceId: "instance-c",
      sessionId: "session-c",
      registrationFence: 3,
      sessionFence: 3,
      health: SUSPECT,
    });
    const request = {
      meshId: "mesh-a",
      targetAgentId: "executor",
      routingKey: "task-123",
      requiredCapability: "org.example.work",
      now,
    };

    const selected = selectWeightedRendezvous([first, second, unavailable], request);
    const reordered = selectWeightedRendezvous([unavailable, second, first], request);

    expect(selected.ok).toBe(true);
    expect(reordered.ok).toBe(true);
    if (!selected.ok || !reordered.ok) return;
    expect(selected.instance.instanceId).toBe(reordered.instance.instanceId);
    expect(selected.instance.instanceId).not.toBe("instance-c");
  });

  it("does not route new exact work to a draining instance but lets an existing pin finish there", () => {
    const draining = instance({ health: DRAINING });
    const exact = selectWeightedRendezvous([draining], {
      meshId: "mesh-a",
      targetAgentId: "executor",
      targetInstanceId: "instance-a",
      routingKey: "task-123",
      now,
    });
    expect(exact).toMatchObject({ ok: false, code: "TARGET_UNAVAILABLE", reason: "DRAINING", retryable: true });

    const pin = createRoutePin(draining, { routeFence: 7 });
    expect(resolvePinnedRoute([draining], pin, { now })).toMatchObject({ ok: true, instance: draining });
  });

  it("fences stale or conflicting session updates and refuses a replacement for a pinned route", () => {
    const current = instance({ registrationFence: 4, sessionFence: 9, sessionId: "session-current" });
    const stale = instance({ registrationFence: 3, sessionFence: 99, sessionId: "session-old" });
    const conflict = instance({ registrationFence: 4, sessionFence: 9, sessionId: "session-other" });
    const replacement = instance({ registrationFence: 5, sessionFence: 1, sessionId: "session-replacement" });

    expect(evaluateFencedInstanceUpdate(current, stale)).toBe("stale");
    expect(shouldDiscardFencedUpdate(current, stale)).toBe(true);
    expect(evaluateFencedInstanceUpdate(current, conflict)).toBe("conflict");
    expect(shouldDiscardFencedUpdate(current, conflict)).toBe(true);
    expect(evaluateFencedInstanceUpdate(current, replacement)).toBe("apply");

    const pin = createRoutePin(current, { routeFence: 2 });
    expect(resolvePinnedRoute([replacement], pin, { now })).toMatchObject({
      ok: false,
      code: "PMX.ROUTING.PINNED_INSTANCE_UNAVAILABLE",
      reason: "FENCE_MISMATCH",
    });
  });
});


import { describe, expect, it } from "vitest";

import { DuplicateAgentError, Registry } from "@polymesh/broker";

describe("Registry", () => {
  it("registers live agents and rejects a competing live agent id", () => {
    let now = 1_000;
    const registry = new Registry({
      ttlMs: 120,
      now: () => now,
      leaseId: () => "lease-a",
    });

    const entry = registry.register({
      agentId: "alice",
      instanceId: "alice-instance",
      sessionId: "session-a",
      transport: { name: "first" },
    });

    expect(entry.leaseId).toBe("lease-a");
    expect(registry.lookup("alice")).toMatchObject({
      agentId: "alice",
      instanceId: "alice-instance",
      sessionId: "session-a",
    });
    expect(() =>
      registry.register({
        agentId: "alice",
        instanceId: "replacement-instance",
        sessionId: "session-b",
      }),
    ).toThrow(DuplicateAgentError);

    now += 1;
    expect(registry.size).toBe(1);
  });

  it("expires leases, extends the matching lease, and never renews an expired record", () => {
    let now = 10_000;
    const registry = new Registry({
      ttlMs: 100,
      now: () => now,
      leaseId: () => "lease-a",
    });
    const entry = registry.register({ agentId: "alice", instanceId: "instance-a" });

    now += 90;
    expect(registry.touch("alice", entry.leaseId)).toBe(true);
    expect(registry.renew(entry.leaseId)?.expiresAt).toBe(10_190);

    now = 10_190;
    expect(registry.lookup("alice")).toBeUndefined();
    expect(registry.renew(entry.leaseId)).toBeUndefined();
    expect(registry.list()).toEqual([]);
  });

  it("uses compare-and-remove so a stale socket callback cannot remove a replacement", () => {
    let now = 1;
    let nextLease = 0;
    const registry = new Registry({
      ttlMs: 1_000,
      now: () => now,
      leaseId: () => `lease-${++nextLease}`,
    });

    const oldRecord = registry.register({
      agent_id: "alice",
      instance_id: "old-instance",
      session_id: "old-session",
    });
    expect(registry.remove("alice", { sessionId: oldRecord.sessionId })).toBe(true);

    const replacement = registry.register({
      agentId: "alice",
      instanceId: "new-instance",
      sessionId: "new-session",
    });
    now += 1;

    expect(registry.remove("alice", { sessionId: "old-session" })).toBe(false);
    expect(registry.lookup("alice")).toMatchObject({
      instanceId: "new-instance",
      leaseId: replacement.leaseId,
    });
  });
});

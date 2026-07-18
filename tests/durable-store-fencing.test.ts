import { describe, expect, it } from "vitest";

import {
  InMemoryDurableStore,
  SqliteDurableStore,
  type DurableAgentInstance,
  type DurableSession,
  type DurableStore,
  type DurableTaskRoute,
  type InboxRecord,
  type OutboxRecord,
} from "../packages/broker/src/durable-store.js";
import { HealthState } from "../packages/broker/src/routing.js";

const now = 10_000;

function instance(overrides: Partial<DurableAgentInstance> = {}): DurableAgentInstance {
  return {
    meshId: "msh-fence",
    agentId: "com.example.executor",
    instanceId: "instance-a",
    principalId: "principal:executor",
    sessionId: "session-current",
    leaseId: "lease-current",
    health: HealthState.HEALTHY,
    registrationFence: 5,
    sessionFence: 5,
    registeredAt: now,
    updatedAt: now,
    expiresAt: now + 60_000,
    ...overrides,
  };
}

function session(overrides: Partial<DurableSession> = {}): DurableSession {
  return {
    sessionId: "session-current",
    ownerBrokerNodeId: "broker-a",
    sessionFence: 5,
    createdAt: now,
    updatedAt: now,
    expiresAt: now + 60_000,
    ...overrides,
  };
}

function inbox(overrides: Partial<InboxRecord> = {}): InboxRecord {
  return {
    scope: "ingress",
    meshId: "msh-fence",
    sourcePrincipalId: "principal:caller",
    sourceAgentId: "com.example.caller",
    sourceInstanceId: "caller-a",
    targetAgentId: "com.example.executor",
    idempotencyKey: "submit:one",
    semanticFingerprint: "fingerprint-one",
    messageId: "message-one",
    envelope: { type: "task.submit", task_id: "task-one" },
    selectedInstanceId: "instance-a",
    createdAt: now,
    expiresAt: now + 60_000,
    ...overrides,
  };
}

function route(overrides: Partial<DurableTaskRoute> = {}): DurableTaskRoute {
  return {
    meshId: "msh-fence",
    taskId: "task-one",
    ownerPrincipalId: "principal:caller",
    ownerAgentId: "com.example.caller",
    ownerInstanceId: "caller-a",
    executorPrincipalId: "principal:executor",
    executorAgentId: "com.example.executor",
    executorInstanceId: "instance-a",
    immutableFingerprint: "route-fingerprint",
    deadlineAt: now + 30_000,
    routeFence: 1,
    state: "SUBMITTED",
    createdAt: now,
    updatedAt: now,
    retainedUntil: now + 60_000,
    ...overrides,
  };
}

function outbox(overrides: Partial<OutboxRecord> = {}): OutboxRecord {
  return {
    deliveryId: "delivery-one",
    meshId: "msh-fence",
    targetAgentId: "com.example.executor",
    targetInstanceId: "instance-a",
    envelope: { type: "task.submit", task_id: "task-one" },
    state: "PENDING",
    attempt: 0,
    createdAt: now,
    updatedAt: now,
    expiresAt: now + 60_000,
    ...overrides,
  };
}

const implementations: ReadonlyArray<readonly [string, () => DurableStore]> = [
  ["in-memory", () => new InMemoryDurableStore()],
  ["sqlite", () => new SqliteDurableStore({ filename: ":memory:", clock: () => now })],
];

for (const [name, createStore] of implementations) {
  describe(`${name} durable fencing`, () => {
    it("does not allow an equal-fence session/lease takeover", async () => {
      const store = createStore();
      try {
        await store.upsertInstance(instance());
        const result = await store.upsertInstance(instance({
          sessionId: "session-stale",
          leaseId: "lease-stale",
          health: HealthState.OFFLINE,
          expiresAt: now + 1,
        }));
        expect(result).toMatchObject({
          sessionId: "session-current",
          leaseId: "lease-current",
          health: HealthState.HEALTHY,
        });
        await store.upsertSession(session());
        const staleSession = await store.upsertSession(session({ ownerBrokerNodeId: "broker-stale" }));
        expect(staleSession.ownerBrokerNodeId).toBe("broker-a");
      } finally {
        store.close?.();
      }
    });

    it("does not partially publish an instance when its durable session CAS fails", async () => {
      const store = createStore();
      try {
        await store.upsertSession(session({ sessionId: "session-contended", sessionFence: 9 }));
        await expect(store.upsertRegistration?.({
          instance: instance({
            instanceId: "instance-contended",
            sessionId: "session-contended",
            sessionFence: 9,
          }),
          session: session({
            sessionId: "session-contended",
            sessionFence: 9,
            ownerBrokerNodeId: "broker-stale",
          }),
        })).rejects.toThrow("Session fence");
        await expect(store.getInstance("msh-fence", "com.example.executor", "instance-contended")).resolves.toBeUndefined();
      } finally {
        store.close?.();
      }
    });

    it("persists relay-owned capacity only under the active fence", async () => {
      const store = createStore();
      try {
        await store.upsertInstance(instance());
        await expect(store.updateInstanceCapacity?.({
          meshId: "msh-fence",
          agentId: "com.example.executor",
          instanceId: "instance-a",
          registrationFence: 5,
          sessionFence: 5,
          capacity: 7,
          capacityWeight: 2.5,
          updatedAt: now + 1,
        })).resolves.toMatchObject({ capacity: 7, capacityWeight: 2.5 });
        await expect(store.updateInstanceCapacity?.({
          meshId: "msh-fence",
          agentId: "com.example.executor",
          instanceId: "instance-a",
          registrationFence: 4,
          sessionFence: 5,
          capacity: 99,
          updatedAt: now + 2,
        })).resolves.toBeUndefined();
        await expect(store.getInstance("msh-fence", "com.example.executor", "instance-a")).resolves.toMatchObject({ capacity: 7 });
      } finally {
        store.close?.();
      }
    });

    it("pins a new ingress to an existing task route and creates its own durable outbox", async () => {
      const store = createStore();
      try {
        await expect(store.persistIngress({ inbox: inbox(), route: route(), outbox: outbox() })).resolves.toMatchObject({
          disposition: "stored",
          outbox: { deliveryId: "delivery-one" },
        });
        await expect(store.persistIngress({
          inbox: inbox({ idempotencyKey: "submit:two", messageId: "message-two" }),
          route: route(),
          outbox: outbox({ deliveryId: "delivery-two" }),
        })).resolves.toMatchObject({
          disposition: "stored",
          inbox: { selectedInstanceId: "instance-a", outboxDeliveryId: "delivery-two" },
          route: { executorInstanceId: "instance-a" },
          outbox: { deliveryId: "delivery-two" },
        });
        await expect(store.getOutbox("delivery-two")).resolves.toMatchObject({ state: "PENDING" });
      } finally {
        store.close?.();
      }
    });

    it("rejects a send after its dispatch lease expires and treats a repeated immutable outbox as idempotent", async () => {
      const store = createStore();
      try {
        await store.enqueueOutbox(outbox());
        await store.leasePendingOutbox({ now, leaseId: "lease-old", leaseMs: 10 });
        await expect(store.markOutboxSent({ deliveryId: "delivery-one", leaseId: "lease-old", now: now + 10 })).resolves.toBeUndefined();
        await store.reclaimExpiredDispatchLeases(now + 10);
        await store.leasePendingOutbox({ now: now + 10, leaseId: "lease-new", leaseMs: 10 });
        await store.markOutboxSent({ deliveryId: "delivery-one", leaseId: "lease-new", now: now + 11 });
        await store.acknowledgeOutbox({ deliveryId: "delivery-one", now: now + 11, receiptState: "stored" });
        await expect(store.enqueueOutbox(outbox())).resolves.toMatchObject({
          deliveryId: "delivery-one",
          state: "DELIVERED",
          receiptState: "stored",
        });
      } finally {
        store.close?.();
      }
    });

    it("accepts a matching late receipt after recovery has reclaimed its dispatch lease", async () => {
      const store = createStore();
      try {
        await store.enqueueOutbox(outbox({ deliveryId: "delivery-late" }));
        await store.leasePendingOutbox({ now, leaseId: "lease-old", leaseMs: 10 });
        await store.markOutboxSent({ deliveryId: "delivery-late", leaseId: "lease-old", now: now + 1 });
        await store.reclaimExpiredDispatchLeases(now + 10);
        await expect(store.getOutbox("delivery-late")).resolves.toMatchObject({ state: "PENDING" });
        await expect(store.acknowledgeOutbox({ deliveryId: "delivery-late", now: now + 10, receiptState: "stored" })).resolves.toMatchObject({
          state: "DELIVERED",
          receiptState: "stored",
        });
        await expect(store.leasePendingOutbox({ now: now + 10, leaseId: "lease-new", leaseMs: 10 })).resolves.toEqual([]);
      } finally {
        store.close?.();
      }
    });
  });
}

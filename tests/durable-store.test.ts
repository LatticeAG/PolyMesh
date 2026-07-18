import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  SqliteDurableStore,
  type DurableAgentInstance,
  type DurableSession,
  type DurableTaskRoute,
  type InboxRecord,
  type OutboxRecord,
} from "../packages/broker/src/durable-store.js";

const stores = new Set<SqliteDurableStore>();
const directories: string[] = [];

afterEach(async () => {
  for (const store of stores) {
    try {
      store.close();
    } catch {
      // A test can explicitly close a simulated-crash store before reopening.
    }
  }
  stores.clear();
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

async function databasePath(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "polymesh-durable-store-"));
  directories.push(directory);
  return join(directory, "mesh.sqlite");
}

function openStore(filename: string, now: () => number): SqliteDurableStore {
  const store = new SqliteDurableStore({ filename, clock: now });
  stores.add(store);
  return store;
}

function closeForCrash(store: SqliteDurableStore): void {
  store.close();
  stores.delete(store);
}

function ingress(now: number, overrides: Partial<InboxRecord> = {}): InboxRecord {
  return {
    scope: "ingress",
    meshId: "msh-test",
    sourcePrincipalId: "principal:caller",
    sourceAgentId: "com.example.caller",
    sourceInstanceId: "caller-instance",
    targetAgentId: "com.example.executor",
    idempotencyKey: "submit:task-1",
    semanticFingerprint: "semantic-a",
    messageId: "message-a",
    envelope: { type: "task.submit", task_id: "task-1" },
    selectedInstanceId: "executor-instance-a",
    createdAt: now,
    expiresAt: now + 60_000,
    ...overrides,
  };
}

function route(now: number, overrides: Partial<DurableTaskRoute> = {}): DurableTaskRoute {
  return {
    meshId: "msh-test",
    taskId: "task-1",
    ownerPrincipalId: "principal:caller",
    ownerAgentId: "com.example.caller",
    ownerInstanceId: "caller-instance",
    ownerSessionId: "caller-session",
    executorPrincipalId: "principal:executor",
    executorAgentId: "com.example.executor",
    executorInstanceId: "executor-instance-a",
    executorSessionId: "executor-session-a",
    immutableFingerprint: "route-fingerprint-a",
    deadlineAt: now + 30_000,
    routeFence: 7,
    state: "SUBMITTED",
    createdAt: now,
    updatedAt: now,
    retainedUntil: now + 60_000,
    ...overrides,
  };
}

function outbox(now: number, overrides: Partial<OutboxRecord> = {}): OutboxRecord {
  return {
    deliveryId: "delivery-a",
    meshId: "msh-test",
    targetAgentId: "com.example.executor",
    targetInstanceId: "executor-instance-a",
    envelope: { type: "task.submit", task_id: "task-1" },
    state: "PENDING",
    attempt: 0,
    createdAt: now,
    updatedAt: now,
    expiresAt: now + 60_000,
    ...overrides,
  };
}

function instanceRegistration(now: number, overrides: Partial<DurableAgentInstance> = {}): DurableAgentInstance {
  return {
    meshId: "msh-test",
    agentId: "com.example.executor",
    instanceId: "executor-instance-a",
    principalId: "principal:executor",
    sessionId: "session-a",
    leaseId: "lease-a",
    health: "HEALTHY",
    registrationFence: 1,
    sessionFence: 1,
    registeredAt: now,
    updatedAt: now,
    expiresAt: now + 60_000,
    ...overrides,
  };
}

function sessionRegistration(now: number, overrides: Partial<DurableSession> = {}): DurableSession {
  return {
    sessionId: "session-a",
    ownerBrokerNodeId: "broker-a",
    sessionFence: 1,
    createdAt: now,
    updatedAt: now,
    expiresAt: now + 60_000,
    ...overrides,
  };
}

describe("SQLite durable ingress persistence", () => {
  it("commits ingress, its pinned route, and outbox together, then preserves dedupe across a reopen", async () => {
    let now = 10_000;
    const filename = await databasePath();
    const first = openStore(filename, () => now);
    const input = { inbox: ingress(now), route: route(now), outbox: outbox(now) };

    await expect(first.persistIngress(input)).resolves.toMatchObject({
      disposition: "stored",
      inbox: { outboxDeliveryId: "delivery-a", selectedInstanceId: "executor-instance-a" },
      route: { routeFence: 7, executorInstanceId: "executor-instance-a" },
      outbox: { deliveryId: "delivery-a", state: "PENDING" },
    });
    closeForCrash(first);

    now += 1;
    const reopened = openStore(filename, () => now);
    await expect(reopened.getInbox({
      scope: "ingress",
      meshId: "msh-test",
      sourcePrincipalId: "principal:caller",
      targetAgentId: "com.example.executor",
      idempotencyKey: "submit:task-1",
    })).resolves.toMatchObject({
      selectedInstanceId: "executor-instance-a",
      outboxDeliveryId: "delivery-a",
    });
    await expect(reopened.getRoute("msh-test", "task-1")).resolves.toMatchObject({
      executorInstanceId: "executor-instance-a",
      immutableFingerprint: "route-fingerprint-a",
    });
    await expect(reopened.getOutbox("delivery-a")).resolves.toMatchObject({ state: "PENDING", attempt: 0 });

    await expect(reopened.persistIngress(input)).resolves.toMatchObject({
      disposition: "duplicate",
      inbox: { selectedInstanceId: "executor-instance-a", outboxDeliveryId: "delivery-a" },
      outbox: { deliveryId: "delivery-a" },
    });
    await expect(reopened.persistIngress({
      ...input,
      inbox: ingress(now, { semanticFingerprint: "semantic-conflict", messageId: "message-conflict" }),
    })).resolves.toMatchObject({
      disposition: "conflict",
      code: "PMX.DELIVERY.IDEMPOTENCY_CONFLICT",
      inbox: { semanticFingerprint: "semantic-a" },
    });
  });

  it("leaves no partial ingress facts when dependent outbox validation fails", async () => {
    const now = 20_000;
    const filename = await databasePath();
    const store = openStore(filename, () => now);
    const input = {
      inbox: ingress(now, { idempotencyKey: "submit:invalid", messageId: "invalid-message" }),
      route: route(now, { taskId: "task-invalid" }),
      outbox: outbox(now, {
        deliveryId: "delivery-invalid",
        targetInstanceId: "wrong-physical-target",
      }),
    };

    await expect(store.persistIngress(input)).rejects.toThrow("Ingress outbox target must match the resolved inbox target");
    await expect(store.getInbox({
      scope: "ingress",
      meshId: "msh-test",
      sourcePrincipalId: "principal:caller",
      targetAgentId: "com.example.executor",
      idempotencyKey: "submit:invalid",
    })).resolves.toBeUndefined();
    await expect(store.getRoute("msh-test", "task-invalid")).resolves.toBeUndefined();
    await expect(store.getOutbox("delivery-invalid")).resolves.toBeUndefined();
  });

  it("persists executor inbox dedupe independently from logical ingress scope", async () => {
    const now = 30_000;
    const filename = await databasePath();
    const initial = openStore(filename, () => now);
    const executorInbox = ingress(now, {
      scope: "executor",
      targetInstanceId: "executor-instance-a",
      idempotencyKey: "executor:delivery-a",
      semanticFingerprint: "executor-semantic-a",
      messageId: "executor-message-a",
    });
    await expect(initial.putInbox(executorInbox)).resolves.toMatchObject({ disposition: "stored" });
    closeForCrash(initial);

    const reopened = openStore(filename, () => now + 1);
    await expect(reopened.putInbox(executorInbox)).resolves.toMatchObject({ disposition: "duplicate" });
    await expect(reopened.putInbox({ ...executorInbox, semanticFingerprint: "executor-semantic-conflict" })).resolves.toMatchObject({
      disposition: "conflict",
      record: { semanticFingerprint: "executor-semantic-a" },
    });
  });
});

describe("SQLite outbox crash recovery", () => {
  it("reclaims an expired sent lease after a restart and allows a new fenced dispatch attempt", async () => {
    let now = 40_000;
    const filename = await databasePath();
    const beforeCrash = openStore(filename, () => now);
    await beforeCrash.enqueueOutbox(outbox(now, { deliveryId: "delivery-recover" }));
    await expect(beforeCrash.leasePendingOutbox({ now, leaseId: "worker-old", leaseMs: 100 })).resolves.toEqual([
      expect.objectContaining({
        deliveryId: "delivery-recover",
        state: "LEASED",
        dispatchLeaseId: "worker-old",
        attempt: 1,
      }),
    ]);
    await expect(beforeCrash.markOutboxSent({ deliveryId: "delivery-recover", leaseId: "worker-old", now: now + 1 })).resolves.toMatchObject({
      state: "SENT_AWAITING_RECEIPT",
      dispatchLeaseId: "worker-old",
    });
    closeForCrash(beforeCrash);

    now += 101;
    const restarted = openStore(filename, () => now);
    await expect(restarted.recover(now)).resolves.toMatchObject({
      reclaimedDispatchLeases: 1,
      pendingOutbox: [expect.objectContaining({ deliveryId: "delivery-recover", state: "PENDING", attempt: 1 })],
    });
    await expect(restarted.leasePendingOutbox({ now, leaseId: "worker-new", leaseMs: 100 })).resolves.toEqual([
      expect.objectContaining({
        deliveryId: "delivery-recover",
        state: "LEASED",
        dispatchLeaseId: "worker-new",
        attempt: 2,
      }),
    ]);
    await expect(restarted.markOutboxSent({
      deliveryId: "delivery-recover",
      leaseId: "worker-new",
      now: now + 1,
    })).resolves.toMatchObject({ state: "SENT_AWAITING_RECEIPT" });
    await expect(restarted.acknowledgeOutbox({
      deliveryId: "delivery-recover",
      now: now + 1,
      receiptState: "stored",
    })).resolves.toMatchObject({
      state: "DELIVERED",
      receiptState: "stored",
    });
  });

  it("moves uncertain expired worker leases to recovery-required unless external work is idempotent", async () => {
    let now = 55_000;
    const filename = await databasePath();
    const beforeCrash = openStore(filename, () => now);
    await beforeCrash.putExecutionTask({
      meshId: "msh-test",
      taskId: "task-uncertain",
      state: "RUNNING",
      workerLeaseId: "worker-old",
      workerFence: 3,
      workerLeaseExpiresAt: now + 10,
      updatedAt: now,
      retainedUntil: now + 60_000,
    });
    await beforeCrash.putExecutionTask({
      meshId: "msh-test",
      taskId: "task-idempotent",
      state: "RUNNING",
      workerLeaseId: "worker-old",
      workerFence: 4,
      workerLeaseExpiresAt: now + 10,
      externalIdempotencyKey: "external-order-42",
      updatedAt: now,
      retainedUntil: now + 60_000,
    });
    closeForCrash(beforeCrash);

    now += 11;
    const restarted = openStore(filename, () => now);
    await expect(restarted.recover(now)).resolves.toMatchObject({
      reconciledWorkerLeases: expect.arrayContaining([
        expect.objectContaining({ taskId: "task-uncertain", state: "RECOVERY_REQUIRED" }),
        expect.objectContaining({ taskId: "task-idempotent", state: "QUEUED" }),
      ]),
    });
    await expect(restarted.getExecutionTask("msh-test", "task-uncertain")).resolves.toMatchObject({ state: "RECOVERY_REQUIRED" });
    await expect(restarted.getExecutionTask("msh-test", "task-uncertain")).resolves.not.toHaveProperty("workerLeaseId");
    await expect(restarted.getExecutionTask("msh-test", "task-idempotent")).resolves.toMatchObject({ state: "QUEUED" });
    await expect(restarted.getExecutionTask("msh-test", "task-idempotent")).resolves.not.toHaveProperty("workerLeaseId");
  });
});

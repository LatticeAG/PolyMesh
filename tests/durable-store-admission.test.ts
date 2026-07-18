import { describe, expect, it } from "vitest";

import {
  InMemoryDurableStore,
  SqliteDurableStore,
  type DurableAgentInstance,
  type DurableSession,
  type DurableStore,
  type ExecutionTaskRecord,
  type InboxRecord,
  type OutboxRecord,
  type PersistExecutorAdmissionInput,
  type TaskEventRecord,
} from "../packages/broker/src/durable-store.js";
import { HealthState } from "../packages/broker/src/routing.js";

const now = 200_000;
const retention = 24 * 60 * 60 * 1_000;

function executorInbox(overrides: Partial<InboxRecord> = {}): InboxRecord {
  return {
    scope: "executor",
    meshId: "msh-executor",
    sourcePrincipalId: "principal:caller",
    sourceAgentId: "com.example.caller",
    sourceInstanceId: "caller-a",
    targetAgentId: "com.example.executor",
    targetInstanceId: "executor-a",
    idempotencyKey: "delivery:one",
    semanticFingerprint: "semantic:one",
    messageId: "message:one",
    envelope: { type: "task.submit", task_id: "task-executor" },
    createdAt: now,
    expiresAt: now + retention,
    ...overrides,
  };
}

function executionTask(overrides: Partial<ExecutionTaskRecord> = {}): ExecutionTaskRecord {
  return {
    meshId: "msh-executor",
    taskId: "task-executor",
    state: "QUEUED",
    updatedAt: now,
    retainedUntil: now + retention,
    ...overrides,
  };
}

function admissionEvent(overrides: Partial<TaskEventRecord> = {}): TaskEventRecord {
  return {
    meshId: "msh-executor",
    taskId: "task-executor",
    eventSeq: 1,
    event: { type: "task.accepted", task_id: "task-executor", event_seq: 1 },
    createdAt: now,
    ...overrides,
  };
}

function lifecycleOutbox(overrides: Partial<OutboxRecord> = {}): OutboxRecord {
  return {
    deliveryId: "delivery:accepted",
    meshId: "msh-executor",
    targetAgentId: "com.example.caller",
    targetInstanceId: "caller-a",
    envelope: { type: "task.accepted", task_id: "task-executor", event_seq: 1 },
    state: "PENDING",
    attempt: 0,
    createdAt: now,
    updatedAt: now,
    expiresAt: now + 60_000,
    ...overrides,
  };
}

function executorAdmission(overrides: Partial<PersistExecutorAdmissionInput> = {}): PersistExecutorAdmissionInput {
  return {
    taskId: "task-executor",
    inbox: executorInbox(),
    executionTask: executionTask(),
    event: admissionEvent(),
    outbox: lifecycleOutbox(),
    ...overrides,
  };
}

function sourceInstance(overrides: Partial<DurableAgentInstance> = {}): DurableAgentInstance {
  return {
    meshId: "msh-executor",
    agentId: "com.example.caller",
    instanceId: "caller-a",
    principalId: "principal:caller",
    sessionId: "caller-session-one",
    leaseId: "caller-lease-one",
    health: HealthState.HEALTHY,
    registrationFence: 1,
    sessionFence: 1,
    registeredAt: now,
    updatedAt: now,
    expiresAt: now + 60_000,
    ...overrides,
  };
}

function sourceSession(overrides: Partial<DurableSession> = {}): DurableSession {
  return {
    sessionId: "caller-session-one",
    ownerBrokerNodeId: "broker-a",
    sessionFence: 1,
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
  describe(`${name} durable executor admission`, () => {
    it("commits executor inbox, execution state, event one, and lifecycle outbox as one fact", async () => {
      const store = createStore();
      try {
        const input = executorAdmission();
        await expect(store.persistExecutorAdmission(input)).resolves.toMatchObject({
          disposition: "stored",
          inbox: { outboxDeliveryId: "delivery:accepted", targetInstanceId: "executor-a" },
          executionTask: { state: "QUEUED" },
          event: { eventSeq: 1 },
          outbox: { deliveryId: "delivery:accepted", state: "PENDING" },
        });
        await expect(store.getInbox({
          scope: "executor",
          meshId: "msh-executor",
          sourcePrincipalId: "principal:caller",
          targetAgentId: "com.example.executor",
          targetInstanceId: "executor-a",
          idempotencyKey: "delivery:one",
        })).resolves.toMatchObject({ outboxDeliveryId: "delivery:accepted" });
        await expect(store.getExecutionTask("msh-executor", "task-executor")).resolves.toMatchObject({ state: "QUEUED" });
        await expect(store.listTaskEvents("msh-executor", "task-executor")).resolves.toEqual([
          expect.objectContaining({ eventSeq: 1 }),
        ]);
        await expect(store.getOutbox("delivery:accepted")).resolves.toMatchObject({ state: "PENDING" });

        await expect(store.persistExecutorAdmission(input)).resolves.toMatchObject({ disposition: "duplicate" });
        await expect(store.persistExecutorAdmission(executorAdmission({
          inbox: executorInbox({ semanticFingerprint: "semantic:conflict" }),
        }))).resolves.toMatchObject({
          disposition: "conflict",
          code: "PMX.DELIVERY.IDEMPOTENCY_CONFLICT",
        });

        const invalid = executorAdmission({
          taskId: "task-invalid",
          inbox: executorInbox({ idempotencyKey: "delivery:invalid" }),
        });
        await expect(store.persistExecutorAdmission(invalid)).rejects.toThrow("one initial task admission");
        await expect(store.getInbox({
          scope: "executor",
          meshId: "msh-executor",
          sourcePrincipalId: "principal:caller",
          targetAgentId: "com.example.executor",
          targetInstanceId: "executor-a",
          idempotencyKey: "delivery:invalid",
        })).resolves.toBeUndefined();

        await store.enqueueOutbox(lifecycleOutbox({
          deliveryId: "delivery:atomic-conflict",
          envelope: { type: "task.rejected", task_id: "unrelated", event_seq: 1 },
        }));
        const collisionTaskId = "task-atomic-conflict";
        await expect(store.persistExecutorAdmission(executorAdmission({
          taskId: collisionTaskId,
          inbox: executorInbox({
            idempotencyKey: "delivery:atomic-conflict",
            messageId: "message:atomic-conflict",
            envelope: { type: "task.submit", task_id: collisionTaskId },
          }),
          executionTask: executionTask({ taskId: collisionTaskId }),
          event: admissionEvent({
            taskId: collisionTaskId,
            event: { type: "task.accepted", task_id: collisionTaskId, event_seq: 1 },
          }),
          outbox: lifecycleOutbox({
            deliveryId: "delivery:atomic-conflict",
            envelope: { type: "task.accepted", task_id: collisionTaskId, event_seq: 1 },
          }),
        }))).resolves.toMatchObject({ disposition: "conflict", code: "PMX.TASK.ID_CONFLICT" });
        await expect(store.getExecutionTask("msh-executor", collisionTaskId)).resolves.toBeUndefined();
        await expect(store.getInbox({
          scope: "executor",
          meshId: "msh-executor",
          sourcePrincipalId: "principal:caller",
          targetAgentId: "com.example.executor",
          targetInstanceId: "executor-a",
          idempotencyKey: "delivery:atomic-conflict",
        })).resolves.toBeUndefined();
      } finally {
        store.close?.();
      }
    });

    it("requires executor dedupe to name the physical target instance", async () => {
      const store = createStore();
      try {
        await expect(store.putInbox(executorInbox({ targetInstanceId: undefined }))).rejects.toThrow("physical targetInstanceId");
        await expect(store.getInbox({
          scope: "executor",
          meshId: "msh-executor",
          sourcePrincipalId: "principal:caller",
          targetAgentId: "com.example.executor",
          idempotencyKey: "delivery:one",
        })).rejects.toThrow("physical targetInstanceId");
      } finally {
        store.close?.();
      }
    });

    it("rejects stale worker writes after recovery hands work to a newer fence", async () => {
      const store = createStore();
      try {
        await store.putExecutionTask(executionTask({
          taskId: "task-worker",
          state: "RUNNING",
          workerLeaseId: "worker-old",
          workerFence: 3,
          workerLeaseExpiresAt: now + 10,
        }));
        await store.reconcileExpiredWorkerLeases(now + 11);
        await expect(store.getExecutionTask("msh-executor", "task-worker")).resolves.toMatchObject({
          state: "RECOVERY_REQUIRED",
          workerFence: 3,
        });

        const replacement = executionTask({
          taskId: "task-worker",
          state: "RUNNING",
          workerLeaseId: "worker-new",
          workerFence: 4,
          workerLeaseExpiresAt: now + 100,
          updatedAt: now + 12,
          retainedUntil: now + retention,
        });
        await expect(store.transitionExecutionTask({
          meshId: "msh-executor",
          taskId: "task-worker",
          expectedWorkerFence: 3,
          expectedWorkerLeaseId: null,
          expectedStates: ["RECOVERY_REQUIRED"],
          next: replacement,
        })).resolves.toMatchObject({ workerLeaseId: "worker-new", workerFence: 4 });

        await expect(store.transitionExecutionTask({
          meshId: "msh-executor",
          taskId: "task-worker",
          expectedWorkerFence: 3,
          expectedWorkerLeaseId: "worker-old",
          next: executionTask({
            taskId: "task-worker",
            state: "COMPLETED",
            workerFence: 3,
            terminalAt: now + 13,
            updatedAt: now + 13,
            retainedUntil: now + retention,
          }),
        })).resolves.toBeUndefined();

        const terminal = executionTask({
          taskId: "task-worker",
          state: "COMPLETED",
          workerFence: 4,
          terminalAt: now + 14,
          updatedAt: now + 14,
          retainedUntil: now + retention,
        });
        await expect(store.transitionExecutionTask({
          meshId: "msh-executor",
          taskId: "task-worker",
          expectedWorkerFence: 4,
          expectedWorkerLeaseId: "worker-new",
          next: terminal,
        })).resolves.toMatchObject({ terminalAt: now + 14 });
        await expect(store.transitionExecutionTask({
          meshId: "msh-executor",
          taskId: "task-worker",
          expectedWorkerFence: 4,
          expectedWorkerLeaseId: null,
          next: terminal,
        })).resolves.toBeUndefined();
      } finally {
        store.close?.();
      }
    });

    it("releases only its current unsent dispatch lease and keeps sent rows fenced", async () => {
      const store = createStore();
      try {
        const pending = lifecycleOutbox({ deliveryId: "delivery:lease" });
        await store.enqueueOutbox(pending);
        await store.leasePendingOutbox({ now, leaseId: "dispatch-one", leaseMs: 100 });
        await expect(store.releaseOutboxLease({
          deliveryId: "delivery:lease",
          leaseId: "dispatch-stale",
          now: now + 1,
        })).resolves.toBeUndefined();
        await expect(store.releaseOutboxLease({
          deliveryId: "delivery:lease",
          leaseId: "dispatch-one",
          now: now + 2,
        })).resolves.toMatchObject({ state: "PENDING" });
        await store.leasePendingOutbox({ now: now + 2, leaseId: "dispatch-two", leaseMs: 100 });
        await store.markOutboxSent({ deliveryId: "delivery:lease", leaseId: "dispatch-two", now: now + 3 });
        await expect(store.releaseOutboxLease({
          deliveryId: "delivery:lease",
          leaseId: "dispatch-two",
          now: now + 4,
        })).resolves.toBeUndefined();
      } finally {
        store.close?.();
      }
    });

    it("validates optional source session fencing inside the ingress transaction", async () => {
      const store = createStore();
      try {
        if (!store.upsertRegistration) throw new Error("test store lacks atomic registration support");
        await store.upsertRegistration({ instance: sourceInstance(), session: sourceSession() });
        const validInbox = executorInbox({
          scope: "ingress",
          targetInstanceId: undefined,
          idempotencyKey: "ingress:current",
          selectedInstanceId: "executor-a",
        });
        await expect(store.persistIngress({
          inbox: validInbox,
          sourceFence: { registrationFence: 1, sessionFence: 1, sessionId: "caller-session-one" },
        })).resolves.toMatchObject({ disposition: "stored" });

        await store.upsertRegistration({
          instance: sourceInstance({
            sessionId: "caller-session-two",
            leaseId: "caller-lease-two",
            registrationFence: 2,
            sessionFence: 2,
            updatedAt: now + 1,
            expiresAt: now + 60_001,
          }),
          session: sourceSession({
            sessionId: "caller-session-two",
            sessionFence: 2,
            updatedAt: now + 1,
            expiresAt: now + 60_001,
          }),
        });
        const staleInbox = { ...validInbox, idempotencyKey: "ingress:stale", messageId: "message:stale", createdAt: now + 2 };
        await expect(store.persistIngress({
          inbox: staleInbox,
          sourceFence: { registrationFence: 1, sessionFence: 1, sessionId: "caller-session-one" },
        })).resolves.toMatchObject({ disposition: "conflict", code: "STALE_FENCE" });
        await expect(store.getInbox({
          scope: "ingress",
          meshId: "msh-executor",
          sourcePrincipalId: "principal:caller",
          targetAgentId: "com.example.executor",
          idempotencyKey: "ingress:stale",
        })).resolves.toBeUndefined();
      } finally {
        store.close?.();
      }
    });

    it("rejects a conflicting duplicate delivery id in both storage backends", async () => {
      const store = createStore();
      try {
        await store.enqueueOutbox(lifecycleOutbox({ deliveryId: "delivery:conflict" }));
        await expect(store.enqueueOutbox(lifecycleOutbox({
          deliveryId: "delivery:conflict",
          envelope: { type: "task.rejected", task_id: "task-executor", event_seq: 1 },
        }))).rejects.toThrow("delivery_id");
      } finally {
        store.close?.();
      }
    });
  });
}

/**
 * Durable v0.2 broker facts.
 *
 * Socket objects deliberately do not appear in this module.  The database
 * contains only facts that survive a broker restart; a DurableRegistry keeps
 * the matching process-local connection index separately.
 */

import Database from "better-sqlite3";

import type { JsonObject } from "./protocol.js";
import { HealthState, type HealthState as InstanceHealth } from "./routing.js";

export type DurableClock = () => number;

export type OutboxState =
  | "PENDING"
  | "LEASED"
  | "SENT_AWAITING_RECEIPT"
  | "DELIVERED"
  | "EXPIRED"
  | "DEAD_LETTER";

export interface DurableAgentInstance {
  meshId: string;
  agentId: string;
  instanceId: string;
  principalId: string;
  card?: JsonObject;
  cardDigest?: string;
  cardRevision?: number;
  sessionId?: string;
  leaseId: string;
  health: InstanceHealth;
  capacity?: number;
  capacityWeight?: number;
  registrationFence: number;
  sessionFence: number;
  registeredAt: number;
  updatedAt: number;
  expiresAt: number;
  cardExpiresAt?: number;
}

export interface DurableSession {
  sessionId: string;
  ownerBrokerNodeId: string;
  sessionFence: number;
  createdAt: number;
  updatedAt: number;
  expiresAt: number;
}

/**
 * Atomically stored registration/session facts.  The session member is
 * optional because loopback/local registrations may not allocate a durable
 * broker-node session, but when it is present it must exactly bind the
 * instance's session id and fence.
 */
export interface DurableRegistration {
  instance: DurableAgentInstance;
  session?: DurableSession;
}

/**
 * Broker ingress and executor admission share this row shape.  The `scope`
 * prevents a logical ingress retry from colliding with executor-side physical
 * inbox dedupe while keeping both durable scopes in one audited table.
 */
export interface InboxRecord {
  scope: "ingress" | "executor";
  meshId: string;
  sourcePrincipalId: string;
  sourceAgentId: string;
  sourceInstanceId: string;
  targetAgentId: string;
  /** Empty/undefined means the requested logical target for ingress. */
  targetInstanceId?: string;
  idempotencyKey: string;
  semanticFingerprint: string;
  messageId: string;
  envelope: JsonObject;
  selectedInstanceId?: string;
  createdAt: number;
  expiresAt: number;
  /** Outbox row created as part of an ingress transaction, if any. */
  outboxDeliveryId?: string;
}

export interface DurableTaskRoute {
  meshId: string;
  taskId: string;
  ownerPrincipalId: string;
  ownerAgentId: string;
  ownerInstanceId: string;
  ownerSessionId?: string;
  executorPrincipalId: string;
  executorAgentId: string;
  executorInstanceId: string;
  executorSessionId?: string;
  immutableFingerprint: string;
  deadlineAt: number;
  routeFence: number;
  state: string;
  createdAt: number;
  updatedAt: number;
  retainedUntil: number;
}

export interface ExecutionTaskRecord {
  meshId: string;
  taskId: string;
  state: string;
  workerLeaseId?: string;
  workerFence?: number;
  workerLeaseExpiresAt?: number;
  cancellationRequestedAt?: number;
  terminalAt?: number;
  externalIdempotencyKey?: string;
  updatedAt: number;
  retainedUntil: number;
}

export interface TaskEventRecord {
  meshId: string;
  taskId: string;
  eventSeq: number;
  event: JsonObject;
  createdAt: number;
}

/**
 * Compare-and-swap input for a worker-owned execution transition.  A worker
 * must present both values it was leased; `null` explicitly means that the
 * task is currently unleased.  This is intentionally not optional: an old
 * worker must never be able to update a task merely by knowing its task id.
 */
export interface FencedExecutionTaskTransition {
  meshId: string;
  taskId: string;
  expectedWorkerFence: number | null;
  expectedWorkerLeaseId: string | null;
  /** Optional state precondition for coordinator-owned transitions. */
  expectedStates?: readonly string[];
  next: ExecutionTaskRecord;
}

export interface OutboxRecord {
  deliveryId: string;
  meshId: string;
  targetAgentId: string;
  targetInstanceId?: string;
  envelope: JsonObject;
  state: OutboxState;
  dispatchLeaseId?: string;
  dispatchLeaseExpiresAt?: number;
  attempt: number;
  receiptState?: "stored" | "delivered";
  createdAt: number;
  updatedAt: number;
  expiresAt: number;
}

export interface CancellationTombstone {
  meshId: string;
  taskId: string;
  ownerPrincipalId: string;
  createdAt: number;
  expiresAt: number;
}

export interface RegistryStore {
  upsertInstance(record: DurableAgentInstance): Promise<DurableAgentInstance>;
  /**
   * Implementations that persist both tables should provide this operation.
   * It prevents a crash from publishing an instance pointing at a session
   * row that failed its fence CAS (or was never written).  It is optional so
   * existing remote RegistryStore adapters remain source-compatible.
   */
  upsertRegistration?(record: DurableRegistration): Promise<DurableRegistration>;
  getInstance(meshId: string, agentId: string, instanceId: string): Promise<DurableAgentInstance | undefined>;
  listInstances(input?: { meshId?: string; agentId?: string; now?: number }): Promise<DurableAgentInstance[]>;
  renewInstance(input: {
    meshId: string;
    agentId: string;
    instanceId: string;
    registrationFence: number;
    sessionFence: number;
    expiresAt: number;
    health?: InstanceHealth;
    updatedAt?: number;
  }): Promise<DurableAgentInstance | undefined>;
  /** Relay-owned capacity changes use the active registration/session fence. */
  updateInstanceCapacity?(input: {
    meshId: string;
    agentId: string;
    instanceId: string;
    registrationFence: number;
    sessionFence: number;
    capacity?: number;
    capacityWeight?: number;
    updatedAt: number;
  }): Promise<DurableAgentInstance | undefined>;
  removeInstance(input: {
    meshId: string;
    agentId: string;
    instanceId: string;
    registrationFence: number;
    sessionFence: number;
  }): Promise<boolean>;
  expireInstances(now: number): Promise<DurableAgentInstance[]>;
  upsertSession(record: DurableSession): Promise<DurableSession>;
  getSession(sessionId: string): Promise<DurableSession | undefined>;
}

export interface TaskRouteStore {
  putRoute(record: DurableTaskRoute): Promise<DurableTaskRoute>;
  getRoute(meshId: string, taskId: string): Promise<DurableTaskRoute | undefined>;
  updateRouteState(input: {
    meshId: string;
    taskId: string;
    routeFence: number;
    state: string;
    updatedAt: number;
  }): Promise<DurableTaskRoute | undefined>;
  putExecutionTask(record: ExecutionTaskRecord): Promise<ExecutionTaskRecord>;
  getExecutionTask(meshId: string, taskId: string): Promise<ExecutionTaskRecord | undefined>;
  /**
   * Fenced task mutation.  It fails closed when an old worker lease/fence, a
   * terminal task, or an unexpected state is observed.
   */
  transitionExecutionTask(input: FencedExecutionTaskTransition): Promise<ExecutionTaskRecord | undefined>;
  /** Never blindly rerun uncertain external work after its worker lease expires. */
  reconcileExpiredWorkerLeases(now: number): Promise<ExecutionTaskRecord[]>;
  appendTaskEvent(record: TaskEventRecord): Promise<"stored" | "duplicate" | "conflict">;
  listTaskEvents(meshId: string, taskId: string): Promise<TaskEventRecord[]>;
  putCancellationTombstone(record: CancellationTombstone): Promise<CancellationTombstone>;
  getCancellationTombstone(meshId: string, taskId: string): Promise<CancellationTombstone | undefined>;
}

export interface InboxStore {
  putInbox(record: InboxRecord): Promise<InboxPutResult>;
  getInbox(input: InboxIdentity): Promise<InboxRecord | undefined>;
}

export interface OutboxStore {
  enqueueOutbox(record: OutboxRecord): Promise<OutboxRecord>;
  getOutbox(deliveryId: string): Promise<OutboxRecord | undefined>;
  leasePendingOutbox(input: { now: number; leaseId: string; leaseMs: number; limit?: number }): Promise<OutboxRecord[]>;
  markOutboxSent(input: { deliveryId: string; leaseId: string; now: number }): Promise<OutboxRecord | undefined>;
  /** Return a current, unsent lease to PENDING without touching sent rows. */
  releaseOutboxLease(input: { deliveryId: string; leaseId: string; now: number }): Promise<OutboxRecord | undefined>;
  acknowledgeOutbox(input: { deliveryId: string; now: number; receiptState?: "stored" | "delivered" }): Promise<OutboxRecord | undefined>;
  reclaimExpiredDispatchLeases(now: number): Promise<number>;
  listDispatchableOutbox(now: number, limit?: number): Promise<OutboxRecord[]>;
}

export interface InboxIdentity {
  scope: "ingress" | "executor";
  meshId: string;
  sourcePrincipalId: string;
  targetAgentId: string;
  targetInstanceId?: string;
  idempotencyKey: string;
}

export type InboxPutResult =
  | { disposition: "stored"; record: InboxRecord }
  | { disposition: "duplicate"; record: InboxRecord }
  | { disposition: "conflict"; record: InboxRecord };

export interface PersistIngressInput {
  inbox: InboxRecord;
  /** A route is persisted with ingress so retries cannot select a sibling. */
  route?: DurableTaskRoute;
  /** Immutable target delivery persisted before a durable stored receipt. */
  outbox?: OutboxRecord;
  /**
   * Optional source-side registration/session CAS.  Brokers pass this after
   * authenticating a v0.2 peer so an old replaced session cannot commit a
   * new durable ingress record after it has lost its fence.
   */
  sourceFence?: PersistIngressSourceFence;
}

export interface PersistIngressSourceFence {
  registrationFence: number;
  sessionFence: number;
  sessionId: string;
}

export type PersistIngressResult =
  | {
    disposition: "stored";
    inbox: InboxRecord;
    route?: DurableTaskRoute;
    outbox?: OutboxRecord;
  }
  | {
    disposition: "duplicate";
    inbox: InboxRecord;
    route?: DurableTaskRoute;
    outbox?: OutboxRecord;
  }
  | {
    disposition: "conflict";
    code: "PMX.DELIVERY.IDEMPOTENCY_CONFLICT" | "PMX.TASK.ID_CONFLICT" | "STALE_FENCE";
    inbox: InboxRecord;
    route?: DurableTaskRoute;
  };

/**
 * Executor admission is the recipient-side transactional inbox/outbox
 * boundary.  `taskId` ties the durable inbox, execution state, canonical
 * admission event, and lifecycle outbox row together without relying on an
 * untyped envelope body.
 */
export interface PersistExecutorAdmissionInput {
  taskId: string;
  inbox: InboxRecord;
  executionTask: ExecutionTaskRecord;
  event: TaskEventRecord;
  outbox: OutboxRecord;
}

export type PersistExecutorAdmissionResult =
  | {
    disposition: "stored" | "duplicate";
    inbox: InboxRecord;
    executionTask: ExecutionTaskRecord;
    event: TaskEventRecord;
    outbox: OutboxRecord;
  }
  | {
    disposition: "conflict";
    code: "PMX.DELIVERY.IDEMPOTENCY_CONFLICT" | "PMX.TASK.ID_CONFLICT";
    inbox: InboxRecord;
    executionTask?: ExecutionTaskRecord;
    event?: TaskEventRecord;
    outbox?: OutboxRecord;
  };

export interface RecoveryReport {
  reclaimedDispatchLeases: number;
  expiredInstances: DurableAgentInstance[];
  reconciledWorkerLeases: ExecutionTaskRecord[];
  pendingOutbox: OutboxRecord[];
}

/** All durable storage surfaces used by the Phase 1 broker. */
export interface DurableStore extends RegistryStore, TaskRouteStore, InboxStore, OutboxStore {
  /**
   * A transaction callback must be synchronous. The public methods are async
   * to permit PostgreSQL/remote implementations, but SQLite cannot safely
   * keep a `BEGIN IMMEDIATE` transaction open across an arbitrary await.
   */
  transaction<T>(operation: (store: DurableStore) => T): Promise<T>;
  persistIngress(input: PersistIngressInput): Promise<PersistIngressResult>;
  persistExecutorAdmission(input: PersistExecutorAdmissionInput): Promise<PersistExecutorAdmissionResult>;
  recover(now?: number): Promise<RecoveryReport>;
  close?(): void;
}

export interface SqliteDurableStoreOptions {
  filename?: string;
  clock?: DurableClock;
}

const OUTBOX_STATES = new Set<OutboxState>([
  "PENDING", "LEASED", "SENT_AWAITING_RECEIPT", "DELIVERED", "EXPIRED", "DEAD_LETTER",
]);

const MIN_RETENTION_MS = 24 * 60 * 60 * 1_000;

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function json(value: JsonObject | undefined): string | null {
  return value === undefined ? null : JSON.stringify(value);
}

function parseJson(value: unknown): JsonObject | undefined {
  if (typeof value !== "string") return undefined;
  const parsed = JSON.parse(value) as unknown;
  return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) ? parsed as JsonObject : undefined;
}

function asString(value: unknown, name: string, allowEmpty = false): string {
  if (typeof value !== "string" || (!allowEmpty && value.length === 0)) throw new TypeError(`${name} must be a non-empty string`);
  return value;
}

function asTimestamp(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) throw new TypeError(`${name} must be a non-negative finite timestamp`);
  return value;
}

function asFence(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw new TypeError(`${name} must be a non-negative safe integer`);
  return value;
}

function normalizeInstance(record: DurableAgentInstance): DurableAgentInstance {
  const health = record.health;
  if (!Object.values(HealthState).includes(health)) throw new TypeError("health is invalid");
  const result: DurableAgentInstance = {
    meshId: asString(record.meshId, "meshId"),
    agentId: asString(record.agentId, "agentId"),
    instanceId: asString(record.instanceId, "instanceId"),
    principalId: asString(record.principalId, "principalId"),
    leaseId: asString(record.leaseId, "leaseId"),
    health,
    registrationFence: asFence(record.registrationFence, "registrationFence"),
    sessionFence: asFence(record.sessionFence, "sessionFence"),
    registeredAt: asTimestamp(record.registeredAt, "registeredAt"),
    updatedAt: asTimestamp(record.updatedAt, "updatedAt"),
    expiresAt: asTimestamp(record.expiresAt, "expiresAt"),
  };
  if (record.card !== undefined) result.card = clone(record.card);
  if (record.cardDigest !== undefined) result.cardDigest = asString(record.cardDigest, "cardDigest");
  if (record.cardRevision !== undefined) result.cardRevision = asFence(record.cardRevision, "cardRevision");
  if (record.sessionId !== undefined) result.sessionId = asString(record.sessionId, "sessionId");
  if (record.capacity !== undefined) {
    if (!Number.isSafeInteger(record.capacity) || record.capacity < 0) throw new TypeError("capacity must be a non-negative safe integer");
    result.capacity = record.capacity;
  }
  if (record.capacityWeight !== undefined) {
    if (!Number.isFinite(record.capacityWeight) || record.capacityWeight <= 0) throw new TypeError("capacityWeight must be positive");
    result.capacityWeight = record.capacityWeight;
  }
  if (record.cardExpiresAt !== undefined) result.cardExpiresAt = asTimestamp(record.cardExpiresAt, "cardExpiresAt");
  return result;
}

function normalizeInbox(record: InboxRecord): InboxRecord {
  if (record.scope !== "ingress" && record.scope !== "executor") throw new TypeError("Inbox scope is invalid");
  const targetInstanceId = record.targetInstanceId ?? "";
  if (record.scope === "executor" && targetInstanceId === "") {
    throw new TypeError("Executor inbox records must name a physical targetInstanceId");
  }
  const createdAt = asTimestamp(record.createdAt, "createdAt");
  const expiresAt = Math.max(asTimestamp(record.expiresAt, "expiresAt"), createdAt + MIN_RETENTION_MS);
  const result: InboxRecord = {
    scope: record.scope,
    meshId: asString(record.meshId, "meshId"),
    sourcePrincipalId: asString(record.sourcePrincipalId, "sourcePrincipalId"),
    sourceAgentId: asString(record.sourceAgentId, "sourceAgentId"),
    sourceInstanceId: asString(record.sourceInstanceId, "sourceInstanceId"),
    targetAgentId: asString(record.targetAgentId, "targetAgentId"),
    targetInstanceId: targetInstanceId === "" ? undefined : asString(targetInstanceId, "targetInstanceId"),
    idempotencyKey: asString(record.idempotencyKey, "idempotencyKey"),
    semanticFingerprint: asString(record.semanticFingerprint, "semanticFingerprint"),
    messageId: asString(record.messageId, "messageId"),
    envelope: clone(record.envelope),
    createdAt,
    expiresAt,
  };
  if (record.selectedInstanceId !== undefined) result.selectedInstanceId = asString(record.selectedInstanceId, "selectedInstanceId");
  if (record.outboxDeliveryId !== undefined) result.outboxDeliveryId = asString(record.outboxDeliveryId, "outboxDeliveryId");
  return result;
}

function normalizeRoute(record: DurableTaskRoute): DurableTaskRoute {
  const result: DurableTaskRoute = {
    meshId: asString(record.meshId, "meshId"),
    taskId: asString(record.taskId, "taskId"),
    ownerPrincipalId: asString(record.ownerPrincipalId, "ownerPrincipalId"),
    ownerAgentId: asString(record.ownerAgentId, "ownerAgentId"),
    ownerInstanceId: asString(record.ownerInstanceId, "ownerInstanceId"),
    executorPrincipalId: asString(record.executorPrincipalId, "executorPrincipalId"),
    executorAgentId: asString(record.executorAgentId, "executorAgentId"),
    executorInstanceId: asString(record.executorInstanceId, "executorInstanceId"),
    immutableFingerprint: asString(record.immutableFingerprint, "immutableFingerprint"),
    deadlineAt: asTimestamp(record.deadlineAt, "deadlineAt"),
    routeFence: asFence(record.routeFence, "routeFence"),
    state: asString(record.state, "state"),
    createdAt: asTimestamp(record.createdAt, "createdAt"),
    updatedAt: asTimestamp(record.updatedAt, "updatedAt"),
    retainedUntil: Math.max(asTimestamp(record.retainedUntil, "retainedUntil"), record.deadlineAt + MIN_RETENTION_MS),
  };
  if (record.ownerSessionId !== undefined) result.ownerSessionId = asString(record.ownerSessionId, "ownerSessionId");
  if (record.executorSessionId !== undefined) result.executorSessionId = asString(record.executorSessionId, "executorSessionId");
  return result;
}

function normalizeOutbox(record: OutboxRecord): OutboxRecord {
  if (!OUTBOX_STATES.has(record.state)) throw new TypeError("Outbox state is invalid");
  const result: OutboxRecord = {
    deliveryId: asString(record.deliveryId, "deliveryId"),
    meshId: asString(record.meshId, "meshId"),
    targetAgentId: asString(record.targetAgentId, "targetAgentId"),
    envelope: clone(record.envelope),
    state: record.state,
    attempt: asFence(record.attempt, "attempt"),
    createdAt: asTimestamp(record.createdAt, "createdAt"),
    updatedAt: asTimestamp(record.updatedAt, "updatedAt"),
    expiresAt: asTimestamp(record.expiresAt, "expiresAt"),
  };
  if (record.targetInstanceId !== undefined) result.targetInstanceId = asString(record.targetInstanceId, "targetInstanceId");
  if (record.dispatchLeaseId !== undefined) result.dispatchLeaseId = asString(record.dispatchLeaseId, "dispatchLeaseId");
  if (record.dispatchLeaseExpiresAt !== undefined) result.dispatchLeaseExpiresAt = asTimestamp(record.dispatchLeaseExpiresAt, "dispatchLeaseExpiresAt");
  if (record.receiptState !== undefined) result.receiptState = record.receiptState;
  return result;
}

function normalizeExecutionTask(record: ExecutionTaskRecord): ExecutionTaskRecord {
  const updatedAt = asTimestamp(record.updatedAt, "updatedAt");
  const result: ExecutionTaskRecord = {
    meshId: asString(record.meshId, "meshId"),
    taskId: asString(record.taskId, "taskId"),
    state: asString(record.state, "state"),
    updatedAt,
    retainedUntil: Math.max(asTimestamp(record.retainedUntil, "retainedUntil"), updatedAt + MIN_RETENTION_MS),
  };
  if (record.workerLeaseId !== undefined) result.workerLeaseId = asString(record.workerLeaseId, "workerLeaseId");
  if (record.workerFence !== undefined) result.workerFence = asFence(record.workerFence, "workerFence");
  if (record.workerLeaseExpiresAt !== undefined) result.workerLeaseExpiresAt = asTimestamp(record.workerLeaseExpiresAt, "workerLeaseExpiresAt");
  if (record.cancellationRequestedAt !== undefined) result.cancellationRequestedAt = asTimestamp(record.cancellationRequestedAt, "cancellationRequestedAt");
  if (record.terminalAt !== undefined) result.terminalAt = asTimestamp(record.terminalAt, "terminalAt");
  if (record.externalIdempotencyKey !== undefined) result.externalIdempotencyKey = asString(record.externalIdempotencyKey, "externalIdempotencyKey");
  return result;
}

function normalizeTaskEvent(record: TaskEventRecord): TaskEventRecord {
  const eventSeq = asFence(record.eventSeq, "eventSeq");
  if (eventSeq < 1) throw new TypeError("eventSeq must be at least one");
  return {
    meshId: asString(record.meshId, "meshId"),
    taskId: asString(record.taskId, "taskId"),
    eventSeq,
    event: clone(record.event),
    createdAt: asTimestamp(record.createdAt, "createdAt"),
  };
}

function normalizeSourceFence(record: PersistIngressSourceFence): PersistIngressSourceFence {
  return {
    registrationFence: asFence(record.registrationFence, "sourceFence.registrationFence"),
    sessionFence: asFence(record.sessionFence, "sourceFence.sessionFence"),
    sessionId: asString(record.sessionId, "sourceFence.sessionId"),
  };
}

function sourceFenceMatches(
  instance: DurableAgentInstance | undefined,
  session: DurableSession | undefined,
  inbox: InboxRecord,
  fence: PersistIngressSourceFence,
): boolean {
  return instance !== undefined && session !== undefined &&
    instance.meshId === inbox.meshId &&
    instance.agentId === inbox.sourceAgentId &&
    instance.instanceId === inbox.sourceInstanceId &&
    instance.registrationFence === fence.registrationFence &&
    instance.sessionFence === fence.sessionFence &&
    instance.sessionId === fence.sessionId &&
    instance.expiresAt > inbox.createdAt &&
    instance.health !== HealthState.OFFLINE &&
    session.sessionId === fence.sessionId &&
    session.sessionFence === fence.sessionFence &&
    session.expiresAt > inbox.createdAt;
}

function sameExecutionTask(left: ExecutionTaskRecord, right: ExecutionTaskRecord): boolean {
  return left.meshId === right.meshId &&
    left.taskId === right.taskId &&
    left.state === right.state &&
    left.workerLeaseId === right.workerLeaseId &&
    left.workerFence === right.workerFence &&
    left.workerLeaseExpiresAt === right.workerLeaseExpiresAt &&
    left.cancellationRequestedAt === right.cancellationRequestedAt &&
    left.terminalAt === right.terminalAt &&
    left.externalIdempotencyKey === right.externalIdempotencyKey &&
    left.updatedAt === right.updatedAt &&
    left.retainedUntil === right.retainedUntil;
}

function sameTaskEvent(left: TaskEventRecord, right: TaskEventRecord): boolean {
  return left.meshId === right.meshId && left.taskId === right.taskId && left.eventSeq === right.eventSeq &&
    left.createdAt === right.createdAt && JSON.stringify(left.event) === JSON.stringify(right.event);
}

function validFencedExecutionTransition(
  current: ExecutionTaskRecord,
  input: FencedExecutionTaskTransition,
  next: ExecutionTaskRecord,
): boolean {
  if (current.meshId !== input.meshId || current.taskId !== input.taskId ||
    next.meshId !== input.meshId || next.taskId !== input.taskId || current.terminalAt !== undefined) {
    return false;
  }
  if ((current.workerFence ?? null) !== input.expectedWorkerFence ||
    (current.workerLeaseId ?? null) !== input.expectedWorkerLeaseId) {
    return false;
  }
  if (input.expectedStates !== undefined &&
    (input.expectedStates.length === 0 || !input.expectedStates.includes(current.state))) {
    return false;
  }
  const currentFence = current.workerFence;
  const nextFence = next.workerFence;
  if (currentFence !== undefined && nextFence !== undefined && nextFence < currentFence) return false;
  // Once a lease has expired/recovery cleared its id, a new worker must carry
  // a strictly higher fence. This is what makes a late old worker harmless.
  if (current.workerLeaseId === undefined && next.workerLeaseId !== undefined &&
    (nextFence === undefined || (currentFence !== undefined && nextFence <= currentFence))) {
    return false;
  }
  // A worker may finish/release its own lease, but cannot silently swap it for
  // another worker under the same task transition.
  if (current.workerLeaseId !== undefined && next.workerLeaseId !== undefined &&
    next.workerLeaseId !== current.workerLeaseId) return false;
  return true;
}

interface NormalizedExecutorAdmission {
  taskId: string;
  inbox: InboxRecord;
  executionTask: ExecutionTaskRecord;
  event: TaskEventRecord;
  outbox: OutboxRecord;
}

function normalizeExecutorAdmission(input: PersistExecutorAdmissionInput): NormalizedExecutorAdmission {
  const taskId = asString(input.taskId, "taskId");
  const inbox = normalizeInbox(input.inbox);
  const executionTask = normalizeExecutionTask(input.executionTask);
  const event = normalizeTaskEvent(input.event);
  const outbox = normalizeOutbox(input.outbox);
  if (inbox.scope !== "executor") throw new TypeError("Executor admission requires an executor inbox record");
  if (executionTask.meshId !== inbox.meshId || executionTask.taskId !== taskId ||
    event.meshId !== inbox.meshId || event.taskId !== taskId || event.eventSeq !== 1 ||
    outbox.meshId !== inbox.meshId || outbox.state !== "PENDING") {
    throw new TypeError("Executor admission facts do not describe one initial task admission");
  }
  if (outbox.targetAgentId !== inbox.sourceAgentId || outbox.targetInstanceId !== inbox.sourceInstanceId) {
    throw new TypeError("Executor lifecycle outbox must target the physical task source");
  }
  if (inbox.outboxDeliveryId !== undefined && inbox.outboxDeliveryId !== outbox.deliveryId) {
    throw new TypeError("Executor inbox outboxDeliveryId must match its lifecycle outbox");
  }
  return {
    taskId,
    inbox: { ...inbox, outboxDeliveryId: outbox.deliveryId },
    executionTask,
    event,
    outbox,
  };
}

function inboxKey(record: InboxIdentity): string {
  if (record.scope === "executor" && (record.targetInstanceId ?? "") === "") {
    throw new TypeError("Executor inbox identities must name a physical targetInstanceId");
  }
  return JSON.stringify([
    record.scope,
    record.meshId,
    record.sourcePrincipalId,
    record.targetAgentId,
    record.targetInstanceId ?? "",
    record.idempotencyKey,
  ]);
}

function routeKey(meshId: string, taskId: string): string {
  return `${meshId}\0${taskId}`;
}

function taskEventKey(meshId: string, taskId: string, eventSeq: number): string {
  return `${meshId}\0${taskId}\0${eventSeq}`;
}

function instanceKey(record: Pick<DurableAgentInstance, "meshId" | "agentId" | "instanceId">): string {
  return `${record.meshId}\0${record.agentId}\0${record.instanceId}`;
}

function isThenable(value: unknown): value is PromiseLike<unknown> {
  return typeof value === "object" && value !== null && typeof (value as { then?: unknown }).then === "function";
}

function assertIngressTargets(inbox: InboxRecord, route: DurableTaskRoute | undefined, outbox: OutboxRecord | undefined): InboxRecord {
  if (route !== undefined && (
    route.meshId !== inbox.meshId ||
    route.ownerPrincipalId !== inbox.sourcePrincipalId ||
    route.ownerAgentId !== inbox.sourceAgentId ||
    route.ownerInstanceId !== inbox.sourceInstanceId ||
    route.executorAgentId !== inbox.targetAgentId
  )) {
    throw new TypeError("Ingress route owner and target must match the authenticated inbox scope");
  }
  const resolved = route === undefined
    ? inbox
    : { ...inbox, selectedInstanceId: route.executorInstanceId };
  if (inbox.selectedInstanceId !== undefined && route !== undefined && inbox.selectedInstanceId !== route.executorInstanceId) {
    throw new TypeError("Ingress selected instance must match its pinned route executor");
  }
  if (outbox && (
    outbox.meshId !== resolved.meshId ||
    outbox.targetAgentId !== resolved.targetAgentId ||
    outbox.targetInstanceId !== resolved.selectedInstanceId
  )) {
    throw new TypeError("Ingress outbox target must match the resolved inbox target");
  }
  return resolved;
}

/**
 * A duplicate task may create a fresh ingress/outbox correlation, but never a
 * fresh route.  Preserve both ends' sessions and the route fence so a retry
 * cannot turn a pinned task into delivery for a replacement session.
 */
function sameRoutePin(left: DurableTaskRoute, right: DurableTaskRoute): boolean {
  return left.routeFence === right.routeFence &&
    left.ownerPrincipalId === right.ownerPrincipalId &&
    left.ownerAgentId === right.ownerAgentId &&
    left.ownerInstanceId === right.ownerInstanceId &&
    (left.ownerSessionId ?? "") === (right.ownerSessionId ?? "") &&
    left.executorPrincipalId === right.executorPrincipalId &&
    left.executorAgentId === right.executorAgentId &&
    left.executorInstanceId === right.executorInstanceId &&
    (left.executorSessionId ?? "") === (right.executorSessionId ?? "");
}

function sameOutbox(left: OutboxRecord, right: OutboxRecord): boolean {
  return left.meshId === right.meshId &&
    left.targetAgentId === right.targetAgentId &&
    left.targetInstanceId === right.targetInstanceId &&
    JSON.stringify(left.envelope) === JSON.stringify(right.envelope);
}

class DurableStoreConflictError extends Error {
  constructor(readonly code: "IDENTITY_COLLISION" | "PMX.DELIVERY.IDEMPOTENCY_CONFLICT" | "STALE_FENCE", message: string) {
    super(message);
    this.name = "DurableStoreConflictError";
  }
}

function sameOptionalText(left: string | undefined, right: string | undefined): boolean {
  return (left ?? "") === (right ?? "");
}

/**
 * Registration writes are replacement operations, not heartbeats.  They
 * therefore require a strictly newer fence tuple.  In particular, an
 * equal-fence record must never refresh a lease/card/session row: a delayed
 * duplicate could otherwise overwrite facts installed by the current owner.
 * Heartbeats use `renewInstance`, which is an explicit equality-CAS path.
 */
function canApplyInstanceWrite(current: DurableAgentInstance | undefined, next: DurableAgentInstance): boolean {
  if (!current) return true;
  if (next.registrationFence < current.registrationFence) return false;
  if (next.registrationFence > current.registrationFence) {
    // A replacement registration always advances the session fence as well.
    return next.sessionFence > current.sessionFence;
  }
  // With one registration epoch, only the exact same session may advance its
  // session fence. This permits a fenced session rollover without allowing a
  // sibling/old session to mutate the registration.
  return sameOptionalText(next.sessionId, current.sessionId) && next.sessionFence > current.sessionFence;
}

/** Session records also require a strict fence advance; renewals are separate. */
function canApplySessionWrite(current: DurableSession | undefined, next: DurableSession): boolean {
  return current === undefined || next.sessionFence > current.sessionFence;
}

function assertRegistrationShape(registration: DurableRegistration): DurableRegistration {
  const instance = normalizeInstance(registration.instance);
  if (registration.session === undefined) return { instance };
  const session: DurableSession = {
    sessionId: asString(registration.session.sessionId, "sessionId"),
    ownerBrokerNodeId: asString(registration.session.ownerBrokerNodeId, "ownerBrokerNodeId"),
    sessionFence: asFence(registration.session.sessionFence, "sessionFence"),
    createdAt: asTimestamp(registration.session.createdAt, "createdAt"),
    updatedAt: asTimestamp(registration.session.updatedAt, "updatedAt"),
    expiresAt: asTimestamp(registration.session.expiresAt, "expiresAt"),
  };
  if (instance.sessionId !== session.sessionId || instance.sessionFence !== session.sessionFence) {
    throw new TypeError("Durable registration session must match the instance session id and fence");
  }
  return { instance, session };
}

/** In-memory fallback for tests and ephemeral local development. */
export class InMemoryDurableStore implements DurableStore {
  private readonly instances = new Map<string, DurableAgentInstance>();
  private readonly sessions = new Map<string, DurableSession>();
  private readonly inboxes = new Map<string, InboxRecord>();
  private readonly routes = new Map<string, DurableTaskRoute>();
  private readonly executionTasks = new Map<string, ExecutionTaskRecord>();
  private readonly taskEvents = new Map<string, TaskEventRecord>();
  private readonly outboxes = new Map<string, OutboxRecord>();
  private readonly cancellations = new Map<string, CancellationTombstone>();

  async transaction<T>(operation: (store: DurableStore) => T): Promise<T> {
    const snapshot = this.snapshot();
    try {
      const result = operation(this);
      if (isThenable(result)) throw new TypeError("In-memory durable transactions cannot cross an await");
      return result;
    } catch (error) {
      this.restore(snapshot);
      throw error;
    }
  }

  async upsertInstance(record: DurableAgentInstance): Promise<DurableAgentInstance> {
    const normalized = normalizeInstance(record);
    this.assertNoIdentityCollision(normalized);
    const key = instanceKey(normalized);
    const current = this.instances.get(key);
    if (!canApplyInstanceWrite(current, normalized)) return clone(current!);
    this.instances.set(key, clone(normalized));
    return clone(normalized);
  }

  /** Atomically apply a session CAS and its instance registration. */
  async upsertRegistration(registration: DurableRegistration): Promise<DurableRegistration> {
    const normalized = assertRegistrationShape(registration);
    const snapshot = this.snapshot();
    try {
      const instanceKeyValue = instanceKey(normalized.instance);
      const currentInstance = this.instances.get(instanceKeyValue);
      if (!canApplyInstanceWrite(currentInstance, normalized.instance)) {
        throw new DurableStoreConflictError("STALE_FENCE", "Registration/session fence is stale or conflicts with the active instance");
      }
      if (normalized.session !== undefined) {
        const currentSession = this.sessions.get(normalized.session.sessionId);
        if (!canApplySessionWrite(currentSession, normalized.session)) {
          throw new DurableStoreConflictError("STALE_FENCE", "Session fence is stale or belongs to another broker node");
        }
      }
      this.assertNoIdentityCollision(normalized.instance);
      if (normalized.session !== undefined) this.sessions.set(normalized.session.sessionId, clone(normalized.session));
      this.instances.set(instanceKeyValue, clone(normalized.instance));
      return {
        instance: clone(normalized.instance),
        ...(normalized.session === undefined ? {} : { session: clone(normalized.session) }),
      };
    } catch (error) {
      this.restore(snapshot);
      throw error;
    }
  }

  async getInstance(meshId: string, agentId: string, instanceId: string): Promise<DurableAgentInstance | undefined> {
    const record = this.instances.get(`${meshId}\0${agentId}\0${instanceId}`);
    return record === undefined ? undefined : clone(record);
  }

  async listInstances(input: { meshId?: string; agentId?: string; now?: number } = {}): Promise<DurableAgentInstance[]> {
    return [...this.instances.values()]
      .filter((record) => (input.meshId === undefined || record.meshId === input.meshId) &&
        (input.agentId === undefined || record.agentId === input.agentId) &&
        (input.now === undefined || record.expiresAt > input.now))
      .map(clone);
  }

  async renewInstance(input: {
    meshId: string; agentId: string; instanceId: string; registrationFence: number; sessionFence: number;
    expiresAt: number; health?: InstanceHealth; updatedAt?: number;
  }): Promise<DurableAgentInstance | undefined> {
    const key = `${input.meshId}\0${input.agentId}\0${input.instanceId}`;
    const current = this.instances.get(key);
    if (!current || current.registrationFence !== input.registrationFence || current.sessionFence !== input.sessionFence) return undefined;
    const updatedAt = asTimestamp(input.updatedAt ?? current.updatedAt, "updatedAt");
    // Same-fence health/renewal frames can be reordered.  Do not let an old
    // heartbeat shorten a current lease or overwrite a newer health state.
    if (updatedAt < current.updatedAt) return undefined;
    current.expiresAt = asTimestamp(input.expiresAt, "expiresAt");
    current.updatedAt = updatedAt;
    if (input.health !== undefined) current.health = input.health;
    return clone(current);
  }

  async updateInstanceCapacity(input: {
    meshId: string; agentId: string; instanceId: string; registrationFence: number; sessionFence: number;
    capacity?: number; capacityWeight?: number; updatedAt: number;
  }): Promise<DurableAgentInstance | undefined> {
    if (input.capacity === undefined && input.capacityWeight === undefined) throw new TypeError("At least one capacity field is required");
    const current = this.instances.get(`${input.meshId}\0${input.agentId}\0${input.instanceId}`);
    if (!current || current.registrationFence !== asFence(input.registrationFence, "registrationFence") ||
      current.sessionFence !== asFence(input.sessionFence, "sessionFence")) return undefined;
    const updatedAt = asTimestamp(input.updatedAt, "updatedAt");
    if (updatedAt < current.updatedAt) return undefined;
    if (input.capacity !== undefined) {
      if (!Number.isSafeInteger(input.capacity) || input.capacity < 0) throw new TypeError("capacity must be a non-negative safe integer");
      current.capacity = input.capacity;
    }
    if (input.capacityWeight !== undefined) {
      if (!Number.isFinite(input.capacityWeight) || input.capacityWeight <= 0) throw new TypeError("capacityWeight must be positive");
      current.capacityWeight = input.capacityWeight;
    }
    current.updatedAt = updatedAt;
    return clone(current);
  }

  async removeInstance(input: {
    meshId: string; agentId: string; instanceId: string; registrationFence: number; sessionFence: number;
  }): Promise<boolean> {
    const key = `${input.meshId}\0${input.agentId}\0${input.instanceId}`;
    const current = this.instances.get(key);
    if (!current || current.registrationFence !== input.registrationFence || current.sessionFence !== input.sessionFence) return false;
    this.instances.delete(key);
    return true;
  }

  async expireInstances(now: number): Promise<DurableAgentInstance[]> {
    const expired: DurableAgentInstance[] = [];
    for (const record of this.instances.values()) {
      if (record.expiresAt <= now && record.health !== HealthState.OFFLINE) {
        record.health = HealthState.OFFLINE;
        record.updatedAt = now;
        expired.push(clone(record));
      }
    }
    return expired;
  }

  async upsertSession(record: DurableSession): Promise<DurableSession> {
    const normalized: DurableSession = {
      sessionId: asString(record.sessionId, "sessionId"),
      ownerBrokerNodeId: asString(record.ownerBrokerNodeId, "ownerBrokerNodeId"),
      sessionFence: asFence(record.sessionFence, "sessionFence"),
      createdAt: asTimestamp(record.createdAt, "createdAt"),
      updatedAt: asTimestamp(record.updatedAt, "updatedAt"),
      expiresAt: asTimestamp(record.expiresAt, "expiresAt"),
    };
    const current = this.sessions.get(normalized.sessionId);
    if (!canApplySessionWrite(current, normalized)) return clone(current!);
    this.sessions.set(normalized.sessionId, clone(normalized));
    return clone(normalized);
  }

  async getSession(sessionId: string): Promise<DurableSession | undefined> {
    const record = this.sessions.get(sessionId);
    return record === undefined ? undefined : clone(record);
  }

  async putInbox(record: InboxRecord): Promise<InboxPutResult> {
    const normalized = normalizeInbox(record);
    const key = inboxKey(normalized);
    const prior = this.inboxes.get(key);
    if (prior) {
      return prior.semanticFingerprint === normalized.semanticFingerprint
        ? { disposition: "duplicate", record: clone(prior) }
        : { disposition: "conflict", record: clone(prior) };
    }
    this.inboxes.set(key, clone(normalized));
    return { disposition: "stored", record: clone(normalized) };
  }

  async getInbox(input: InboxIdentity): Promise<InboxRecord | undefined> {
    const record = this.inboxes.get(inboxKey(input));
    return record === undefined ? undefined : clone(record);
  }

  async putRoute(record: DurableTaskRoute): Promise<DurableTaskRoute> {
    const normalized = normalizeRoute(record);
    const key = routeKey(normalized.meshId, normalized.taskId);
    const prior = this.routes.get(key);
    if (prior && prior.immutableFingerprint !== normalized.immutableFingerprint) throw new Error("PMX.TASK.ID_CONFLICT");
    if (prior) return clone(prior);
    this.routes.set(key, clone(normalized));
    return clone(normalized);
  }

  async getRoute(meshId: string, taskId: string): Promise<DurableTaskRoute | undefined> {
    const record = this.routes.get(routeKey(meshId, taskId));
    return record === undefined ? undefined : clone(record);
  }

  async updateRouteState(input: { meshId: string; taskId: string; routeFence: number; state: string; updatedAt: number }): Promise<DurableTaskRoute | undefined> {
    const record = this.routes.get(routeKey(input.meshId, input.taskId));
    if (!record || record.routeFence !== input.routeFence) return undefined;
    record.state = asString(input.state, "state");
    record.updatedAt = asTimestamp(input.updatedAt, "updatedAt");
    return clone(record);
  }

  async putExecutionTask(record: ExecutionTaskRecord): Promise<ExecutionTaskRecord> {
    const normalized = normalizeExecutionTask(record);
    const key = routeKey(normalized.meshId, normalized.taskId);
    const existing = this.executionTasks.get(key);
    if (existing) {
      if (sameExecutionTask(existing, normalized)) return clone(existing);
      throw new DurableStoreConflictError("STALE_FENCE", "Execution task already exists; use a fenced transition");
    }
    this.executionTasks.set(key, clone(normalized));
    return clone(normalized);
  }

  async getExecutionTask(meshId: string, taskId: string): Promise<ExecutionTaskRecord | undefined> {
    const record = this.executionTasks.get(routeKey(meshId, taskId));
    return record === undefined ? undefined : clone(record);
  }

  async transitionExecutionTask(input: FencedExecutionTaskTransition): Promise<ExecutionTaskRecord | undefined> {
    const expectedWorkerFence = input.expectedWorkerFence === null
      ? null
      : asFence(input.expectedWorkerFence, "expectedWorkerFence");
    const expectedWorkerLeaseId = input.expectedWorkerLeaseId === null
      ? null
      : asString(input.expectedWorkerLeaseId, "expectedWorkerLeaseId");
    const expectedStates = input.expectedStates === undefined
      ? undefined
      : [...input.expectedStates].map((state) => asString(state, "expectedStates entry"));
    const transition: FencedExecutionTaskTransition = {
      meshId: asString(input.meshId, "meshId"),
      taskId: asString(input.taskId, "taskId"),
      expectedWorkerFence,
      expectedWorkerLeaseId,
      ...(expectedStates === undefined ? {} : { expectedStates }),
      next: normalizeExecutionTask(input.next),
    };
    const key = routeKey(transition.meshId, transition.taskId);
    const current = this.executionTasks.get(key);
    if (!current || !validFencedExecutionTransition(current, transition, transition.next)) return undefined;
    this.executionTasks.set(key, clone(transition.next));
    return clone(transition.next);
  }

  async reconcileExpiredWorkerLeases(now: number): Promise<ExecutionTaskRecord[]> {
    const reconciled: ExecutionTaskRecord[] = [];
    for (const record of this.executionTasks.values()) {
      if (record.terminalAt !== undefined || record.workerLeaseId === undefined ||
        record.workerLeaseExpiresAt === undefined || record.workerLeaseExpiresAt > now) continue;
      // A lease expiry means execution is uncertain. Only a workload with an
      // external idempotency key is eligible for dispatcher retry; all other
      // work must be surfaced for explicit recovery rather than rerun.
      record.state = record.externalIdempotencyKey === undefined ? "RECOVERY_REQUIRED" : "QUEUED";
      record.workerLeaseId = undefined;
      record.workerLeaseExpiresAt = undefined;
      record.updatedAt = now;
      reconciled.push(clone(record));
    }
    return reconciled;
  }

  async appendTaskEvent(record: TaskEventRecord): Promise<"stored" | "duplicate" | "conflict"> {
    const normalized = normalizeTaskEvent(record);
    const key = taskEventKey(normalized.meshId, normalized.taskId, normalized.eventSeq);
    const prior = this.taskEvents.get(key);
    if (!prior) {
      this.taskEvents.set(key, clone(normalized));
      return "stored";
    }
    return sameTaskEvent(prior, normalized) ? "duplicate" : "conflict";
  }

  async listTaskEvents(meshId: string, taskId: string): Promise<TaskEventRecord[]> {
    return [...this.taskEvents.values()].filter((event) => event.meshId === meshId && event.taskId === taskId)
      .sort((left, right) => left.eventSeq - right.eventSeq).map(clone);
  }

  async putCancellationTombstone(record: CancellationTombstone): Promise<CancellationTombstone> {
    const normalized = clone(record);
    normalized.expiresAt = Math.max(normalized.expiresAt, normalized.createdAt + MIN_RETENTION_MS);
    this.cancellations.set(routeKey(normalized.meshId, normalized.taskId), normalized);
    return clone(normalized);
  }

  async getCancellationTombstone(meshId: string, taskId: string): Promise<CancellationTombstone | undefined> {
    const record = this.cancellations.get(routeKey(meshId, taskId));
    return record === undefined ? undefined : clone(record);
  }

  async enqueueOutbox(record: OutboxRecord): Promise<OutboxRecord> {
    const normalized = normalizeOutbox(record);
    const prior = this.outboxes.get(normalized.deliveryId);
    if (prior) {
      if (!sameOutbox(prior, normalized)) {
        throw new DurableStoreConflictError("PMX.DELIVERY.IDEMPOTENCY_CONFLICT", "Outbox delivery_id was reused with different immutable content");
      }
      return clone(prior);
    }
    this.outboxes.set(normalized.deliveryId, clone(normalized));
    return clone(normalized);
  }

  async getOutbox(deliveryId: string): Promise<OutboxRecord | undefined> {
    const record = this.outboxes.get(deliveryId);
    return record === undefined ? undefined : clone(record);
  }

  async leasePendingOutbox(input: { now: number; leaseId: string; leaseMs: number; limit?: number }): Promise<OutboxRecord[]> {
    const limit = input.limit ?? 100;
    const selected = [...this.outboxes.values()]
      .filter((record) => record.state === "PENDING" && record.expiresAt > input.now)
      .sort((left, right) => left.createdAt - right.createdAt)
      .slice(0, limit);
    for (const record of selected) {
      record.state = "LEASED";
      record.dispatchLeaseId = input.leaseId;
      record.dispatchLeaseExpiresAt = input.now + input.leaseMs;
      record.attempt += 1;
      record.updatedAt = input.now;
    }
    return selected.map(clone);
  }

  async markOutboxSent(input: { deliveryId: string; leaseId: string; now: number }): Promise<OutboxRecord | undefined> {
    const record = this.outboxes.get(input.deliveryId);
    if (!record || record.state !== "LEASED" || record.dispatchLeaseId !== input.leaseId ||
      record.dispatchLeaseExpiresAt === undefined || record.dispatchLeaseExpiresAt <= input.now) return undefined;
    record.state = "SENT_AWAITING_RECEIPT";
    record.updatedAt = input.now;
    return clone(record);
  }

  async releaseOutboxLease(input: { deliveryId: string; leaseId: string; now: number }): Promise<OutboxRecord | undefined> {
    const record = this.outboxes.get(input.deliveryId);
    if (!record || record.state !== "LEASED" || record.dispatchLeaseId !== input.leaseId) return undefined;
    record.state = "PENDING";
    record.dispatchLeaseId = undefined;
    record.dispatchLeaseExpiresAt = undefined;
    record.updatedAt = asTimestamp(input.now, "now");
    return clone(record);
  }

  async acknowledgeOutbox(input: { deliveryId: string; now: number; receiptState?: "stored" | "delivered" }): Promise<OutboxRecord | undefined> {
    const record = this.outboxes.get(input.deliveryId);
    // A valid receipt is keyed by the immutable delivery id.  It can arrive
    // after crash recovery has reclaimed an expired dispatch lease back to
    // PENDING (or while a retry is LEASED); ignoring it would cause needless
    // redelivery after the target has already committed its inbox.
    if (!record || record.state === "DELIVERED" || record.state === "EXPIRED" || record.state === "DEAD_LETTER") return undefined;
    record.state = "DELIVERED";
    record.receiptState = input.receiptState ?? "delivered";
    record.dispatchLeaseId = undefined;
    record.dispatchLeaseExpiresAt = undefined;
    record.updatedAt = input.now;
    return clone(record);
  }

  async reclaimExpiredDispatchLeases(now: number): Promise<number> {
    let reclaimed = 0;
    for (const record of this.outboxes.values()) {
      if ((record.state === "LEASED" || record.state === "SENT_AWAITING_RECEIPT") &&
        (record.dispatchLeaseExpiresAt === undefined || record.dispatchLeaseExpiresAt <= now)) {
        record.state = record.expiresAt <= now ? "EXPIRED" : "PENDING";
        record.dispatchLeaseId = undefined;
        record.dispatchLeaseExpiresAt = undefined;
        record.updatedAt = now;
        reclaimed += 1;
      }
    }
    return reclaimed;
  }

  async listDispatchableOutbox(now: number, limit = 100): Promise<OutboxRecord[]> {
    return [...this.outboxes.values()]
      .filter((record) => record.state === "PENDING" && record.expiresAt > now)
      .sort((left, right) => left.createdAt - right.createdAt).slice(0, limit).map(clone);
  }

  async persistIngress(input: PersistIngressInput): Promise<PersistIngressResult> {
    const snapshot = this.snapshot();
    try {
      const route = input.route === undefined ? undefined : normalizeRoute(input.route);
      const outbox = input.outbox === undefined ? undefined : normalizeOutbox(input.outbox);
      const inbox = assertIngressTargets(normalizeInbox(input.inbox), route, outbox);
      const sourceFence = input.sourceFence === undefined ? undefined : normalizeSourceFence(input.sourceFence);
      if (sourceFence !== undefined && !sourceFenceMatches(
        this.instances.get(instanceKey({ meshId: inbox.meshId, agentId: inbox.sourceAgentId, instanceId: inbox.sourceInstanceId })),
        this.sessions.get(sourceFence.sessionId),
        inbox,
        sourceFence,
      )) {
        return { disposition: "conflict", code: "STALE_FENCE", inbox };
      }
      const prior = this.inboxes.get(inboxKey(inbox));
      if (prior) {
        if (prior.semanticFingerprint !== inbox.semanticFingerprint) {
          return { disposition: "conflict", code: "PMX.DELIVERY.IDEMPOTENCY_CONFLICT", inbox: clone(prior) };
        }
        const priorRoute = route === undefined ? undefined : this.routes.get(routeKey(route.meshId, route.taskId));
        const priorOutbox = prior.outboxDeliveryId === undefined ? undefined : this.outboxes.get(prior.outboxDeliveryId);
        return {
          disposition: "duplicate",
          inbox: clone(prior),
          ...(priorRoute === undefined ? {} : { route: clone(priorRoute) }),
          ...(priorOutbox === undefined ? {} : { outbox: clone(priorOutbox) }),
        };
      }
      if (route) {
        const existingRoute = this.routes.get(routeKey(route.meshId, route.taskId));
        if (existingRoute) {
          if (existingRoute.immutableFingerprint !== route.immutableFingerprint) {
            return { disposition: "conflict", code: "PMX.TASK.ID_CONFLICT", inbox, route: clone(existingRoute) };
          }
          // A task id may be retransmitted with a fresh message/ingress key,
          // but it must retain the original physical executor.  Persist the
          // fresh ingress/outbox together so correlation can be replayed
          // without silently selecting a sibling instance.
          if (!sameRoutePin(existingRoute, route)) {
            return { disposition: "conflict", code: "PMX.TASK.ID_CONFLICT", inbox, route: clone(existingRoute) };
          }
          const duplicateInbox = assertIngressTargets(
            { ...inbox, selectedInstanceId: existingRoute.executorInstanceId },
            existingRoute,
            outbox,
          );
          const storedInbox = outbox ? { ...duplicateInbox, outboxDeliveryId: outbox.deliveryId } : duplicateInbox;
          if (outbox) {
            const priorOutbox = this.outboxes.get(outbox.deliveryId);
            if (priorOutbox && !sameOutbox(priorOutbox, outbox)) {
              throw new DurableStoreConflictError("PMX.DELIVERY.IDEMPOTENCY_CONFLICT", "Outbox delivery_id was reused with different immutable content");
            }
            if (!priorOutbox) this.outboxes.set(outbox.deliveryId, clone(outbox));
          }
          this.inboxes.set(inboxKey(storedInbox), clone(storedInbox));
          return {
            disposition: "stored",
            inbox: clone(storedInbox),
            route: clone(existingRoute),
            ...(outbox === undefined ? {} : { outbox: clone(this.outboxes.get(outbox.deliveryId)!) }),
          };
        }
      }
      const storedInbox = outbox ? { ...inbox, outboxDeliveryId: outbox.deliveryId } : inbox;
      if (outbox) {
        const priorOutbox = this.outboxes.get(outbox.deliveryId);
        if (priorOutbox && !sameOutbox(priorOutbox, outbox)) {
          throw new DurableStoreConflictError("PMX.DELIVERY.IDEMPOTENCY_CONFLICT", "Outbox delivery_id was reused with different immutable content");
        }
      }
      this.inboxes.set(inboxKey(storedInbox), clone(storedInbox));
      if (route) this.routes.set(routeKey(route.meshId, route.taskId), clone(route));
      if (outbox) this.outboxes.set(outbox.deliveryId, clone(outbox));
      return {
        disposition: "stored",
        inbox: clone(storedInbox),
        ...(route === undefined ? {} : { route: clone(route) }),
        ...(outbox === undefined ? {} : { outbox: clone(outbox) }),
      };
    } catch (error) {
      this.restore(snapshot);
      throw error;
    }
  }

  async persistExecutorAdmission(input: PersistExecutorAdmissionInput): Promise<PersistExecutorAdmissionResult> {
    const snapshot = this.snapshot();
    try {
      const admission = normalizeExecutorAdmission(input);
      const priorInbox = this.inboxes.get(inboxKey(admission.inbox));
      if (priorInbox) {
        if (priorInbox.semanticFingerprint !== admission.inbox.semanticFingerprint) {
          return { disposition: "conflict", code: "PMX.DELIVERY.IDEMPOTENCY_CONFLICT", inbox: clone(priorInbox) };
        }
        const executionTask = this.executionTasks.get(routeKey(admission.inbox.meshId, admission.taskId));
        const event = this.taskEvents.get(taskEventKey(admission.inbox.meshId, admission.taskId, 1));
        const outbox = priorInbox.outboxDeliveryId === undefined ? undefined : this.outboxes.get(priorInbox.outboxDeliveryId);
        if (!executionTask || !event || !outbox) {
          return {
            disposition: "conflict",
            code: "PMX.TASK.ID_CONFLICT",
            inbox: clone(priorInbox),
            ...(executionTask === undefined ? {} : { executionTask: clone(executionTask) }),
            ...(event === undefined ? {} : { event: clone(event) }),
            ...(outbox === undefined ? {} : { outbox: clone(outbox) }),
          };
        }
        return { disposition: "duplicate", inbox: clone(priorInbox), executionTask: clone(executionTask), event: clone(event), outbox: clone(outbox) };
      }
      const existingTask = this.executionTasks.get(routeKey(admission.inbox.meshId, admission.taskId));
      const existingEvent = this.taskEvents.get(taskEventKey(admission.inbox.meshId, admission.taskId, 1));
      const existingOutbox = this.outboxes.get(admission.outbox.deliveryId);
      if (existingTask || existingEvent || (existingOutbox && !sameOutbox(existingOutbox, admission.outbox))) {
        return {
          disposition: "conflict",
          code: "PMX.TASK.ID_CONFLICT",
          inbox: clone(admission.inbox),
          ...(existingTask === undefined ? {} : { executionTask: clone(existingTask) }),
          ...(existingEvent === undefined ? {} : { event: clone(existingEvent) }),
          ...(existingOutbox === undefined ? {} : { outbox: clone(existingOutbox) }),
        };
      }
      if (existingOutbox) {
        return { disposition: "conflict", code: "PMX.TASK.ID_CONFLICT", inbox: clone(admission.inbox), outbox: clone(existingOutbox) };
      }
      this.inboxes.set(inboxKey(admission.inbox), clone(admission.inbox));
      this.executionTasks.set(routeKey(admission.executionTask.meshId, admission.executionTask.taskId), clone(admission.executionTask));
      this.taskEvents.set(taskEventKey(admission.event.meshId, admission.event.taskId, admission.event.eventSeq), clone(admission.event));
      this.outboxes.set(admission.outbox.deliveryId, clone(admission.outbox));
      return {
        disposition: "stored",
        inbox: clone(admission.inbox),
        executionTask: clone(admission.executionTask),
        event: clone(admission.event),
        outbox: clone(admission.outbox),
      };
    } catch (error) {
      this.restore(snapshot);
      throw error;
    }
  }

  async recover(now = Date.now()): Promise<RecoveryReport> {
    const reclaimedDispatchLeases = await this.reclaimExpiredDispatchLeases(now);
    const expiredInstances = await this.expireInstances(now);
    const reconciledWorkerLeases = await this.reconcileExpiredWorkerLeases(now);
    const pendingOutbox = await this.listDispatchableOutbox(now);
    return { reclaimedDispatchLeases, expiredInstances, reconciledWorkerLeases, pendingOutbox };
  }

  private assertNoIdentityCollision(record: DurableAgentInstance): void {
    for (const existing of this.instances.values()) {
      if (existing.meshId === record.meshId && existing.agentId === record.agentId &&
        existing.principalId !== record.principalId && existing.expiresAt > record.updatedAt) {
        throw new DurableStoreConflictError("IDENTITY_COLLISION", "A live logical agent cannot be owned by multiple principals");
      }
    }
  }

  private snapshot(): {
    instances: Map<string, DurableAgentInstance>;
    sessions: Map<string, DurableSession>;
    inboxes: Map<string, InboxRecord>;
    routes: Map<string, DurableTaskRoute>;
    executionTasks: Map<string, ExecutionTaskRecord>;
    taskEvents: Map<string, TaskEventRecord>;
    outboxes: Map<string, OutboxRecord>;
    cancellations: Map<string, CancellationTombstone>;
  } {
    const copy = <T>(source: Map<string, T>): Map<string, T> => new Map([...source].map(([key, value]) => [key, clone(value)]));
    return {
      instances: copy(this.instances), sessions: copy(this.sessions), inboxes: copy(this.inboxes), routes: copy(this.routes),
      executionTasks: copy(this.executionTasks), taskEvents: copy(this.taskEvents), outboxes: copy(this.outboxes), cancellations: copy(this.cancellations),
    };
  }

  private restore(snapshot: ReturnType<InMemoryDurableStore["snapshot"]>): void {
    const restoreMap = <T>(target: Map<string, T>, source: Map<string, T>): void => {
      target.clear();
      for (const [key, value] of source) target.set(key, clone(value));
    };
    restoreMap(this.instances, snapshot.instances);
    restoreMap(this.sessions, snapshot.sessions);
    restoreMap(this.inboxes, snapshot.inboxes);
    restoreMap(this.routes, snapshot.routes);
    restoreMap(this.executionTasks, snapshot.executionTasks);
    restoreMap(this.taskEvents, snapshot.taskEvents);
    restoreMap(this.outboxes, snapshot.outboxes);
    restoreMap(this.cancellations, snapshot.cancellations);
  }
}

/**
 * SQLite persistence. Every mutating method uses BEGIN IMMEDIATE so a second
 * local broker cannot observe an ingress row before its pinned route/outbox
 * facts exist. WAL + FULL sync are configured at construction.
 */
export class SqliteDurableStore implements DurableStore {
  private readonly db: Database.Database;
  private readonly clock: DurableClock;

  constructor(options: SqliteDurableStoreOptions | string = {}) {
    const normalized = typeof options === "string" ? { filename: options } : options;
    this.clock = normalized.clock ?? Date.now;
    this.db = new Database(normalized.filename ?? ":memory:");
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("synchronous = FULL");
    this.db.pragma("foreign_keys = ON");
    this.migrate();
  }

  close(): void {
    this.db.close();
  }

  async transaction<T>(operation: (store: DurableStore) => T): Promise<T> {
    return this.immediate(() => operation(this));
  }

  async upsertInstance(record: DurableAgentInstance): Promise<DurableAgentInstance> {
    const normalized = normalizeInstance(record);
    return this.immediate(() => {
      this.assertNoIdentityCollisionSync(normalized);
      return this.upsertInstanceSync(normalized);
    });
  }

  /** Commit a session CAS and its instance registration in one BEGIN IMMEDIATE transaction. */
  async upsertRegistration(registration: DurableRegistration): Promise<DurableRegistration> {
    const normalized = assertRegistrationShape(registration);
    return this.immediate(() => {
      const currentInstance = this.instanceFromRow(this.db.prepare(
        `SELECT * FROM agent_instances WHERE mesh_id = ? AND agent_id = ? AND instance_id = ?`,
      ).get(normalized.instance.meshId, normalized.instance.agentId, normalized.instance.instanceId));
      if (!canApplyInstanceWrite(currentInstance, normalized.instance)) {
        throw new DurableStoreConflictError("STALE_FENCE", "Registration/session fence is stale or conflicts with the active instance");
      }
      if (normalized.session !== undefined) {
        const currentSession = this.sessionFromRow(this.db.prepare(`SELECT * FROM sessions WHERE session_id = ?`).get(normalized.session.sessionId));
        if (!canApplySessionWrite(currentSession, normalized.session)) {
          throw new DurableStoreConflictError("STALE_FENCE", "Session fence is stale or belongs to another broker node");
        }
      }
      this.assertNoIdentityCollisionSync(normalized.instance);
      const session = normalized.session === undefined ? undefined : this.upsertSessionSync(normalized.session);
      const instance = this.upsertInstanceSync(normalized.instance);
      return { instance, ...(session === undefined ? {} : { session }) };
    });
  }

  async getInstance(meshId: string, agentId: string, instanceId: string): Promise<DurableAgentInstance | undefined> {
    return this.instanceFromRow(this.db.prepare(`SELECT * FROM agent_instances WHERE mesh_id = ? AND agent_id = ? AND instance_id = ?`).get(meshId, agentId, instanceId));
  }

  async listInstances(input: { meshId?: string; agentId?: string; now?: number } = {}): Promise<DurableAgentInstance[]> {
    const clauses: string[] = [];
    const parameters: unknown[] = [];
    if (input.meshId !== undefined) { clauses.push("mesh_id = ?"); parameters.push(input.meshId); }
    if (input.agentId !== undefined) { clauses.push("agent_id = ?"); parameters.push(input.agentId); }
    if (input.now !== undefined) { clauses.push("expires_at > ?"); parameters.push(input.now); }
    const where = clauses.length === 0 ? "" : ` WHERE ${clauses.join(" AND ")}`;
    return (this.db.prepare(`SELECT * FROM agent_instances${where} ORDER BY agent_id, instance_id`).all(...parameters) as unknown[])
      .map((row) => this.instanceFromRow(row)!).filter((record): record is DurableAgentInstance => record !== undefined);
  }

  async renewInstance(input: {
    meshId: string; agentId: string; instanceId: string; registrationFence: number; sessionFence: number;
    expiresAt: number; health?: InstanceHealth; updatedAt?: number;
  }): Promise<DurableAgentInstance | undefined> {
    return this.immediate(() => {
      const updatedAt = asTimestamp(input.updatedAt ?? this.clock(), "updatedAt");
      const expiresAt = asTimestamp(input.expiresAt, "expiresAt");
      const registrationFence = asFence(input.registrationFence, "registrationFence");
      const sessionFence = asFence(input.sessionFence, "sessionFence");
      if (input.health !== undefined && !Object.values(HealthState).includes(input.health)) throw new TypeError("health is invalid");
      const result = this.db.prepare(`UPDATE agent_instances
        SET expires_at = ?, updated_at = ?, health = COALESCE(?, health)
        WHERE mesh_id = ? AND agent_id = ? AND instance_id = ?
          AND registration_fence = ? AND session_fence = ? AND updated_at <= ?`).run(
        expiresAt, updatedAt, input.health ?? null,
        input.meshId, input.agentId, input.instanceId, registrationFence, sessionFence, updatedAt,
      );
      if (result.changes !== 1) return undefined;
      return this.instanceFromRow(this.db.prepare(`SELECT * FROM agent_instances WHERE mesh_id = ? AND agent_id = ? AND instance_id = ?`).get(input.meshId, input.agentId, input.instanceId));
    });
  }

  async updateInstanceCapacity(input: {
    meshId: string; agentId: string; instanceId: string; registrationFence: number; sessionFence: number;
    capacity?: number; capacityWeight?: number; updatedAt: number;
  }): Promise<DurableAgentInstance | undefined> {
    if (input.capacity === undefined && input.capacityWeight === undefined) throw new TypeError("At least one capacity field is required");
    if (input.capacity !== undefined && (!Number.isSafeInteger(input.capacity) || input.capacity < 0)) throw new TypeError("capacity must be a non-negative safe integer");
    if (input.capacityWeight !== undefined && (!Number.isFinite(input.capacityWeight) || input.capacityWeight <= 0)) throw new TypeError("capacityWeight must be positive");
    return this.immediate(() => {
      const current = this.instanceFromRow(this.db.prepare(
        `SELECT * FROM agent_instances WHERE mesh_id = ? AND agent_id = ? AND instance_id = ?`,
      ).get(input.meshId, input.agentId, input.instanceId));
      if (!current || current.registrationFence !== asFence(input.registrationFence, "registrationFence") ||
        current.sessionFence !== asFence(input.sessionFence, "sessionFence") || current.updatedAt > asTimestamp(input.updatedAt, "updatedAt")) return undefined;
      const result = this.db.prepare(`UPDATE agent_instances
        SET capacity = COALESCE(?, capacity), capacity_weight = COALESCE(?, capacity_weight), updated_at = ?
        WHERE mesh_id = ? AND agent_id = ? AND instance_id = ?
          AND registration_fence = ? AND session_fence = ? AND updated_at <= ?`).run(
        input.capacity ?? null, input.capacityWeight ?? null, input.updatedAt,
        input.meshId, input.agentId, input.instanceId, input.registrationFence, input.sessionFence, input.updatedAt,
      );
      return result.changes === 1
        ? this.instanceFromRow(this.db.prepare(`SELECT * FROM agent_instances WHERE mesh_id = ? AND agent_id = ? AND instance_id = ?`).get(input.meshId, input.agentId, input.instanceId))
        : undefined;
    });
  }

  async removeInstance(input: {
    meshId: string; agentId: string; instanceId: string; registrationFence: number; sessionFence: number;
  }): Promise<boolean> {
    return this.immediate(() => this.db.prepare(`DELETE FROM agent_instances
      WHERE mesh_id = ? AND agent_id = ? AND instance_id = ? AND registration_fence = ? AND session_fence = ?`).run(
      input.meshId, input.agentId, input.instanceId, input.registrationFence, input.sessionFence,
    ).changes === 1);
  }

  async expireInstances(now: number): Promise<DurableAgentInstance[]> {
    return this.immediate(() => {
      const rows = this.db.prepare(`SELECT * FROM agent_instances WHERE expires_at <= ? AND health <> ?`).all(now, HealthState.OFFLINE) as unknown[];
      this.db.prepare(`UPDATE agent_instances SET health = ?, updated_at = ? WHERE expires_at <= ? AND health <> ?`).run(
        HealthState.OFFLINE, now, now, HealthState.OFFLINE,
      );
      return rows.map((row) => this.instanceFromRow(row)!).filter((record): record is DurableAgentInstance => record !== undefined);
    });
  }

  async upsertSession(record: DurableSession): Promise<DurableSession> {
    const normalized: DurableSession = {
      sessionId: asString(record.sessionId, "sessionId"), ownerBrokerNodeId: asString(record.ownerBrokerNodeId, "ownerBrokerNodeId"),
      sessionFence: asFence(record.sessionFence, "sessionFence"), createdAt: asTimestamp(record.createdAt, "createdAt"),
      updatedAt: asTimestamp(record.updatedAt, "updatedAt"), expiresAt: asTimestamp(record.expiresAt, "expiresAt"),
    };
    return this.immediate(() => this.upsertSessionSync(normalized));
  }

  async getSession(sessionId: string): Promise<DurableSession | undefined> {
    return this.sessionFromRow(this.db.prepare(`SELECT * FROM sessions WHERE session_id = ?`).get(sessionId));
  }

  async putInbox(record: InboxRecord): Promise<InboxPutResult> {
    const normalized = normalizeInbox(record);
    return this.immediate(() => this.putInboxSync(normalized));
  }

  async getInbox(input: InboxIdentity): Promise<InboxRecord | undefined> {
    return this.inboxFromRow(this.selectInbox(input));
  }

  async putRoute(record: DurableTaskRoute): Promise<DurableTaskRoute> {
    const normalized = normalizeRoute(record);
    return this.immediate(() => this.putRouteSync(normalized));
  }

  async getRoute(meshId: string, taskId: string): Promise<DurableTaskRoute | undefined> {
    return this.routeFromRow(this.db.prepare(`SELECT * FROM task_routes WHERE mesh_id = ? AND task_id = ?`).get(meshId, taskId));
  }

  async updateRouteState(input: { meshId: string; taskId: string; routeFence: number; state: string; updatedAt: number }): Promise<DurableTaskRoute | undefined> {
    return this.immediate(() => {
      const result = this.db.prepare(`UPDATE task_routes SET state = ?, updated_at = ? WHERE mesh_id = ? AND task_id = ? AND route_fence = ?`).run(
        asString(input.state, "state"), asTimestamp(input.updatedAt, "updatedAt"), input.meshId, input.taskId, input.routeFence,
      );
      return result.changes === 1 ? this.routeFromRow(this.db.prepare(`SELECT * FROM task_routes WHERE mesh_id = ? AND task_id = ?`).get(input.meshId, input.taskId)) : undefined;
    });
  }

  async putExecutionTask(record: ExecutionTaskRecord): Promise<ExecutionTaskRecord> {
    const normalized = normalizeExecutionTask(record);
    return this.immediate(() => {
      const existing = this.executionTaskFromRow(this.db.prepare(`SELECT * FROM execution_tasks WHERE mesh_id = ? AND task_id = ?`).get(normalized.meshId, normalized.taskId));
      if (existing) {
        if (sameExecutionTask(existing, normalized)) return existing;
        throw new DurableStoreConflictError("STALE_FENCE", "Execution task already exists; use a fenced transition");
      }
      this.insertExecutionTaskSync(normalized);
      return normalized;
    });
  }

  async getExecutionTask(meshId: string, taskId: string): Promise<ExecutionTaskRecord | undefined> {
    return this.executionTaskFromRow(this.db.prepare(`SELECT * FROM execution_tasks WHERE mesh_id = ? AND task_id = ?`).get(meshId, taskId));
  }

  async transitionExecutionTask(input: FencedExecutionTaskTransition): Promise<ExecutionTaskRecord | undefined> {
    const expectedWorkerFence = input.expectedWorkerFence === null
      ? null
      : asFence(input.expectedWorkerFence, "expectedWorkerFence");
    const expectedWorkerLeaseId = input.expectedWorkerLeaseId === null
      ? null
      : asString(input.expectedWorkerLeaseId, "expectedWorkerLeaseId");
    const expectedStates = input.expectedStates === undefined
      ? undefined
      : [...input.expectedStates].map((state) => asString(state, "expectedStates entry"));
    const transition: FencedExecutionTaskTransition = {
      meshId: asString(input.meshId, "meshId"),
      taskId: asString(input.taskId, "taskId"),
      expectedWorkerFence,
      expectedWorkerLeaseId,
      ...(expectedStates === undefined ? {} : { expectedStates }),
      next: normalizeExecutionTask(input.next),
    };
    return this.immediate(() => {
      const current = this.executionTaskFromRow(this.db.prepare(`SELECT * FROM execution_tasks WHERE mesh_id = ? AND task_id = ?`).get(
        transition.meshId,
        transition.taskId,
      ));
      if (!current || !validFencedExecutionTransition(current, transition, transition.next)) return undefined;
      const next = transition.next;
      const result = this.db.prepare(`UPDATE execution_tasks
        SET state = ?, worker_lease_id = ?, worker_fence = ?, worker_lease_expires_at = ?,
          cancellation_requested_at = ?, terminal_at = ?, external_idempotency_key = ?, updated_at = ?, retained_until = ?
        WHERE mesh_id = ? AND task_id = ? AND terminal_at IS NULL
          AND worker_fence IS ? AND worker_lease_id IS ?`).run(
        next.state, next.workerLeaseId ?? null, next.workerFence ?? null, next.workerLeaseExpiresAt ?? null,
        next.cancellationRequestedAt ?? null, next.terminalAt ?? null, next.externalIdempotencyKey ?? null,
        next.updatedAt, next.retainedUntil,
        transition.meshId, transition.taskId, transition.expectedWorkerFence, transition.expectedWorkerLeaseId,
      );
      return result.changes === 1
        ? this.executionTaskFromRow(this.db.prepare(`SELECT * FROM execution_tasks WHERE mesh_id = ? AND task_id = ?`).get(transition.meshId, transition.taskId))
        : undefined;
    });
  }

  async reconcileExpiredWorkerLeases(now: number): Promise<ExecutionTaskRecord[]> {
    return this.immediate(() => {
      const rows = this.db.prepare(`SELECT * FROM execution_tasks
        WHERE terminal_at IS NULL AND worker_lease_id IS NOT NULL AND worker_lease_expires_at <= ?`).all(now) as unknown[];
      this.db.prepare(`UPDATE execution_tasks
        SET state = CASE WHEN external_idempotency_key IS NULL THEN 'RECOVERY_REQUIRED' ELSE 'QUEUED' END,
          worker_lease_id = NULL, worker_lease_expires_at = NULL, updated_at = ?
        WHERE terminal_at IS NULL AND worker_lease_id IS NOT NULL AND worker_lease_expires_at <= ?`).run(now, now);
      return rows.map((row) => {
        const previous = this.executionTaskFromRow(row)!;
        return {
          ...previous,
          state: previous.externalIdempotencyKey === undefined ? "RECOVERY_REQUIRED" : "QUEUED",
          workerLeaseId: undefined,
          workerLeaseExpiresAt: undefined,
          updatedAt: now,
        };
      });
    });
  }

  async appendTaskEvent(record: TaskEventRecord): Promise<"stored" | "duplicate" | "conflict"> {
    const normalized = normalizeTaskEvent(record);
    return this.immediate(() => {
      const prior = this.taskEventFromRow(this.selectTaskEvent(normalized.meshId, normalized.taskId, normalized.eventSeq));
      if (prior) return sameTaskEvent(prior, normalized) ? "duplicate" : "conflict";
      this.insertTaskEventSync(normalized);
      return "stored";
    });
  }

  async listTaskEvents(meshId: string, taskId: string): Promise<TaskEventRecord[]> {
    return (this.db.prepare(`SELECT * FROM task_events WHERE mesh_id = ? AND task_id = ? ORDER BY event_seq`).all(meshId, taskId) as unknown[])
      .map((row) => this.taskEventFromRow(row)!).filter((record): record is TaskEventRecord => record !== undefined);
  }

  async putCancellationTombstone(record: CancellationTombstone): Promise<CancellationTombstone> {
    const expiresAt = Math.max(record.expiresAt, record.createdAt + MIN_RETENTION_MS);
    return this.immediate(() => {
      this.db.prepare(`INSERT INTO cancellation_tombstones (mesh_id, task_id, owner_principal_id, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(mesh_id, task_id) DO UPDATE SET owner_principal_id = excluded.owner_principal_id, expires_at = excluded.expires_at`).run(
        record.meshId, record.taskId, record.ownerPrincipalId, record.createdAt, expiresAt,
      );
      return this.cancellationFromRow(this.db.prepare(`SELECT * FROM cancellation_tombstones WHERE mesh_id = ? AND task_id = ?`).get(record.meshId, record.taskId))!;
    });
  }

  async getCancellationTombstone(meshId: string, taskId: string): Promise<CancellationTombstone | undefined> {
    return this.cancellationFromRow(this.db.prepare(`SELECT * FROM cancellation_tombstones WHERE mesh_id = ? AND task_id = ?`).get(meshId, taskId));
  }

  async enqueueOutbox(record: OutboxRecord): Promise<OutboxRecord> {
    const normalized = normalizeOutbox(record);
    return this.immediate(() => this.enqueueOutboxSync(normalized));
  }

  async getOutbox(deliveryId: string): Promise<OutboxRecord | undefined> {
    return this.outboxFromRow(this.db.prepare(`SELECT * FROM outbox WHERE delivery_id = ?`).get(deliveryId));
  }

  async leasePendingOutbox(input: { now: number; leaseId: string; leaseMs: number; limit?: number }): Promise<OutboxRecord[]> {
    return this.immediate(() => {
      const rows = this.db.prepare(`SELECT delivery_id FROM outbox WHERE state = 'PENDING' AND expires_at > ? ORDER BY created_at LIMIT ?`).all(input.now, input.limit ?? 100) as Array<{ delivery_id: string }>;
      const update = this.db.prepare(`UPDATE outbox SET state = 'LEASED', dispatch_lease_id = ?, dispatch_lease_expires_at = ?, attempt = attempt + 1, updated_at = ? WHERE delivery_id = ? AND state = 'PENDING'`);
      const selected: OutboxRecord[] = [];
      for (const row of rows) {
        if (update.run(input.leaseId, input.now + input.leaseMs, input.now, row.delivery_id).changes === 1) {
          const record = this.outboxFromRow(this.db.prepare(`SELECT * FROM outbox WHERE delivery_id = ?`).get(row.delivery_id));
          if (record) selected.push(record);
        }
      }
      return selected;
    });
  }

  async markOutboxSent(input: { deliveryId: string; leaseId: string; now: number }): Promise<OutboxRecord | undefined> {
    return this.immediate(() => {
      const result = this.db.prepare(`UPDATE outbox SET state = 'SENT_AWAITING_RECEIPT', updated_at = ?
        WHERE delivery_id = ? AND state = 'LEASED' AND dispatch_lease_id = ?
          AND dispatch_lease_expires_at IS NOT NULL AND dispatch_lease_expires_at > ?`).run(input.now, input.deliveryId, input.leaseId, input.now);
      return result.changes === 1 ? this.outboxFromRow(this.db.prepare(`SELECT * FROM outbox WHERE delivery_id = ?`).get(input.deliveryId)) : undefined;
    });
  }

  async releaseOutboxLease(input: { deliveryId: string; leaseId: string; now: number }): Promise<OutboxRecord | undefined> {
    return this.immediate(() => {
      const result = this.db.prepare(`UPDATE outbox
        SET state = 'PENDING', dispatch_lease_id = NULL, dispatch_lease_expires_at = NULL, updated_at = ?
        WHERE delivery_id = ? AND state = 'LEASED' AND dispatch_lease_id = ?`).run(
        asTimestamp(input.now, "now"),
        input.deliveryId,
        input.leaseId,
      );
      return result.changes === 1
        ? this.outboxFromRow(this.db.prepare(`SELECT * FROM outbox WHERE delivery_id = ?`).get(input.deliveryId))
        : undefined;
    });
  }

  async acknowledgeOutbox(input: { deliveryId: string; now: number; receiptState?: "stored" | "delivered" }): Promise<OutboxRecord | undefined> {
    return this.immediate(() => {
      const result = this.db.prepare(`UPDATE outbox SET state = 'DELIVERED', receipt_state = ?, dispatch_lease_id = NULL, dispatch_lease_expires_at = NULL, updated_at = ?
        WHERE delivery_id = ? AND state IN ('PENDING', 'LEASED', 'SENT_AWAITING_RECEIPT')`).run(
        input.receiptState ?? "delivered", input.now, input.deliveryId,
      );
      return result.changes === 1 ? this.outboxFromRow(this.db.prepare(`SELECT * FROM outbox WHERE delivery_id = ?`).get(input.deliveryId)) : undefined;
    });
  }

  async reclaimExpiredDispatchLeases(now: number): Promise<number> {
    return this.immediate(() => {
      const pending = this.db.prepare(`UPDATE outbox SET state = 'PENDING', dispatch_lease_id = NULL, dispatch_lease_expires_at = NULL, updated_at = ?
        WHERE state IN ('LEASED', 'SENT_AWAITING_RECEIPT')
          AND (dispatch_lease_expires_at IS NULL OR dispatch_lease_expires_at <= ?) AND expires_at > ?`).run(now, now, now).changes;
      const expired = this.db.prepare(`UPDATE outbox SET state = 'EXPIRED', dispatch_lease_id = NULL, dispatch_lease_expires_at = NULL, updated_at = ?
        WHERE state IN ('PENDING', 'LEASED', 'SENT_AWAITING_RECEIPT') AND expires_at <= ?`).run(now, now).changes;
      return pending + expired;
    });
  }

  async listDispatchableOutbox(now: number, limit = 100): Promise<OutboxRecord[]> {
    return (this.db.prepare(`SELECT * FROM outbox WHERE state = 'PENDING' AND expires_at > ? ORDER BY created_at LIMIT ?`).all(now, limit) as unknown[])
      .map((row) => this.outboxFromRow(row)!).filter((record): record is OutboxRecord => record !== undefined);
  }

  async persistIngress(input: PersistIngressInput): Promise<PersistIngressResult> {
    const route = input.route === undefined ? undefined : normalizeRoute(input.route);
    const outbox = input.outbox === undefined ? undefined : normalizeOutbox(input.outbox);
    const inbox = assertIngressTargets(normalizeInbox(input.inbox), route, outbox);
    const sourceFence = input.sourceFence === undefined ? undefined : normalizeSourceFence(input.sourceFence);
    return this.immediate(() => {
      if (sourceFence !== undefined && !sourceFenceMatches(
        this.instanceFromRow(this.db.prepare(`SELECT * FROM agent_instances WHERE mesh_id = ? AND agent_id = ? AND instance_id = ?`).get(
          inbox.meshId,
          inbox.sourceAgentId,
          inbox.sourceInstanceId,
        )),
        this.sessionFromRow(this.db.prepare(`SELECT * FROM sessions WHERE session_id = ?`).get(sourceFence.sessionId)),
        inbox,
        sourceFence,
      )) {
        return { disposition: "conflict", code: "STALE_FENCE", inbox };
      }
      const prior = this.inboxFromRow(this.selectInbox(inbox));
      if (prior) {
        if (prior.semanticFingerprint !== inbox.semanticFingerprint) {
          const priorRoute = route ? this.routeFromRow(this.db.prepare(`SELECT * FROM task_routes WHERE mesh_id = ? AND task_id = ?`).get(route.meshId, route.taskId)) : undefined;
          return { disposition: "conflict", code: "PMX.DELIVERY.IDEMPOTENCY_CONFLICT", inbox: prior, ...(priorRoute === undefined ? {} : { route: priorRoute }) };
        }
        const priorRoute = route ? this.routeFromRow(this.db.prepare(`SELECT * FROM task_routes WHERE mesh_id = ? AND task_id = ?`).get(route.meshId, route.taskId)) : undefined;
        const priorOutbox = prior.outboxDeliveryId ? this.outboxFromRow(this.db.prepare(`SELECT * FROM outbox WHERE delivery_id = ?`).get(prior.outboxDeliveryId)) : undefined;
        return { disposition: "duplicate", inbox: prior, ...(priorRoute === undefined ? {} : { route: priorRoute }), ...(priorOutbox === undefined ? {} : { outbox: priorOutbox }) };
      }
      if (route) {
        const existingRoute = this.routeFromRow(this.db.prepare(`SELECT * FROM task_routes WHERE mesh_id = ? AND task_id = ?`).get(route.meshId, route.taskId));
        if (existingRoute) {
          if (existingRoute.immutableFingerprint !== route.immutableFingerprint) {
            return { disposition: "conflict", code: "PMX.TASK.ID_CONFLICT", inbox, route: existingRoute };
          }
          if (!sameRoutePin(existingRoute, route)) {
            return { disposition: "conflict", code: "PMX.TASK.ID_CONFLICT", inbox, route: existingRoute };
          }
          const duplicateInbox = assertIngressTargets(
            { ...inbox, selectedInstanceId: existingRoute.executorInstanceId },
            existingRoute,
            outbox,
          );
          const storedInbox = outbox ? { ...duplicateInbox, outboxDeliveryId: outbox.deliveryId } : duplicateInbox;
          const storedOutbox = outbox === undefined ? undefined : this.enqueueOutboxSync(outbox);
          this.insertInboxSync(storedInbox);
          return {
            disposition: "stored",
            inbox: storedInbox,
            route: existingRoute,
            ...(storedOutbox === undefined ? {} : { outbox: storedOutbox }),
          };
        }
      }
      const storedInbox = outbox ? { ...inbox, outboxDeliveryId: outbox.deliveryId } : inbox;
      if (outbox) {
        const priorOutbox = this.outboxFromRow(this.db.prepare(`SELECT * FROM outbox WHERE delivery_id = ?`).get(outbox.deliveryId));
        if (priorOutbox && !sameOutbox(priorOutbox, outbox)) {
          throw new DurableStoreConflictError("PMX.DELIVERY.IDEMPOTENCY_CONFLICT", "Outbox delivery_id was reused with different immutable content");
        }
      }
      this.insertInboxSync(storedInbox);
      const storedRoute = route ? this.putRouteSync(route) : undefined;
      const storedOutbox = outbox ? this.enqueueOutboxSync(outbox) : undefined;
      return { disposition: "stored", inbox: storedInbox, ...(storedRoute === undefined ? {} : { route: storedRoute }), ...(storedOutbox === undefined ? {} : { outbox: storedOutbox }) };
    });
  }

  async persistExecutorAdmission(input: PersistExecutorAdmissionInput): Promise<PersistExecutorAdmissionResult> {
    const admission = normalizeExecutorAdmission(input);
    return this.immediate(() => {
      const priorInbox = this.inboxFromRow(this.selectInbox(admission.inbox));
      if (priorInbox) {
        if (priorInbox.semanticFingerprint !== admission.inbox.semanticFingerprint) {
          return { disposition: "conflict", code: "PMX.DELIVERY.IDEMPOTENCY_CONFLICT", inbox: priorInbox };
        }
        const executionTask = this.executionTaskFromRow(this.db.prepare(`SELECT * FROM execution_tasks WHERE mesh_id = ? AND task_id = ?`).get(
          admission.inbox.meshId,
          admission.taskId,
        ));
        const event = this.taskEventFromRow(this.selectTaskEvent(admission.inbox.meshId, admission.taskId, 1));
        const outbox = priorInbox.outboxDeliveryId === undefined
          ? undefined
          : this.outboxFromRow(this.db.prepare(`SELECT * FROM outbox WHERE delivery_id = ?`).get(priorInbox.outboxDeliveryId));
        if (!executionTask || !event || !outbox) {
          return {
            disposition: "conflict",
            code: "PMX.TASK.ID_CONFLICT",
            inbox: priorInbox,
            ...(executionTask === undefined ? {} : { executionTask }),
            ...(event === undefined ? {} : { event }),
            ...(outbox === undefined ? {} : { outbox }),
          };
        }
        return { disposition: "duplicate", inbox: priorInbox, executionTask, event, outbox };
      }
      const existingTask = this.executionTaskFromRow(this.db.prepare(`SELECT * FROM execution_tasks WHERE mesh_id = ? AND task_id = ?`).get(
        admission.inbox.meshId,
        admission.taskId,
      ));
      const existingEvent = this.taskEventFromRow(this.selectTaskEvent(admission.inbox.meshId, admission.taskId, 1));
      const existingOutbox = this.outboxFromRow(this.db.prepare(`SELECT * FROM outbox WHERE delivery_id = ?`).get(admission.outbox.deliveryId));
      if (existingTask || existingEvent || existingOutbox) {
        return {
          disposition: "conflict",
          code: "PMX.TASK.ID_CONFLICT",
          inbox: admission.inbox,
          ...(existingTask === undefined ? {} : { executionTask: existingTask }),
          ...(existingEvent === undefined ? {} : { event: existingEvent }),
          ...(existingOutbox === undefined ? {} : { outbox: existingOutbox }),
        };
      }
      this.insertInboxSync(admission.inbox);
      this.insertExecutionTaskSync(admission.executionTask);
      this.insertTaskEventSync(admission.event);
      this.enqueueOutboxSync(admission.outbox);
      return {
        disposition: "stored",
        inbox: admission.inbox,
        executionTask: admission.executionTask,
        event: admission.event,
        outbox: admission.outbox,
      };
    });
  }

  async recover(now = this.clock()): Promise<RecoveryReport> {
    const reclaimedDispatchLeases = await this.reclaimExpiredDispatchLeases(now);
    const expiredInstances = await this.expireInstances(now);
    const reconciledWorkerLeases = await this.reconcileExpiredWorkerLeases(now);
    const pendingOutbox = await this.listDispatchableOutbox(now);
    return { reclaimedDispatchLeases, expiredInstances, reconciledWorkerLeases, pendingOutbox };
  }

  private immediate<T>(operation: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = operation();
      if (result && typeof (result as unknown as { then?: unknown }).then === "function") {
        throw new TypeError("SQLite durable transactions cannot cross an await");
      }
      this.db.exec("COMMIT");
      return result;
    } catch (error) {
      try { this.db.exec("ROLLBACK"); } catch { /* transaction was not opened */ }
      throw error;
    }
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS agent_instances (
        mesh_id TEXT NOT NULL, agent_id TEXT NOT NULL, instance_id TEXT NOT NULL, principal_id TEXT NOT NULL,
        card_json TEXT, card_digest TEXT, card_revision INTEGER, session_id TEXT, lease_id TEXT NOT NULL,
        health TEXT NOT NULL, capacity INTEGER, capacity_weight REAL, registration_fence INTEGER NOT NULL,
        session_fence INTEGER NOT NULL, registered_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL, card_expires_at INTEGER,
        PRIMARY KEY (mesh_id, agent_id, instance_id)
      );
      CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY, owner_broker_node_id TEXT NOT NULL, session_fence INTEGER NOT NULL,
        created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS ingress_inbox (
        scope TEXT NOT NULL, mesh_id TEXT NOT NULL, source_principal_id TEXT NOT NULL,
        source_agent_id TEXT NOT NULL, source_instance_id TEXT NOT NULL, target_agent_id TEXT NOT NULL,
        target_instance_id TEXT NOT NULL DEFAULT '', idempotency_key TEXT NOT NULL, semantic_fingerprint TEXT NOT NULL,
        message_id TEXT NOT NULL, envelope_json TEXT NOT NULL, selected_instance_id TEXT,
        outbox_delivery_id TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
        PRIMARY KEY (scope, mesh_id, source_principal_id, target_agent_id, target_instance_id, idempotency_key)
      );
      CREATE TABLE IF NOT EXISTS task_routes (
        mesh_id TEXT NOT NULL, task_id TEXT NOT NULL, owner_principal_id TEXT NOT NULL,
        owner_agent_id TEXT NOT NULL, owner_instance_id TEXT NOT NULL, owner_session_id TEXT,
        executor_principal_id TEXT NOT NULL, executor_agent_id TEXT NOT NULL, executor_instance_id TEXT NOT NULL,
        executor_session_id TEXT, immutable_fingerprint TEXT NOT NULL, deadline_at INTEGER NOT NULL,
        route_fence INTEGER NOT NULL, state TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
        retained_until INTEGER NOT NULL, PRIMARY KEY (mesh_id, task_id)
      );
      CREATE TABLE IF NOT EXISTS execution_tasks (
        mesh_id TEXT NOT NULL, task_id TEXT NOT NULL, state TEXT NOT NULL, worker_lease_id TEXT,
        worker_fence INTEGER, worker_lease_expires_at INTEGER, cancellation_requested_at INTEGER, terminal_at INTEGER, external_idempotency_key TEXT,
        updated_at INTEGER NOT NULL, retained_until INTEGER NOT NULL, PRIMARY KEY (mesh_id, task_id)
      );
      CREATE TABLE IF NOT EXISTS task_events (
        mesh_id TEXT NOT NULL, task_id TEXT NOT NULL, event_seq INTEGER NOT NULL, event_json TEXT NOT NULL,
        created_at INTEGER NOT NULL, PRIMARY KEY (mesh_id, task_id, event_seq)
      );
      CREATE TABLE IF NOT EXISTS outbox (
        delivery_id TEXT PRIMARY KEY, mesh_id TEXT NOT NULL, target_agent_id TEXT NOT NULL,
        target_instance_id TEXT NOT NULL DEFAULT '', envelope_json TEXT NOT NULL, state TEXT NOT NULL,
        dispatch_lease_id TEXT, dispatch_lease_expires_at INTEGER, attempt INTEGER NOT NULL,
        receipt_state TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS cancellation_tombstones (
        mesh_id TEXT NOT NULL, task_id TEXT NOT NULL, owner_principal_id TEXT NOT NULL,
        created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY (mesh_id, task_id)
      );
      CREATE INDEX IF NOT EXISTS idx_outbox_dispatch ON outbox (state, expires_at, created_at);
      CREATE INDEX IF NOT EXISTS idx_agent_instances_live ON agent_instances (mesh_id, agent_id, expires_at);
      CREATE INDEX IF NOT EXISTS idx_execution_tasks_recovery ON execution_tasks (terminal_at, worker_lease_expires_at);
    `);
    // A pre-release v0.2 database may have been created before worker lease
    // expiry was tracked. Keep this additive migration idempotent so opening
    // it cannot strand already durable ingress/outbox facts.
    this.ensureColumn("execution_tasks", "worker_lease_expires_at", "INTEGER");
  }

  private ensureColumn(table: "execution_tasks", column: "worker_lease_expires_at", declaration: string): void {
    const columns = this.db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name?: unknown }>;
    if (columns.some((entry) => entry.name === column)) return;
    this.db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${declaration}`);
  }

  private upsertInstanceSync(record: DurableAgentInstance): DurableAgentInstance {
    const current = this.instanceFromRow(this.db.prepare(
      `SELECT * FROM agent_instances WHERE mesh_id = ? AND agent_id = ? AND instance_id = ?`,
    ).get(record.meshId, record.agentId, record.instanceId));
    if (!canApplyInstanceWrite(current, record)) return current!;
    this.db.prepare(`INSERT INTO agent_instances
      (mesh_id, agent_id, instance_id, principal_id, card_json, card_digest, card_revision, session_id, lease_id,
       health, capacity, capacity_weight, registration_fence, session_fence, registered_at, updated_at, expires_at, card_expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(mesh_id, agent_id, instance_id) DO UPDATE SET
       principal_id = excluded.principal_id, card_json = excluded.card_json, card_digest = excluded.card_digest,
       card_revision = excluded.card_revision, session_id = excluded.session_id, lease_id = excluded.lease_id,
       health = excluded.health, capacity = excluded.capacity, capacity_weight = excluded.capacity_weight,
       registration_fence = excluded.registration_fence, session_fence = excluded.session_fence,
       updated_at = excluded.updated_at, expires_at = excluded.expires_at, card_expires_at = excluded.card_expires_at
      `).run(
      record.meshId, record.agentId, record.instanceId, record.principalId, json(record.card), record.cardDigest ?? null,
      record.cardRevision ?? null, record.sessionId ?? null, record.leaseId, record.health, record.capacity ?? null,
      record.capacityWeight ?? null, record.registrationFence, record.sessionFence, record.registeredAt, record.updatedAt,
      record.expiresAt, record.cardExpiresAt ?? null,
    );
    return this.instanceFromRow(this.db.prepare(`SELECT * FROM agent_instances WHERE mesh_id = ? AND agent_id = ? AND instance_id = ?`).get(record.meshId, record.agentId, record.instanceId))!;
  }

  private upsertSessionSync(record: DurableSession): DurableSession {
    const current = this.sessionFromRow(this.db.prepare(`SELECT * FROM sessions WHERE session_id = ?`).get(record.sessionId));
    if (!canApplySessionWrite(current, record)) return current!;
    this.db.prepare(`INSERT INTO sessions (session_id, owner_broker_node_id, session_fence, created_at, updated_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(session_id) DO UPDATE SET owner_broker_node_id = excluded.owner_broker_node_id,
        session_fence = excluded.session_fence, updated_at = excluded.updated_at, expires_at = excluded.expires_at`).run(
      record.sessionId, record.ownerBrokerNodeId, record.sessionFence, record.createdAt, record.updatedAt, record.expiresAt,
    );
    return this.sessionFromRow(this.db.prepare(`SELECT * FROM sessions WHERE session_id = ?`).get(record.sessionId))!;
  }

  private selectInbox(input: InboxIdentity): unknown {
    // Keep lookup validation aligned with insertion: executor dedupe is never
    // allowed to collapse onto a logical target with no physical instance.
    void inboxKey(input);
    return this.db.prepare(`SELECT * FROM ingress_inbox WHERE scope = ? AND mesh_id = ? AND source_principal_id = ? AND target_agent_id = ? AND target_instance_id = ? AND idempotency_key = ?`).get(
      input.scope, input.meshId, input.sourcePrincipalId, input.targetAgentId, input.targetInstanceId ?? "", input.idempotencyKey,
    );
  }

  private putInboxSync(record: InboxRecord): InboxPutResult {
    const prior = this.inboxFromRow(this.selectInbox(record));
    if (prior) return prior.semanticFingerprint === record.semanticFingerprint
      ? { disposition: "duplicate", record: prior }
      : { disposition: "conflict", record: prior };
    this.insertInboxSync(record);
    return { disposition: "stored", record: clone(record) };
  }

  private insertInboxSync(record: InboxRecord): void {
    this.db.prepare(`INSERT INTO ingress_inbox
      (scope, mesh_id, source_principal_id, source_agent_id, source_instance_id, target_agent_id, target_instance_id,
       idempotency_key, semantic_fingerprint, message_id, envelope_json, selected_instance_id, outbox_delivery_id, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      record.scope, record.meshId, record.sourcePrincipalId, record.sourceAgentId, record.sourceInstanceId,
      record.targetAgentId, record.targetInstanceId ?? "", record.idempotencyKey, record.semanticFingerprint,
      record.messageId, JSON.stringify(record.envelope), record.selectedInstanceId ?? null, record.outboxDeliveryId ?? null,
      record.createdAt, record.expiresAt,
    );
  }

  private selectTaskEvent(meshId: string, taskId: string, eventSeq: number): unknown {
    return this.db.prepare(`SELECT * FROM task_events WHERE mesh_id = ? AND task_id = ? AND event_seq = ?`).get(
      meshId,
      taskId,
      eventSeq,
    );
  }

  private insertExecutionTaskSync(record: ExecutionTaskRecord): void {
    this.db.prepare(`INSERT INTO execution_tasks
      (mesh_id, task_id, state, worker_lease_id, worker_fence, worker_lease_expires_at, cancellation_requested_at, terminal_at, external_idempotency_key, updated_at, retained_until)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      record.meshId,
      record.taskId,
      record.state,
      record.workerLeaseId ?? null,
      record.workerFence ?? null,
      record.workerLeaseExpiresAt ?? null,
      record.cancellationRequestedAt ?? null,
      record.terminalAt ?? null,
      record.externalIdempotencyKey ?? null,
      record.updatedAt,
      record.retainedUntil,
    );
  }

  private insertTaskEventSync(record: TaskEventRecord): void {
    this.db.prepare(`INSERT INTO task_events (mesh_id, task_id, event_seq, event_json, created_at) VALUES (?, ?, ?, ?, ?)`).run(
      record.meshId,
      record.taskId,
      record.eventSeq,
      JSON.stringify(record.event),
      record.createdAt,
    );
  }

  private putRouteSync(record: DurableTaskRoute): DurableTaskRoute {
    const prior = this.routeFromRow(this.db.prepare(`SELECT * FROM task_routes WHERE mesh_id = ? AND task_id = ?`).get(record.meshId, record.taskId));
    if (prior) {
      if (prior.immutableFingerprint !== record.immutableFingerprint) throw new Error("PMX.TASK.ID_CONFLICT");
      return prior;
    }
    this.db.prepare(`INSERT INTO task_routes
      (mesh_id, task_id, owner_principal_id, owner_agent_id, owner_instance_id, owner_session_id,
       executor_principal_id, executor_agent_id, executor_instance_id, executor_session_id, immutable_fingerprint,
       deadline_at, route_fence, state, created_at, updated_at, retained_until)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      record.meshId, record.taskId, record.ownerPrincipalId, record.ownerAgentId, record.ownerInstanceId,
      record.ownerSessionId ?? null, record.executorPrincipalId, record.executorAgentId, record.executorInstanceId,
      record.executorSessionId ?? null, record.immutableFingerprint, record.deadlineAt, record.routeFence,
      record.state, record.createdAt, record.updatedAt, record.retainedUntil,
    );
    return clone(record);
  }

  private enqueueOutboxSync(record: OutboxRecord): OutboxRecord {
    const prior = this.outboxFromRow(this.db.prepare(`SELECT * FROM outbox WHERE delivery_id = ?`).get(record.deliveryId));
    if (prior) {
      if (!sameOutbox(prior, record)) {
        throw new DurableStoreConflictError("PMX.DELIVERY.IDEMPOTENCY_CONFLICT", "Outbox delivery_id was reused with different immutable content");
      }
      return prior;
    }
    this.db.prepare(`INSERT INTO outbox
      (delivery_id, mesh_id, target_agent_id, target_instance_id, envelope_json, state, dispatch_lease_id,
       dispatch_lease_expires_at, attempt, receipt_state, created_at, updated_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      record.deliveryId, record.meshId, record.targetAgentId, record.targetInstanceId ?? "", JSON.stringify(record.envelope),
      record.state, record.dispatchLeaseId ?? null, record.dispatchLeaseExpiresAt ?? null, record.attempt,
      record.receiptState ?? null, record.createdAt, record.updatedAt, record.expiresAt,
    );
    return clone(record);
  }

  private assertNoIdentityCollisionSync(record: DurableAgentInstance): void {
    const collision = this.db.prepare(`SELECT 1 FROM agent_instances
      WHERE mesh_id = ? AND agent_id = ? AND principal_id <> ? AND expires_at > ?
      LIMIT 1`).get(record.meshId, record.agentId, record.principalId, record.updatedAt);
    if (collision) {
      throw new DurableStoreConflictError("IDENTITY_COLLISION", "A live logical agent cannot be owned by multiple principals");
    }
  }

  private instanceFromRow(row: unknown): DurableAgentInstance | undefined {
    if (!row || typeof row !== "object") return undefined;
    const value = row as Record<string, unknown>;
    return {
      meshId: String(value.mesh_id), agentId: String(value.agent_id), instanceId: String(value.instance_id), principalId: String(value.principal_id),
      ...(parseJson(value.card_json) === undefined ? {} : { card: parseJson(value.card_json)! }),
      ...(value.card_digest === null || value.card_digest === undefined ? {} : { cardDigest: String(value.card_digest) }),
      ...(value.card_revision === null || value.card_revision === undefined ? {} : { cardRevision: Number(value.card_revision) }),
      ...(value.session_id === null || value.session_id === undefined ? {} : { sessionId: String(value.session_id) }),
      leaseId: String(value.lease_id), health: String(value.health) as InstanceHealth,
      ...(value.capacity === null || value.capacity === undefined ? {} : { capacity: Number(value.capacity) }),
      ...(value.capacity_weight === null || value.capacity_weight === undefined ? {} : { capacityWeight: Number(value.capacity_weight) }),
      registrationFence: Number(value.registration_fence), sessionFence: Number(value.session_fence),
      registeredAt: Number(value.registered_at), updatedAt: Number(value.updated_at), expiresAt: Number(value.expires_at),
      ...(value.card_expires_at === null || value.card_expires_at === undefined ? {} : { cardExpiresAt: Number(value.card_expires_at) }),
    };
  }

  private sessionFromRow(row: unknown): DurableSession | undefined {
    if (!row || typeof row !== "object") return undefined;
    const value = row as Record<string, unknown>;
    return { sessionId: String(value.session_id), ownerBrokerNodeId: String(value.owner_broker_node_id), sessionFence: Number(value.session_fence), createdAt: Number(value.created_at), updatedAt: Number(value.updated_at), expiresAt: Number(value.expires_at) };
  }

  private inboxFromRow(row: unknown): InboxRecord | undefined {
    if (!row || typeof row !== "object") return undefined;
    const value = row as Record<string, unknown>;
    const envelope = parseJson(value.envelope_json);
    if (!envelope) throw new TypeError("Stored inbox envelope is invalid");
    return {
      scope: value.scope === "executor" ? "executor" : "ingress", meshId: String(value.mesh_id), sourcePrincipalId: String(value.source_principal_id),
      sourceAgentId: String(value.source_agent_id), sourceInstanceId: String(value.source_instance_id), targetAgentId: String(value.target_agent_id),
      ...(value.target_instance_id ? { targetInstanceId: String(value.target_instance_id) } : {}), idempotencyKey: String(value.idempotency_key),
      semanticFingerprint: String(value.semantic_fingerprint), messageId: String(value.message_id), envelope,
      ...(value.selected_instance_id ? { selectedInstanceId: String(value.selected_instance_id) } : {}),
      ...(value.outbox_delivery_id ? { outboxDeliveryId: String(value.outbox_delivery_id) } : {}),
      createdAt: Number(value.created_at), expiresAt: Number(value.expires_at),
    };
  }

  private routeFromRow(row: unknown): DurableTaskRoute | undefined {
    if (!row || typeof row !== "object") return undefined;
    const value = row as Record<string, unknown>;
    return {
      meshId: String(value.mesh_id), taskId: String(value.task_id), ownerPrincipalId: String(value.owner_principal_id), ownerAgentId: String(value.owner_agent_id),
      ownerInstanceId: String(value.owner_instance_id), ...(value.owner_session_id ? { ownerSessionId: String(value.owner_session_id) } : {}),
      executorPrincipalId: String(value.executor_principal_id), executorAgentId: String(value.executor_agent_id), executorInstanceId: String(value.executor_instance_id),
      ...(value.executor_session_id ? { executorSessionId: String(value.executor_session_id) } : {}), immutableFingerprint: String(value.immutable_fingerprint),
      deadlineAt: Number(value.deadline_at), routeFence: Number(value.route_fence), state: String(value.state), createdAt: Number(value.created_at),
      updatedAt: Number(value.updated_at), retainedUntil: Number(value.retained_until),
    };
  }

  private executionTaskFromRow(row: unknown): ExecutionTaskRecord | undefined {
    if (!row || typeof row !== "object") return undefined;
    const value = row as Record<string, unknown>;
    return {
      meshId: String(value.mesh_id), taskId: String(value.task_id), state: String(value.state),
      ...(value.worker_lease_id ? { workerLeaseId: String(value.worker_lease_id) } : {}),
      ...(value.worker_fence === null || value.worker_fence === undefined ? {} : { workerFence: Number(value.worker_fence) }),
      ...(value.worker_lease_expires_at === null || value.worker_lease_expires_at === undefined ? {} : { workerLeaseExpiresAt: Number(value.worker_lease_expires_at) }),
      ...(value.cancellation_requested_at === null || value.cancellation_requested_at === undefined ? {} : { cancellationRequestedAt: Number(value.cancellation_requested_at) }),
      ...(value.terminal_at === null || value.terminal_at === undefined ? {} : { terminalAt: Number(value.terminal_at) }),
      ...(value.external_idempotency_key ? { externalIdempotencyKey: String(value.external_idempotency_key) } : {}),
      updatedAt: Number(value.updated_at), retainedUntil: Number(value.retained_until),
    };
  }

  private taskEventFromRow(row: unknown): TaskEventRecord | undefined {
    if (!row || typeof row !== "object") return undefined;
    const value = row as Record<string, unknown>;
    const event = parseJson(value.event_json);
    if (!event) throw new TypeError("Stored task event is invalid");
    return { meshId: String(value.mesh_id), taskId: String(value.task_id), eventSeq: Number(value.event_seq), event, createdAt: Number(value.created_at) };
  }

  private outboxFromRow(row: unknown): OutboxRecord | undefined {
    if (!row || typeof row !== "object") return undefined;
    const value = row as Record<string, unknown>;
    const envelope = parseJson(value.envelope_json);
    if (!envelope) throw new TypeError("Stored outbox envelope is invalid");
    return {
      deliveryId: String(value.delivery_id), meshId: String(value.mesh_id), targetAgentId: String(value.target_agent_id),
      ...(value.target_instance_id ? { targetInstanceId: String(value.target_instance_id) } : {}), envelope,
      state: String(value.state) as OutboxState, ...(value.dispatch_lease_id ? { dispatchLeaseId: String(value.dispatch_lease_id) } : {}),
      ...(value.dispatch_lease_expires_at === null || value.dispatch_lease_expires_at === undefined ? {} : { dispatchLeaseExpiresAt: Number(value.dispatch_lease_expires_at) }),
      attempt: Number(value.attempt), ...(value.receipt_state ? { receiptState: String(value.receipt_state) as "stored" | "delivered" } : {}),
      createdAt: Number(value.created_at), updatedAt: Number(value.updated_at), expiresAt: Number(value.expires_at),
    };
  }

  private cancellationFromRow(row: unknown): CancellationTombstone | undefined {
    if (!row || typeof row !== "object") return undefined;
    const value = row as Record<string, unknown>;
    return { meshId: String(value.mesh_id), taskId: String(value.task_id), ownerPrincipalId: String(value.owner_principal_id), createdAt: Number(value.created_at), expiresAt: Number(value.expires_at) };
  }
}

/**
 * Durable replay and idempotency admission primitives.
 *
 * The client deliberately keeps this interface small: a production adapter
 * owns its database transaction and calls `admit` as one atomic operation
 * before work starts.  In particular, keys are derived from a verified stable
 * principal (normally an enrolled key ID), never from `instance_id`.
 */
import {
  canonicalize,
  parseStrictJson,
  sha256,
  type AgentIdentity,
  type AgentRef,
  type Envelope,
  type JsonValue,
} from "@polymesh/broker";

export interface ReplayPrincipal {
  /** Stable authenticated principal, such as `key:<key-id>` or `uid:1000`. */
  principalId: string;
  /** Optional enrolled key ID.  When supplied it is the preferred stable key. */
  keyId?: string;
}

export interface ReplayLedgerKeys {
  /** `(principal, target, protocol, type, message_id)` namespace. */
  message: string;
  /** `(principal, target, protocol, type, idempotency_key)` namespace. */
  idempotency: string;
  /** `(principal, target, protocol, type, task_id)` namespace. */
  task: string;
}

export interface ReplayArtifacts {
  /** Canonical, recipient-filtered lifecycle artifacts suitable for replay. */
  events: readonly Envelope[];
  /** True once a terminal outcome has been committed. */
  terminal: boolean;
}

export interface ReplayLedgerRecord {
  keys: ReplayLedgerKeys;
  principal: ReplayPrincipal;
  target: AgentIdentity;
  protocol: string;
  type: string;
  taskId: string;
  /** Digest of semantic envelope content, excluding volatile message metadata. */
  semanticDigest: string;
  /** Digest of immutable task content used for task-ID conflict detection. */
  taskDigest: string;
  admittedAt: number;
  expiresAt: number;
  artifacts: ReplayArtifacts;
}

export interface ReplayAdmission {
  principal: ReplayPrincipal;
  target: AgentIdentity;
  envelope: Envelope<"task.submit">;
  taskId: string;
  /** Retain at least until task/result retention expires. */
  expiresAt: number;
  now: number;
}

export type ReplayAdmissionResult =
  | { disposition: "new"; record: ReplayLedgerRecord }
  | { disposition: "duplicate"; record: ReplayLedgerRecord }
  | { disposition: "message-conflict"; record: ReplayLedgerRecord }
  | { disposition: "idempotency-conflict"; record: ReplayLedgerRecord }
  | { disposition: "task-conflict"; record: ReplayLedgerRecord }
  | { disposition: "overloaded" };

export interface ReplayArtifactUpdate {
  /** The `record.keys.task` returned by `admit`. */
  taskKey: string;
  artifacts: ReplayArtifacts;
  /** Terminal tombstones must live through the full result-retention window. */
  expiresAt: number;
}

/**
 * A store must make `admit` atomic with respect to all three key namespaces.
 * `durable` is a capability declaration used by secure/enrolled execution to
 * fail closed when a process-local cache is all that is available.
 */
export interface ReplayLedger {
  readonly durable: boolean;
  admit(admission: ReplayAdmission): Promise<ReplayAdmissionResult>;
  recordArtifacts(update: ReplayArtifactUpdate): Promise<void>;
  prune?(now: number): Promise<void>;
}

export interface InMemoryReplayLedgerOptions {
  now?: () => number;
  maxRecords?: number;
  /**
   * Test-only switch for adapters that exercise the durable-required branch.
   * It does not make memory survive a process restart and must not be used in
   * production as a durable store.
   */
  durableForTesting?: boolean;
}

function isNonEmptyString(value: unknown, maximum = 1024): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maximum;
}

export function isReplayPrincipal(value: unknown): value is ReplayPrincipal {
  return typeof value === "object" && value !== null && !Array.isArray(value) &&
    isNonEmptyString((value as ReplayPrincipal).principalId, 512) &&
    ((value as ReplayPrincipal).keyId === undefined || isNonEmptyString((value as ReplayPrincipal).keyId, 512));
}

function stablePrincipalId(principal: ReplayPrincipal): string {
  return principal.keyId === undefined ? principal.principalId : `key:${principal.keyId}`;
}

function keyMaterial(
  namespace: "message" | "idempotency" | "task",
  principal: ReplayPrincipal,
  target: AgentIdentity,
  envelope: Envelope<"task.submit">,
  value: string,
): string {
  return sha256(canonicalize({
    namespace,
    principal: stablePrincipalId(principal),
    target: { agent_id: target.agent_id, instance_id: target.instance_id },
    protocol: envelope.protocol,
    type: envelope.type,
    value,
  }));
}

export function replayLedgerKeys(admission: Pick<ReplayAdmission, "principal" | "target" | "envelope" | "taskId">): ReplayLedgerKeys {
  const { principal, target, envelope, taskId } = admission;
  return {
    message: keyMaterial("message", principal, target, envelope, envelope.message_id),
    idempotency: keyMaterial("idempotency", principal, target, envelope, envelope.delivery.idempotency_key),
    task: keyMaterial("task", principal, target, envelope, taskId),
  };
}

/**
 * Semantic content deliberately excludes `message_id`, `timestamp`, and
 * `source.instance_id`: delivery retries and legitimate restarts may change
 * those volatile fields without gaining a second execution.
 */
export function replaySemanticDigest(envelope: Envelope<"task.submit">): string {
  return sha256(canonicalize({
    protocol: envelope.protocol,
    type: envelope.type,
    source: { agent_id: envelope.source.agent_id },
    target: envelope.target.instance_id === undefined
      ? { agent_id: envelope.target.agent_id }
      : { agent_id: envelope.target.agent_id, instance_id: envelope.target.instance_id },
    delivery: { mode: envelope.delivery.mode, deadline: envelope.delivery.deadline ?? null },
    params: envelope.params,
  } as JsonValue));
}

export function replayTaskDigest(envelope: Envelope<"task.submit">): string {
  const params = envelope.params as Record<string, JsonValue>;
  return sha256(canonicalize({
    task_id: params.task_id,
    method: params.method,
    capability_version: params.capability_version,
    capability_contract_digest: params.capability_contract_digest,
    params: params.params,
    deadline: params.deadline,
  } as JsonValue));
}

function cloneEnvelopeList(events: readonly Envelope[]): Envelope[] {
  const parsed = parseStrictJson(canonicalize(events as unknown as JsonValue));
  if (!parsed.ok || !Array.isArray(parsed.value)) throw new TypeError("Replay artifacts must be bounded JSON envelopes");
  return parsed.value as unknown as Envelope[];
}

function cloneRecord(record: ReplayLedgerRecord): ReplayLedgerRecord {
  return {
    ...record,
    keys: { ...record.keys },
    principal: { ...record.principal },
    target: { ...record.target },
    artifacts: {
      terminal: record.artifacts.terminal,
      events: cloneEnvelopeList(record.artifacts.events),
    },
  };
}

/**
 * Deterministic process-local ledger for unit tests and local development.
 * It implements the same atomic admission semantics as a database adapter,
 * but advertises `durable: false` unless an explicit test-only switch is set.
 */
export class InMemoryReplayLedger implements ReplayLedger {
  readonly durable: boolean;
  private readonly now: () => number;
  private readonly maxRecords: number;
  private readonly byMessage = new Map<string, ReplayLedgerRecord>();
  private readonly byIdempotency = new Map<string, ReplayLedgerRecord>();
  private readonly byTask = new Map<string, ReplayLedgerRecord>();

  constructor(options: InMemoryReplayLedgerOptions = {}) {
    this.now = options.now ?? Date.now;
    this.maxRecords = options.maxRecords ?? 1_024;
    this.durable = options.durableForTesting === true;
    if (!Number.isSafeInteger(this.maxRecords) || this.maxRecords < 1) {
      throw new RangeError("maxRecords must be a positive safe integer");
    }
  }

  async admit(admission: ReplayAdmission): Promise<ReplayAdmissionResult> {
    this.pruneNow(admission.now);
    if (!isReplayPrincipal(admission.principal) || !isNonEmptyString(admission.taskId, 256) ||
      !isNonEmptyString(admission.target.agent_id, 512) || !isNonEmptyString(admission.target.instance_id, 512) ||
      !Number.isFinite(admission.now) || !Number.isFinite(admission.expiresAt) || admission.expiresAt < admission.now) {
      throw new TypeError("Invalid replay ledger admission");
    }
    const keys = replayLedgerKeys(admission);
    const semanticDigest = replaySemanticDigest(admission.envelope);
    const taskDigest = replayTaskDigest(admission.envelope);
    const message = this.byMessage.get(keys.message);
    if (message) {
      return message.semanticDigest === semanticDigest
        ? { disposition: "duplicate", record: cloneRecord(message) }
        : { disposition: "message-conflict", record: cloneRecord(message) };
    }
    const idempotency = this.byIdempotency.get(keys.idempotency);
    if (idempotency) {
      return idempotency.semanticDigest === semanticDigest
        ? { disposition: "duplicate", record: cloneRecord(idempotency) }
        : { disposition: "idempotency-conflict", record: cloneRecord(idempotency) };
    }
    const task = this.byTask.get(keys.task);
    if (task) {
      return task.taskDigest === taskDigest
        ? { disposition: "duplicate", record: cloneRecord(task) }
        : { disposition: "task-conflict", record: cloneRecord(task) };
    }
    if (this.byTask.size >= this.maxRecords) return { disposition: "overloaded" };

    const record: ReplayLedgerRecord = {
      keys,
      principal: { ...admission.principal },
      target: { agent_id: admission.target.agent_id, instance_id: admission.target.instance_id },
      protocol: admission.envelope.protocol,
      type: admission.envelope.type,
      taskId: admission.taskId,
      semanticDigest,
      taskDigest,
      admittedAt: admission.now,
      expiresAt: admission.expiresAt,
      artifacts: { events: [], terminal: false },
    };
    // These three writes have no await boundary: they are one logical atomic
    // admission in this test implementation.
    this.byMessage.set(keys.message, record);
    this.byIdempotency.set(keys.idempotency, record);
    this.byTask.set(keys.task, record);
    return { disposition: "new", record: cloneRecord(record) };
  }

  async recordArtifacts(update: ReplayArtifactUpdate): Promise<void> {
    if (!isNonEmptyString(update.taskKey, 128) || !Number.isFinite(update.expiresAt)) {
      throw new TypeError("Invalid replay artifact update");
    }
    const record = this.byTask.get(update.taskKey);
    if (!record) throw new Error("Replay record was not found");
    const events = cloneEnvelopeList(update.artifacts.events);
    record.artifacts = { events, terminal: update.artifacts.terminal === true };
    record.expiresAt = Math.max(record.expiresAt, update.expiresAt);
  }

  async prune(now = this.now()): Promise<void> {
    this.pruneNow(now);
  }

  /** Snapshot is intentionally test-oriented and returns defensive copies. */
  snapshot(): readonly ReplayLedgerRecord[] {
    this.pruneNow(this.now());
    return [...this.byTask.values()].map(cloneRecord);
  }

  private pruneNow(now: number): void {
    if (!Number.isFinite(now)) throw new RangeError("Replay ledger clock returned a non-finite value");
    for (const [taskKey, record] of this.byTask) {
      if (record.expiresAt > now) continue;
      this.byTask.delete(taskKey);
      if (this.byMessage.get(record.keys.message) === record) this.byMessage.delete(record.keys.message);
      if (this.byIdempotency.get(record.keys.idempotency) === record) this.byIdempotency.delete(record.keys.idempotency);
    }
  }
}

/**
 * Converts a policy-style verified principal to the narrow replay identity
 * shape without coupling this module to the policy engine.
 */
export function replayPrincipalFromVerified(value: {
  principalId: string;
  keyId?: string;
}): ReplayPrincipal | undefined {
  const principal: ReplayPrincipal = {
    principalId: value.principalId,
    ...(value.keyId === undefined ? {} : { keyId: value.keyId }),
  };
  return isReplayPrincipal(principal) ? principal : undefined;
}

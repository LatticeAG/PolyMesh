/**
 * A deliberately small, in-memory registry used by the reference broker.
 *
 * The registry owns leases, rather than merely keeping a `Map`, so a close
 * event from an old connection cannot accidentally remove a newer connection
 * which reused the same agent id.  It has no timers of its own: callers may
 * call `cleanup()` periodically, while all read operations also discard stale
 * records.  This makes it deterministic (and easy to test) with an injected
 * clock.
 */

import { randomBytes } from "node:crypto";

import type { JsonObject } from "./protocol.js";
import type { DurableAgentInstance, DurableRegistration, DurableSession, RegistryStore } from "./durable-store.js";
import { HealthState, type HealthState as InstanceHealth } from "./routing.js";

export type RegistryClock = () => number;

export interface RegistryOptions {
  /** Lease duration in milliseconds. Defaults to the discovery lease (120 s). */
  ttlMs?: number;
  /** Alias for `clock`, retained for ergonomic tests. */
  now?: RegistryClock;
  clock?: RegistryClock;
  leaseId?: () => string;
}

export interface RegistryEntry<TTransport = unknown, TCard = unknown> {
  agentId: string;
  instanceId: string;
  /** Wire-session id that installed this record. */
  sessionId?: string;
  /** Opaque, unique handle used for safe renewals/removals. */
  leaseId: string;
  card?: TCard;
  transport?: TTransport;
  registeredAt: number;
  expiresAt: number;
}

/** Input accepted by `register`. Snake-case identity keys are accepted too. */
export interface RegistryRegistration<TTransport = unknown, TCard = unknown> {
  agentId?: string;
  agent_id?: string;
  instanceId?: string;
  instance_id?: string;
  sessionId?: string;
  session_id?: string;
  leaseId?: string;
  lease_id?: string;
  card?: TCard;
  transport?: TTransport;
}

/**
 * Options for the opt-in v0.2 registry. The inherited Registry remains the
 * lightweight, single-process implementation; this subclass stores durable
 * identity/lease facts while keeping socket handles only in a local index.
 */
export interface DurableRegistryOptions extends RegistryOptions {
  store: RegistryStore;
  meshId: string;
  /** Optional default authenticated principal for registrations. */
  principalId?: string;
}

export interface DurableRegistryRegistration<TTransport = unknown, TCard = unknown>
  extends RegistryRegistration<TTransport, TCard> {
  meshId?: string;
  principalId?: string;
  registrationFence?: number;
  sessionFence?: number;
  health?: InstanceHealth;
  capacity?: number;
  capacityWeight?: number;
  cardDigest?: string;
  cardRevision?: number;
  cardExpiresAt?: number;
  ownerBrokerNodeId?: string;
  sessionExpiresAt?: number;
}

/** Durable registration fact augmented with a process-local connection. */
export interface DurableRegistryEntry<TTransport = unknown, TCard = unknown>
  extends Omit<DurableAgentInstance, "card"> {
  card?: TCard;
  transport?: TTransport;
}

export interface DurableRegistryRemoval {
  meshId?: string;
  agentId: string;
  instanceId: string;
  registrationFence: number;
  sessionFence: number;
}

export interface DurableRegistryRenewal extends DurableRegistryRemoval {
  expiresAt?: number;
  health?: InstanceHealth;
}

export type RegistryMatch<TTransport = unknown> =
  | string
  | Pick<Partial<RegistryEntry<TTransport>>, "sessionId" | "instanceId" | "leaseId" | "transport">;

export class DuplicateAgentError extends Error {
  readonly agentId: string;

  constructor(agentId: string) {
    super(`Agent '${agentId}' is already registered`);
    this.name = "DuplicateAgentError";
    this.agentId = agentId;
  }
}

export class InvalidRegistrationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidRegistrationError";
  }
}

/** A logical agent cannot be shared by unrelated authenticated principals. */
export class DurableIdentityCollisionError extends Error {
  readonly meshId: string;
  readonly agentId: string;

  constructor(meshId: string, agentId: string) {
    super(`Agent '${agentId}' in mesh '${meshId}' is already bound to a different principal`);
    this.name = "DurableIdentityCollisionError";
    this.meshId = meshId;
    this.agentId = agentId;
  }
}

const DEFAULT_TTL_MS = 120_000;

function defaultLeaseId(): string {
  return randomBytes(18).toString("base64url");
}

function normalizeRegistration<TTransport, TCard>(
  input: RegistryRegistration<TTransport, TCard>,
): Required<Pick<RegistryRegistration<TTransport, TCard>, "agentId" | "instanceId">> &
  RegistryRegistration<TTransport, TCard> {
  const agentId = input.agentId ?? input.agent_id;
  const instanceId = input.instanceId ?? input.instance_id;
  if (typeof agentId !== "string" || agentId.length === 0) {
    throw new InvalidRegistrationError("agentId is required");
  }
  if (typeof instanceId !== "string" || instanceId.length === 0) {
    throw new InvalidRegistrationError("instanceId is required");
  }
  return { ...input, agentId, instanceId };
}

/**
 * Lease-based agent registry.  Agent IDs are unique while their lease is live.
 * A caller may refresh its own record by registering again with the same lease
 * or session id; a different live connection receives DuplicateAgentError.
 */
export class Registry<TTransport = unknown, TCard = unknown> {
  readonly ttlMs: number;
  private readonly clock: RegistryClock;
  private readonly makeLeaseId: () => string;
  private readonly records = new Map<string, RegistryEntry<TTransport, TCard>>();

  constructor(options: RegistryOptions | number | RegistryClock = {}) {
    const normalized: RegistryOptions =
      typeof options === "number"
        ? { ttlMs: options }
        : typeof options === "function"
          ? { clock: options }
          : options;
    this.ttlMs = normalized.ttlMs ?? DEFAULT_TTL_MS;
    if (!Number.isFinite(this.ttlMs) || this.ttlMs <= 0) {
      throw new RangeError("ttlMs must be a positive finite number");
    }
    this.clock = normalized.clock ?? normalized.now ?? Date.now;
    this.makeLeaseId = normalized.leaseId ?? defaultLeaseId;
  }

  /** Number of live records (also removes expired records). */
  get size(): number {
    this.cleanup();
    return this.records.size;
  }

  /**
   * Register an agent.  Either pass a registration object or an id plus the
   * remaining fields.  The overload is convenient for the tiny reference API
   * and keeps compatibility with direct registry tests.
   */
  register(entry: RegistryRegistration<TTransport, TCard>): RegistryEntry<TTransport, TCard>;
  register(
    agentId: string,
    entry: Omit<RegistryRegistration<TTransport, TCard>, "agentId" | "agent_id">,
  ): RegistryEntry<TTransport, TCard>;
  register(
    first: string | RegistryRegistration<TTransport, TCard>,
    second?: Omit<RegistryRegistration<TTransport, TCard>, "agentId" | "agent_id">,
  ): RegistryEntry<TTransport, TCard> {
    const candidate = normalizeRegistration<TTransport, TCard>(
      typeof first === "string" ? { ...second, agentId: first } : first,
    );
    const now = this.now();
    this.cleanup(now);

    const existing = this.records.get(candidate.agentId);
    const sessionId = candidate.sessionId ?? candidate.session_id;
    const requestedLease = candidate.leaseId ?? candidate.lease_id;
    if (existing && !this.isSameRegistration(existing, { sessionId, leaseId: requestedLease })) {
      throw new DuplicateAgentError(candidate.agentId);
    }

    const record: RegistryEntry<TTransport, TCard> = {
      agentId: candidate.agentId,
      instanceId: candidate.instanceId,
      sessionId,
      // Preserve a self-renewed lease.  A re-register with a known session is
      // also treated as a renewal so connection setup can be idempotent.
      leaseId: requestedLease ?? existing?.leaseId ?? this.makeLeaseId(),
      card: candidate.card,
      transport: candidate.transport,
      registeredAt: existing?.registeredAt ?? now,
      expiresAt: now + this.ttlMs,
    };
    this.records.set(record.agentId, record);
    return record;
  }

  /** Return false instead of throwing when the agent id is already live. */
  tryRegister(entry: RegistryRegistration<TTransport, TCard>): RegistryEntry<TTransport, TCard> | undefined;
  tryRegister(
    agentId: string,
    entry: Omit<RegistryRegistration<TTransport, TCard>, "agentId" | "agent_id">,
  ): RegistryEntry<TTransport, TCard> | undefined;
  tryRegister(
    first: string | RegistryRegistration<TTransport, TCard>,
    second?: Omit<RegistryRegistration<TTransport, TCard>, "agentId" | "agent_id">,
  ): RegistryEntry<TTransport, TCard> | undefined {
    try {
      return typeof first === "string"
        ? this.register(first, second ?? {})
        : this.register(first);
    } catch (error) {
      if (error instanceof DuplicateAgentError) return undefined;
      throw error;
    }
  }

  lookup(agentId: string, instanceId?: string): RegistryEntry<TTransport, TCard> | undefined {
    const entry = this.live(agentId);
    return entry && (!instanceId || entry.instanceId === instanceId) ? entry : undefined;
  }

  /** Alias for lookup, useful for Map-like consumers. */
  get(agentId: string, instanceId?: string): RegistryEntry<TTransport, TCard> | undefined {
    return this.lookup(agentId, instanceId);
  }

  has(agentId: string, instanceId?: string): boolean {
    return this.lookup(agentId, instanceId) !== undefined;
  }

  list(): RegistryEntry<TTransport, TCard>[] {
    this.cleanup();
    return [...this.records.values()];
  }

  /** Alias commonly used by discovery implementations. */
  entries(): RegistryEntry<TTransport, TCard>[] {
    return this.list();
  }

  /** Extend a registration's lease only when its expected identity matches. */
  touch(agentId: string, expected?: RegistryMatch<TTransport> | TTransport): boolean {
    const entry = this.live(agentId);
    if (!entry || !this.matches(entry, expected)) return false;
    entry.expiresAt = this.now() + this.ttlMs;
    return true;
  }

  /** Renew by lease id, as required by the local discovery registry protocol. */
  renew(leaseId: string): RegistryEntry<TTransport, TCard> | undefined {
    this.cleanup();
    for (const entry of this.records.values()) {
      if (entry.leaseId === leaseId) {
        entry.expiresAt = this.now() + this.ttlMs;
        return entry;
      }
    }
    return undefined;
  }

  /**
   * Remove a record.  Passing a session, lease, instance, or transport turns
   * this into a compare-and-remove operation, protecting a newer registration
   * from stale disconnect callbacks.
   */
  remove(agentId: string, expected?: RegistryMatch<TTransport> | TTransport): boolean {
    const entry = this.records.get(agentId);
    if (!entry) return false;
    if (entry.expiresAt <= this.now()) {
      this.records.delete(agentId);
      return false;
    }
    if (!this.matches(entry, expected)) return false;
    this.records.delete(agentId);
    return true;
  }

  unregister(agentId: string, expected?: RegistryMatch<TTransport> | TTransport): boolean {
    return this.remove(agentId, expected);
  }

  /** Drop expired entries and return the ones removed. */
  cleanup(now = this.now()): RegistryEntry<TTransport, TCard>[] {
    const expired: RegistryEntry<TTransport, TCard>[] = [];
    for (const [agentId, entry] of this.records) {
      if (entry.expiresAt <= now) {
        this.records.delete(agentId);
        expired.push(entry);
      }
    }
    return expired;
  }

  /** Alias for callers which prefer the discovery terminology. */
  sweep(now?: number): RegistryEntry<TTransport, TCard>[] {
    return this.cleanup(now);
  }

  clear(): void {
    this.records.clear();
  }

  private now(): number {
    const value = this.clock();
    if (!Number.isFinite(value)) throw new RangeError("Registry clock returned a non-finite value");
    return value;
  }

  private live(agentId: string): RegistryEntry<TTransport, TCard> | undefined {
    const entry = this.records.get(agentId);
    if (!entry) return undefined;
    if (entry.expiresAt <= this.now()) {
      this.records.delete(agentId);
      return undefined;
    }
    return entry;
  }

  private isSameRegistration(
    entry: RegistryEntry<TTransport, TCard>,
    expected: Pick<RegistryRegistration<TTransport, TCard>, "sessionId" | "leaseId">,
  ): boolean {
    return Boolean(
      (expected.leaseId && entry.leaseId === expected.leaseId) ||
      (expected.sessionId && entry.sessionId && entry.sessionId === expected.sessionId),
    );
  }

  private matches(entry: RegistryEntry<TTransport, TCard>, expected?: RegistryMatch<TTransport> | TTransport): boolean {
    if (expected === undefined) return true;
    if (typeof expected === "string") {
      return expected === entry.leaseId || expected === entry.sessionId || expected === entry.instanceId;
    }
    // Passing the old transport directly is a common disconnect callback
    // shape.  Treat it as a compare-and-remove token rather than interpreting
    // an arbitrary object as an empty match (which would be unsafe).
    if (typeof expected !== "object" || expected === null) return entry.transport === expected;
    const matcher = expected as Partial<RegistryEntry<TTransport>>;
    const hasMatcherField = "leaseId" in matcher || "sessionId" in matcher || "instanceId" in matcher || "transport" in matcher;
    if (!hasMatcherField) return entry.transport === expected;
    if (matcher.leaseId !== undefined && entry.leaseId !== matcher.leaseId) return false;
    if (matcher.sessionId !== undefined && entry.sessionId !== matcher.sessionId) return false;
    if (matcher.instanceId !== undefined && entry.instanceId !== matcher.instanceId) return false;
    if (matcher.transport !== undefined && entry.transport !== matcher.transport) return false;
    return true;
  }
}

function durableRegistryKey(meshId: string, agentId: string, instanceId: string): string {
  return `${meshId}\0${agentId}\0${instanceId}`;
}

function requiredText(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) throw new InvalidRegistrationError(`${field} is required`);
  return value;
}

function validFence(value: unknown, field: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new InvalidRegistrationError(`${field} must be a non-negative safe integer`);
  return value as number;
}

function optionalJsonObject(value: unknown): JsonObject | undefined {
  if (value === undefined) return undefined;
  try {
    const cloned = JSON.parse(JSON.stringify(value)) as unknown;
    if (typeof cloned !== "object" || cloned === null || Array.isArray(cloned)) {
      throw new InvalidRegistrationError("Durable cards must be JSON objects");
    }
    return cloned as JsonObject;
  } catch (error) {
    if (error instanceof InvalidRegistrationError) throw error;
    throw new InvalidRegistrationError("Durable cards must be JSON serializable");
  }
}

function durableStoreConflictCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && typeof (error as { code?: unknown }).code === "string"
    ? (error as { code: string }).code
    : undefined;
}

/**
 * v0.2 durable registry.
 *
 * `Registry` is intentionally left unchanged for legacy tests and ephemeral
 * local mode. This subclass adds asynchronous, fence-aware durable methods
 * and deliberately never persists `transport`; the `connections` map is
 * rebuilt as sessions reconnect after a process restart.
 */
export class DurableRegistry<TTransport = unknown, TCard = unknown> extends Registry<TTransport, TCard> {
  readonly store: RegistryStore;
  readonly meshId: string;

  private readonly durableClock: RegistryClock;
  private readonly defaultPrincipalId?: string;
  private readonly connections = new Map<string, {
    transport?: TTransport;
    card?: TCard;
    registrationFence: number;
    sessionFence: number;
  }>();

  constructor(options: DurableRegistryOptions) {
    super(options);
    this.store = options.store;
    this.meshId = requiredText(options.meshId, "meshId");
    this.defaultPrincipalId = options.principalId;
    if (this.defaultPrincipalId !== undefined) requiredText(this.defaultPrincipalId, "principalId");
    this.durableClock = options.clock ?? options.now ?? Date.now;
  }

  /** Persist a registration before exposing its process-local connection. */
  async registerDurable(input: DurableRegistryRegistration<TTransport, TCard>): Promise<DurableRegistryEntry<TTransport, TCard>> {
    const agentId = requiredText(input.agentId ?? input.agent_id, "agentId");
    const instanceId = requiredText(input.instanceId ?? input.instance_id, "instanceId");
    const meshId = requiredText(input.meshId ?? this.meshId, "meshId");
    const principalId = requiredText(input.principalId ?? this.defaultPrincipalId, "principalId");
    const sessionId = input.sessionId ?? input.session_id;
    if (sessionId !== undefined) requiredText(sessionId, "sessionId");
    const now = this.nowDurable();
    const prior = await this.store.getInstance(meshId, agentId, instanceId);
    const logicalPeers = await this.store.listInstances({ meshId, agentId, now });
    if (logicalPeers.some((entry) => entry.principalId !== principalId)) {
      throw new DurableIdentityCollisionError(meshId, agentId);
    }

    const sameSession = prior !== undefined && sessionId !== undefined && prior.sessionId === sessionId;
    const registrationFence = input.registrationFence ?? (sameSession ? prior!.registrationFence : (prior?.registrationFence ?? 0) + 1);
    const sessionFence = input.sessionFence ?? (sameSession ? prior!.sessionFence : (prior?.sessionFence ?? 0) + 1);
    validFence(registrationFence, "registrationFence");
    validFence(sessionFence, "sessionFence");
    const leaseId = input.leaseId ?? input.lease_id ?? (sameSession ? prior!.leaseId : randomBytes(18).toString("base64url"));
    const card = optionalJsonObject(input.card);
    const expiresAt = now + this.ttlMs;
    const record: DurableAgentInstance = {
      meshId,
      agentId,
      instanceId,
      principalId,
      ...(card === undefined ? {} : { card }),
      ...(input.cardDigest === undefined ? {} : { cardDigest: requiredText(input.cardDigest, "cardDigest") }),
      ...(input.cardRevision === undefined ? {} : { cardRevision: validFence(input.cardRevision, "cardRevision") }),
      ...(sessionId === undefined ? {} : { sessionId }),
      leaseId: requiredText(leaseId, "leaseId"),
      health: input.health ?? HealthState.HEALTHY,
      ...(input.capacity === undefined ? {} : { capacity: validFence(input.capacity, "capacity") }),
      ...(input.capacityWeight === undefined ? {} : { capacityWeight: input.capacityWeight }),
      registrationFence,
      sessionFence,
      registeredAt: sameSession ? prior!.registeredAt : now,
      updatedAt: now,
      expiresAt,
      ...(input.cardExpiresAt === undefined ? {} : { cardExpiresAt: input.cardExpiresAt }),
    };
    const session: DurableSession | undefined = sessionId !== undefined && input.ownerBrokerNodeId !== undefined
      ? {
        sessionId,
        ownerBrokerNodeId: requiredText(input.ownerBrokerNodeId, "ownerBrokerNodeId"),
        sessionFence,
        createdAt: sameSession && prior?.sessionId === sessionId ? prior.registeredAt : now,
        updatedAt: now,
        expiresAt: input.sessionExpiresAt ?? expiresAt,
      }
      : undefined;
    const registration: DurableRegistration = {
      instance: record,
      ...(session === undefined ? {} : { session }),
    };
    let persistedRegistration: DurableRegistration;
    try {
      if (this.store.upsertRegistration !== undefined) {
        persistedRegistration = await this.store.upsertRegistration(registration);
      } else {
        // A legacy adapter can still serve local instance-only registrations,
        // but it cannot safely publish an instance that names a durable
        // session: a crash between the two writes would leave a torn fence.
        if (session !== undefined) {
          throw new InvalidRegistrationError("RegistryStore must support atomic instance/session registration");
        }
        persistedRegistration = { instance: await this.store.upsertInstance(record) };
      }
    } catch (error) {
      const code = durableStoreConflictCode(error);
      if (code === "IDENTITY_COLLISION") throw new DurableIdentityCollisionError(meshId, agentId);
      if (code === "STALE_FENCE") {
        throw new InvalidRegistrationError("A stale or equal registration/session fence cannot replace the active durable instance");
      }
      throw error;
    }
    const persisted = persistedRegistration.instance;
    if (persisted.registrationFence !== registrationFence || persisted.sessionFence !== sessionFence ||
      persisted.principalId !== principalId || persisted.leaseId !== record.leaseId ||
      persisted.sessionId !== record.sessionId) {
      throw new InvalidRegistrationError("A stale registration fence cannot replace the active durable instance");
    }
    if (session !== undefined && (
      persistedRegistration.session === undefined ||
      persistedRegistration.session.sessionFence !== session.sessionFence ||
      persistedRegistration.session.ownerBrokerNodeId !== session.ownerBrokerNodeId
    )) {
      throw new InvalidRegistrationError("A stale session fence cannot replace the active durable session");
    }
    this.connections.set(durableRegistryKey(meshId, agentId, instanceId), {
      ...(input.transport === undefined ? {} : { transport: input.transport }),
      ...(persisted.card === undefined ? {} : { card: persisted.card as unknown as TCard }),
      registrationFence,
      sessionFence,
    });
    return this.withConnection(persisted);
  }

  /** Fetch one live durable instance. Expired entries are marked offline. */
  async lookupDurable(agentId: string, instanceId: string, meshId = this.meshId): Promise<DurableRegistryEntry<TTransport, TCard> | undefined> {
    const record = await this.store.getInstance(meshId, agentId, instanceId);
    if (!record) return undefined;
    if (record.expiresAt <= this.nowDurable()) {
      await this.store.expireInstances(this.nowDurable());
      return undefined;
    }
    if (record.health === HealthState.OFFLINE) return undefined;
    return this.withConnection(record);
  }

  /** List live durable instances for a mesh/logical agent. */
  async listDurable(input: { meshId?: string; agentId?: string } = {}): Promise<DurableRegistryEntry<TTransport, TCard>[]> {
    const records = await this.store.listInstances({ ...input, meshId: input.meshId ?? this.meshId, now: this.nowDurable() });
    return records.filter((record) => record.health !== HealthState.OFFLINE).map((record) => this.withConnection(record));
  }

  /** Lease renewal uses both registration and session fences. */
  async renewDurable(input: DurableRegistryRenewal): Promise<DurableRegistryEntry<TTransport, TCard> | undefined> {
    const meshId = input.meshId ?? this.meshId;
    const updated = await this.store.renewInstance({
      meshId,
      agentId: input.agentId,
      instanceId: input.instanceId,
      registrationFence: validFence(input.registrationFence, "registrationFence"),
      sessionFence: validFence(input.sessionFence, "sessionFence"),
      expiresAt: input.expiresAt ?? this.nowDurable() + this.ttlMs,
      ...(input.health === undefined ? {} : { health: input.health }),
      updatedAt: this.nowDurable(),
    });
    return updated === undefined ? undefined : this.withConnection(updated);
  }

  /** Stale disconnects cannot remove the durable replacement registration. */
  async removeDurable(input: DurableRegistryRemoval): Promise<boolean> {
    const meshId = input.meshId ?? this.meshId;
    const registrationFence = validFence(input.registrationFence, "registrationFence");
    const sessionFence = validFence(input.sessionFence, "sessionFence");
    const removed = await this.store.removeInstance({
      meshId,
      agentId: input.agentId,
      instanceId: input.instanceId,
      registrationFence,
      sessionFence,
    });
    if (removed) this.connections.delete(durableRegistryKey(meshId, input.agentId, input.instanceId));
    return removed;
  }

  /** Expire leases and discard only the corresponding local socket handles. */
  async cleanupDurable(now = this.nowDurable()): Promise<DurableRegistryEntry<TTransport, TCard>[]> {
    const expired = await this.store.expireInstances(now);
    for (const record of expired) {
      const key = durableRegistryKey(record.meshId, record.agentId, record.instanceId);
      const live = this.connections.get(key);
      if (live && live.registrationFence === record.registrationFence && live.sessionFence === record.sessionFence) {
        this.connections.delete(key);
      }
    }
    return expired.map((record) => this.withConnection(record));
  }

  /** A socket handle is visible only when it carries the active durable fence. */
  transportFor(agentId: string, instanceId: string, meshId = this.meshId): TTransport | undefined {
    return this.connections.get(durableRegistryKey(meshId, agentId, instanceId))?.transport;
  }

  /** Resolve a local socket only after checking its durable fence. */
  async activeTransportFor(agentId: string, instanceId: string, meshId = this.meshId): Promise<TTransport | undefined> {
    const record = await this.lookupDurable(agentId, instanceId, meshId);
    if (!record || record.health === HealthState.OFFLINE) return undefined;
    const live = this.connections.get(durableRegistryKey(meshId, agentId, instanceId));
    return live && live.registrationFence === record.registrationFence && live.sessionFence === record.sessionFence
      ? live.transport
      : undefined;
  }

  private withConnection(record: DurableAgentInstance): DurableRegistryEntry<TTransport, TCard> {
    const live = this.connections.get(durableRegistryKey(record.meshId, record.agentId, record.instanceId));
    const active = live !== undefined && live.registrationFence === record.registrationFence && live.sessionFence === record.sessionFence
      ? live
      : undefined;
    const { card: _durableCard, ...withoutCard } = record;
    return {
      ...withoutCard,
      ...(active?.card !== undefined
        ? { card: active.card }
        : record.card === undefined
          ? {}
          : { card: record.card as unknown as TCard }),
      ...(active?.transport === undefined ? {} : { transport: active.transport }),
    };
  }

  private nowDurable(): number {
    const now = this.durableClock();
    if (!Number.isFinite(now) || now < 0) throw new RangeError("Registry clock returned an invalid durable timestamp");
    return now;
  }
}

/** More explicit name for consumers that import an agent registry. */
export const AgentRegistry = Registry;

export default Registry;

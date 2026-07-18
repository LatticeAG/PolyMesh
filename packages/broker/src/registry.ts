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

/** More explicit name for consumers that import an agent registry. */
export const AgentRegistry = Registry;

export default Registry;

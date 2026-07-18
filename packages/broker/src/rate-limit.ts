/**
 * Hierarchical token-bucket admission control.
 *
 * The broker calls this module before it commits or forwards work.  A rate
 * limit decision is deliberately synchronous: the current broker receive path
 * is synchronous and a better-sqlite3-backed coordinator can run the required
 * `BEGIN IMMEDIATE` transaction synchronously too.  Deployments with more
 * than one broker process MUST supply an AtomicTokenBucketStore backed by a
 * shared coordinator or database; InMemoryAtomicTokenBucketStore is only for
 * tests and explicitly-local development.
 */

import { performance } from "node:perf_hooks";

import Database from "better-sqlite3";

/** Operations for which independent quota budgets may be configured. */
export const RATE_LIMIT_OPERATION_CLASSES = [
  "handshake",
  "control",
  "envelope_count",
  "compressed_bytes",
  "uncompressed_bytes",
  "task_submissions",
  "running_tasks",
  "subscriptions",
  "artifact_bytes",
] as const;

export type RateLimitOperationClass = (typeof RATE_LIMIT_OPERATION_CLASSES)[number];

/** The four required hierarchy dimensions from the v0.2 profile. */
export const RATE_LIMIT_SCOPES = [
  "principal_operation",
  "principal_target",
  "credential",
  "connection",
] as const;

export type RateLimitScope = (typeof RATE_LIMIT_SCOPES)[number];

const OPERATION_SET = new Set<string>(RATE_LIMIT_OPERATION_CLASSES);

/** One bucket's maximum burst and monotonic refill speed. */
export interface TokenBucketPolicy {
  /** Maximum tokens that may be accumulated. Must be a positive finite number. */
  capacity: number;
  /** Tokens refilled for each monotonic millisecond. May be zero for a fixed quota. */
  refillPerMs: number;
}

/** Policies for individual operations in one hierarchy scope. */
export type RateLimitOperationPolicies = Partial<Record<RateLimitOperationClass, TokenBucketPolicy>>;

/**
 * Policy hierarchy.  A configured policy participates only for the matching
 * operation class.  This keeps count, compressed-byte, and uncompressed-byte
 * budgets independent instead of mixing unlike units in one bucket.
 */
export interface HierarchicalRateLimitPolicies {
  /** Keyed by `(mesh_id, principal_id, operation_class)`. */
  principalOperation?: RateLimitOperationPolicies;
  /** Keyed by `(mesh_id, principal_id, target_agent_id, operation_class)`. */
  principalTarget?: RateLimitOperationPolicies;
  /** Keyed by `(mesh_id, credential_id, operation_class)`. */
  credential?: RateLimitOperationPolicies;
  /** Keyed by `(pre_auth_ip, connection_id, operation_class)`. */
  connection?: RateLimitOperationPolicies;
}

/** Identifiers established by transport authentication, never envelope claims. */
export interface RateLimitContext {
  meshId?: string;
  principalId?: string;
  credentialId?: string;
  targetAgentId?: string;
  /** Peer IP observed before authentication, not a forwarded client header. */
  preAuthIp?: string;
  /** Stable only for the lifetime of the physical transport/session. */
  connectionId?: string;
}

/** One unit of work to debit.  Multiple charges are admitted atomically. */
export interface RateLimitCharge {
  operation: RateLimitOperationClass;
  cost: number;
}

/** An opaque bucket charge passed to a durable/shared atomic store. */
export interface TokenBucketStoreCharge {
  key: string;
  capacity: number;
  refillPerMs: number;
  cost: number;
}

/** The persisted portion of an individual token bucket. */
export interface TokenBucketState {
  tokens: number;
  /**
   * Store-local elapsed-time coordinate. In-memory stores use the caller's
   * monotonic clock; shared SQLite stores use SQLite's database clock so two
   * broker processes never compare unrelated `performance.now()` origins.
   */
  updatedAt: number;
}

/** A failed bucket returned by the atomic store. */
export interface TokenBucketStoreFailure {
  key: string;
  capacity: number;
  available: number;
  cost: number;
  /** Null means the request can never fit this policy or the bucket cannot refill. */
  retry_after_ms: number | null;
}

export interface AtomicTokenBucketConsumeRequest {
  /**
   * A monotonic timestamp in milliseconds for local stores. Shared stores
   * may validate it but MUST source persisted timestamps from a clock common
   * to every process using the same coordinator.
   */
  now: number;
  charges: readonly TokenBucketStoreCharge[];
}

export type AtomicTokenBucketConsumeResult =
  | { allowed: true }
  | { allowed: false; failures: readonly TokenBucketStoreFailure[] };

/**
 * A shared store MUST evaluate every charge and debit all of them in one
 * atomic transaction.  It must never debit an earlier bucket when a later
 * bucket rejects the same admission.
 */
export interface AtomicTokenBucketStore {
  /** True only when admissions coordinate across broker processes. */
  readonly distributed?: boolean;
  consume(request: AtomicTokenBucketConsumeRequest): AtomicTokenBucketConsumeResult;
}

/** A concrete failed hierarchy bucket, useful for audit and diagnostics. */
export interface RateLimitFailure extends TokenBucketStoreFailure {
  scope: RateLimitScope;
  operation: RateLimitOperationClass;
}

export type RateLimitDecision =
  | {
    allowed: true;
    code: undefined;
    retry_after_ms: 0;
    bucketKeys: readonly string[];
  }
  | {
    allowed: false;
    code: "RATE_LIMITED";
    retry_after_ms: number | null;
    failures: readonly RateLimitFailure[];
    bucketKeys: readonly string[];
  }
  | {
    allowed: false;
    code: "RATE_LIMIT_CONTEXT_MISSING";
    retry_after_ms: null;
    missingScopes: readonly RateLimitScope[];
    bucketKeys: readonly string[];
  }
  | {
    /**
     * The atomic coordinator, local clock, or limiter configuration failed
     * while attempting admission.  Treat this exactly as a denial: callers
     * must never proceed with work when quota state is unavailable.
     */
    allowed: false;
    code: "RATE_LIMIT_UNAVAILABLE";
    retry_after_ms: null;
    bucketKeys: readonly string[];
  };

export interface HierarchicalRateLimiterOptions {
  /** Omit or leave empty to disable rate limiting completely. */
  policies?: HierarchicalRateLimitPolicies;
  /** Defaults to a process-local store; do not use that default across instances. */
  store?: AtomicTokenBucketStore;
  /** Must return a monotonic millisecond timestamp. */
  clock?: () => number;
}

export interface RateLimitAdmissionOptions {
  /**
   * Handshake traffic has no authenticated principal yet. In that phase a
   * broker may skip principal-scoped policies while still enforcing its
   * pre-auth connection/credential buckets. Envelope admission remains
   * fail-closed by default when a configured context key is missing.
   */
  missingScopeBehavior?: "reject" | "skip";
}

interface BuiltBucketCharge extends TokenBucketStoreCharge {
  scope: RateLimitScope;
  operation: RateLimitOperationClass;
}

type NormalizedPolicies = Record<RateLimitScope, ReadonlyMap<RateLimitOperationClass, TokenBucketPolicy>>;

const EMPTY_POLICIES: NormalizedPolicies = {
  principal_operation: new Map(),
  principal_target: new Map(),
  credential: new Map(),
  connection: new Map(),
};

/** True only for the closed v0.2 operation-class vocabulary. */
export function isRateLimitOperationClass(value: unknown): value is RateLimitOperationClass {
  return typeof value === "string" && OPERATION_SET.has(value);
}

/**
 * Build an unambiguous, stable key without delimiter-collision hazards.  The
 * key deliberately includes `operation_class` in every scope: byte quotas and
 * message-count quotas cannot safely share one numeric token unit.
 */
export function rateLimitBucketKey(
  scope: RateLimitScope,
  context: RateLimitContext,
  operation: RateLimitOperationClass,
): string {
  switch (scope) {
    case "principal_operation":
      if (context.meshId === undefined || context.principalId === undefined) {
        throw new TypeError("meshId and principalId are required for a principal-operation bucket");
      }
      return JSON.stringify(["polymesh.rate-limit/1", scope, context.meshId, context.principalId, operation]);
    case "principal_target":
      if (context.meshId === undefined || context.principalId === undefined || context.targetAgentId === undefined) {
        throw new TypeError("meshId, principalId, and targetAgentId are required for a principal-target bucket");
      }
      return JSON.stringify(["polymesh.rate-limit/1", scope, context.meshId, context.principalId, context.targetAgentId, operation]);
    case "credential":
      if (context.meshId === undefined || context.credentialId === undefined) {
        throw new TypeError("meshId and credentialId are required for a credential bucket");
      }
      return JSON.stringify(["polymesh.rate-limit/1", scope, context.meshId, context.credentialId, operation]);
    case "connection":
      if (context.preAuthIp === undefined || context.connectionId === undefined) {
        throw new TypeError("preAuthIp and connectionId are required for a connection bucket");
      }
      return JSON.stringify(["polymesh.rate-limit/1", scope, context.preAuthIp, context.connectionId, operation]);
  }
}

/**
 * In-memory implementation for tests and a single local process.  It has no
 * cross-process coordination; production multi-instance brokers must inject a
 * durable/shared AtomicTokenBucketStore instead.
 */
export class InMemoryAtomicTokenBucketStore implements AtomicTokenBucketStore {
  readonly distributed = false;
  private readonly states = new Map<string, TokenBucketState>();

  consume(request: AtomicTokenBucketConsumeRequest): AtomicTokenBucketConsumeResult {
    assertMonotonicTimestamp(request.now);
    const charges = aggregateStoreCharges(request.charges);
    const evaluations: Array<{ charge: TokenBucketStoreCharge; state: TokenBucketState; available: number }> = [];
    const failures: TokenBucketStoreFailure[] = [];

    for (const charge of charges) {
      const prior = this.states.get(charge.key);
      const available = refilledTokens(prior, charge, request.now);
      const state: TokenBucketState = prior ?? { tokens: charge.capacity, updatedAt: request.now };
      evaluations.push({ charge, state, available });
      if (available < charge.cost) {
        failures.push({
          key: charge.key,
          capacity: charge.capacity,
          available,
          cost: charge.cost,
          retry_after_ms: retryAfterMs(charge, available),
        });
      }
    }

    // No state is debited on failure.  Refills are derived from timestamps, so
    // persisting them is unnecessary and would not change a later decision.
    if (failures.length > 0) return { allowed: false, failures };

    for (const evaluation of evaluations) {
      this.states.set(evaluation.charge.key, {
        tokens: evaluation.available - evaluation.charge.cost,
        // A test clock may move backwards. Never move a stored monotonic
        // timestamp backwards, as that would create artificial refill time.
        updatedAt: Math.max(evaluation.state.updatedAt, request.now),
      });
    }
    return { allowed: true };
  }

  /** Test/diagnostic snapshot; it intentionally does not refill or mutate state. */
  get(key: string): TokenBucketState | undefined {
    const state = this.states.get(key);
    return state === undefined ? undefined : { ...state };
  }

  clear(): void {
    this.states.clear();
  }
}

export interface SqliteAtomicTokenBucketStoreOptions {
  /** A shared SQLite file; `:memory:` is deliberately rejected. */
  filename: string;
}

/**
 * SQLite-backed atomic bucket coordinator for multi-process brokers sharing a
 * filesystem/database. Each admission takes BEGIN IMMEDIATE and evaluates all
 * hierarchy buckets before debiting any one of them, preserving all-or-none
 * semantics across instances. A production cluster may replace it with a
 * PostgreSQL/Redis coordinator through the same AtomicTokenBucketStore API.
 */
export class SqliteAtomicTokenBucketStore implements AtomicTokenBucketStore {
  readonly distributed = true;
  private readonly db: Database.Database;

  constructor(options: SqliteAtomicTokenBucketStoreOptions | string) {
    const filename = typeof options === "string" ? options : options.filename;
    if (typeof filename !== "string" || filename.length === 0 || filename === ":memory:") {
      throw new TypeError("SqliteAtomicTokenBucketStore requires a shared file-backed database");
    }
    this.db = new Database(filename);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("synchronous = FULL");
    // BEGIN IMMEDIATE serializes writers. Waiting briefly is important when
    // several broker processes share one coordinator; otherwise a transient
    // SQLITE_BUSY would turn normal concurrent admission into a fail-open
    // caller retry pattern.
    this.db.pragma("busy_timeout = 5000");
    this.db.exec(`CREATE TABLE IF NOT EXISTS rate_limit_buckets (
      bucket_key TEXT PRIMARY KEY,
      tokens REAL NOT NULL,
      updated_at INTEGER NOT NULL
    )`);
  }

  close(): void {
    this.db.close();
  }

  consume(request: AtomicTokenBucketConsumeRequest): AtomicTokenBucketConsumeResult {
    // Preserve the interface's input validation for adapters that share a
    // limiter, but never write this process-local time into the database.
    // `performance.now()` has a different origin in each process, so using it
    // here would let a later process manufacture refill elapsed time.
    assertMonotonicTimestamp(request.now);
    const charges = aggregateStoreCharges(request.charges);
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const now = this.sharedNow();
      const evaluations: Array<{ charge: TokenBucketStoreCharge; prior?: TokenBucketState; available: number }> = [];
      const failures: TokenBucketStoreFailure[] = [];
      const select = this.db.prepare(`SELECT tokens, updated_at FROM rate_limit_buckets WHERE bucket_key = ?`);
      for (const charge of charges) {
        const row = select.get(charge.key) as { tokens?: unknown; updated_at?: unknown } | undefined;
        const prior = row === undefined
          ? undefined
          : { tokens: Number(row.tokens), updatedAt: Number(row.updated_at) };
        const available = refilledTokens(prior, charge, now);
        evaluations.push({ charge, prior, available });
        if (available < charge.cost) {
          failures.push({
            key: charge.key,
            capacity: charge.capacity,
            available,
            cost: charge.cost,
            retry_after_ms: retryAfterMs(charge, available),
          });
        }
      }
      if (failures.length > 0) {
        this.db.exec("COMMIT");
        return { allowed: false, failures };
      }
      const upsert = this.db.prepare(`INSERT INTO rate_limit_buckets (bucket_key, tokens, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(bucket_key) DO UPDATE SET tokens = excluded.tokens, updated_at = excluded.updated_at`);
      for (const evaluation of evaluations) {
        upsert.run(
          evaluation.charge.key,
          evaluation.available - evaluation.charge.cost,
          // SQLite's wall clock can move backward. Persisting the maximum
          // prevents a rollback from creating artificial refill time on a
          // later request while still using one shared clock across processes.
          Math.max(evaluation.prior?.updatedAt ?? now, now),
        );
      }
      this.db.exec("COMMIT");
      return { allowed: true };
    } catch (error) {
      try { this.db.exec("ROLLBACK"); } catch { /* transaction is already closed */ }
      throw error;
    }
  }

  /**
   * Read a millisecond epoch from SQLite while the write transaction is held.
   * This is deliberately not `Date.now()` and not `performance.now()`: all
   * brokers that coordinate through this database observe the same timestamp
   * domain. `julianday('now')` is available on the SQLite versions supported
   * by better-sqlite3, unlike newer convenience functions such as unixepoch
   * with fractional subsecond arguments.
   */
  private sharedNow(): number {
    const row = this.db.prepare(
      "SELECT CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER) AS now_ms",
    ).get() as { now_ms?: unknown } | undefined;
    const now = Number(row?.now_ms);
    if (!Number.isSafeInteger(now) || now < 0) {
      throw new TypeError("SQLite returned an invalid shared rate-limit timestamp");
    }
    return now;
  }
}

/**
 * Builds the configured hierarchy and asks its store to atomically consume
 * every relevant bucket.  With no configured policies it is a no-op, making
 * rate limiting opt-in for the v0.1-compatible broker path.
 */
export class HierarchicalRateLimiter {
  private readonly policies: NormalizedPolicies;
  private readonly store: AtomicTokenBucketStore;
  private readonly clock: () => number;

  constructor(options: HierarchicalRateLimiterOptions = {}) {
    this.policies = normalizePolicies(options.policies);
    this.store = options.store ?? new InMemoryAtomicTokenBucketStore();
    this.clock = options.clock ?? (() => performance.now());
  }

  get enabled(): boolean {
    return RATE_LIMIT_SCOPES.some((scope) => this.policies[scope].size > 0);
  }

  /** Whether this limiter's state is coordinated beyond one Node process. */
  get distributed(): boolean {
    return this.store.distributed === true;
  }

  /** Admit multiple work dimensions (for example count plus compressed bytes) atomically. */
  admit(
    context: RateLimitContext,
    charges: readonly RateLimitCharge[],
    options: RateLimitAdmissionOptions = {},
  ): RateLimitDecision {
    const normalizedContext = normalizeContext(context);
    const normalizedCharges = normalizeRateLimitCharges(charges);
    if (!this.enabled || normalizedCharges.length === 0) {
      return { allowed: true, code: undefined, retry_after_ms: 0, bucketKeys: [] };
    }

    const built = this.buildCharges(normalizedContext, normalizedCharges);
    if (built.missingScopes.length > 0 && options.missingScopeBehavior !== "skip") {
      return {
        allowed: false,
        code: "RATE_LIMIT_CONTEXT_MISSING",
        retry_after_ms: null,
        missingScopes: [...new Set(built.missingScopes)],
        bucketKeys: built.charges.map((charge) => charge.key),
      };
    }
    if (built.charges.length === 0) {
      return { allowed: true, code: undefined, retry_after_ms: 0, bucketKeys: [] };
    }

    const now = this.clock();
    assertMonotonicTimestamp(now);
    const result = this.store.consume({ now, charges: built.charges });
    const bucketKeys = built.charges.map((charge) => charge.key);
    if (result.allowed) return { allowed: true, code: undefined, retry_after_ms: 0, bucketKeys };

    const byKey = new Map(built.charges.map((charge) => [charge.key, charge] as const));
    const failures: RateLimitFailure[] = result.failures.map((failure) => {
      const bucket = byKey.get(failure.key);
      if (!bucket) throw new TypeError("Atomic token bucket store returned an unknown bucket key");
      return { ...failure, scope: bucket.scope, operation: bucket.operation };
    });
    return {
      allowed: false,
      code: "RATE_LIMITED",
      retry_after_ms: aggregateRetryAfter(failures),
      failures,
      bucketKeys,
    };
  }

  /**
   * Non-throwing, fail-closed form of `admit` for network admission paths.
   *
   * An atomic coordinator may fail because its database is busy, unavailable,
   * or corrupt.  Letting that exception escape a WebSocket listener can turn a
   * quota outage into a process-level availability failure; treating it as an
   * allow would be worse.  This helper converts every evaluation failure into
   * a deliberately non-retry-timed denial.  It intentionally exposes no
   * underlying error text, which could reveal coordinator details to peers.
   *
   * Use `admit` where a caller wants configuration/programming errors to be
   * surfaced directly (for example startup validation); use this method at a
   * transport trust boundary.
   */
  admitFailClosed(
    context: RateLimitContext,
    charges: readonly RateLimitCharge[],
    options: RateLimitAdmissionOptions = {},
  ): RateLimitDecision {
    try {
      return this.admit(context, charges, options);
    } catch {
      return {
        allowed: false,
        code: "RATE_LIMIT_UNAVAILABLE",
        retry_after_ms: null,
        bucketKeys: [],
      };
    }
  }

  /** Convenience form for the broker's common single-operation admission check. */
  consume(context: RateLimitContext, operation: RateLimitOperationClass, cost = 1): RateLimitDecision {
    return this.admit(context, [{ operation, cost }]);
  }

  /** Non-throwing, fail-closed convenience form of `consume`. */
  consumeFailClosed(context: RateLimitContext, operation: RateLimitOperationClass, cost = 1): RateLimitDecision {
    return this.admitFailClosed(context, [{ operation, cost }]);
  }

  private buildCharges(
    context: RateLimitContext,
    input: readonly RateLimitCharge[],
  ): { charges: BuiltBucketCharge[]; missingScopes: RateLimitScope[] } {
    const charges: BuiltBucketCharge[] = [];
    const missingScopes: RateLimitScope[] = [];
    for (const inputCharge of input) {
      for (const scope of RATE_LIMIT_SCOPES) {
        const policy = this.policies[scope].get(inputCharge.operation);
        if (!policy) continue;
        if (!hasScopeContext(scope, context)) {
          missingScopes.push(scope);
          continue;
        }
        charges.push({
          key: rateLimitBucketKey(scope, context, inputCharge.operation),
          scope,
          operation: inputCharge.operation,
          capacity: policy.capacity,
          refillPerMs: policy.refillPerMs,
          cost: inputCharge.cost,
        });
      }
    }
    return { charges: aggregateBuiltCharges(charges), missingScopes };
  }
}

function normalizePolicies(input: HierarchicalRateLimitPolicies | undefined): NormalizedPolicies {
  if (input === undefined) return EMPTY_POLICIES;
  const source: Record<RateLimitScope, RateLimitOperationPolicies | undefined> = {
    principal_operation: input.principalOperation,
    principal_target: input.principalTarget,
    credential: input.credential,
    connection: input.connection,
  };
  const normalized = {} as Record<RateLimitScope, ReadonlyMap<RateLimitOperationClass, TokenBucketPolicy>>;
  for (const scope of RATE_LIMIT_SCOPES) {
    const values = new Map<RateLimitOperationClass, TokenBucketPolicy>();
    for (const [operation, policy] of Object.entries(source[scope] ?? {})) {
      if (!isRateLimitOperationClass(operation) || policy === undefined) {
        throw new TypeError(`Unknown rate-limit operation policy '${operation}'`);
      }
      values.set(operation, normalizePolicy(policy));
    }
    normalized[scope] = values;
  }
  return normalized;
}

function normalizePolicy(policy: TokenBucketPolicy): TokenBucketPolicy {
  if (!policy || typeof policy !== "object" ||
    !Number.isFinite(policy.capacity) || policy.capacity <= 0 ||
    !Number.isFinite(policy.refillPerMs) || policy.refillPerMs < 0) {
    throw new TypeError("A token bucket policy needs a positive finite capacity and non-negative finite refillPerMs");
  }
  return { capacity: policy.capacity, refillPerMs: policy.refillPerMs };
}

function normalizeContext(context: RateLimitContext): RateLimitContext {
  if (!context || typeof context !== "object") throw new TypeError("Rate-limit context must be an object");
  const normalized: RateLimitContext = {};
  for (const key of ["meshId", "principalId", "credentialId", "targetAgentId", "preAuthIp", "connectionId"] as const) {
    const value = context[key];
    if (value === undefined) continue;
    if (typeof value !== "string" || value.length === 0 || value.length > 1_024 || /[\u0000-\u001f\u007f]/.test(value)) {
      throw new TypeError(`${key} must be a bounded non-control string when supplied`);
    }
    normalized[key] = value;
  }
  return normalized;
}

function normalizeRateLimitCharges(charges: readonly RateLimitCharge[]): RateLimitCharge[] {
  if (!Array.isArray(charges)) throw new TypeError("Rate-limit charges must be an array");
  return charges.map((charge) => {
    if (!charge || typeof charge !== "object" || !isRateLimitOperationClass(charge.operation) ||
      !Number.isFinite(charge.cost) || charge.cost <= 0) {
      throw new TypeError("Every rate-limit charge needs a known operation and positive finite cost");
    }
    return { operation: charge.operation, cost: charge.cost };
  });
}

function hasScopeContext(scope: RateLimitScope, context: RateLimitContext): boolean {
  switch (scope) {
    case "principal_operation":
      return context.meshId !== undefined && context.principalId !== undefined;
    case "principal_target":
      return context.meshId !== undefined && context.principalId !== undefined && context.targetAgentId !== undefined;
    case "credential":
      return context.meshId !== undefined && context.credentialId !== undefined;
    case "connection":
      return context.preAuthIp !== undefined && context.connectionId !== undefined;
  }
}

function aggregateBuiltCharges(charges: readonly BuiltBucketCharge[]): BuiltBucketCharge[] {
  const result = new Map<string, BuiltBucketCharge>();
  for (const charge of charges) {
    const existing = result.get(charge.key);
    if (!existing) {
      result.set(charge.key, { ...charge });
      continue;
    }
    if (existing.capacity !== charge.capacity || existing.refillPerMs !== charge.refillPerMs ||
      existing.scope !== charge.scope || existing.operation !== charge.operation) {
      throw new TypeError("A rate-limit bucket key cannot have conflicting policies");
    }
    existing.cost += charge.cost;
    if (!Number.isFinite(existing.cost)) throw new RangeError("Aggregated rate-limit cost is not finite");
  }
  return [...result.values()];
}

function aggregateStoreCharges(charges: readonly TokenBucketStoreCharge[]): TokenBucketStoreCharge[] {
  if (!Array.isArray(charges)) throw new TypeError("Atomic token-bucket charges must be an array");
  const result = new Map<string, TokenBucketStoreCharge>();
  for (const charge of charges) {
    if (!charge || typeof charge !== "object" || typeof charge.key !== "string" || charge.key.length === 0 ||
      !Number.isFinite(charge.capacity) || charge.capacity <= 0 ||
      !Number.isFinite(charge.refillPerMs) || charge.refillPerMs < 0 ||
      !Number.isFinite(charge.cost) || charge.cost <= 0) {
      throw new TypeError("Atomic token-bucket charge is invalid");
    }
    const existing = result.get(charge.key);
    if (!existing) {
      result.set(charge.key, { ...charge });
      continue;
    }
    if (existing.capacity !== charge.capacity || existing.refillPerMs !== charge.refillPerMs) {
      throw new TypeError("A token-bucket key cannot use conflicting policies in one atomic operation");
    }
    existing.cost += charge.cost;
    if (!Number.isFinite(existing.cost)) throw new RangeError("Aggregated token-bucket cost is not finite");
  }
  return [...result.values()];
}

function refilledTokens(prior: TokenBucketState | undefined, charge: TokenBucketStoreCharge, now: number): number {
  if (!prior) return charge.capacity;
  if (!Number.isFinite(prior.tokens) || !Number.isFinite(prior.updatedAt)) {
    throw new TypeError("Stored token-bucket state is invalid");
  }
  const elapsed = Math.max(0, now - prior.updatedAt);
  return Math.min(charge.capacity, Math.max(0, prior.tokens) + elapsed * charge.refillPerMs);
}

function retryAfterMs(charge: TokenBucketStoreCharge, available: number): number | null {
  if (charge.cost > charge.capacity || charge.refillPerMs <= 0) return null;
  const wait = Math.ceil((charge.cost - available) / charge.refillPerMs);
  return Number.isSafeInteger(wait) && wait >= 0 ? wait : null;
}

function aggregateRetryAfter(failures: readonly TokenBucketStoreFailure[]): number | null {
  if (failures.some((failure) => failure.retry_after_ms === null)) return null;
  return Math.max(...failures.map((failure) => failure.retry_after_ms ?? 0));
}

function assertMonotonicTimestamp(value: number): void {
  if (!Number.isFinite(value) || value < 0) throw new RangeError("Rate-limit clock must return a non-negative finite monotonic timestamp");
}

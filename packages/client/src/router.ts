/**
 * PolyMesh v6 M1 capability routing engine (PRODUCT layer).
 *
 * Normative algorithm: PM-V6-SPEC Part B (§B.3–§B.17), types §E.2.2 / §E.2.3,
 * error codes §B.14 / Appendix F.2.1, conformance vectors Appendix H.
 *
 * This module MUST NOT parse A2A payloads. Dialect `"a2a"` is a routing
 * attribute only; outbound dispatch goes through an optional bridge hook.
 */
import { uuidv7 } from "@latticeag/polymesh-broker";

// ---------------------------------------------------------------------------
// E.2.2 / Part B shared types
// ---------------------------------------------------------------------------

/** Wire dialect tags understood by v6 ranking (§B.12). */
export type Dialect = "native" | "a2a";

/** Locality tiers for Preference 2 (§B.6.2 / §B.11.4). */
export type LocalityClass = "same_host" | "lan" | "relay" | "unknown";

/** Agent health states (§B.5.1). */
export type HealthState = "healthy" | "degraded" | "unhealthy" | "offline" | "unknown";

/** Bare routing error codes (§B.14 / F.2.1) — byte-identical, no PMX prefix. */
export type RoutingErrorCode =
  | "NO_CANDIDATES"
  | "ALL_CANDIDATES_EXHAUSTED"
  | "TARGET_UNAVAILABLE"
  | "AMBIGUOUS_TARGET"
  | "CAPABILITY_NOT_ADVERTISED"
  | "DIALECT_UNSUPPORTED";

/** Canonical code list for conformance (`routing_error_bare_codes_byte_identical`). */
export const ROUTING_ERROR_CODES = [
  "NO_CANDIDATES",
  "ALL_CANDIDATES_EXHAUSTED",
  "TARGET_UNAVAILABLE",
  "AMBIGUOUS_TARGET",
  "CAPABILITY_NOT_ADVERTISED",
  "DIALECT_UNSUPPORTED",
] as const satisfies readonly RoutingErrorCode[];

/**
 * Heartbeat / freshness-bucket granularity by locality (§B.5.3 / §B.6.5).
 * Values match lease TTLs: same_host=30s, lan=60s, relay=120s, unknown=60s.
 */
export const HEARTBEAT_MS: Readonly<Record<LocalityClass, number>> = Object.freeze({
  same_host: 30_000,
  lan: 60_000,
  relay: 120_000,
  unknown: 60_000,
});

/** Registry lease TTLs used to mark stale entries offline before routing (§B.5.3). */
export const LEASE_TTL_MS: Readonly<Record<LocalityClass, number>> = Object.freeze({
  same_host: 30_000,
  lan: 60_000,
  relay: 120_000,
  unknown: 60_000,
});

/** @deprecated Alias — prefer {@link HEARTBEAT_MS}. */
export const HEARTBEAT_MS_BY_LOCALITY = HEARTBEAT_MS;
/** @deprecated Alias — prefer {@link LEASE_TTL_MS}. */
export const LEASE_TTL_MS_BY_LOCALITY = LEASE_TTL_MS;

/** Routing candidate after collection (§E.2.2). */
export interface RoutingCandidate {
  agent_id: string;
  instance_id?: string;
  capability: string;
  dialect: Dialect;
  a2a_url?: string;
  locality: LocalityClass;
  last_seen_ms: number;
  /** True when registry last_seen was present; false → Pref3 treats as missing. */
  has_last_seen?: boolean;
  health: HealthState;
  perm_hint?: "allow" | "deny" | "absent";
}

/** Capability advertisement in the RegistryView (§B.11.2). */
export interface CapabilityEntry {
  name: string;
  schema?: Record<string, unknown>;
  scope?: string;
  dialect?: Dialect;
  a2a_url?: string;
  version?: string;
  contract_digest?: string;
  [key: string]: unknown;
}

/** Agent row in the RegistryView (§B.11.1). */
export interface RegistryAgentEntry {
  agent_id: string;
  display_name?: string;
  capabilities: CapabilityEntry[];
  health: HealthState;
  last_seen: string | null;
  locality: LocalityClass;
  metadata?: Record<string, string | number | boolean>;
  mesh_member?: boolean;
  instance_id?: string;
  perm_hint?: "allow" | "deny" | "absent";
  [key: string]: unknown;
}

/** Frozen (or freezable) registry snapshot used for a route attempt (§B.4 / §B.17). */
export interface RegistryView {
  agents: readonly RegistryAgentEntry[];
  last_refreshed_at?: string;
  [key: string]: unknown;
}

/** Full B.8 `task.routed` event (required fields + optional ranked_scores). */
export interface TaskRoutedEvent {
  type: "task.routed";
  task_id: string;
  candidate_count: number;
  chosen_agent: string;
  dialect: Dialect;
  reroute_count: number;
  excluded_agents: string[];
  locality_tier: LocalityClass;
  observed_at: string;
  capability?: string;
  ranked_scores?: RankedScoreRow[];
}

export interface RankedScoreRow {
  agent_id: string;
  dialect: Dialect;
  locality_tier: LocalityClass;
  dialect_rank: number;
  locality_rank: number;
  last_seen: string | null;
  rr_index: number;
  position: number;
}

export type RerouteReason =
  | "retryable_transport"
  | "retryable_remote"
  | "timeout"
  | "unhealthy"
  | "policy_reject";

/** Re-route observability event (§E.2.3). */
export interface RerouteEvent {
  task_id: string;
  failed_agent: string;
  reason: RerouteReason;
  /** 1-based; equal to reroute_count + 1 at emit time (1..3). */
  attempt: number;
  excluded_agents: string[];
}

export interface RankCandidatesOptions {
  capability: string;
  exclude?: ReadonlySet<string> | readonly string[];
  preferDialects?: readonly Dialect[];
  nowMs?: number;
  /** Include ranked_scores bookkeeping; default false. */
  includeScores?: boolean;
}

export interface SelectCandidateOptions {
  capability: string;
  exclude?: ReadonlySet<string> | readonly string[];
  preferDialects?: readonly Dialect[];
  roundRobinKey?: string;
  nowMs?: number;
}

export interface RouteTaskOptions {
  capability: string;
  payload: unknown;
  taskId?: string;
  /** Explicit target bypasses candidate collection but MUST still verify (§B.13). */
  target?: string;
  /** Max dispatch attempts; default 3; MUST NOT exceed 3. */
  maxReroutes?: number;
  preferDialects?: readonly Dialect[];
  signal?: AbortSignal;
  /**
   * Capability contract hints for retryability (§B.7.3).
   * `idempotency`: pure | idempotent | ... ; `side_effects`: write | approval | ...
   */
  idempotency?: string;
  side_effects?: string;
  caller_id?: string;
}

export interface DialectPreferenceHooks {
  /** Default MUST be ["native", "a2a"]. */
  preferDialects?(capability: string): readonly Dialect[] | Promise<readonly Dialect[]>;
  /** Veto only; MUST NOT grant authorization. */
  acceptCandidate?(candidate: RoutingCandidate, capability: string): boolean | Promise<boolean>;
}

export interface A2AOutboundBridge {
  send(input: {
    a2a_url: string;
    capability: string;
    payload: unknown;
    task_id: string;
    signal?: AbortSignal;
  }): Promise<void>;
}

export interface NativeDispatchInput {
  agent_id: string;
  capability: string;
  payload: unknown;
  task_id: string;
  signal?: AbortSignal;
}

export type ColdStartPolicy = "eager" | "lazy" | "manual";

export interface CapabilityRouterOptions {
  registry?: RegistryView;
  observedAt?: () => Date | string;
  rrState?: Map<string, number>;
  a2aBridge?: A2AOutboundBridge | null;
  nativeDispatch?: (input: NativeDispatchInput) => Promise<void>;
  /** Whether an A2A adapter/bridge is available. Default false for M1. */
  adapterAvailable?: boolean;
  /** Canonical-identifier expansion map; off by default (§B.13.5). */
  canonicalExpansion?: Record<string, string[]>;
  coldStartPolicy?: ColdStartPolicy;
  onDiscover?: () => Promise<void>;
  callerId?: string;
}

/** Routing attempt lifecycle states (§B.16 + SUBMITTED/ROUTING/SUCCEEDED). */
export type RoutingAttemptState =
  | "SUBMITTED"
  | "ROUTING"
  | "COLLECTING"
  | "FILTERING"
  | "RANKING"
  | "DISPATCHING"
  | "WAITING"
  | "HANDOFF"
  | "FAILED"
  | "REROUTING"
  | "EXHAUSTED"
  | "SUCCEEDED";

/**
 * Normative transitions (§B.16.3). `REROUTING` may only be entered from
 * `FAILED` when `reroute_count` (before increment) is in `{0,1}`.
 */
export const ROUTING_ATTEMPT_TRANSITIONS: Readonly<
  Record<RoutingAttemptState, readonly RoutingAttemptState[]>
> = Object.freeze({
  SUBMITTED: Object.freeze(["ROUTING", "COLLECTING"] as const),
  ROUTING: Object.freeze(["COLLECTING", "EXHAUSTED"] as const),
  COLLECTING: Object.freeze(["FILTERING", "EXHAUSTED"] as const),
  FILTERING: Object.freeze(["RANKING", "EXHAUSTED"] as const),
  RANKING: Object.freeze(["DISPATCHING"] as const),
  DISPATCHING: Object.freeze(["WAITING", "FAILED", "SUCCEEDED"] as const),
  WAITING: Object.freeze(["HANDOFF", "FAILED", "SUCCEEDED"] as const),
  HANDOFF: Object.freeze(["SUCCEEDED"] as const),
  FAILED: Object.freeze(["REROUTING", "EXHAUSTED"] as const),
  REROUTING: Object.freeze(["COLLECTING"] as const),
  EXHAUSTED: Object.freeze([] as const),
  SUCCEEDED: Object.freeze([] as const),
});

export interface RoutingAttemptRecord {
  task_id: string;
  state: RoutingAttemptState;
  reroute_count: number;
  excluded_agents: string[];
  observed_at?: string;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class RoutingError extends Error {
  readonly code: string;
  readonly task_id?: string;
  readonly capability?: string;
  readonly target?: string | null;
  readonly excluded_agents?: string[];
  readonly reroute_count?: number;
  readonly observed_at?: string;
  override readonly cause?: unknown;

  constructor(
    code: string,
    message = code,
    options?: {
      task_id?: string;
      capability?: string;
      target?: string | null;
      excluded_agents?: readonly string[];
      reroute_count?: number;
      observed_at?: string;
      cause?: unknown;
    },
  ) {
    super(message);
    this.name = "RoutingError";
    this.code = code;
    this.task_id = options?.task_id;
    this.capability = options?.capability;
    this.target = options?.target;
    this.excluded_agents = options?.excluded_agents ? [...options.excluded_agents] : undefined;
    this.reroute_count = options?.reroute_count;
    this.observed_at = options?.observed_at;
    if (options?.cause !== undefined) this.cause = options.cause;
  }

  toJSON(): Record<string, unknown> {
    return {
      code: this.code,
      message: this.message,
      ...(this.task_id !== undefined ? { task_id: this.task_id } : {}),
      ...(this.capability !== undefined ? { capability: this.capability } : {}),
      ...(this.target !== undefined ? { target: this.target } : {}),
      ...(this.excluded_agents !== undefined ? { excluded_agents: this.excluded_agents } : {}),
      ...(this.reroute_count !== undefined ? { reroute_count: this.reroute_count } : {}),
      ...(this.observed_at !== undefined ? { observed_at: this.observed_at } : {}),
    };
  }
}

// ---------------------------------------------------------------------------
// Pure helpers (§B.10, §B.6, §B.7.3)
// ---------------------------------------------------------------------------

/** Exact capability equality (§B.10.4). */
export function capabilityExactMatch(name: string, pattern: string): boolean {
  return name === pattern;
}

/**
 * Capability glob match for discovery filters (§B.10.5–§B.10.6).
 * `*` matches exactly one segment; patterns with `*` inside a segment are invalid.
 */
export function capabilityGlobMatch(name: string, pattern: string): boolean {
  if (!pattern.includes("*")) return name === pattern;
  if (!isValidCapabilityGlob(pattern)) return false;
  const ns = name.split(".");
  const ps = pattern.split(".");
  if (ns.length !== ps.length) return false;
  if (ns.some((s) => s.length === 0) || ps.some((s) => s.length === 0)) return false;
  for (let i = 0; i < ns.length; i++) {
    if (ps[i] === "*") continue;
    if (ps[i] !== ns[i]) return false;
  }
  return true;
}

/** Reject invalid globs such as `cal*` or `*check` (§B.10.7). */
export function isValidCapabilityGlob(pattern: string): boolean {
  const segments = pattern.split(".");
  if (segments.some((s) => s.length === 0)) return false;
  for (const seg of segments) {
    if (seg === "*") continue;
    if (seg.includes("*")) return false;
  }
  return true;
}

export function dialectRank(dialect: Dialect, preferDialects?: readonly Dialect[]): number {
  if (preferDialects && preferDialects.length > 0) {
    const idx = preferDialects.indexOf(dialect);
    if (idx >= 0) return idx;
    return preferDialects.length + (dialect === "native" ? 0 : 1);
  }
  return dialect === "native" ? 0 : 1;
}

export function localityRank(locality: LocalityClass): number {
  switch (locality) {
    case "same_host":
      return 0;
    case "lan":
      return 1;
    case "relay":
      return 2;
    case "unknown":
      return 3;
    default:
      return 3;
  }
}

/**
 * Quantized freshness bucket (§B.6.5 / user Pref3).
 * `floor(last_seen_ms / heartbeat_ms)`; missing → `"missing"`.
 */
export function freshnessBucket(
  lastSeenMs: number | null | undefined,
  locality: LocalityClass,
  hasLastSeen = true,
): string {
  if (!hasLastSeen || lastSeenMs == null || !Number.isFinite(lastSeenMs)) return "missing";
  const hb = HEARTBEAT_MS[locality] ?? HEARTBEAT_MS.unknown;
  return String(Math.floor(lastSeenMs / hb));
}

/** Pref3 sort key: missing = +Infinity; else negative ms so fresher sorts first. */
export function freshnessSortKey(candidate: RoutingCandidate): number {
  if (candidate.has_last_seen === false || !Number.isFinite(candidate.last_seen_ms)) {
    return Number.POSITIVE_INFINITY;
  }
  // Bucket-quantized Pref3 (K3 / §B.6.5 operational resolution).
  const bucket = Math.floor(candidate.last_seen_ms / (HEARTBEAT_MS[candidate.locality] ?? HEARTBEAT_MS.unknown));
  return -bucket;
}

export function exclusionKey(agentId: string, instanceId?: string): string {
  if (instanceId !== undefined && instanceId.length > 0) return `${agentId}\0${instanceId}`;
  return agentId;
}

/** Agent id strings for event payloads (strip instance suffix from composite keys). */
export function exclusionAgentId(key: string): string {
  const nul = key.indexOf("\0");
  return nul >= 0 ? key.slice(0, nul) : key;
}

export function isCandidateExcluded(
  candidate: RoutingCandidate,
  excluded: ReadonlySet<string>,
): boolean {
  if (excluded.size === 0) return false;
  if (excluded.has(candidate.agent_id)) return true;
  const key = exclusionKey(candidate.agent_id, candidate.instance_id);
  return excluded.has(key);
}

function toExclusionSet(exclude?: ReadonlySet<string> | readonly string[]): Set<string> {
  if (!exclude) return new Set();
  if (exclude instanceof Set) return new Set(exclude);
  return new Set(exclude);
}

function parseTimestampMs(value: string | null | undefined): { ms: number; has: boolean } {
  if (value == null || value === "") return { ms: Number.NaN, has: false };
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) return { ms: Number.NaN, has: false };
  return { ms, has: true };
}

function toIsoObservedAt(value: Date | string): string {
  if (typeof value === "string") {
    const ms = Date.parse(value);
    return Number.isFinite(ms) ? new Date(ms).toISOString() : value;
  }
  return value.toISOString();
}

function compareUnicode(a: string, b: string): number {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

function sortAgents(agents: readonly RegistryAgentEntry[]): RegistryAgentEntry[] {
  return [...agents].sort((a, b) => compareUnicode(a.agent_id, b.agent_id));
}

function sortAds(ads: readonly CapabilityEntry[]): CapabilityEntry[] {
  return [...ads].sort((a, b) => {
    const byName = compareUnicode(a.name, b.name);
    if (byName !== 0) return byName;
    const da = a.dialect ?? "native";
    const db = b.dialect ?? "native";
    return compareUnicode(da, db);
  });
}

export interface RetryabilityContext {
  idempotency?: string;
  side_effects?: string;
  /** True when failure occurred after accept / mid-execution. */
  postAccept?: boolean;
  phase?: "accept" | "post-accept" | "dispatch" | string;
}

/**
 * Classify whether a failure is retryable for bounded re-route (§B.7.3).
 * Also exported as {@link classifyRetryability}.
 */
export function isRetryableFailure(error: unknown, context?: RetryabilityContext): boolean {
  return classifyRetryability(error, context).retryable;
}

export function classifyRetryability(
  error: unknown,
  context?: RetryabilityContext,
): { retryable: boolean; reason: RerouteReason | "non_retryable"; code?: string } {
  const code = extractErrorCode(error);
  const message = extractErrorMessage(error).toLowerCase();
  const status = extractHttpStatus(error);

  // Permission / authz — never retryable.
  if (
    code === "PERMISSION_DENIED" ||
    code === "AUTHORIZATION_DENIED" ||
    code === "AUTHZ" ||
    /permission\s*denied|authz|authorization.?denied|forbidden/i.test(message) ||
    /permission\s*denied/i.test(code)
  ) {
    return { retryable: false, reason: "non_retryable", code };
  }

  // Schema / invalid params — never retryable.
  if (
    code === "INVALID_PARAMS" ||
    code === "SCHEMA" ||
    code === "INVALID_SCHEMA" ||
    code === "SCHEMA_INVALID" ||
    /schema\s*invalid|invalid[_\s]?params|invalid[_\s]?schema/i.test(message) ||
    /schema/i.test(code) && /invalid/i.test(message + code)
  ) {
    return { retryable: false, reason: "non_retryable", code };
  }

  // RESULT_TOO_LARGE unless idempotency === "pure".
  if (code === "RESULT_TOO_LARGE" || /result[_\s]?too[_\s]?large/i.test(message)) {
    if (context?.idempotency === "pure") {
      return { retryable: true, reason: "retryable_remote", code };
    }
    return { retryable: false, reason: "non_retryable", code };
  }

  // Caller cancel — not retryable.
  if (code === "CANCELLED" || code === "CANCELED" || /cancel/i.test(code)) {
    return { retryable: false, reason: "non_retryable", code };
  }

  // Transport timeout.
  if (
    code === "ETIMEDOUT" ||
    code === "TIMEOUT" ||
    code === "PMX.TASK.DEADLINE_EXCEEDED" ||
    /etimedout|timeout|timed\s*out/i.test(message) ||
    /timeout/i.test(code)
  ) {
    return { retryable: true, reason: "timeout", code };
  }

  // A2A 502/503/504.
  if (status === 502 || status === 503 || status === 504) {
    return { retryable: true, reason: "retryable_transport", code };
  }
  if (/^5(?:0[234])$/.test(code) || /http\s*50[234]/i.test(message)) {
    return { retryable: true, reason: "retryable_transport", code };
  }

  // TARGET_UNAVAILABLE — MUST be retryable (baseline).
  if (code === "TARGET_UNAVAILABLE") {
    return { retryable: true, reason: "retryable_remote", code };
  }

  // Accept-time CAPABILITY_NOT_ADVERTISED — MUST be retryable.
  if (code === "CAPABILITY_NOT_ADVERTISED") {
    return { retryable: true, reason: "retryable_remote", code };
  }

  // Post-accept disconnect: YES if idempotency pure/idempotent AND side_effects not write/approval.
  const postAccept =
    context?.postAccept === true ||
    context?.phase === "post-accept" ||
    /econnreset|disconnect|ws\s*close|heartbeat\s*timeout/i.test(message) ||
    code === "ECONNRESET" ||
    code === "DISCONNECT";

  if (postAccept) {
    const idem = (context?.idempotency ?? "").toLowerCase();
    const side = (context?.side_effects ?? "").toLowerCase();
    const idemOk = idem === "pure" || idem === "idempotent";
    const sideBlocks = side === "write" || side === "approval";
    if (idemOk && !sideBlocks) {
      return { retryable: true, reason: "retryable_transport", code };
    }
    return { retryable: false, reason: "non_retryable", code };
  }

  // Generic connection refused / relay disconnect mid-submit.
  if (
    code === "ECONNREFUSED" ||
    /connection\s*refused|relay\s*disconnect/i.test(message)
  ) {
    return { retryable: true, reason: "retryable_transport", code };
  }

  if (code === "UNHEALTHY" || /unhealthy/i.test(message)) {
    return { retryable: true, reason: "unhealthy", code };
  }

  return { retryable: false, reason: "non_retryable", code };
}

function extractErrorCode(error: unknown): string {
  if (error instanceof RoutingError) return error.code;
  if (error && typeof error === "object") {
    const obj = error as Record<string, unknown>;
    if (typeof obj.code === "string") return obj.code;
    if (typeof obj.name === "string" && obj.name !== "Error") return obj.name;
  }
  if (typeof error === "string") return error;
  return "";
}

function extractErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  if (error && typeof error === "object" && typeof (error as { message?: unknown }).message === "string") {
    return (error as { message: string }).message;
  }
  return String(error ?? "");
}

function extractHttpStatus(error: unknown): number | undefined {
  if (!error || typeof error !== "object") return undefined;
  const obj = error as Record<string, unknown>;
  if (typeof obj.status === "number") return obj.status;
  if (typeof obj.statusCode === "number") return obj.statusCode;
  if (typeof obj.httpStatus === "number") return obj.httpStatus;
  return undefined;
}

// ---------------------------------------------------------------------------
// Registry helpers
// ---------------------------------------------------------------------------

/** Deep-freeze a RegistryView for snapshot routing (§B.17). */
export function freezeRegistryView(view: RegistryView): Readonly<RegistryView> {
  const agents: RegistryAgentEntry[] = view.agents.map((agent) => {
    const caps: CapabilityEntry[] = agent.capabilities.map((c) => Object.freeze({ ...c }) as CapabilityEntry);
    return Object.freeze({
      ...agent,
      capabilities: Object.freeze(caps) as CapabilityEntry[],
      metadata: agent.metadata ? Object.freeze({ ...agent.metadata }) : undefined,
    }) as RegistryAgentEntry;
  });
  return Object.freeze({
    ...view,
    agents: Object.freeze(agents) as RegistryAgentEntry[],
  }) as Readonly<RegistryView>;
}

export function emptyRegistryView(lastRefreshedAt?: string): RegistryView {
  return {
    agents: [],
    last_refreshed_at: lastRefreshedAt ?? new Date(0).toISOString(),
  };
}

/** Merge gateway discovery agents into a RegistryView (locality default: relay). */
export function mergeGatewayAgentsIntoRegistry(
  view: RegistryView,
  agents: readonly {
    id: string;
    display_name?: string;
    capabilities?: unknown[];
    last_seen?: string | null;
    metadata?: Record<string, unknown>;
    health?: HealthState;
    locality?: LocalityClass;
    mesh_member?: boolean;
    instance_id?: string;
    perm_hint?: "allow" | "deny" | "absent";
  }[],
  options?: { locality?: LocalityClass; observedAt?: string },
): RegistryView {
  const byId = new Map<string, RegistryAgentEntry>();
  for (const a of view.agents) byId.set(a.agent_id, { ...a, capabilities: [...a.capabilities] });

  const localityDefault = options?.locality ?? "relay";
  for (const g of agents) {
    const caps: CapabilityEntry[] = [];
    for (const raw of g.capabilities ?? []) {
      if (!raw || typeof raw !== "object") continue;
      const c = raw as Record<string, unknown>;
      const name = typeof c.name === "string" ? c.name : undefined;
      if (!name) continue;
      const dialect = c.dialect === "a2a" || c.dialect === "native" ? c.dialect : "native";
      caps.push({
        name,
        schema: typeof c.schema === "object" && c.schema ? (c.schema as Record<string, unknown>) : undefined,
        scope: typeof c.scope === "string" ? c.scope : undefined,
        dialect,
        a2a_url: typeof c.a2a_url === "string" ? c.a2a_url : undefined,
        version: typeof c.version === "string" ? c.version : undefined,
      });
    }
    const prev = byId.get(g.id);
    const incomingLocality = g.locality ?? localityDefault;
    const bestLocality =
      prev && localityRank(prev.locality) < localityRank(incomingLocality)
        ? prev.locality
        : incomingLocality;
    const meta = g.metadata ?? prev?.metadata;
    const scalarMeta = meta
      ? Object.fromEntries(
          Object.entries(meta).filter(
            ([, v]) => typeof v === "string" || typeof v === "number" || typeof v === "boolean",
          ),
        ) as Record<string, string | number | boolean>
      : undefined;
    byId.set(g.id, {
      agent_id: g.id,
      display_name: g.display_name ?? prev?.display_name,
      capabilities: caps.length > 0 ? caps : (prev?.capabilities ?? []),
      health: g.health ?? prev?.health ?? "healthy",
      last_seen: g.last_seen !== undefined ? g.last_seen : (prev?.last_seen ?? null),
      locality: bestLocality,
      metadata: scalarMeta,
      mesh_member: g.mesh_member ?? prev?.mesh_member ?? true,
      instance_id: g.instance_id ?? prev?.instance_id,
      perm_hint: g.perm_hint ?? prev?.perm_hint,
    });
  }

  return {
    agents: sortAgents([...byId.values()]),
    last_refreshed_at: options?.observedAt ?? new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// CapabilityRouter
// ---------------------------------------------------------------------------

type TaskRoutedHandler = (event: TaskRoutedEvent) => void;
type RerouteHandler = (event: RerouteEvent) => void;

/**
 * PRODUCT-layer capability router (§B.3). Process-local RR state; frozen
 * RegistryView per route.begin.
 */
export class CapabilityRouter {
  private registry: RegistryView;
  private readonly observedAtFn: () => Date | string;
  private readonly rrState: Map<string, number>;
  private readonly rrLocks = new Map<string, Promise<void>>();
  private a2aBridge: A2AOutboundBridge | null;
  private nativeDispatch?: (input: NativeDispatchInput) => Promise<void>;
  private adapterAvailable: boolean;
  private canonicalExpansion: Record<string, string[]>;
  readonly coldStartPolicy: ColdStartPolicy;
  private onDiscover?: () => Promise<void>;
  private callerId?: string;
  private dialectHooks: DialectPreferenceHooks | null = null;
  private readonly taskRoutedHandlers = new Set<TaskRoutedHandler>();
  private readonly rerouteHandlers = new Set<RerouteHandler>();
  private readonly attemptByTask = new Map<string, RoutingAttemptRecord>();
  /** One-shot discovery guard for lazy cold-start (must not bump reroute_count). */
  private coldStartDiscoveryUsed = false;

  constructor(options: CapabilityRouterOptions = {}) {
    this.registry = options.registry ? freezeRegistryView(options.registry) : emptyRegistryView();
    this.observedAtFn = options.observedAt ?? (() => new Date());
    this.rrState = options.rrState ?? new Map();
    this.a2aBridge = options.a2aBridge ?? null;
    this.nativeDispatch = options.nativeDispatch;
    this.adapterAvailable = options.adapterAvailable ?? false;
    this.canonicalExpansion = options.canonicalExpansion ?? {};
    this.coldStartPolicy = options.coldStartPolicy ?? "eager";
    this.onDiscover = options.onDiscover;
    this.callerId = options.callerId;
  }

  /** Replace the live registry (tests / discovery merges). */
  setRegistry(view: RegistryView): void {
    this.registry = freezeRegistryView(view);
  }

  /** Alias used by client test hooks. */
  setRegistryView(view: RegistryView): void {
    this.setRegistry(view);
  }

  getRegistry(): Readonly<RegistryView> {
    return this.registry;
  }

  /** Freeze and install a snapshot; returns the frozen view. */
  freezeSnapshot(view?: RegistryView): Readonly<RegistryView> {
    const snap = freezeRegistryView(view ?? this.registry);
    this.registry = snap;
    return snap;
  }

  setDialectPreferenceHooks(hooks: DialectPreferenceHooks | null): void {
    this.dialectHooks = hooks;
  }

  setA2AOutboundBridge(bridge: A2AOutboundBridge | null): void {
    this.a2aBridge = bridge;
    if (bridge) this.adapterAvailable = true;
  }

  setNativeDispatch(fn: ((input: NativeDispatchInput) => Promise<void>) | undefined): void {
    this.nativeDispatch = fn;
  }

  setOnDiscover(fn: (() => Promise<void>) | undefined): void {
    this.onDiscover = fn;
  }

  setAdapterAvailable(available: boolean): void {
    this.adapterAvailable = available;
  }

  setCanonicalExpansion(map: Record<string, string[]>): void {
    this.canonicalExpansion = map;
  }

  onTaskRouted(handler: TaskRoutedHandler): () => void {
    this.taskRoutedHandlers.add(handler);
    return () => {
      this.taskRoutedHandlers.delete(handler);
    };
  }

  onReroute(handler: RerouteHandler): () => void {
    this.rerouteHandlers.add(handler);
    return () => {
      this.rerouteHandlers.delete(handler);
    };
  }

  getRoundRobinState(): ReadonlyMap<string, number> {
    return this.rrState;
  }

  resetRoundRobin(): void {
    this.rrState.clear();
  }

  getAttemptState(taskId: string): RoutingAttemptRecord | undefined {
    const rec = this.attemptByTask.get(taskId);
    return rec ? { ...rec, excluded_agents: [...rec.excluded_agents] } : undefined;
  }

  /**
   * Transition helper for tests / observability. Enforces REROUTING gate:
   * only from FAILED when reroute_count ∈ {0,1}.
   */
  transitionAttempt(
    taskId: string,
    to: RoutingAttemptState,
    opts?: { reroute_count?: number },
  ): RoutingAttemptRecord {
    const rec = this.attemptByTask.get(taskId) ?? {
      task_id: taskId,
      state: "SUBMITTED" as RoutingAttemptState,
      reroute_count: 0,
      excluded_agents: [],
    };
    const allowed = ROUTING_ATTEMPT_TRANSITIONS[rec.state];
    if (!allowed.includes(to) && rec.state !== to) {
      throw new RoutingError(
        "INVALID_TASK",
        `Illegal routing transition ${rec.state} → ${to}`,
        { task_id: taskId },
      );
    }
    if (to === "REROUTING") {
      const count = opts?.reroute_count ?? rec.reroute_count;
      if (count !== 0 && count !== 1) {
        throw new RoutingError(
          "ALL_CANDIDATES_EXHAUSTED",
          "REROUTING only allowed when reroute_count is 0 or 1",
          { task_id: taskId, reroute_count: count },
        );
      }
    }
    rec.state = to;
    if (opts?.reroute_count !== undefined) rec.reroute_count = opts.reroute_count;
    this.attemptByTask.set(taskId, rec);
    return { ...rec, excluded_agents: [...rec.excluded_agents] };
  }

  // ---- Collection / filters / rank (§B.3–§B.6) ----

  /** Collect raw candidates for exact capability C (§B.4). */
  collectCandidates(capability: string, registry: RegistryView = this.registry): RoutingCandidate[] {
    const out: RoutingCandidate[] = [];
    const seen = new Set<string>(); // agent_id\0dialect first-wins

    for (const agent of sortAgents(registry.agents)) {
      for (const adv of sortAds(agent.capabilities)) {
        if (!capabilityExactMatch(adv.name, capability)) continue;
        // Unknown / future dialect tags MUST be ignored for v6 ranking (§B.4.2 / §B.12.2).
        if (adv.dialect != null && adv.dialect !== "native" && adv.dialect !== "a2a") continue;
        const dialect: Dialect = adv.dialect === "a2a" ? "a2a" : "native";
        if (dialect === "a2a" && (!adv.a2a_url || String(adv.a2a_url).length === 0)) continue;

        const dedupeKey = `${agent.agent_id}\0${dialect}`;
        if (seen.has(dedupeKey)) continue;
        seen.add(dedupeKey);

        const ts = parseTimestampMs(agent.last_seen);
        out.push({
          agent_id: agent.agent_id,
          instance_id: agent.instance_id,
          capability,
          dialect,
          a2a_url: dialect === "a2a" ? String(adv.a2a_url) : undefined,
          locality: agent.locality,
          last_seen_ms: ts.has ? ts.ms : Number.NaN,
          has_last_seen: ts.has,
          health: agent.health,
          perm_hint: agent.perm_hint ?? "absent",
        });
      }
    }
    return out;
  }

  /**
   * Mark stale last_seen as offline using lease TTL vs observed_at (§B.5.3),
   * then keep healthy|degraded only.
   */
  filterHealth(
    raw: readonly RoutingCandidate[],
    observedAtMs: number,
  ): RoutingCandidate[] {
    const out: RoutingCandidate[] = [];
    for (const c of raw) {
      let health = c.health;
      if (c.has_last_seen !== false && Number.isFinite(c.last_seen_ms)) {
        const ttl = LEASE_TTL_MS[c.locality] ?? LEASE_TTL_MS.unknown;
        if (observedAtMs - c.last_seen_ms > ttl) {
          health = "offline";
        }
      }
      if (health === "healthy" || health === "degraded") {
        out.push(health === c.health ? c : { ...c, health });
      }
    }
    return out;
  }

  /** Deny excludes; allow/absent keep (§B.6.1). */
  filterPermission(candidates: readonly RoutingCandidate[]): RoutingCandidate[] {
    return candidates.filter((c) => c.perm_hint !== "deny");
  }

  applyExclusion(
    candidates: readonly RoutingCandidate[],
    excluded: ReadonlySet<string>,
  ): RoutingCandidate[] {
    return candidates.filter((c) => !isCandidateExcluded(c, excluded));
  }

  /**
   * StableRank with Pref1–5 and RR assignment (§B.6.3–§B.6.5).
   * Advances the winner's RR cursor under a per-key lock.
   */
  stableRank(
    candidates: readonly RoutingCandidate[],
    capability: string,
    preferDialects?: readonly Dialect[],
  ): { ordered: RoutingCandidate[]; rrIndex: Map<string, number>; winnerKey: string | null } {
    if (candidates.length === 0) {
      return { ordered: [], rrIndex: new Map(), winnerKey: null };
    }

    // Group by Pref1–3 tie key.
    const groups = new Map<string, RoutingCandidate[]>();
    for (const c of candidates) {
      const key = this.tieGroupKey(c, capability, preferDialects);
      const list = groups.get(key);
      if (list) list.push(c);
      else groups.set(key, [c]);
    }

    const rrIndex = new Map<string, number>();
    let winnerKey: string | null = null;
    let bestSort: [number, number, number] | null = null;

    for (const [key, group] of groups) {
      const sorted = [...group].sort((a, b) => {
        const byId = compareUnicode(a.agent_id, b.agent_id);
        if (byId !== 0) return byId;
        return compareUnicode(a.dialect, b.dialect);
      });
      const n = sorted.length;
      const cursor = (this.rrState.get(key) ?? 0) % n;
      for (let i = 0; i < n; i++) {
        const c = sorted[(cursor + i) % n]!;
        rrIndex.set(candidateIdentity(c), i);
      }
      const sample = sorted[0]!;
      const sortTriple: [number, number, number] = [
        dialectRank(sample.dialect, preferDialects),
        localityRank(sample.locality),
        freshnessSortKey(sample),
      ];
      if (
        bestSort == null ||
        sortTriple[0] < bestSort[0] ||
        (sortTriple[0] === bestSort[0] && sortTriple[1] < bestSort[1]) ||
        (sortTriple[0] === bestSort[0] && sortTriple[1] === bestSort[1] && sortTriple[2] < bestSort[2])
      ) {
        bestSort = sortTriple;
        // Winner of this group after RR rotation.
        winnerKey = key;
      }
    }

    const ordered = [...candidates].sort((a, b) => {
      const d = dialectRank(a.dialect, preferDialects) - dialectRank(b.dialect, preferDialects);
      if (d !== 0) return d;
      const loc = localityRank(a.locality) - localityRank(b.locality);
      if (loc !== 0) return loc;
      const fr = freshnessSortKey(a) - freshnessSortKey(b);
      if (fr !== 0) return fr;
      const rra = rrIndex.get(candidateIdentity(a)) ?? 0;
      const rrb = rrIndex.get(candidateIdentity(b)) ?? 0;
      if (rra !== rrb) return rra - rrb;
      const byId = compareUnicode(a.agent_id, b.agent_id);
      if (byId !== 0) return byId;
      return compareUnicode(a.dialect, b.dialect);
    });

    return { ordered, rrIndex, winnerKey: winnerKey ?? this.tieGroupKey(ordered[0]!, capability, preferDialects) };
  }

  private tieGroupKey(
    c: RoutingCandidate,
    capability: string,
    preferDialects?: readonly Dialect[],
  ): string {
    const d = dialectRank(c.dialect, preferDialects);
    const loc = localityRank(c.locality);
    const bucket = freshnessBucket(c.last_seen_ms, c.locality, c.has_last_seen !== false);
    return `${capability}\0${d}\0${loc}\0${bucket}`;
  }

  /**
   * Advance RR cursor for the winner's tie set (§B.6.5 / §B.16.4).
   * Per-key Promise chain serializes concurrent advances; the cursor update
   * itself is synchronous so single-threaded tests stay deterministic.
   */
  private advanceRoundRobin(rrKey: string, n: number): void {
    if (n <= 0) return;
    const prev = this.rrLocks.get(rrKey) ?? Promise.resolve();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    this.rrLocks.set(
      rrKey,
      prev.then(() => gate).catch(() => gate),
    );
    // Critical section (sync): fetch cursor and advance.
    const cursor = (this.rrState.get(rrKey) ?? 0) % n;
    this.rrState.set(rrKey, (cursor + 1) % n);
    release();
  }

  /**
   * Pure sync CapabilityRoute selection (§B.3.3) without dispatch.
   * Throws {@link RoutingError} on failure.
   */
  capabilityRoute(
    task: {
      capability: string;
      target?: string;
      task_id?: string;
      caller_id?: string;
      preferDialects?: readonly Dialect[];
    },
    excludedAgents: ReadonlySet<string> | readonly string[] = [],
    rerouteCount = 0,
    registry: RegistryView = this.registry,
    observedAt?: Date | string,
  ): { winner: RoutingCandidate; routed: TaskRoutedEvent; ordered: RoutingCandidate[] } {
    const capability = task.capability;
    if (capability.includes("*")) {
      throw new RoutingError("INVALID_TASK", "capability for dispatch must be exact", {
        capability,
        task_id: task.task_id,
      });
    }

    const observed = toIsoObservedAt(observedAt ?? this.observedAtFn());
    const observedMs = Date.parse(observed);
    const excluded = toExclusionSet(excludedAgents);
    const preferDialects = task.preferDialects;

    if (task.target != null && String(task.target).length > 0) {
      return this.explicitTargetVerify(
        {
          capability,
          target: String(task.target),
          task_id: task.task_id,
          caller_id: task.caller_id ?? this.callerId,
          preferDialects,
        },
        registry,
        observed,
        rerouteCount,
      );
    }

    // Step 1: Collect
    const raw = this.collectCandidates(capability, registry);

    // Step 2: Health
    const healthy = this.filterHealth(raw, observedMs);
    if (healthy.length === 0) {
      throw new RoutingError("NO_CANDIDATES", "no healthy advertisers", {
        capability,
        task_id: task.task_id,
        excluded_agents: [...excluded].map(exclusionAgentId).sort(compareUnicode),
        reroute_count: rerouteCount,
        observed_at: observed,
      });
    }

    // Step 3: Permission
    const allowed = this.filterPermission(healthy);
    if (allowed.length === 0) {
      throw new RoutingError("NO_CANDIDATES", "no authorized advertisers", {
        capability,
        task_id: task.task_id,
        excluded_agents: [...excluded].map(exclusionAgentId).sort(compareUnicode),
        reroute_count: rerouteCount,
        observed_at: observed,
      });
    }

    // Exclusion — candidate_count is pre-exclusion (§B.3.5)
    const candidateCount = allowed.length;
    const candidates = this.applyExclusion(allowed, excluded);
    if (candidates.length === 0) {
      if (excluded.size > 0) {
        throw new RoutingError("ALL_CANDIDATES_EXHAUSTED", "all candidates excluded or failed", {
          capability,
          task_id: task.task_id,
          excluded_agents: [...excluded].map(exclusionAgentId).sort(compareUnicode),
          reroute_count: rerouteCount,
          observed_at: observed,
        });
      }
      throw new RoutingError("NO_CANDIDATES", "empty after filters", {
        capability,
        task_id: task.task_id,
        reroute_count: rerouteCount,
        observed_at: observed,
      });
    }

    const { ordered, rrIndex, winnerKey } = this.stableRank(candidates, capability, preferDialects);
    const winner = ordered[0]!;

    // Advance RR for winner's Pref1–3 class.
    if (winnerKey) {
      const tieSize = ordered.filter(
        (c) => this.tieGroupKey(c, capability, preferDialects) === winnerKey,
      ).length;
      this.advanceRoundRobin(winnerKey, tieSize);
    }

    const excludedSorted = [...excluded].map(exclusionAgentId);
    // Unique + sorted Unicode ascending (§B.8.3).
    const excludedUnique = [...new Set(excludedSorted)].sort(compareUnicode);

    const routed: TaskRoutedEvent = {
      type: "task.routed",
      task_id: task.task_id ?? "",
      candidate_count: candidateCount,
      chosen_agent: winner.agent_id,
      dialect: winner.dialect,
      reroute_count: rerouteCount,
      excluded_agents: excludedUnique,
      locality_tier: winner.locality,
      observed_at: observed,
      capability,
      ranked_scores: ordered.map((c, position) => ({
        agent_id: c.agent_id,
        dialect: c.dialect,
        locality_tier: c.locality,
        dialect_rank: dialectRank(c.dialect, preferDialects),
        locality_rank: localityRank(c.locality),
        last_seen: c.has_last_seen === false || !Number.isFinite(c.last_seen_ms)
          ? null
          : new Date(c.last_seen_ms).toISOString(),
        rr_index: rrIndex.get(candidateIdentity(c)) ?? 0,
        position,
      })),
    };

    return { winner, routed, ordered };
  }

  /**
   * Explicit-target verification (§B.13). No multi-candidate re-route.
   */
  explicitTargetVerify(
    task: {
      capability: string;
      target: string;
      task_id?: string;
      caller_id?: string;
      preferDialects?: readonly Dialect[];
    },
    registry: RegistryView = this.registry,
    observedAt?: string,
    rerouteCount = 0,
  ): { winner: RoutingCandidate; routed: TaskRoutedEvent; ordered: RoutingCandidate[] } {
    const observed = observedAt ?? toIsoObservedAt(this.observedAtFn());
    const entries = this.lookupAgent(registry, task.target);

    if (entries.length === 0) {
      throw new RoutingError("TARGET_UNAVAILABLE", `Target not found: ${task.target}`, {
        target: task.target,
        capability: task.capability,
        task_id: task.task_id,
        observed_at: observed,
        reroute_count: rerouteCount,
      });
    }

    const uniqueIds = new Set(entries.map((e) => e.agent_id));
    if (uniqueIds.size > 1) {
      throw new RoutingError("AMBIGUOUS_TARGET", `Target resolves to multiple agents: ${task.target}`, {
        target: task.target,
        capability: task.capability,
        task_id: task.task_id,
        observed_at: observed,
        reroute_count: rerouteCount,
      });
    }

    const agent = entries[0]!;
    const advs = sortAds(agent.capabilities).filter((a) =>
      capabilityExactMatch(a.name, task.capability),
    );
    if (advs.length === 0) {
      throw new RoutingError("CAPABILITY_NOT_ADVERTISED", `Target lacks capability ${task.capability}`, {
        target: task.target,
        capability: task.capability,
        task_id: task.task_id,
        observed_at: observed,
        reroute_count: rerouteCount,
      });
    }

    const usable: RoutingCandidate[] = [];
    let sawA2aOnly = false;
    const ts = parseTimestampMs(agent.last_seen);

    for (const a of advs) {
      const dialect = a.dialect ?? "native";
      if (dialect === "native" || dialect == null) {
        usable.push({
          agent_id: agent.agent_id,
          instance_id: agent.instance_id,
          capability: task.capability,
          dialect: "native",
          locality: agent.locality,
          last_seen_ms: ts.has ? ts.ms : Number.NaN,
          has_last_seen: ts.has,
          health: agent.health,
          perm_hint: agent.perm_hint ?? "absent",
        });
      } else if (dialect === "a2a") {
        if ((this.adapterAvailable || this.a2aBridge) && a.a2a_url) {
          usable.push({
            agent_id: agent.agent_id,
            instance_id: agent.instance_id,
            capability: task.capability,
            dialect: "a2a",
            a2a_url: String(a.a2a_url),
            locality: agent.locality,
            last_seen_ms: ts.has ? ts.ms : Number.NaN,
            has_last_seen: ts.has,
            health: agent.health,
            perm_hint: agent.perm_hint ?? "absent",
          });
        } else {
          sawA2aOnly = true;
        }
      }
    }

    // Dedupe (agent_id, dialect)
    const deduped: RoutingCandidate[] = [];
    const seen = new Set<string>();
    for (const c of usable) {
      const k = `${c.agent_id}\0${c.dialect}`;
      if (seen.has(k)) continue;
      seen.add(k);
      deduped.push(c);
    }

    if (deduped.length === 0) {
      if (sawA2aOnly && advs.every((a) => (a.dialect ?? "native") === "a2a")) {
        throw new RoutingError("DIALECT_UNSUPPORTED", "A2A dialect required but no adapter/bridge", {
          target: task.target,
          capability: task.capability,
          task_id: task.task_id,
          observed_at: observed,
          reroute_count: rerouteCount,
        });
      }
      throw new RoutingError("CAPABILITY_NOT_ADVERTISED", `No usable dialect for ${task.capability}`, {
        target: task.target,
        capability: task.capability,
        task_id: task.task_id,
        observed_at: observed,
        reroute_count: rerouteCount,
      });
    }

    if (agent.perm_hint === "deny") {
      throw new RoutingError("TARGET_UNAVAILABLE", "Caller denied by perm_hint", {
        target: task.target,
        capability: task.capability,
        task_id: task.task_id,
        observed_at: observed,
        reroute_count: rerouteCount,
      });
    }

    const { ordered, rrIndex, winnerKey } = this.stableRank(
      deduped,
      task.capability,
      task.preferDialects,
    );
    const winner = ordered[0]!;
    if (winnerKey) {
      const tieSize = ordered.filter(
        (c) => this.tieGroupKey(c, task.capability, task.preferDialects) === winnerKey,
      ).length;
      this.advanceRoundRobin(winnerKey, tieSize);
    }

    const routed: TaskRoutedEvent = {
      type: "task.routed",
      task_id: task.task_id ?? "",
      candidate_count: 1,
      chosen_agent: agent.agent_id,
      dialect: winner.dialect,
      reroute_count: rerouteCount,
      excluded_agents: [],
      locality_tier: winner.locality,
      observed_at: observed,
      capability: task.capability,
      ranked_scores: ordered.map((c, position) => ({
        agent_id: c.agent_id,
        dialect: c.dialect,
        locality_tier: c.locality,
        dialect_rank: dialectRank(c.dialect, task.preferDialects),
        locality_rank: localityRank(c.locality),
        last_seen: c.has_last_seen === false || !Number.isFinite(c.last_seen_ms)
          ? null
          : new Date(c.last_seen_ms).toISOString(),
        rr_index: rrIndex.get(candidateIdentity(c)) ?? 0,
        position,
      })),
    };

    return { winner, routed, ordered };
  }

  /** LookupAgent with optional canonical expansion (§B.13.5). Off by default. */
  lookupAgent(registry: RegistryView, target: string): RegistryAgentEntry[] {
    const exact = registry.agents.filter((a) => a.agent_id === target);
    if (exact.length > 0) return exact;

    const expanded = this.canonicalExpansion[target];
    if (!expanded || expanded.length === 0) return [];

    const matches: RegistryAgentEntry[] = [];
    const seen = new Set<string>();
    for (const id of expanded) {
      for (const a of registry.agents) {
        if (a.agent_id === id && !seen.has(a.agent_id)) {
          seen.add(a.agent_id);
          matches.push(a);
        }
      }
    }
    return matches;
  }

  /**
   * Rank pre-built candidates (E.2.3 API): health + permission + exclusion + StableRank.
   */
  rankCandidates(
    candidates: readonly RoutingCandidate[],
    options: RankCandidatesOptions,
  ): RoutingCandidate[] {
    const nowMs = options.nowMs ?? Date.parse(toIsoObservedAt(this.observedAtFn()));
    const healthy = this.filterHealth(candidates, nowMs);
    const allowed = this.filterPermission(healthy);
    const excluded = toExclusionSet(options.exclude);
    const remaining = this.applyExclusion(allowed, excluded);
    const prefer = options.preferDialects;
    const { ordered } = this.stableRank(remaining, options.capability, prefer);
    // rankCandidates MUST NOT advance RR (selectCandidate / capabilityRoute do).
    // Re-run without mutating: restore cursors by not calling advance here.
    return ordered;
  }

  /**
   * Select winner from pre-built candidates (E.2.3). Advances RR.
   */
  selectCandidate(
    candidates: readonly RoutingCandidate[],
    options: SelectCandidateOptions,
  ): RoutingCandidate | undefined {
    const nowMs = options.nowMs ?? Date.parse(toIsoObservedAt(this.observedAtFn()));
    const healthy = this.filterHealth(candidates, nowMs);
    const allowed = this.filterPermission(healthy);
    const excluded = toExclusionSet(options.exclude);
    const remaining = this.applyExclusion(allowed, excluded);
    if (remaining.length === 0) return undefined;

    const prefer = options.preferDialects;
    const { ordered, winnerKey } = this.stableRank(remaining, options.capability, prefer);
    const winner = ordered[0];
    if (!winner) return undefined;

    const key = options.roundRobinKey ?? winnerKey;
    if (key) {
      const tieSize = ordered.filter(
        (c) => this.tieGroupKey(c, options.capability, prefer) === (winnerKey ?? key),
      ).length;
      this.advanceRoundRobin(winnerKey ?? key, tieSize);
    }
    return winner;
  }

  /**
   * Async route with bounded re-route (§B.7) and dispatch.
   */
  async routeTask(
    options: RouteTaskOptions,
  ): Promise<{ task_id: string; chosen: RoutingCandidate; routed: TaskRoutedEvent }> {
    const taskId = options.taskId ?? uuidv7();
    const maxAttempts = Math.min(options.maxReroutes ?? 3, 3);
    const excluded = new Set<string>();
    let rerouteCount = 0;
    let lastError: unknown;
    let preferDialects = options.preferDialects;

    if (this.dialectHooks?.preferDialects) {
      preferDialects = await this.dialectHooks.preferDialects(options.capability);
    }

    this.attemptByTask.set(taskId, {
      task_id: taskId,
      state: "SUBMITTED",
      reroute_count: 0,
      excluded_agents: [],
    });
    this.transitionAttempt(taskId, "ROUTING");

    // Freeze snapshot at route.begin (§B.17). Lazy discovery may refresh it once.
    let snapshot = freezeRegistryView(this.registry);
    let discoveredOnce = false;

    while (rerouteCount < maxAttempts) {
      const observed = toIsoObservedAt(this.observedAtFn());
      const rec = this.attemptByTask.get(taskId)!;
      rec.reroute_count = rerouteCount;
      rec.excluded_agents = [...excluded].map(exclusionAgentId);
      rec.observed_at = observed;
      this.transitionAttempt(taskId, "COLLECTING", { reroute_count: rerouteCount });

      let selection: { winner: RoutingCandidate; routed: TaskRoutedEvent; ordered: RoutingCandidate[] };
      try {
        selection = this.capabilityRoute(
          {
            capability: options.capability,
            target: options.target,
            task_id: taskId,
            caller_id: options.caller_id ?? this.callerId,
            preferDialects,
          },
          excluded,
          rerouteCount,
          snapshot,
          observed,
        );
        this.transitionAttempt(taskId, "FILTERING", { reroute_count: rerouteCount });
        this.transitionAttempt(taskId, "RANKING", { reroute_count: rerouteCount });
      } catch (err) {
        // Lazy cold-start: discovery MUST NOT increment reroute_count (§B.4.1.1).
        if (
          err instanceof RoutingError &&
          err.code === "NO_CANDIDATES" &&
          this.coldStartPolicy === "lazy" &&
          this.onDiscover &&
          !discoveredOnce &&
          !this.coldStartDiscoveryUsed
        ) {
          discoveredOnce = true;
          this.coldStartDiscoveryUsed = true;
          await this.onDiscover();
          snapshot = freezeRegistryView(this.registry);
          continue;
        }
        this.transitionAttempt(taskId, "EXHAUSTED", { reroute_count: rerouteCount });
        throw err;
      }

      // Optional acceptCandidate veto (Preference hooks) — veto only.
      if (this.dialectHooks?.acceptCandidate) {
        const ok = await this.dialectHooks.acceptCandidate(selection.winner, options.capability);
        if (!ok) {
          excluded.add(exclusionKey(selection.winner.agent_id, selection.winner.instance_id));
          lastError = new RoutingError("TARGET_UNAVAILABLE", "Candidate vetoed by acceptCandidate hook");
          if (rerouteCount >= maxAttempts - 1 || options.target) {
            this.transitionAttempt(taskId, "EXHAUSTED", { reroute_count: rerouteCount });
            throw lastError;
          }
          this.emitReroute({
            task_id: taskId,
            failed_agent: selection.winner.agent_id,
            reason: "policy_reject",
            attempt: rerouteCount + 1,
            excluded_agents: [...excluded].map(exclusionAgentId).sort(compareUnicode),
          });
          this.transitionAttempt(taskId, "FAILED", { reroute_count: rerouteCount });
          this.transitionAttempt(taskId, "REROUTING", { reroute_count: rerouteCount });
          rerouteCount += 1;
          this.transitionAttempt(taskId, "COLLECTING", { reroute_count: rerouteCount });
          continue;
        }
      }

      selection.routed.task_id = taskId;
      this.emitTaskRouted(selection.routed);

      this.transitionAttempt(taskId, "DISPATCHING", { reroute_count: rerouteCount });

      try {
        await this.dispatchWinner(selection.winner, options, taskId);
        this.transitionAttempt(taskId, "WAITING", { reroute_count: rerouteCount });
        this.transitionAttempt(taskId, "HANDOFF", { reroute_count: rerouteCount });
        this.transitionAttempt(taskId, "SUCCEEDED", { reroute_count: rerouteCount });
        return { task_id: taskId, chosen: selection.winner, routed: selection.routed };
      } catch (dispatchErr) {
        lastError = dispatchErr;
        this.transitionAttempt(taskId, "FAILED", { reroute_count: rerouteCount });

        const classification = classifyRetryability(dispatchErr, {
          idempotency: options.idempotency,
          side_effects: options.side_effects,
        });

        // Explicit-target: same-target retry only, max 3, then TARGET_UNAVAILABLE (§B.7.5 / §B.13).
        if (options.target) {
          if (!classification.retryable || rerouteCount >= maxAttempts - 1) {
            this.transitionAttempt(taskId, "EXHAUSTED", { reroute_count: rerouteCount });
            if (classification.retryable) {
              throw new RoutingError("TARGET_UNAVAILABLE", "Explicit target retries exhausted", {
                target: options.target,
                capability: options.capability,
                task_id: taskId,
                reroute_count: rerouteCount,
                cause: dispatchErr,
              });
            }
            throw dispatchErr;
          }
          // Same-target retry — do NOT add alternate agents; still count attempts.
          this.emitReroute({
            task_id: taskId,
            failed_agent: selection.winner.agent_id,
            reason: classification.reason === "non_retryable" ? "retryable_transport" : classification.reason,
            attempt: rerouteCount + 1,
            excluded_agents: [...excluded].map(exclusionAgentId).sort(compareUnicode),
          });
          this.transitionAttempt(taskId, "REROUTING", { reroute_count: rerouteCount });
          rerouteCount += 1;
          continue;
        }

        if (!classification.retryable || rerouteCount >= maxAttempts - 1) {
          this.transitionAttempt(taskId, "EXHAUSTED", { reroute_count: rerouteCount });
          if (classification.retryable && excluded.size >= 0) {
            throw new RoutingError("ALL_CANDIDATES_EXHAUSTED", "Re-route attempts depleted", {
              capability: options.capability,
              task_id: taskId,
              excluded_agents: [...excluded].map(exclusionAgentId).sort(compareUnicode),
              reroute_count: rerouteCount,
              cause: dispatchErr,
            });
          }
          throw dispatchErr;
        }

        excluded.add(exclusionKey(selection.winner.agent_id, selection.winner.instance_id));
        // Also exclude by agent_id alone so all dialect records drop (§B.7.2).
        excluded.add(selection.winner.agent_id);

        this.emitReroute({
          task_id: taskId,
          failed_agent: selection.winner.agent_id,
          reason: classification.reason === "non_retryable" ? "retryable_transport" : classification.reason,
          attempt: rerouteCount + 1,
          excluded_agents: [...excluded].map(exclusionAgentId).sort(compareUnicode),
        });

        this.transitionAttempt(taskId, "REROUTING", { reroute_count: rerouteCount });
        rerouteCount += 1;
      }
    }

    // Safety net: loop exited without a terminal transition (should be rare).
    const terminal = this.attemptByTask.get(taskId);
    if (terminal && terminal.state === "REROUTING") {
      // REROUTING → COLLECTING → EXHAUSTED is the legal path when depleted mid-loop.
      this.transitionAttempt(taskId, "COLLECTING", { reroute_count: rerouteCount });
    }
    if (terminal && terminal.state !== "EXHAUSTED") {
      const from = this.attemptByTask.get(taskId)!.state;
      if (from === "FAILED" || from === "COLLECTING" || from === "FILTERING" || from === "ROUTING") {
        this.transitionAttempt(taskId, "EXHAUSTED", { reroute_count: rerouteCount });
      } else if (from !== "EXHAUSTED") {
        // Force terminal for observability even if transition table is exhausted.
        this.attemptByTask.get(taskId)!.state = "EXHAUSTED";
      }
    }
    throw new RoutingError("ALL_CANDIDATES_EXHAUSTED", "Re-route attempts depleted", {
      capability: options.capability,
      task_id: taskId,
      excluded_agents: [...excluded].map(exclusionAgentId).sort(compareUnicode),
      reroute_count: rerouteCount,
      cause: lastError,
    });
  }

  private async dispatchWinner(
    winner: RoutingCandidate,
    options: RouteTaskOptions,
    taskId: string,
  ): Promise<void> {
    if (winner.dialect === "native") {
      if (this.nativeDispatch) {
        await this.nativeDispatch({
          agent_id: winner.agent_id,
          capability: options.capability,
          payload: options.payload,
          task_id: taskId,
          signal: options.signal,
        });
      }
      // Missing nativeDispatch → no-op success for pure routing tests (§dispatch).
      return;
    }

    // a2a
    if (!this.a2aBridge) {
      throw new RoutingError(
        "DIALECT_UNSUPPORTED",
        "A2A outbound bridge unbound (BRIDGE_UNBOUND)",
        {
          capability: options.capability,
          task_id: taskId,
          target: winner.agent_id,
        },
      );
    }
    if (!winner.a2a_url) {
      throw new RoutingError("DIALECT_UNSUPPORTED", "A2A winner missing a2a_url", {
        capability: options.capability,
        task_id: taskId,
        target: winner.agent_id,
      });
    }
    // MUST NOT parse A2A payloads — pass through to bridge.
    await this.a2aBridge.send({
      a2a_url: winner.a2a_url,
      capability: options.capability,
      payload: options.payload,
      task_id: taskId,
      signal: options.signal,
    });
  }

  private emitTaskRouted(event: TaskRoutedEvent): void {
    for (const h of this.taskRoutedHandlers) {
      try {
        h(event);
      } catch {
        // Subscriber errors MUST NOT break routing.
      }
    }
  }

  private emitReroute(event: RerouteEvent): void {
    for (const h of this.rerouteHandlers) {
      try {
        h(event);
      } catch {
        // ignore
      }
    }
  }
}

function candidateIdentity(c: RoutingCandidate): string {
  return `${c.agent_id}\0${c.dialect}`;
}

export function createCapabilityRouter(options?: CapabilityRouterOptions): CapabilityRouter {
  return new CapabilityRouter(options);
}

// ---------------------------------------------------------------------------
// Appendix H — conformance vector helpers (normative)
// ---------------------------------------------------------------------------

export const APPENDIX_H_VECTOR_IDS = [
  "H.native_over_a2a",
  "H.locality_same_host",
  "H.freshness_bucket",
  "H.rr_three_tied",
  "H.exclusion_reroute",
  "H.explicit_cap_missing",
  "H.explicit_ambiguous",
] as const;

export type AppendixHVectorId = (typeof APPENDIX_H_VECTOR_IDS)[number];

const FIXED_NOW = "2026-08-08T12:00:00.000Z";
const FIXED_NOW_MS = Date.parse(FIXED_NOW);

function agentEntry(partial: {
  agent_id: string;
  display_name?: string;
  capabilities: CapabilityEntry[];
  health?: HealthState;
  last_seen?: string | null;
  locality?: LocalityClass;
  mesh_member?: boolean;
  instance_id?: string;
  perm_hint?: "allow" | "deny" | "absent";
  metadata?: Record<string, string | number | boolean>;
}): RegistryAgentEntry {
  return {
    agent_id: partial.agent_id,
    display_name: partial.display_name,
    capabilities: partial.capabilities,
    health: partial.health ?? "healthy",
    last_seen: partial.last_seen !== undefined ? partial.last_seen : FIXED_NOW,
    locality: partial.locality ?? "lan",
    mesh_member: partial.mesh_member ?? true,
    instance_id: partial.instance_id,
    perm_hint: partial.perm_hint,
    metadata: partial.metadata,
  };
}

/** Build the registry snapshot for an Appendix H vector id. */
export function buildAppendixHRegistry(vectorId: AppendixHVectorId): RegistryView {
  switch (vectorId) {
    case "H.native_over_a2a":
      return freezeRegistryView({
        agents: [
          agentEntry({
            agent_id: "org.polymesh.dual",
            locality: "lan",
            capabilities: [
              { name: "calendar.check", dialect: "a2a", a2a_url: "https://example.test/a2a" },
              { name: "calendar.check", dialect: "native" },
            ],
          }),
        ],
        last_refreshed_at: FIXED_NOW,
      });
    case "H.locality_same_host":
      return freezeRegistryView({
        agents: [
          agentEntry({
            agent_id: "org.polymesh.lan-peer",
            locality: "lan",
            capabilities: [{ name: "ping", dialect: "native" }],
          }),
          agentEntry({
            agent_id: "org.polymesh.local",
            locality: "same_host",
            capabilities: [{ name: "ping", dialect: "native" }],
          }),
        ],
        last_refreshed_at: FIXED_NOW,
      });
    case "H.freshness_bucket": {
      // Same Pref1–2; last_seen within same same_host bucket (30s).
      const t0 = FIXED_NOW_MS;
      return freezeRegistryView({
        agents: [
          agentEntry({
            agent_id: "org.polymesh.a",
            locality: "same_host",
            last_seen: new Date(t0 - 5_000).toISOString(),
            capabilities: [{ name: "echo", dialect: "native" }],
          }),
          agentEntry({
            agent_id: "org.polymesh.b",
            locality: "same_host",
            last_seen: new Date(t0 - 10_000).toISOString(),
            capabilities: [{ name: "echo", dialect: "native" }],
          }),
        ],
        last_refreshed_at: FIXED_NOW,
      });
    }
    case "H.rr_three_tied":
      return freezeRegistryView({
        agents: [
          agentEntry({
            agent_id: "org.polymesh.worker-a",
            locality: "lan",
            capabilities: [{ name: "work", dialect: "native" }],
          }),
          agentEntry({
            agent_id: "org.polymesh.worker-b",
            locality: "lan",
            capabilities: [{ name: "work", dialect: "native" }],
          }),
          agentEntry({
            agent_id: "org.polymesh.worker-c",
            locality: "lan",
            capabilities: [{ name: "work", dialect: "native" }],
          }),
        ],
        last_refreshed_at: FIXED_NOW,
      });
    case "H.exclusion_reroute":
      return freezeRegistryView({
        agents: [
          agentEntry({
            agent_id: "org.polymesh.flaky",
            locality: "lan",
            capabilities: [{ name: "job", dialect: "native" }],
          }),
          agentEntry({
            agent_id: "org.polymesh.stable",
            locality: "lan",
            capabilities: [{ name: "job", dialect: "native" }],
          }),
        ],
        last_refreshed_at: FIXED_NOW,
      });
    case "H.explicit_cap_missing":
      return freezeRegistryView({
        agents: [
          agentEntry({
            agent_id: "org.polymesh.target",
            locality: "lan",
            capabilities: [{ name: "other.thing", dialect: "native" }],
          }),
        ],
        last_refreshed_at: FIXED_NOW,
      });
    case "H.explicit_ambiguous":
      return freezeRegistryView({
        agents: [
          agentEntry({
            agent_id: "org.personal.alice",
            locality: "lan",
            capabilities: [{ name: "greet", dialect: "native" }],
          }),
          agentEntry({
            agent_id: "org.work.alice",
            locality: "lan",
            capabilities: [{ name: "greet", dialect: "native" }],
          }),
        ],
        last_refreshed_at: FIXED_NOW,
      });
    default: {
      const _exhaustive: never = vectorId;
      throw new Error(`Unknown Appendix H vector: ${String(_exhaustive)}`);
    }
  }
}

export interface AppendixHExpectation {
  chosen_agent?: string;
  dialect?: Dialect;
  error_code?: RoutingErrorCode | "INVALID_TASK";
  capability: string;
  target?: string;
  /** For RR / exclusion vectors. */
  exclude?: string[];
  reroute_count?: number;
}

export function appendixHExpectation(vectorId: AppendixHVectorId): AppendixHExpectation {
  switch (vectorId) {
    case "H.native_over_a2a":
      return { capability: "calendar.check", chosen_agent: "org.polymesh.dual", dialect: "native" };
    case "H.locality_same_host":
      return { capability: "ping", chosen_agent: "org.polymesh.local", dialect: "native" };
    case "H.freshness_bucket":
      // Same bucket → Pref4 RR; cursor 0 → first Unicode agent_id.
      return { capability: "echo", chosen_agent: "org.polymesh.a", dialect: "native" };
    case "H.rr_three_tied":
      return { capability: "work", chosen_agent: "org.polymesh.worker-a", dialect: "native" };
    case "H.exclusion_reroute":
      return {
        capability: "job",
        chosen_agent: "org.polymesh.stable",
        dialect: "native",
        exclude: ["org.polymesh.flaky"],
        reroute_count: 1,
      };
    case "H.explicit_cap_missing":
      return {
        capability: "missing.cap",
        target: "org.polymesh.target",
        error_code: "CAPABILITY_NOT_ADVERTISED",
      };
    case "H.explicit_ambiguous":
      return {
        capability: "greet",
        target: "alice",
        error_code: "AMBIGUOUS_TARGET",
      };
    default: {
      const _exhaustive: never = vectorId;
      throw new Error(`Unknown Appendix H vector: ${String(_exhaustive)}`);
    }
  }
}

/**
 * Run one Appendix H vector against a fresh router (process-local RR cursor 0).
 * Returns `{ ok, chosen_agent?, dialect?, error_code? }`.
 */
export function runAppendixHVector(
  vectorId: AppendixHVectorId,
  router?: CapabilityRouter,
): {
  ok: boolean;
  chosen_agent?: string;
  dialect?: Dialect;
  error_code?: string;
  expected: AppendixHExpectation;
} {
  const expected = appendixHExpectation(vectorId);
  const registry = buildAppendixHRegistry(vectorId);
  const r =
    router ??
    createCapabilityRouter({
      registry,
      observedAt: () => FIXED_NOW,
      adapterAvailable: false,
      canonicalExpansion:
        vectorId === "H.explicit_ambiguous"
          ? { alice: ["org.personal.alice", "org.work.alice"] }
          : undefined,
    });
  if (router) r.setRegistry(registry);
  if (vectorId === "H.explicit_ambiguous") {
    r.setCanonicalExpansion({ alice: ["org.personal.alice", "org.work.alice"] });
  }

  try {
    const result = r.capabilityRoute(
      {
        capability: expected.capability,
        target: expected.target,
        task_id: "01900000-0000-7000-8000-000000000001",
      },
      expected.exclude ?? [],
      expected.reroute_count ?? 0,
      registry,
      FIXED_NOW,
    );
    if (expected.error_code) {
      return { ok: false, chosen_agent: result.winner.agent_id, dialect: result.winner.dialect, expected };
    }
    const ok =
      result.winner.agent_id === expected.chosen_agent && result.winner.dialect === expected.dialect;
    return {
      ok,
      chosen_agent: result.winner.agent_id,
      dialect: result.winner.dialect,
      expected,
    };
  } catch (err) {
    const code = err instanceof RoutingError ? err.code : extractErrorCode(err);
    const ok = expected.error_code != null && code === expected.error_code;
    return { ok, error_code: code, expected };
  }
}

/** Run all Appendix H vectors; returns per-vector results. */
export function runAllAppendixHVectors(): ReturnType<typeof runAppendixHVector>[] {
  return APPENDIX_H_VECTOR_IDS.map((id) => runAppendixHVector(id));
}

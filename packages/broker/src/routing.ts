/**
 * Multi-instance routing primitives for the opt-in PolyMesh v0.2 profile.
 *
 * This module deliberately contains no transports and no storage access. A
 * durable store owns registration and route records; the broker supplies a
 * snapshot of those records here to make a deterministic selection. Keeping
 * the functions pure makes the important ordering rule explicit: persist the
 * selected instance and route pin before attempting delivery.
 */

import { createHash } from "node:crypto";

/** Health states defined by the v0.2 routing profile. */
export const HealthState = Object.freeze({
  HEALTHY: "HEALTHY",
  SUSPECT: "SUSPECT",
  UNHEALTHY: "UNHEALTHY",
  DRAINING: "DRAINING",
  OFFLINE: "OFFLINE",
} as const);

export type HealthState = (typeof HealthState)[keyof typeof HealthState];

/** Alias retained for callers that prefer the noun-first name. */
export const InstanceHealth = HealthState;
export type InstanceHealth = HealthState;

export const HEALTHY = HealthState.HEALTHY;
export const SUSPECT = HealthState.SUSPECT;
export const UNHEALTHY = HealthState.UNHEALTHY;
export const DRAINING = HealthState.DRAINING;
export const OFFLINE = HealthState.OFFLINE;

/**
 * Events that may advance a registered instance's durable health state.
 *
 * This is deliberately a pure transition vocabulary: the relay/store owns
 * the fenced compare-and-set and timestamp write, while callers can use this
 * helper to reject an impossible state change before they allocate a route or
 * publish an in-memory health signal.
 */
export const HealthTransitionEvent = Object.freeze({
  SOFT_DEADLINE_MISSED: "soft_deadline_missed",
  HARD_DEADLINE_MISSED: "hard_deadline_missed",
  FRESH_AUTHENTICATED_PROOF: "fresh_authenticated_proof",
  FATAL_TRANSPORT_FAILURE: "fatal_transport_failure",
  ADMIN_DRAIN: "admin_drain",
  RECOVERY_DRAIN: "recovery_drain",
  SESSION_OR_LEASE_ENDED: "session_or_lease_ended",
  DRAIN_DEADLINE_ELAPSED: "drain_deadline_elapsed",
  AUTHENTICATED_REGISTRATION: "authenticated_registration",
} as const);

export type HealthTransitionEvent = (typeof HealthTransitionEvent)[keyof typeof HealthTransitionEvent];

/** Inputs needed for one pure, fence-aware health-state decision. */
export interface HealthTransitionInput {
  state: HealthState;
  event: HealthTransitionEvent;
  /** Current durable registration fence, required for offline recovery. */
  registrationFence?: number;
  /** Candidate fence supplied by an authenticated replacement registration. */
  nextRegistrationFence?: number;
}

export type HealthTransitionResult =
  | { ok: true; state: HealthState; changed: boolean }
  | {
    ok: false;
    state: HealthState;
    code: "INVALID_HEALTH_TRANSITION" | "REGISTRATION_FENCE_REQUIRED";
  };

/**
 * Apply the normative v0.2 health graph without mutating durable state.
 *
 * In particular, only a fresh authenticated proof can restore SUSPECT, and
 * OFFLINE can return to HEALTHY only after a registration fence increases.
 * A caller must still make this result durable with the relevant
 * registration/session fence in the same transaction as its health update.
 */
export function transitionHealthState(input: HealthTransitionInput): HealthTransitionResult {
  const { state, event } = input;
  if (!isHealthState(state) || !isHealthTransitionEvent(event)) {
    return { ok: false, state: isHealthState(state) ? state : OFFLINE, code: "INVALID_HEALTH_TRANSITION" };
  }

  if (event === HealthTransitionEvent.AUTHENTICATED_REGISTRATION) {
    if (state !== OFFLINE) return { ok: false, state, code: "INVALID_HEALTH_TRANSITION" };
    if (!isPositiveRegistrationFence(input.registrationFence) ||
      !isPositiveRegistrationFence(input.nextRegistrationFence) ||
      input.nextRegistrationFence <= input.registrationFence) {
      return { ok: false, state, code: "REGISTRATION_FENCE_REQUIRED" };
    }
    return { ok: true, state: HEALTHY, changed: true };
  }

  if (event === HealthTransitionEvent.SESSION_OR_LEASE_ENDED) {
    return state === OFFLINE
      ? { ok: false, state, code: "INVALID_HEALTH_TRANSITION" }
      : { ok: true, state: OFFLINE, changed: true };
  }

  if (event === HealthTransitionEvent.DRAIN_DEADLINE_ELAPSED) {
    return state === DRAINING
      ? { ok: true, state: OFFLINE, changed: true }
      : { ok: false, state, code: "INVALID_HEALTH_TRANSITION" };
  }

  if (event === HealthTransitionEvent.ADMIN_DRAIN || event === HealthTransitionEvent.RECOVERY_DRAIN) {
    return state === HEALTHY || state === SUSPECT || state === UNHEALTHY
      ? { ok: true, state: DRAINING, changed: true }
      : { ok: false, state, code: "INVALID_HEALTH_TRANSITION" };
  }

  if (event === HealthTransitionEvent.SOFT_DEADLINE_MISSED) {
    return state === HEALTHY
      ? { ok: true, state: SUSPECT, changed: true }
      : { ok: false, state, code: "INVALID_HEALTH_TRANSITION" };
  }

  if (event === HealthTransitionEvent.HARD_DEADLINE_MISSED) {
    return state === SUSPECT
      ? { ok: true, state: UNHEALTHY, changed: true }
      : { ok: false, state, code: "INVALID_HEALTH_TRANSITION" };
  }

  if (event === HealthTransitionEvent.FRESH_AUTHENTICATED_PROOF) {
    return state === SUSPECT
      ? { ok: true, state: HEALTHY, changed: true }
      : { ok: false, state, code: "INVALID_HEALTH_TRANSITION" };
  }

  if (event === HealthTransitionEvent.FATAL_TRANSPORT_FAILURE) {
    return state === HEALTHY || state === SUSPECT
      ? { ok: true, state: UNHEALTHY, changed: true }
      : { ok: false, state, code: "INVALID_HEALTH_TRANSITION" };
  }

  return { ok: false, state, code: "INVALID_HEALTH_TRANSITION" };
}

/**
 * A durable instance registration projected into the routing layer. These
 * fields are intentionally metadata only: a process-local socket belongs in
 * a broker connection index, never in a durable route or registry row.
 */
export interface RoutingInstance {
  meshId: string;
  agentId: string;
  instanceId: string;
  /** Authenticated principal to which this logical agent ID is bound. */
  principalId: string;
  /** Current physical session/channel identifier. */
  sessionId: string;
  /** Monotonic fence allocated on registration/replacement. */
  registrationFence: number;
  /** Monotonic fence for the current session lease. Defaults to registrationFence when omitted. */
  sessionFence?: number;
  health: HealthState;
  /** Capacity supplied by relay policy, never trusted from an agent Card. */
  capacity?: number;
  currentInflight?: number;
  /** Policy-controlled HRW weight. One is the neutral/default weight. */
  capacityWeight?: number;
  /** `false` means card validation failed; omitted is legacy-compatible valid. */
  cardValid?: boolean;
  /** Optional card expiry expressed as epoch milliseconds. */
  cardExpiresAt?: number;
  /** Registration/session lease expiry expressed as epoch milliseconds. */
  leaseExpiresAt: number;
  /** Capabilities from the verified current card, if the caller needs capability filtering. */
  capabilities?: readonly string[] | ReadonlySet<string>;
  /** Optional precomputed policy decision for this specific candidate. */
  policyAllowed?: boolean;
}

/** A fully specified session/registration fencing token. */
export interface InstanceFence {
  sessionId: string;
  registrationFence: number;
  sessionFence: number;
}

/** Target constraints shared by normal and pinned routing. */
export interface RouteTargetRequest {
  meshId: string;
  targetAgentId: string;
  /** Exact delivery, rather than logical-agent selection. */
  targetInstanceId?: string;
  /** Expected authenticated identity binding for the target logical agent. */
  expectedPrincipalId?: string;
  /** Require the verified target Card to advertise this capability. */
  requiredCapability?: string;
  /** Current trusted monotonic/wall clock value. Defaults to Date.now(). */
  now?: number;
  /** Existing pinned work may finish on a draining instance; new work may not. */
  allowDraining?: boolean;
  /** Existing pinned work does not reserve new capacity by default. */
  requireCapacity?: boolean;
  /** Additional relay policy predicate. A throw is a fail-closed denial. */
  policyAllows?: (instance: RoutingInstance) => boolean;
}

/** Normal HRW selection adds the stable partition/routing key. */
export interface RouteSelectionRequest extends RouteTargetRequest {
  /** task_id for submissions, or source.instance_id + idempotency key otherwise. */
  routingKey: string;
}

export type CandidateRejectionReason =
  | "INVALID_INSTANCE"
  | "MESH_MISMATCH"
  | "AGENT_MISMATCH"
  | "INSTANCE_MISMATCH"
  | "PRINCIPAL_MISMATCH"
  | "INVALID_CARD"
  | "CARD_EXPIRED"
  | "LEASE_EXPIRED"
  | "UNHEALTHY"
  | "DRAINING"
  | "CAPACITY_EXHAUSTED"
  | "CAPABILITY_UNAVAILABLE"
  | "POLICY_DENIED";

export type CandidateEligibility =
  | { eligible: true; health: HealthState }
  | { eligible: false; health: HealthState; reason: CandidateRejectionReason };

export type RouteSelectionCode = "UNKNOWN_TARGET" | "TARGET_UNAVAILABLE" | "IDENTITY_COLLISION";

export interface RouteSelectionSuccess<T extends RoutingInstance = RoutingInstance> {
  ok: true;
  /** Alias kept alongside `selected` to make call sites self-documenting. */
  instance: T;
  selected: T;
  /** Lower scores win; see weightedRendezvousScore(). */
  score: number;
}

export interface RouteSelectionFailure {
  ok: false;
  code: RouteSelectionCode;
  retryable: boolean;
  /** Present for an exact target or a known logical target which was filtered. */
  reason?: CandidateRejectionReason;
}

export type RouteSelectionResult<T extends RoutingInstance = RoutingInstance> =
  | RouteSelectionSuccess<T>
  | RouteSelectionFailure;

/** A persisted immutable physical target for a task lifecycle. */
export interface RoutePin {
  readonly meshId: string;
  readonly agentId: string;
  readonly instanceId: string;
  readonly principalId: string;
  readonly sessionId: string;
  readonly registrationFence: number;
  readonly sessionFence: number;
  /** Fence held by the task-route record itself. */
  readonly routeFence: number;
}

export interface CreateRoutePinOptions {
  /** Durable task-route fence. Defaults to one for in-memory/local callers. */
  routeFence?: number;
}

export type PinnedRouteUnavailableReason = CandidateRejectionReason | "FENCE_MISMATCH";

export type PinnedRouteResolution<T extends RoutingInstance = RoutingInstance> =
  | { ok: true; instance: T; selected: T }
  | {
    ok: false;
    code: "PMX.ROUTING.PINNED_INSTANCE_UNAVAILABLE";
    retryable: true;
    reason: PinnedRouteUnavailableReason;
  };

/** Result of applying an ordered registration/session update. */
export type FencedUpdateDecision = "apply" | "stale" | "conflict";

const HRW_DOMAIN = "PMX-HRW/0.2\0";
const TWO_TO_53 = 9_007_199_254_740_992;

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isFiniteTimestamp(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function isFence(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isHealthState(value: unknown): value is HealthState {
  return value === HEALTHY || value === SUSPECT || value === UNHEALTHY || value === DRAINING || value === OFFLINE;
}

const HEALTH_TRANSITION_EVENT_SET = new Set<string>(Object.values(HealthTransitionEvent));

function isHealthTransitionEvent(value: unknown): value is HealthTransitionEvent {
  return typeof value === "string" && HEALTH_TRANSITION_EVENT_SET.has(value);
}

function isPositiveRegistrationFence(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 1;
}

function sessionFenceOf(instance: Pick<RoutingInstance, "registrationFence" | "sessionFence">): number | undefined {
  const candidate = instance.sessionFence ?? instance.registrationFence;
  return isFence(candidate) ? candidate : undefined;
}

function normalizedNow(now: number | undefined): number {
  const value = now ?? Date.now();
  if (!isFiniteTimestamp(value)) throw new RangeError("Routing clock must be a finite non-negative timestamp");
  return value;
}

function validInstanceIdentity(instance: RoutingInstance): boolean {
  return isNonEmptyString(instance.meshId) &&
    isNonEmptyString(instance.agentId) &&
    isNonEmptyString(instance.instanceId) &&
    isNonEmptyString(instance.principalId) &&
    isNonEmptyString(instance.sessionId) &&
    isFence(instance.registrationFence) &&
    sessionFenceOf(instance) !== undefined &&
    isHealthState(instance.health) &&
    isFiniteTimestamp(instance.leaseExpiresAt);
}

function hasCapability(instance: RoutingInstance, requiredCapability: string | undefined): boolean {
  if (requiredCapability === undefined) return true;
  const advertised = instance.capabilities;
  if (advertised === undefined) return false;
  return "has" in advertised ? advertised.has(requiredCapability) : advertised.includes(requiredCapability);
}

function hasUsableCapacity(instance: RoutingInstance): boolean {
  const capacity = instance.capacity;
  const inflight = instance.currentInflight ?? 0;
  if (capacity === undefined) return Number.isSafeInteger(inflight) && inflight >= 0;
  return Number.isSafeInteger(capacity) && capacity >= 0 &&
    Number.isSafeInteger(inflight) && inflight >= 0 && inflight < capacity;
}

function capacityWeightOf(instance: RoutingInstance): number | undefined {
  const weight = instance.capacityWeight ?? 1;
  return typeof weight === "number" && Number.isFinite(weight) && weight > 0 ? weight : undefined;
}

function firstRejection<T extends RoutingInstance>(
  instances: readonly T[],
  request: RouteTargetRequest,
): CandidateRejectionReason | undefined {
  for (const instance of instances) {
    const eligibility = evaluateRoutingCandidate(instance, request);
    if (!eligibility.eligible) return eligibility.reason;
  }
  return undefined;
}

function sameRouteTarget(instance: RoutingInstance, request: Pick<RouteTargetRequest, "meshId" | "targetAgentId">): boolean {
  return instance.meshId === request.meshId && instance.agentId === request.targetAgentId;
}

function compareFresherInstance(left: RoutingInstance, right: RoutingInstance): number {
  if (left.registrationFence !== right.registrationFence) return right.registrationFence - left.registrationFence;
  const leftSessionFence = sessionFenceOf(left) ?? -1;
  const rightSessionFence = sessionFenceOf(right) ?? -1;
  if (leftSessionFence !== rightSessionFence) return rightSessionFence - leftSessionFence;
  return left.sessionId.localeCompare(right.sessionId);
}

/**
 * Return the effective health after lease expiry. An expired lease is OFFLINE
 * regardless of the last persisted heartbeat state.
 */
export function effectiveHealth(instance: RoutingInstance, now = Date.now()): HealthState {
  const trustedNow = normalizedNow(now);
  if (!isFiniteTimestamp(instance.leaseExpiresAt) || instance.leaseExpiresAt <= trustedNow) return OFFLINE;
  return isHealthState(instance.health) ? instance.health : OFFLINE;
}

/**
 * Check one candidate against v0.2 new-work routing requirements. This does
 * not make a selection and therefore is also useful for diagnostics/metrics.
 */
export function evaluateRoutingCandidate(
  instance: RoutingInstance,
  request: RouteTargetRequest,
): CandidateEligibility {
  const now = normalizedNow(request.now);
  const health = effectiveHealth(instance, now);
  if (!validInstanceIdentity(instance)) return { eligible: false, health, reason: "INVALID_INSTANCE" };
  if (instance.meshId !== request.meshId) return { eligible: false, health, reason: "MESH_MISMATCH" };
  if (instance.agentId !== request.targetAgentId) return { eligible: false, health, reason: "AGENT_MISMATCH" };
  if (request.targetInstanceId !== undefined && instance.instanceId !== request.targetInstanceId) {
    return { eligible: false, health, reason: "INSTANCE_MISMATCH" };
  }
  if (request.expectedPrincipalId !== undefined && instance.principalId !== request.expectedPrincipalId) {
    return { eligible: false, health, reason: "PRINCIPAL_MISMATCH" };
  }
  if (instance.cardValid === false) return { eligible: false, health, reason: "INVALID_CARD" };
  if (instance.cardExpiresAt !== undefined && (!isFiniteTimestamp(instance.cardExpiresAt) || instance.cardExpiresAt <= now)) {
    return { eligible: false, health, reason: "CARD_EXPIRED" };
  }
  if (health === OFFLINE) return { eligible: false, health, reason: "LEASE_EXPIRED" };
  if (health === DRAINING && request.allowDraining !== true) return { eligible: false, health, reason: "DRAINING" };
  if (health !== HEALTHY && !(health === DRAINING && request.allowDraining === true)) {
    return { eligible: false, health, reason: "UNHEALTHY" };
  }
  if (request.requireCapacity !== false && !hasUsableCapacity(instance)) {
    return { eligible: false, health, reason: "CAPACITY_EXHAUSTED" };
  }
  if (!hasCapability(instance, request.requiredCapability)) {
    return { eligible: false, health, reason: "CAPABILITY_UNAVAILABLE" };
  }
  if (instance.policyAllowed === false) return { eligible: false, health, reason: "POLICY_DENIED" };
  try {
    if (request.policyAllows && request.policyAllows(instance) !== true) {
      return { eligible: false, health, reason: "POLICY_DENIED" };
    }
  } catch {
    return { eligible: false, health, reason: "POLICY_DENIED" };
  }
  return { eligible: true, health };
}

/** Filter candidate registrations using the same rules as selection. */
export function filterEligibleRoutingInstances<T extends RoutingInstance>(
  instances: readonly T[],
  request: RouteTargetRequest,
): T[] {
  return instances.filter((instance) => evaluateRoutingCandidate(instance, request).eligible);
}

/** Alias for callers that use the shorter routing terminology. */
export const filterRoutingCandidates = filterEligibleRoutingInstances;

function updateHashField(hash: ReturnType<typeof createHash>, value: string): void {
  const data = Buffer.from(value, "utf8");
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(data.byteLength, 0);
  hash.update(length);
  hash.update(data);
}

/**
 * A domain-separated 64-bit hash for HRW. Fields are length-prefixed so two
 * distinct routing tuples cannot become the same byte stream by concatenation.
 */
export function rendezvousHash64(
  meshId: string,
  targetAgentId: string,
  routingKey: string,
  instanceId: string,
): bigint {
  for (const value of [meshId, targetAgentId, routingKey, instanceId]) {
    if (!isNonEmptyString(value)) throw new TypeError("Rendezvous hash fields must be non-empty strings");
  }
  const hash = createHash("sha256");
  hash.update(HRW_DOMAIN, "utf8");
  updateHashField(hash, meshId);
  updateHashField(hash, targetAgentId);
  updateHashField(hash, routingKey);
  updateHashField(hash, instanceId);
  return hash.digest().readBigUInt64BE(0);
}

/**
 * Weighted rendezvous score. Lower scores win. This is the exponential-race
 * form of weighted HRW: `-ln(U) / weight`, which preserves a candidate's
 * probability share in proportion to its policy-controlled capacity weight.
 */
export function weightedRendezvousScore(
  meshId: string,
  targetAgentId: string,
  routingKey: string,
  instanceId: string,
  weight = 1,
): number {
  if (typeof weight !== "number" || !Number.isFinite(weight) || weight <= 0) {
    throw new RangeError("Weighted rendezvous weight must be a positive finite number");
  }
  // Retain 53 uniformly distributed high bits. Adding 0.5 keeps U strictly
  // inside (0, 1), so Math.log never sees zero and score stays finite.
  const high53 = Number(rendezvousHash64(meshId, targetAgentId, routingKey, instanceId) >> 11n);
  const uniform = (high53 + 0.5) / TWO_TO_53;
  return -Math.log(uniform) / weight;
}

function hasIdentityCollision<T extends RoutingInstance>(
  instances: readonly T[],
  request: RouteTargetRequest,
): boolean {
  const principals = new Set<string>();
  for (const instance of instances) {
    if (!sameRouteTarget(instance, request) || !validInstanceIdentity(instance)) continue;
    // An expired registration no longer participates in the logical-agent
    // binding. It must not let an abandoned historical row block recovery.
    if (effectiveHealth(instance, request.now) === OFFLINE) continue;
    principals.add(instance.principalId);
  }
  if (principals.size > 1) return true;
  return request.expectedPrincipalId !== undefined && principals.size === 1 && !principals.has(request.expectedPrincipalId);
}

function chooseExactInstance<T extends RoutingInstance>(instances: readonly T[]): T | undefined {
  if (instances.length === 0) return undefined;
  return [...instances].sort(compareFresherInstance)[0];
}

/**
 * Select exactly one healthy target. Logical-target selection never broadcasts
 * and exact-target selection never falls back to a sibling instance.
 */
export function selectWeightedRendezvous<T extends RoutingInstance>(
  instances: readonly T[],
  request: RouteSelectionRequest,
): RouteSelectionResult<T> {
  if (!isNonEmptyString(request.meshId) || !isNonEmptyString(request.targetAgentId) || !isNonEmptyString(request.routingKey)) {
    throw new TypeError("meshId, targetAgentId, and routingKey are required for routing");
  }
  normalizedNow(request.now);
  if (hasIdentityCollision(instances, request)) {
    return { ok: false, code: "IDENTITY_COLLISION", retryable: false };
  }

  const logicalCandidates = instances.filter((instance) => sameRouteTarget(instance, request));
  if (request.targetInstanceId !== undefined) {
    const exactCandidates = logicalCandidates.filter((instance) => instance.instanceId === request.targetInstanceId);
    const exact = chooseExactInstance(exactCandidates);
    if (!exact) return { ok: false, code: "TARGET_UNAVAILABLE", retryable: true };
    const eligibility = evaluateRoutingCandidate(exact, request);
    if (!eligibility.eligible) {
      return { ok: false, code: "TARGET_UNAVAILABLE", retryable: true, reason: eligibility.reason };
    }
    const weight = capacityWeightOf(exact);
    if (weight === undefined) {
      return { ok: false, code: "TARGET_UNAVAILABLE", retryable: true, reason: "CAPACITY_EXHAUSTED" };
    }
    const score = weightedRendezvousScore(request.meshId, request.targetAgentId, request.routingKey, exact.instanceId, weight);
    return { ok: true, instance: exact, selected: exact, score };
  }

  if (logicalCandidates.length === 0) return { ok: false, code: "UNKNOWN_TARGET", retryable: true };
  const eligible = filterEligibleRoutingInstances(logicalCandidates, request)
    .filter((instance) => capacityWeightOf(instance) !== undefined);
  if (eligible.length === 0) {
    return {
      ok: false,
      code: "TARGET_UNAVAILABLE",
      retryable: true,
      reason: firstRejection(logicalCandidates, request),
    };
  }

  let selected: T | undefined;
  let selectedScore = Number.POSITIVE_INFINITY;
  for (const candidate of eligible) {
    const score = weightedRendezvousScore(
      request.meshId,
      request.targetAgentId,
      request.routingKey,
      candidate.instanceId,
      capacityWeightOf(candidate)!,
    );
    if (!selected || score < selectedScore || (score === selectedScore && tieBreak(candidate, selected) < 0)) {
      selected = candidate;
      selectedScore = score;
    }
  }
  // eligible is non-empty, but retain a fail-closed guard for future changes.
  if (!selected) return { ok: false, code: "TARGET_UNAVAILABLE", retryable: true };
  return { ok: true, instance: selected, selected, score: selectedScore };
}

function tieBreak(left: RoutingInstance, right: RoutingInstance): number {
  const leftInflight = left.currentInflight ?? 0;
  const rightInflight = right.currentInflight ?? 0;
  if (leftInflight !== rightInflight) return leftInflight - rightInflight;
  const instance = left.instanceId.localeCompare(right.instanceId);
  if (instance !== 0) return instance;
  return compareFresherInstance(left, right);
}

/** Alias used by broker call sites that do not need to name the HRW policy. */
export const selectRouteInstance = selectWeightedRendezvous;

/** Extract a strict fence token from a registration snapshot. */
export function instanceFence(instance: Pick<RoutingInstance, "sessionId" | "registrationFence" | "sessionFence">): InstanceFence | undefined {
  const sessionFence = sessionFenceOf(instance);
  if (!isNonEmptyString(instance.sessionId) || !isFence(instance.registrationFence) || sessionFence === undefined) return undefined;
  return {
    sessionId: instance.sessionId,
    registrationFence: instance.registrationFence,
    sessionFence,
  };
}

/**
 * Compare an incoming registration/session update with the durable current
 * snapshot. A newer registration fence may replace an old session; a same
 * registration fence may only advance the matching session's fence.
 */
export function evaluateFencedInstanceUpdate(
  current: Pick<RoutingInstance, "sessionId" | "registrationFence" | "sessionFence"> | InstanceFence | undefined,
  incoming: Pick<RoutingInstance, "sessionId" | "registrationFence" | "sessionFence"> | InstanceFence,
): FencedUpdateDecision {
  const next = instanceFence(incoming);
  if (!next) return "conflict";
  if (current === undefined) return "apply";
  const existing = instanceFence(current);
  if (!existing) return "conflict";
  if (next.registrationFence < existing.registrationFence) return "stale";
  if (next.registrationFence > existing.registrationFence) return "apply";
  if (next.sessionId !== existing.sessionId) return "conflict";
  if (next.sessionFence < existing.sessionFence) return "stale";
  return "apply";
}

/** True only for an update made obsolete by a higher known fence. */
export function isStaleInstanceUpdate(
  current: Pick<RoutingInstance, "sessionId" | "registrationFence" | "sessionFence"> | InstanceFence | undefined,
  incoming: Pick<RoutingInstance, "sessionId" | "registrationFence" | "sessionFence"> | InstanceFence,
): boolean {
  return evaluateFencedInstanceUpdate(current, incoming) === "stale";
}

/**
 * Fail closed for both stale and conflicting mutations. Use this for renewal,
 * health, and close updates so a stale disconnect cannot delete a replacement
 * session.
 */
export function shouldDiscardFencedUpdate(
  current: Pick<RoutingInstance, "sessionId" | "registrationFence" | "sessionFence"> | InstanceFence | undefined,
  incoming: Pick<RoutingInstance, "sessionId" | "registrationFence" | "sessionFence"> | InstanceFence,
): boolean {
  return evaluateFencedInstanceUpdate(current, incoming) !== "apply";
}

/** A close/renew operation must match the current registration and session exactly. */
export function isCurrentInstanceFence(
  current: Pick<RoutingInstance, "sessionId" | "registrationFence" | "sessionFence"> | InstanceFence | undefined,
  expected: Pick<RoutingInstance, "sessionId" | "registrationFence" | "sessionFence"> | InstanceFence,
): boolean {
  const existing = current === undefined ? undefined : instanceFence(current);
  const candidate = instanceFence(expected);
  return existing !== undefined && candidate !== undefined &&
    existing.sessionId === candidate.sessionId &&
    existing.registrationFence === candidate.registrationFence &&
    existing.sessionFence === candidate.sessionFence;
}

/** Simple fence comparison for adapters that store registration fences separately. */
export function isStaleRegistrationFence(incoming: number, current: number): boolean {
  return !isFence(incoming) || !isFence(current) || incoming < current;
}

/**
 * Persist this snapshot with the ingress dedupe and task route. It includes
 * both fences so an instance replacement cannot inherit a prior task route.
 */
export function createRoutePin(instance: RoutingInstance, options: CreateRoutePinOptions = {}): RoutePin {
  if (!validInstanceIdentity(instance)) throw new TypeError("Cannot pin an invalid routing instance");
  const routeFence = options.routeFence ?? 1;
  if (!isFence(routeFence) || routeFence === 0) throw new RangeError("routeFence must be a positive safe integer");
  return Object.freeze({
    meshId: instance.meshId,
    agentId: instance.agentId,
    instanceId: instance.instanceId,
    principalId: instance.principalId,
    sessionId: instance.sessionId,
    registrationFence: instance.registrationFence,
    sessionFence: sessionFenceOf(instance)!,
    routeFence,
  });
}

/** Alias matching the route-coordinator vocabulary. */
export const pinRoute = createRoutePin;

/** Test whether a live registration is the exact physical target stored in a route. */
export function routePinMatchesInstance(pin: RoutePin, instance: RoutingInstance): boolean {
  const fence = instanceFence(instance);
  return fence !== undefined &&
    pin.meshId === instance.meshId &&
    pin.agentId === instance.agentId &&
    pin.instanceId === instance.instanceId &&
    pin.principalId === instance.principalId &&
    pin.sessionId === fence.sessionId &&
    pin.registrationFence === fence.registrationFence &&
    pin.sessionFence === fence.sessionFence;
}

/**
 * Resolve only the instance pinned into a task route. It intentionally does
 * not invoke HRW or fall back to a sibling when the pinned instance vanished,
 * became unhealthy, or was replaced behind a new fence.
 */
export function resolvePinnedRoute<T extends RoutingInstance>(
  instances: readonly T[],
  pin: RoutePin,
  options: Omit<RouteTargetRequest, "meshId" | "targetAgentId" | "targetInstanceId" | "expectedPrincipalId" | "allowDraining" | "requireCapacity"> = {},
): PinnedRouteResolution<T> {
  const exact = instances.filter((instance) =>
    instance.meshId === pin.meshId &&
    instance.agentId === pin.agentId &&
    instance.instanceId === pin.instanceId,
  );
  const current = exact.filter((instance) => routePinMatchesInstance(pin, instance));
  if (current.length === 0) {
    return {
      ok: false,
      code: "PMX.ROUTING.PINNED_INSTANCE_UNAVAILABLE",
      retryable: true,
      reason: "FENCE_MISMATCH",
    };
  }
  const request: RouteTargetRequest = {
    ...options,
    meshId: pin.meshId,
    targetAgentId: pin.agentId,
    targetInstanceId: pin.instanceId,
    expectedPrincipalId: pin.principalId,
    // A draining target may finish its previously pinned work. New work uses
    // selectWeightedRendezvous(), which leaves this false.
    allowDraining: true,
    requireCapacity: false,
  };
  const selected = chooseExactInstance(current);
  if (!selected) {
    return {
      ok: false,
      code: "PMX.ROUTING.PINNED_INSTANCE_UNAVAILABLE",
      retryable: true,
      reason: "FENCE_MISMATCH",
    };
  }
  const eligibility = evaluateRoutingCandidate(selected, request);
  if (!eligibility.eligible) {
    return {
      ok: false,
      code: "PMX.ROUTING.PINNED_INSTANCE_UNAVAILABLE",
      retryable: true,
      reason: eligibility.reason,
    };
  }
  return { ok: true, instance: selected, selected };
}

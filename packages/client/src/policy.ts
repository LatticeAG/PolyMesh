/**
 * Scoped, fail-closed authorization primitives.
 *
 * This module intentionally has no database or expression-language dependency.
 * A deployment supplies a policy store backed by its database and an audit
 * signing key held outside the policy database/process boundary.  The included
 * in-memory store and audit chain are useful for tests and local development;
 * they are not a substitute for database least privilege or an external seal.
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import path from "node:path";

import { canonicalize, parseStrictJson, sha256, type JsonObject, type JsonValue } from "@polymesh/broker";

export type AuthStrength =
  | "local-unix"
  | "loopback-token"
  | "pairwise-psk"
  | "enrolled-key"
  | "mutual-tls";

/** A principal produced by a trusted transport authenticator, never an envelope claim. */
export interface VerifiedPrincipal {
  /** Stable transport/key/UID principal, for example `key:<key-id>` or `uid:1000`. */
  principalId: string;
  authStrength: AuthStrength;
  /** Present only when the authenticator has verified an enrolled agent binding. */
  agentId?: string;
  keyId?: string;
  credentialId?: string;
}

export interface PolicySubject {
  principalId: string;
  agentId?: string;
  enabled: boolean;
  minimumAuthStrength?: AuthStrength;
  credentialId?: string;
}

export type PermissionEffect = "allow" | "deny";

/**
 * Only exact capability IDs, `*`, and a complete namespace followed by `.*`
 * are accepted.  SQL LIKE/regex/partial-label wildcards are deliberately not
 * part of the policy grammar.
 */
export interface PermissionRule {
  id: string;
  targetPrincipal: string;
  callerPrincipal: string;
  capability: string;
  effect: PermissionEffect;
  priority?: number;
  enabled?: boolean;
  expiresAt?: number;
  minAuthStrength?: AuthStrength;
  credentialId?: string;
  resourceScope?: JsonObject;
  dataFilter?: BuiltinDataFilter;
  maxResults?: number;
}

export interface PolicyAuthorizationRequest {
  principal: VerifiedPrincipal;
  targetPrincipal: string;
  capability: string;
  input: JsonObject;
  taskId?: string;
  messageId?: string;
}

export interface AuthorizationLease {
  id: string;
  /** Monotonic fencing value; workers must not commit with an older fence. */
  fence: number;
  policyGeneration: number;
  principalId: string;
  targetPrincipal: string;
  capability: string;
  scopeHash: string;
  filter: BuiltinDataFilter;
  issuedAt: number;
  expiresAt: number;
}

export interface PolicyAllowDecision {
  effect: "allow";
  ruleId: string;
  policyGeneration: number;
  leaseId: string;
  /** Opaque lease metadata for an adapter/worker that needs fencing. */
  lease: AuthorizationLease;
  /** Canonical, scope-constrained input to pass to the resource adapter. */
  constrainedInput: JsonObject;
  maxResults: number;
  dataFilter: BuiltinDataFilter;
}

export interface PolicyDenyDecision {
  effect: "deny";
  code: string;
}

/** This is intentionally a discriminated object, never a truthy/falsy value. */
export type PolicyAuthorizationDecision = PolicyAllowDecision | PolicyDenyDecision;

export type BuiltinDataFilter = "full" | "no_personal" | "metadata_only";

export interface ScopeConstraint {
  input: JsonObject;
  scopeHash: string;
}

export type ScopeConstraintResult =
  | { ok: true; value: ScopeConstraint }
  | { ok: false; code: "RESOURCE_SCOPE_VIOLATION" | "INVALID_RESOURCE_SCOPE" };

/** Implementation-owned capability adapter. Generic JSON comparisons are unsafe. */
export interface ResourceScopeAdapter {
  readonly capability: string;
  validateScope(scope: JsonObject): boolean;
  constrain(input: JsonObject, scope: JsonObject | undefined, maxResults: number): ScopeConstraintResult;
}

/** Local risk classification; Card advertisements must never lower this classification. */
export type CapabilityRisk = "none" | "read" | "write" | "network" | "approval" | "execution" | "sensitive";

export interface CapabilityPolicyDescriptor {
  id: string;
  risk: CapabilityRisk;
}

export interface PolicyStoreTransaction {
  getSubject(principalId: string): Promise<PolicySubject | undefined>;
  listPermissions(input: {
    targetPrincipal: string;
    callerPrincipal: string;
    trustedNow: number;
  }): Promise<PermissionRule[]>;
  getPolicyGeneration(): Promise<number>;
}

/**
 * Transactional stores are required so policy snapshot, audit decision, and
 * lease issuance can be ordered as one authorization operation.
 */
export interface PolicyStore {
  transaction<T>(operation: (transaction: PolicyStoreTransaction) => Promise<T>): Promise<T>;
}

export type SqlParameter = string | number | boolean | null;

export interface ParameterizedSqlResult<Row extends Record<string, unknown> = Record<string, unknown>> {
  rows: Row[];
}

/** Minimal interface compatible with pg-style and SQLite adapters. */
export interface ParameterizedSqlExecutor {
  query<Row extends Record<string, unknown> = Record<string, unknown>>(
    statement: string,
    parameters: readonly SqlParameter[],
  ): Promise<ParameterizedSqlResult<Row>>;
  /** Policy evaluation must run against one transactional database snapshot. */
  transaction<T>(operation: (executor: ParameterizedSqlExecutor) => Promise<T>): Promise<T>;
}

/**
 * Static SQL only: untrusted protocol values are always passed as parameters.
 * Capability matching happens in the bounded policy evaluator, not via LIKE.
 */
export const SQL_SELECT_POLICY_SUBJECT = `
  SELECT principal_id, agent_id, enabled, minimum_auth_strength, credential_id
    FROM agents
   WHERE principal_id = $1
   LIMIT 1`;

export const SQL_SELECT_POLICY_GENERATION = `
  SELECT generation
    FROM policy_generation
   WHERE singleton = TRUE
   LIMIT 1`;

export const SQL_SELECT_PERMISSION_CANDIDATES = `
  SELECT id, target_principal, caller_principal, capability, resource_scope,
         data_filter, max_results, priority, effect, enabled, expires_at,
         min_auth_strength, credential_id
    FROM permissions
   WHERE target_principal = $1
     AND caller_principal = $2
     AND enabled = TRUE
     AND (expires_at IS NULL OR expires_at > $3)`;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isSafeNonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

const AUTH_STRENGTH_RANK: Readonly<Record<AuthStrength, number>> = Object.freeze({
  "loopback-token": 1,
  "local-unix": 2,
  "pairwise-psk": 3,
  "enrolled-key": 4,
  "mutual-tls": 5,
});

function isAuthStrength(value: unknown): value is AuthStrength {
  return typeof value === "string" && value in AUTH_STRENGTH_RANK;
}

function isCapabilityRisk(value: unknown): value is CapabilityRisk {
  return value === "none" || value === "read" || value === "write" || value === "network" ||
    value === "approval" || value === "execution" || value === "sensitive";
}

function isAtLeastAuthStrength(actual: AuthStrength, minimum: AuthStrength | undefined): boolean {
  return minimum === undefined || AUTH_STRENGTH_RANK[actual] >= AUTH_STRENGTH_RANK[minimum];
}

// Keep policy matching aligned with the wire grammar: namespace labels are
// canonical lowercase ASCII, while the final operation label may use internal
// hyphens (for example `org.example.file-read`).  Wildcards apply only to a
// complete namespace, never to a partial label or a regular-expression-like
// fragment.
const CANONICAL_CAPABILITY_RE = /^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)*\.[a-z](?:[a-z0-9-]*[a-z0-9])?$/;
const NAMESPACE_PATTERN_RE = /^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)*\.\*$/;

export function isCapabilityPattern(value: unknown): value is string {
  return typeof value === "string" && (value === "*" || CANONICAL_CAPABILITY_RE.test(value) || NAMESPACE_PATTERN_RE.test(value));
}

export function capabilityMatches(pattern: string, capability: string): boolean {
  if (!isCapabilityPattern(pattern) || !CANONICAL_CAPABILITY_RE.test(capability)) return false;
  if (pattern === "*") return true;
  if (pattern.endsWith(".*")) return capability.startsWith(`${pattern.slice(0, -2)}.`);
  return pattern === capability;
}

function capabilitySpecificity(pattern: string): number {
  if (pattern === "*") return 0;
  if (pattern.endsWith(".*")) return pattern.split(".").length - 1;
  return 1_000 + pattern.split(".").length;
}

function cloneJson<T extends JsonValue>(value: T): T {
  return JSON.parse(canonicalize(value)) as T;
}

function isBoundedJson(value: unknown, maximumDepth = 32, maximumNodes = 10_000): value is JsonValue {
  let nodes = 0;
  const visit = (entry: unknown, depth: number): boolean => {
    if (++nodes > maximumNodes || depth > maximumDepth) return false;
    if (entry === null || typeof entry === "string" || typeof entry === "boolean") return true;
    if (typeof entry === "number") return Number.isFinite(entry);
    if (Array.isArray(entry)) return entry.every((item) => visit(item, depth + 1));
    if (!isRecord(entry)) return false;
    return Object.entries(entry).every(([key, child]) => key.length <= 256 && visit(child, depth + 1));
  };
  return visit(value, 0);
}

export function isVerifiedPrincipal(value: unknown): value is VerifiedPrincipal {
  return isRecord(value) &&
    isNonEmptyString(value.principalId) && value.principalId.length <= 512 &&
    isAuthStrength(value.authStrength) &&
    (value.agentId === undefined || (isNonEmptyString(value.agentId) && value.agentId.length <= 512)) &&
    (value.keyId === undefined || (isNonEmptyString(value.keyId) && value.keyId.length <= 512)) &&
    (value.credentialId === undefined || (isNonEmptyString(value.credentialId) && value.credentialId.length <= 512));
}

/** Runtime validation for client callbacks and policy-engine consumers. */
export function isPolicyAuthorizationDecision(value: unknown): value is PolicyAuthorizationDecision {
  if (!isRecord(value) || typeof value.effect !== "string") return false;
  if (value.effect === "deny") return isNonEmptyString(value.code) && value.code.length <= 128;
  if (value.effect !== "allow") return false;
  if (!isNonEmptyString(value.ruleId) || !isSafeNonNegativeInteger(value.policyGeneration) || !isNonEmptyString(value.leaseId)) return false;
  if (!isRecord(value.lease) || !isNonEmptyString(value.lease.id) || !isSafeNonNegativeInteger(value.lease.fence) ||
    !isSafeNonNegativeInteger(value.lease.policyGeneration) || !isNonEmptyString(value.lease.principalId) ||
    !isNonEmptyString(value.lease.targetPrincipal) || !isNonEmptyString(value.lease.capability) ||
    !isNonEmptyString(value.lease.scopeHash) || !isBuiltinDataFilter(value.lease.filter) ||
    !isSafeNonNegativeInteger(value.lease.issuedAt) || !isSafeNonNegativeInteger(value.lease.expiresAt)) return false;
  return isRecord(value.constrainedInput) && isSafePositiveInteger(value.maxResults) && isBuiltinDataFilter(value.dataFilter);
}

function isSafePositiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

export function isBuiltinDataFilter(value: unknown): value is BuiltinDataFilter {
  return value === "full" || value === "no_personal" || value === "metadata_only";
}

function normalizedFilter(value: unknown): BuiltinDataFilter | undefined {
  return value === undefined ? "full" : isBuiltinDataFilter(value) ? value : undefined;
}

function validStringList(value: unknown, maximum = 256): value is string[] {
  return Array.isArray(value) && value.length <= maximum && value.every((entry) => isNonEmptyString(entry) && entry.length <= 4_096);
}

function enforceResultLimit(input: JsonObject, field: string, maximum: number): JsonObject | undefined {
  const copy = cloneJson(input);
  const existing = copy[field];
  if (existing === undefined) {
    copy[field] = maximum;
    return copy;
  }
  if (!isSafePositiveInteger(existing) || existing > maximum) return undefined;
  return copy;
}

function constrainedScope(scope: JsonObject, input: JsonObject): ScopeConstraintResult {
  return { ok: true, value: { input, scopeHash: sha256(scope) } };
}

/** Scope adapter for `org.polymesh.calendar.read`. */
export class CalendarReadScopeAdapter implements ResourceScopeAdapter {
  readonly capability = "org.polymesh.calendar.read";

  validateScope(scope: JsonObject): boolean {
    const users = scope.users;
    const calendars = scope.calendars;
    return (users === undefined || validStringList(users)) && (calendars === undefined || validStringList(calendars)) &&
      (users !== undefined || calendars !== undefined);
  }

  constrain(input: JsonObject, scope: JsonObject | undefined, maxResults: number): ScopeConstraintResult {
    if (scope && !this.validateScope(scope)) return { ok: false, code: "INVALID_RESOURCE_SCOPE" };
    let constrained = enforceResultLimit(input, "page_size", maxResults);
    if (!constrained) return { ok: false, code: "RESOURCE_SCOPE_VIOLATION" };
    if (!scope) return constrainedScope({}, constrained);
    const users = scope.users as string[] | undefined;
    const calendars = scope.calendars as string[] | undefined;
    if (users) {
      const selector = constrained.user;
      if (typeof selector !== "string" || !users.includes(selector)) return { ok: false, code: "RESOURCE_SCOPE_VIOLATION" };
    }
    if (calendars) {
      const selector = constrained.calendar ?? constrained.calendar_id;
      if (typeof selector !== "string" || !calendars.includes(selector)) return { ok: false, code: "RESOURCE_SCOPE_VIOLATION" };
    }
    return constrainedScope(scope, constrained);
  }
}

/** Scope adapter for `org.polymesh.email.read`. */
export class EmailReadScopeAdapter implements ResourceScopeAdapter {
  readonly capability = "org.polymesh.email.read";

  validateScope(scope: JsonObject): boolean {
    return validStringList(scope.folders) && (scope.users === undefined || validStringList(scope.users));
  }

  constrain(input: JsonObject, scope: JsonObject | undefined, maxResults: number): ScopeConstraintResult {
    if (scope && !this.validateScope(scope)) return { ok: false, code: "INVALID_RESOURCE_SCOPE" };
    const constrained = enforceResultLimit(input, "limit", maxResults);
    if (!constrained) return { ok: false, code: "RESOURCE_SCOPE_VIOLATION" };
    if (!scope) return constrainedScope({}, constrained);
    const folder = constrained.folder;
    if (typeof folder !== "string" || !(scope.folders as string[]).includes(folder)) {
      return { ok: false, code: "RESOURCE_SCOPE_VIOLATION" };
    }
    if (scope.users) {
      const user = constrained.user;
      if (typeof user !== "string" || !(scope.users as string[]).includes(user)) {
        return { ok: false, code: "RESOURCE_SCOPE_VIOLATION" };
      }
    }
    return constrainedScope(scope, constrained);
  }
}

function isWithinRoot(candidate: string, root: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

/** Scope adapter for `org.polymesh.file.read`; the file adapter must also enforce this at open time. */
export class FileReadScopeAdapter implements ResourceScopeAdapter {
  readonly capability = "org.polymesh.file.read";

  validateScope(scope: JsonObject): boolean {
    return validStringList(scope.roots, 64) && scope.roots.every((root) => path.isAbsolute(root) && !root.includes("\0")) &&
      scope.followSymlinks === false &&
      (scope.maxBytes === undefined || isSafePositiveInteger(scope.maxBytes));
  }

  constrain(input: JsonObject, scope: JsonObject | undefined, maxResults: number): ScopeConstraintResult {
    if (!scope || !this.validateScope(scope)) return { ok: false, code: scope ? "INVALID_RESOURCE_SCOPE" : "RESOURCE_SCOPE_VIOLATION" };
    const requestedPath = input.path;
    if (typeof requestedPath !== "string" || requestedPath.length === 0 || requestedPath.includes("\0") || !path.isAbsolute(requestedPath)) {
      return { ok: false, code: "RESOURCE_SCOPE_VIOLATION" };
    }
    const normalized = path.resolve(requestedPath);
    const roots = (scope.roots as string[]).map((root) => path.resolve(root));
    if (!roots.some((root) => isWithinRoot(normalized, root))) return { ok: false, code: "RESOURCE_SCOPE_VIOLATION" };
    const scopeMax = scope.maxBytes === undefined ? maxResults : Math.min(maxResults, scope.maxBytes as number);
    const constrained = enforceResultLimit(input, "max_bytes", scopeMax);
    if (!constrained) return { ok: false, code: "RESOURCE_SCOPE_VIOLATION" };
    constrained.path = normalized;
    return constrainedScope(scope, constrained);
  }
}

/** Scope adapter for `org.polymesh.shell.exec`; a worker still needs OS-level isolation. */
export class ShellExecScopeAdapter implements ResourceScopeAdapter {
  readonly capability = "org.polymesh.shell.exec";

  validateScope(scope: JsonObject): boolean {
    return validStringList(scope.programs, 64) && (scope.maxRuntimeMs === undefined || isSafePositiveInteger(scope.maxRuntimeMs)) &&
      (scope.network === undefined || scope.network === "disabled");
  }

  constrain(input: JsonObject, scope: JsonObject | undefined, maxResults: number): ScopeConstraintResult {
    if (!scope || !this.validateScope(scope)) return { ok: false, code: scope ? "INVALID_RESOURCE_SCOPE" : "RESOURCE_SCOPE_VIOLATION" };
    const program = input.program ?? input.command;
    if (typeof program !== "string" || !path.isAbsolute(program) || !(scope.programs as string[]).includes(program)) {
      return { ok: false, code: "RESOURCE_SCOPE_VIOLATION" };
    }
    if (input.args !== undefined && (!Array.isArray(input.args) || input.args.length > 128 || !input.args.every((entry) => typeof entry === "string" && entry.length <= 4_096))) {
      return { ok: false, code: "RESOURCE_SCOPE_VIOLATION" };
    }
    const runtime = scope.maxRuntimeMs === undefined ? maxResults : Math.min(maxResults, scope.maxRuntimeMs as number);
    const constrained = enforceResultLimit(input, "timeout_ms", runtime);
    if (!constrained) return { ok: false, code: "RESOURCE_SCOPE_VIOLATION" };
    constrained.program = program;
    delete constrained.command;
    if (scope.network === "disabled") constrained.network = "disabled";
    return constrainedScope(scope, constrained);
  }
}

export const DEFAULT_RESOURCE_SCOPE_ADAPTERS: readonly ResourceScopeAdapter[] = Object.freeze([
  new CalendarReadScopeAdapter(),
  new EmailReadScopeAdapter(),
  new FileReadScopeAdapter(),
  new ShellExecScopeAdapter(),
]);

const WILDCARD_SAFE_CAPABILITIES: readonly CapabilityPolicyDescriptor[] = Object.freeze([
  { id: "org.polymesh.agent.ping", risk: "none" },
  { id: "org.polymesh.agent.info", risk: "read" },
  { id: "org.polymesh.capabilities.list", risk: "read" },
  { id: "org.polymesh.calendar.read", risk: "read" },
  { id: "org.polymesh.email.read", risk: "read" },
  { id: "org.polymesh.file.read", risk: "read" },
]);

const PERSONAL_KEY_RE = /(?:^|[_-])(name|email|e-?mail|phone|mobile|address|street|postal|zip|body|content|message|attachment|token|secret|password)(?:$|[_-])/i;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PHONE_RE = /\+?[0-9][0-9() .-]{6,}[0-9]/;
const METADATA_KEYS = new Set(["id", "status", "count", "size", "next_cursor", "completed_at", "created_at", "updated_at", "truncated"]);

function redactPersonal(value: JsonValue): JsonValue {
  if (typeof value === "string") return EMAIL_RE.test(value) || PHONE_RE.test(value) ? "[redacted]" : value;
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((entry) => redactPersonal(entry));
  const result: JsonObject = {};
  for (const [key, child] of Object.entries(value)) {
    if (PERSONAL_KEY_RE.test(key)) continue;
    result[key] = redactPersonal(child);
  }
  return result;
}

function metadataOnly(value: JsonValue): JsonValue {
  if (value === null || typeof value !== "object") return {};
  if (Array.isArray(value)) return { count: value.length };
  const result: JsonObject = {};
  for (const [key, child] of Object.entries(value)) {
    if (!METADATA_KEYS.has(key)) continue;
    if (child === null || typeof child === "string" || typeof child === "number" || typeof child === "boolean") result[key] = child;
  }
  return result;
}

/**
 * Deterministic, implementation-owned filters only.  This API intentionally
 * has no JavaScript, JSONata, template, URL, SQL, or callback escape hatch.
 */
export function applyBuiltinDataFilter(filter: BuiltinDataFilter, value: JsonValue): JsonValue {
  if (!isBuiltinDataFilter(filter)) throw new TypeError("Only registered deterministic data filters are allowed");
  const copy = cloneJson(value);
  if (filter === "full") return copy;
  if (filter === "no_personal") return redactPersonal(copy);
  return metadataOnly(copy);
}

export interface AuditEvent {
  timestamp: number;
  targetPrincipal: string;
  callerPrincipal: string;
  capability: string;
  effect: PermissionEffect;
  reason: string;
  policyGeneration: number;
  ruleId?: string;
  leaseId?: string;
  fence?: number;
  scopeHash?: string;
  filter?: BuiltinDataFilter;
  taskId?: string;
  messageId?: string;
}

export interface AuditRecord extends AuditEvent {
  sequence: number;
  previousDigest: string;
  eventDigest: string;
  chainDigest: string;
  signature: string;
}

export interface AuditSigner {
  sign(payload: string): string;
  verify(payload: string, signature: string): boolean;
}

/** HMAC signer; production should inject one backed by a key outside the policy DB identity. */
export class HmacAuditSigner implements AuditSigner {
  private readonly key: Buffer;

  constructor(key: Uint8Array) {
    if (key.byteLength < 32) throw new RangeError("Audit HMAC key must be at least 32 bytes");
    this.key = Buffer.from(key);
  }

  sign(payload: string): string {
    return createHmac("sha256", this.key).update(payload, "utf8").digest("hex");
  }

  verify(payload: string, signature: string): boolean {
    if (!/^[0-9a-f]{64}$/i.test(signature)) return false;
    const expected = Buffer.from(this.sign(payload), "hex");
    const candidate = Buffer.from(signature, "hex");
    return candidate.length === expected.length && timingSafeEqual(candidate, expected);
  }
}

/** Append-only, HMAC/signer-protected audit chain. */
export class AuditChain {
  private records: AuditRecord[] = [];

  constructor(private readonly signer: AuditSigner) {}

  append(event: AuditEvent): AuditRecord {
    const previous = this.records.at(-1)?.chainDigest ?? "0".repeat(64);
    const sequence = this.records.length + 1;
    const eventDigest = sha256(auditEventPayload(event));
    const chainDigest = sha256({ sequence, previousDigest: previous, eventDigest });
    const signature = this.signer.sign(`PMX-AUDIT/1\0${chainDigest}`);
    const record = Object.freeze({ ...event, sequence, previousDigest: previous, eventDigest, chainDigest, signature });
    this.records = [...this.records, record];
    return record;
  }

  snapshot(): readonly AuditRecord[] {
    return this.records.map((record) => ({ ...record }));
  }

  verify(records: readonly AuditRecord[] = this.records): boolean {
    let previous = "0".repeat(64);
    for (let index = 0; index < records.length; index += 1) {
      const record = records[index]!;
      if (record.sequence !== index + 1 || record.previousDigest !== previous) return false;
      const eventDigest = sha256(auditEventPayload(record));
      const chainDigest = sha256({ sequence: record.sequence, previousDigest: previous, eventDigest });
      if (record.eventDigest !== eventDigest || record.chainDigest !== chainDigest || !this.signer.verify(`PMX-AUDIT/1\0${chainDigest}`, record.signature)) return false;
      previous = chainDigest;
    }
    return true;
  }
}

function auditEventPayload(event: AuditEvent): JsonObject {
  return {
    timestamp: event.timestamp,
    targetPrincipal: event.targetPrincipal,
    callerPrincipal: event.callerPrincipal,
    capability: event.capability,
    effect: event.effect,
    reason: event.reason,
    policyGeneration: event.policyGeneration,
    ...(event.ruleId === undefined ? {} : { ruleId: event.ruleId }),
    ...(event.leaseId === undefined ? {} : { leaseId: event.leaseId }),
    ...(event.fence === undefined ? {} : { fence: event.fence }),
    ...(event.scopeHash === undefined ? {} : { scopeHash: event.scopeHash }),
    ...(event.filter === undefined ? {} : { filter: event.filter }),
    ...(event.taskId === undefined ? {} : { taskId: event.taskId }),
    ...(event.messageId === undefined ? {} : { messageId: event.messageId }),
  };
}

interface StoredLease extends AuthorizationLease {
  revoked: boolean;
}

export interface PolicyEngineOptions {
  store: PolicyStore;
  /** A signer-backed append-only log. Authorization fails closed if append fails. */
  auditLog?: AuditChain;
  adapters?: readonly ResourceScopeAdapter[];
  /** Trusted local capability registry used to constrain wildcard grants. */
  capabilityDescriptors?: readonly CapabilityPolicyDescriptor[];
  now?: () => number;
  leaseTtlMs?: number;
  absoluteMaxResults?: number;
}

const DEFAULT_LEASE_TTL_MS = 30_000;
const DEFAULT_MAX_RESULTS = 1_000;

/**
 * Policy evaluator.  It only accepts verified principals and returns a
 * discriminated decision.  Any malformed input/store/audit failure is deny.
 */
export class PolicyEngine {
  private readonly adapters = new Map<string, ResourceScopeAdapter>();
  private readonly capabilityDescriptors = new Map<string, CapabilityPolicyDescriptor>();
  private readonly auditLog: AuditChain;
  private readonly now: () => number;
  private readonly leaseTtlMs: number;
  private readonly absoluteMaxResults: number;
  private readonly leases = new Map<string, StoredLease>();
  private policyGeneration = 0;
  private nextFence = 0;
  private serial = Promise.resolve();

  constructor(private readonly options: PolicyEngineOptions) {
    this.now = options.now ?? Date.now;
    this.leaseTtlMs = options.leaseTtlMs ?? DEFAULT_LEASE_TTL_MS;
    this.absoluteMaxResults = options.absoluteMaxResults ?? DEFAULT_MAX_RESULTS;
    if (!isSafePositiveInteger(this.leaseTtlMs) || !isSafePositiveInteger(this.absoluteMaxResults)) {
      throw new RangeError("leaseTtlMs and absoluteMaxResults must be positive safe integers");
    }
    this.auditLog = options.auditLog ?? new AuditChain(new HmacAuditSigner(randomBytes(32)));
    for (const adapter of options.adapters ?? DEFAULT_RESOURCE_SCOPE_ADAPTERS) {
      if (!adapter.capability || this.adapters.has(adapter.capability)) throw new TypeError("Scope adapters require unique capability IDs");
      this.adapters.set(adapter.capability, adapter);
    }
    for (const descriptor of [...WILDCARD_SAFE_CAPABILITIES, ...(options.capabilityDescriptors ?? [])]) {
      if (!CANONICAL_CAPABILITY_RE.test(descriptor.id) || !isCapabilityRisk(descriptor.risk)) {
        throw new TypeError("Capability descriptors require canonical IDs and a known local risk classification");
      }
      this.capabilityDescriptors.set(descriptor.id, { ...descriptor });
    }
  }

  /** Evaluate policy, reserve an authorization lease, and append an audit event. */
  async authorize(request: PolicyAuthorizationRequest): Promise<PolicyAuthorizationDecision> {
    return this.serialize(async () => {
      const trustedNow = this.now();
      if (!this.validRequest(request)) return this.denyAndAudit(request, "AUTHORIZATION_DENIED", "invalid authorization request", trustedNow, 0);
      try {
        return await this.options.store.transaction(async (transaction) => {
          const generation = await transaction.getPolicyGeneration();
          if (!isSafeNonNegativeInteger(generation)) throw new TypeError("Invalid policy generation");
          this.applyGeneration(generation);
          const [caller, target] = await Promise.all([
            transaction.getSubject(request.principal.principalId),
            transaction.getSubject(request.targetPrincipal),
          ]);
          if (!this.subjectMatches(caller, request.principal) || !target?.enabled) {
            return this.denyAndAudit(request, "AUTHORIZATION_DENIED", "unknown, disabled, or mismatched principal", trustedNow, generation);
          }
          const rules = await transaction.listPermissions({
            targetPrincipal: request.targetPrincipal,
            callerPrincipal: request.principal.principalId,
            trustedNow,
          });
          const matched = rules.filter((rule) => this.ruleMatches(rule, request, trustedNow));
          const denied = matched.filter((rule) => rule.effect === "deny").sort(compareRules)[0];
          // An explicit deny always wins, independent of priority or insertion order.
          if (denied) return this.denyAndAudit(request, "EXPLICIT_DENY", `matched deny rule ${denied.id}`, trustedNow, generation, denied.id);
          const allowed = matched.filter((rule) => rule.effect === "allow").sort(compareRules)[0];
          if (!allowed) return this.denyAndAudit(request, "NO_MATCHING_RULE", "no matching allow rule", trustedNow, generation);
          return this.allowAndAudit(request, allowed, trustedNow, generation);
        });
      } catch {
        return this.denyAndAudit(request, "POLICY_UNAVAILABLE", "policy store or audit unavailable", trustedNow, this.policyGeneration);
      }
    });
  }

  /**
   * Re-check before each sensitive resource access and before data release.
   * Fence values let a worker reject stale work after revocation/rotation.
   */
  validateLease(leaseId: string, context: Pick<PolicyAuthorizationRequest, "principal" | "targetPrincipal" | "capability">, fence?: number): boolean {
    const lease = this.leases.get(leaseId);
    if (!lease || lease.revoked || lease.expiresAt <= this.now() || lease.policyGeneration !== this.policyGeneration) return false;
    if (fence !== undefined && (!isSafeNonNegativeInteger(fence) || fence !== lease.fence)) return false;
    return lease.principalId === context.principal.principalId &&
      lease.targetPrincipal === context.targetPrincipal &&
      lease.capability === context.capability;
  }

  /** Revocation is monotonic: once revoked, no worker may use this lease again. */
  revokeLease(leaseId: string): boolean {
    const lease = this.leases.get(leaseId);
    if (!lease || lease.revoked) return false;
    lease.revoked = true;
    return true;
  }

  /** Policy changes fence all previously issued leases. */
  revokeAllForPolicyChange(nextGeneration?: number): void {
    const generation = nextGeneration ?? this.policyGeneration + 1;
    if (!isSafeNonNegativeInteger(generation) || generation < this.policyGeneration) throw new RangeError("Policy generation must be monotonic");
    this.policyGeneration = generation;
    for (const lease of this.leases.values()) lease.revoked = true;
  }

  /** Filter a recipient-visible artifact only while the exact lease remains valid. */
  filterForRelease(
    leaseId: string,
    context: Pick<PolicyAuthorizationRequest, "principal" | "targetPrincipal" | "capability">,
    value: JsonValue,
  ): JsonValue | undefined {
    if (!this.validateLease(leaseId, context)) return undefined;
    const lease = this.leases.get(leaseId)!;
    try {
      return applyBuiltinDataFilter(lease.filter, value);
    } catch {
      return undefined;
    }
  }

  getAuditRecords(): readonly AuditRecord[] {
    return this.auditLog.snapshot();
  }

  verifyAuditChain(records?: readonly AuditRecord[]): boolean {
    return this.auditLog.verify(records);
  }

  private async serialize<T>(operation: () => Promise<T>): Promise<T> {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const previous = this.serial;
    this.serial = previous.then(() => gate, () => gate);
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }

  private validRequest(request: PolicyAuthorizationRequest): boolean {
    return isRecord(request) && isVerifiedPrincipal(request.principal) && isNonEmptyString(request.targetPrincipal) &&
      isCapabilityPattern(request.capability) && request.capability !== "*" && isRecord(request.input) && isBoundedJson(request.input) &&
      (request.taskId === undefined || isNonEmptyString(request.taskId)) &&
      (request.messageId === undefined || isNonEmptyString(request.messageId));
  }

  private subjectMatches(subject: PolicySubject | undefined, principal: VerifiedPrincipal): boolean {
    return Boolean(subject && subject.enabled && subject.principalId === principal.principalId &&
      (!subject.agentId || subject.agentId === principal.agentId) &&
      (!subject.credentialId || subject.credentialId === principal.credentialId) &&
      isAtLeastAuthStrength(principal.authStrength, subject.minimumAuthStrength));
  }

  private ruleMatches(rule: PermissionRule, request: PolicyAuthorizationRequest, trustedNow: number): boolean {
    return isNonEmptyString(rule.id) && rule.targetPrincipal === request.targetPrincipal && rule.callerPrincipal === request.principal.principalId &&
      rule.enabled !== false && rule.effect !== undefined && (rule.effect === "allow" || rule.effect === "deny") &&
      isCapabilityPattern(rule.capability) && capabilityMatches(rule.capability, request.capability) &&
      (rule.expiresAt === undefined || (isSafeNonNegativeInteger(rule.expiresAt) && rule.expiresAt > trustedNow)) &&
      isAtLeastAuthStrength(request.principal.authStrength, rule.minAuthStrength) &&
      (!rule.credentialId || rule.credentialId === request.principal.credentialId);
  }

  private allowAndAudit(request: PolicyAuthorizationRequest, rule: PermissionRule, trustedNow: number, generation: number): PolicyAuthorizationDecision {
    const maxResults = Math.min(this.absoluteMaxResults, rule.maxResults ?? this.absoluteMaxResults);
    if (!isSafePositiveInteger(maxResults)) return this.denyAndAudit(request, "INVALID_POLICY", "invalid maximum result limit", trustedNow, generation, rule.id);
    if (rule.capability !== request.capability && !this.wildcardMayAuthorize(request.capability)) {
      return this.denyAndAudit(request, "WILDCARD_CAPABILITY_DENIED", "wildcard rule cannot authorize an unknown or sensitive capability", trustedNow, generation, rule.id);
    }
    const adapter = this.adapters.get(request.capability);
    // A scoped rule or max-result promise is unsafe without a concrete adapter.
    if ((rule.resourceScope !== undefined || rule.maxResults !== undefined) && !adapter) {
      return this.denyAndAudit(request, "RESOURCE_SCOPE_VIOLATION", "no capability scope adapter", trustedNow, generation, rule.id);
    }
    if (rule.resourceScope !== undefined && (!isBoundedJson(rule.resourceScope) || !adapter?.validateScope(rule.resourceScope))) {
      return this.denyAndAudit(request, "INVALID_RESOURCE_SCOPE", "invalid resource scope", trustedNow, generation, rule.id);
    }
    const constrained = adapter
      ? adapter.constrain(request.input, rule.resourceScope, maxResults)
      : constrainedScope({}, cloneJson(request.input));
    if (!constrained.ok) return this.denyAndAudit(request, constrained.code, "resource scope constraint rejected", trustedNow, generation, rule.id);
    const filter = normalizedFilter(rule.dataFilter);
    if (!filter) return this.denyAndAudit(request, "INVALID_POLICY", "non-deterministic or unknown data filter", trustedNow, generation, rule.id);
    const lease: StoredLease = {
      id: randomBytes(18).toString("base64url"),
      fence: ++this.nextFence,
      policyGeneration: generation,
      principalId: request.principal.principalId,
      targetPrincipal: request.targetPrincipal,
      capability: request.capability,
      scopeHash: constrained.value.scopeHash,
      filter,
      issuedAt: trustedNow,
      expiresAt: trustedNow + this.leaseTtlMs,
      revoked: false,
    };
    try {
      this.auditLog.append({
        timestamp: trustedNow,
        targetPrincipal: request.targetPrincipal,
        callerPrincipal: request.principal.principalId,
        capability: request.capability,
        effect: "allow",
        reason: `matched rule ${rule.id}`,
        policyGeneration: generation,
        ruleId: rule.id,
        leaseId: lease.id,
        fence: lease.fence,
        scopeHash: lease.scopeHash,
        filter,
        ...(request.taskId === undefined ? {} : { taskId: request.taskId }),
        ...(request.messageId === undefined ? {} : { messageId: request.messageId }),
      });
    } catch {
      return { effect: "deny", code: "AUDIT_UNAVAILABLE" };
    }
    this.leases.set(lease.id, lease);
    return {
      effect: "allow",
      ruleId: rule.id,
      policyGeneration: generation,
      leaseId: lease.id,
      lease: { ...lease },
      constrainedInput: constrained.value.input,
      maxResults,
      dataFilter: filter,
    };
  }

  private denyAndAudit(
    request: Partial<PolicyAuthorizationRequest>,
    code: string,
    reason: string,
    trustedNow: number,
    generation: number,
    ruleId?: string,
  ): PolicyDenyDecision {
    try {
      this.auditLog.append({
        timestamp: trustedNow,
        targetPrincipal: request.targetPrincipal ?? "unknown-target",
        callerPrincipal: request.principal?.principalId ?? "unverified",
        capability: request.capability ?? "unknown-capability",
        effect: "deny",
        reason,
        policyGeneration: generation,
        ...(ruleId === undefined ? {} : { ruleId }),
        ...(request.taskId === undefined ? {} : { taskId: request.taskId }),
        ...(request.messageId === undefined ? {} : { messageId: request.messageId }),
      });
      return { effect: "deny", code };
    } catch {
      return { effect: "deny", code: "AUDIT_UNAVAILABLE" };
    }
  }

  private applyGeneration(generation: number): void {
    if (generation < this.policyGeneration) throw new RangeError("Policy generation rolled back");
    if (generation > this.policyGeneration) this.revokeAllForPolicyChange(generation);
  }

  private wildcardMayAuthorize(capability: string): boolean {
    const descriptor = this.capabilityDescriptors.get(capability);
    return descriptor?.risk === "none" || descriptor?.risk === "read";
  }
}

function compareRules(left: PermissionRule, right: PermissionRule): number {
  const priority = (right.priority ?? 0) - (left.priority ?? 0);
  if (priority !== 0) return priority;
  const specificity = capabilitySpecificity(right.capability) - capabilitySpecificity(left.capability);
  if (specificity !== 0) return specificity;
  return left.id.localeCompare(right.id);
}

/** Deterministic in-memory store used by tests and local development. */
export class InMemoryPolicyStore implements PolicyStore, PolicyStoreTransaction {
  private readonly subjects = new Map<string, PolicySubject>();
  private rules: PermissionRule[] = [];
  private generation = 1;

  constructor(subjects: readonly PolicySubject[] = [], rules: readonly PermissionRule[] = [], generation = 1) {
    if (!isSafeNonNegativeInteger(generation)) throw new RangeError("generation must be a non-negative safe integer");
    for (const subject of subjects) this.putSubject(subject);
    this.replaceRules(rules, generation);
  }

  async transaction<T>(operation: (transaction: PolicyStoreTransaction) => Promise<T>): Promise<T> {
    return operation(this);
  }

  async getSubject(principalId: string): Promise<PolicySubject | undefined> {
    const subject = this.subjects.get(principalId);
    return subject ? { ...subject } : undefined;
  }

  async listPermissions(input: { targetPrincipal: string; callerPrincipal: string; trustedNow: number }): Promise<PermissionRule[]> {
    return this.rules
      .filter((rule) => rule.targetPrincipal === input.targetPrincipal && rule.callerPrincipal === input.callerPrincipal)
      .map((rule) => ({ ...rule, ...(rule.resourceScope === undefined ? {} : { resourceScope: cloneJson(rule.resourceScope) }) }));
  }

  async getPolicyGeneration(): Promise<number> {
    return this.generation;
  }

  putSubject(subject: PolicySubject): void {
    if (!isNonEmptyString(subject.principalId) || typeof subject.enabled !== "boolean" ||
      (subject.agentId !== undefined && !isNonEmptyString(subject.agentId)) ||
      (subject.minimumAuthStrength !== undefined && !isAuthStrength(subject.minimumAuthStrength)) ||
      (subject.credentialId !== undefined && !isNonEmptyString(subject.credentialId))) {
      throw new TypeError("Invalid policy subject");
    }
    this.subjects.set(subject.principalId, { ...subject });
  }

  replaceRules(rules: readonly PermissionRule[], generation = this.generation + 1): void {
    if (!isSafeNonNegativeInteger(generation) || generation < this.generation) throw new RangeError("Policy generation must be monotonic");
    for (const rule of rules) {
      if (!isNonEmptyString(rule.id) || !isNonEmptyString(rule.targetPrincipal) || !isNonEmptyString(rule.callerPrincipal) ||
        !isCapabilityPattern(rule.capability) || (rule.effect !== "allow" && rule.effect !== "deny") ||
        (rule.priority !== undefined && !Number.isSafeInteger(rule.priority)) ||
        (rule.maxResults !== undefined && !isSafePositiveInteger(rule.maxResults)) ||
        (rule.dataFilter !== undefined && !isBuiltinDataFilter(rule.dataFilter)) ||
        (rule.minAuthStrength !== undefined && !isAuthStrength(rule.minAuthStrength)) ||
        (rule.resourceScope !== undefined && (!isRecord(rule.resourceScope) || !isBoundedJson(rule.resourceScope)))) {
        throw new TypeError("Invalid permission rule");
      }
    }
    this.rules = rules.map((rule) => ({ ...rule, ...(rule.resourceScope === undefined ? {} : { resourceScope: cloneJson(rule.resourceScope) }) }));
    this.generation = generation;
  }
}

class SqlPolicyTransaction implements PolicyStoreTransaction {
  constructor(private readonly executor: ParameterizedSqlExecutor) {}

  async getSubject(principalId: string): Promise<PolicySubject | undefined> {
    const result = await this.executor.query(SQL_SELECT_POLICY_SUBJECT, [principalId]);
    const row = result.rows[0];
    if (!row) return undefined;
    return rowToSubject(row);
  }

  async listPermissions(input: { targetPrincipal: string; callerPrincipal: string; trustedNow: number }): Promise<PermissionRule[]> {
    const result = await this.executor.query(SQL_SELECT_PERMISSION_CANDIDATES, [input.targetPrincipal, input.callerPrincipal, new Date(input.trustedNow).toISOString()]);
    return result.rows.map(rowToRule);
  }

  async getPolicyGeneration(): Promise<number> {
    const result = await this.executor.query(SQL_SELECT_POLICY_GENERATION, []);
    const value = result.rows[0]?.generation;
    if (typeof value === "number" && isSafeNonNegativeInteger(value)) return value;
    if (typeof value === "string" && /^\d+$/.test(value)) {
      const parsed = Number(value);
      if (isSafeNonNegativeInteger(parsed)) return parsed;
    }
    throw new TypeError("Policy generation row is invalid");
  }
}

/**
 * SQL adapter whose statements are fixed and parameterized.  It does not
 * interpolate any protocol/card/policy/task value into SQL syntax.
 */
export class SqlPolicyStore implements PolicyStore {
  constructor(private readonly executor: ParameterizedSqlExecutor) {}

  async transaction<T>(operation: (transaction: PolicyStoreTransaction) => Promise<T>): Promise<T> {
    const run = async (executor: ParameterizedSqlExecutor) => operation(new SqlPolicyTransaction(executor));
    return this.executor.transaction(run);
  }
}

function rowToSubject(row: Record<string, unknown>): PolicySubject {
  if (!isNonEmptyString(row.principal_id) || typeof row.enabled !== "boolean" ||
    (row.agent_id !== null && row.agent_id !== undefined && !isNonEmptyString(row.agent_id)) ||
    (row.minimum_auth_strength !== null && row.minimum_auth_strength !== undefined && !isAuthStrength(row.minimum_auth_strength)) ||
    (row.credential_id !== null && row.credential_id !== undefined && !isNonEmptyString(row.credential_id))) {
    throw new TypeError("Policy subject row is invalid");
  }
  return {
    principalId: row.principal_id,
    enabled: row.enabled,
    ...(typeof row.agent_id === "string" ? { agentId: row.agent_id } : {}),
    ...(typeof row.minimum_auth_strength === "string" ? { minimumAuthStrength: row.minimum_auth_strength } : {}),
    ...(typeof row.credential_id === "string" ? { credentialId: row.credential_id } : {}),
  };
}

function rowToRule(row: Record<string, unknown>): PermissionRule {
  const resourceScope = parseScope(row.resource_scope);
  const expiresAt = parseExpiry(row.expires_at);
  if (!isNonEmptyString(row.id) || !isNonEmptyString(row.target_principal) || !isNonEmptyString(row.caller_principal) ||
    !isCapabilityPattern(row.capability) || (row.effect !== "allow" && row.effect !== "deny") ||
    (row.priority !== null && row.priority !== undefined && !Number.isSafeInteger(row.priority)) ||
    (row.max_results !== null && row.max_results !== undefined && !isSafePositiveInteger(row.max_results)) ||
    (row.enabled !== null && row.enabled !== undefined && typeof row.enabled !== "boolean") ||
    (row.data_filter !== null && row.data_filter !== undefined && !isBuiltinDataFilter(row.data_filter)) ||
    (row.min_auth_strength !== null && row.min_auth_strength !== undefined && !isAuthStrength(row.min_auth_strength)) ||
    (row.credential_id !== null && row.credential_id !== undefined && !isNonEmptyString(row.credential_id)) ||
    (resourceScope === "invalid") || (expiresAt === "invalid")) {
    throw new TypeError("Permission row is invalid");
  }
  return {
    id: row.id,
    targetPrincipal: row.target_principal,
    callerPrincipal: row.caller_principal,
    capability: row.capability,
    effect: row.effect,
    ...(typeof row.priority === "number" ? { priority: row.priority } : {}),
    ...(typeof row.enabled === "boolean" ? { enabled: row.enabled } : {}),
    ...(typeof expiresAt === "number" ? { expiresAt } : {}),
    ...(typeof row.min_auth_strength === "string" ? { minAuthStrength: row.min_auth_strength } : {}),
    ...(typeof row.credential_id === "string" ? { credentialId: row.credential_id } : {}),
    ...(resourceScope === undefined ? {} : { resourceScope }),
    ...(typeof row.data_filter === "string" ? { dataFilter: row.data_filter } : {}),
    ...(typeof row.max_results === "number" ? { maxResults: row.max_results } : {}),
  };
}

function parseScope(value: unknown): JsonObject | undefined | "invalid" {
  if (value === null || value === undefined) return undefined;
  if (isRecord(value) && isBoundedJson(value)) return cloneJson(value as JsonObject);
  if (typeof value !== "string" || value.length > 32_768) return "invalid";
  const parsed = parseStrictJson(value, {
    maxBytes: 32_768,
    maxDepth: 32,
    maxNodes: 4_096,
    maxObjectMembers: 1_024,
    maxArrayItems: 4_096,
    maxStringBytes: 16_384,
  });
  return parsed.ok && isRecord(parsed.value) && isBoundedJson(parsed.value)
    ? cloneJson(parsed.value as JsonObject)
    : "invalid";
}

function parseExpiry(value: unknown): number | undefined | "invalid" {
  if (value === null || value === undefined) return undefined;
  if (typeof value === "number" && isSafeNonNegativeInteger(value)) return value;
  if (typeof value === "string") {
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) && parsed >= 0 ? parsed : "invalid";
  }
  return "invalid";
}

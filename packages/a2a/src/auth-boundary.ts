/**
 * A2A auth boundary (PM-V6-SPEC §A.13).
 *
 * Invariant A.13-1: A2A credentials terminate at the adapter and mesh
 * credentials MUST NEVER cross the dialect boundary in either direction.
 */
import { createHash } from "node:crypto";

import { A2ADialectError } from "./errors.js";
import type { A2AAuthConfig, TrustedEndpoint } from "./config.js";

/** Header names that would leak mesh-side credentials onto an A2A request. */
export const MESH_CREDENTIAL_HEADERS: readonly string[] = Object.freeze([
  "x-polymesh-token",
  "x-polymesh-session",
  "x-polymesh-ticket",
  "x-polymesh-mesh-token",
  "x-mesh-token",
  "x-gateway-jwt",
  "x-room-token",
]);

export const REDACTED = "[REDACTED]";

/**
 * JWT-shaped base64url triplet (§A.13.5). Segment minimums keep dotted
 * capability ids and version strings out of the match.
 */
const JWT_SOURCE = "[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}";
const BEARER_SOURCE = "Bearer\\s+[A-Za-z0-9._~+/=-]+";

export interface RedactionEvent {
  path: string;
  pattern: "jwt" | "bearer";
}

export interface HygieneResult<T = unknown> {
  value: T;
  redactions: RedactionEvent[];
}

/**
 * Redact credential-shaped strings from an outbound payload (§A.13.5).
 * Defense in depth only — the primary control is the header-level boundary.
 */
export function redactCredentialPatterns<T>(value: T, path = "$"): HygieneResult<T> {
  const redactions: RedactionEvent[] = [];
  const out = walk(value, path, redactions);
  return { value: out as T, redactions };
}

function walk(value: unknown, path: string, redactions: RedactionEvent[]): unknown {
  if (typeof value === "string") {
    let next = value;
    const afterBearer = next.replace(new RegExp(BEARER_SOURCE, "gi"), REDACTED);
    if (afterBearer !== next) {
      next = afterBearer;
      redactions.push({ path, pattern: "bearer" });
    }
    const afterJwt = next.replace(new RegExp(JWT_SOURCE, "g"), REDACTED);
    if (afterJwt !== next) {
      next = afterJwt;
      redactions.push({ path, pattern: "jwt" });
    }
    return next;
  }
  if (Array.isArray(value)) {
    return value.map((item, index) => walk(item, `${path}[${index}]`, redactions));
  }
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      out[key] = walk(item, `${path}.${key}`, redactions);
    }
    return out;
  }
  return value;
}

/** Truncated thumbprint for audit logs; raw tokens MUST NOT be logged (§A.13.2). */
export function credentialThumbprint(secret: string): string {
  return createHash("sha256").update(secret, "utf8").digest("hex").slice(0, 12);
}

export interface AuthBoundaryOptions {
  trustedEndpoints: readonly TrustedEndpoint[];
  /** Fallback credential when a trusted endpoint declares none. */
  defaultAuth?: A2AAuthConfig;
  onRedaction?: (event: RedactionEvent & { task_id?: string }) => void;
}

/**
 * Outbound credential store + payload hygiene. Credentials are scoped by
 * operator-declared endpoint identity, never by discovered `a2a_url`
 * (§A.13.3.1).
 */
export class A2AAuthBoundary {
  private readonly trusted: readonly TrustedEndpoint[];
  private readonly defaultAuth?: A2AAuthConfig;
  private readonly onRedaction?: AuthBoundaryOptions["onRedaction"];

  constructor(options: AuthBoundaryOptions) {
    this.trusted = options.trustedEndpoints;
    this.defaultAuth = options.defaultAuth;
    this.onRedaction = options.onRedaction;
  }

  /**
   * Resolve the operator-declared endpoint for a discovered `a2a_url`.
   * Returns `undefined` when the URL is not in the allowlist.
   */
  resolveEndpoint(a2aUrl: string): TrustedEndpoint | undefined {
    let parsed: URL;
    try {
      parsed = new URL(a2aUrl);
    } catch {
      return undefined;
    }
    for (const endpoint of this.trusted) {
      if (matchesEndpoint(parsed, endpoint)) return endpoint;
    }
    return undefined;
  }

  /**
   * §A.13.3.1: an advertisement's `a2a_url` MUST match a preconfigured trusted
   * endpoint; otherwise fail with `AUTHORIZATION_DENIED` at the adapter.
   */
  assertTrustedEndpoint(a2aUrl: string): TrustedEndpoint {
    const endpoint = this.resolveEndpoint(a2aUrl);
    if (!endpoint) {
      throw new A2ADialectError(
        "AUTHORIZATION_DENIED",
        `A2A endpoint not in outbound credential allowlist: ${a2aUrl}`,
        { data: { a2a_url: a2aUrl } },
      );
    }
    return endpoint;
  }

  /** Outbound headers carrying A2A-world credentials only (§A.13.1). */
  outboundHeaders(a2aUrl: string): Record<string, string> {
    const endpoint = this.assertTrustedEndpoint(a2aUrl);
    const auth = endpoint.auth ?? this.defaultAuth;
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (!auth || auth.mode === "none" || !auth.token) return headers;
    if (auth.mode === "bearer") {
      headers[(auth.header_name ?? "Authorization").toLowerCase()] = `Bearer ${auth.token}`;
      return headers;
    }
    headers[(auth.header_name ?? "X-API-Key").toLowerCase()] = auth.token;
    return headers;
  }

  /** Fail closed if a mesh credential header ever reaches the outbound path. */
  assertNoMeshCredentials(headers: Record<string, string>): void {
    for (const name of Object.keys(headers)) {
      if (MESH_CREDENTIAL_HEADERS.includes(name.toLowerCase())) {
        throw new A2ADialectError(
          "AUTHORIZATION_DENIED",
          `Mesh credential header ${name} MUST NOT cross the A2A boundary`,
        );
      }
    }
  }

  /** Apply payload hygiene and report each redaction (§A.13.5). */
  sanitizeOutboundPayload<T>(payload: T, taskId?: string): HygieneResult<T> {
    const result = redactCredentialPatterns(payload);
    for (const event of result.redactions) {
      this.onRedaction?.({ ...event, task_id: taskId });
    }
    return result;
  }

  /**
   * Terminate inbound A2A credentials and mint a mesh-local trust scope
   * (§A.13.1–§A.13.2). Mesh credential headers are ignored, never forwarded.
   */
  terminateInboundAuth(
    headers: Record<string, string | string[] | undefined> = {},
    options?: { auth?: A2AAuthConfig; allowPublicUnauthenticated?: boolean },
  ): MeshTrustScope {
    const hdrs = normalizeHeaders(headers);
    const auth = options?.auth ?? this.defaultAuth ?? { mode: "none" as const };
    const mode = auth.mode ?? "none";
    const allowPublic = options?.allowPublicUnauthenticated ?? false;
    const expected = auth.token;

    let subject = "anonymous";
    if (mode === "none" || !expected) {
      subject = allowPublic || mode === "none" ? "anonymous-public" : "anonymous";
    } else if (mode === "bearer") {
      const headerName = (auth.header_name ?? "Authorization").toLowerCase();
      const provided = hdrs[headerName] ?? "";
      if (provided !== `Bearer ${expected}` && provided !== expected) {
        throw new A2ADialectError("AUTHENTICATION_FAILED", "Authentication failed");
      }
      subject = `bearer:${credentialThumbprint(expected)}`;
    } else {
      const headerName = (auth.header_name ?? "X-API-Key").toLowerCase();
      const provided = hdrs[headerName] ?? "";
      if (provided !== expected) {
        throw new A2ADialectError("AUTHENTICATION_FAILED", "Authentication failed");
      }
      subject = `apikey:${credentialThumbprint(expected)}`;
    }
    return mapToMeshTrustScope(subject);
  }

  /** Drop mesh credential headers from a header map (§A.13.1). */
  stripMeshCredentialsFromHeaders(
    headers: Record<string, string | string[] | undefined>,
  ): Record<string, string> {
    const out: Record<string, string> = {};
    for (const [key, value] of Object.entries(headers)) {
      if (MESH_CREDENTIAL_HEADERS.includes(key.toLowerCase())) continue;
      if (value === undefined) continue;
      out[key] = Array.isArray(value) ? (value[0] ?? "") : value;
    }
    return out;
  }
}

export interface MeshTrustScope {
  kind: "a2a_remote";
  principal_id: string;
  subject: string;
  capabilities_allowed: string[] | null;
  rooms: [];
  topology_read: false;
  dialect: "a2a";
}

/** Mint the adapter-local trust scope for an A2A principal (§A.13.2). */
export function mapToMeshTrustScope(
  a2aSubject: string,
  capabilitiesAllowed?: string[] | null,
): MeshTrustScope {
  const digest = createHash("sha256").update(String(a2aSubject), "utf8").digest("hex").slice(0, 16);
  return {
    kind: "a2a_remote",
    principal_id: `a2a:${digest}`,
    subject: String(a2aSubject),
    capabilities_allowed: capabilitiesAllowed ?? null,
    rooms: [],
    topology_read: false,
    dialect: "a2a",
  };
}

function normalizeHeaders(
  headers: Record<string, string | string[] | undefined>,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    out[key.toLowerCase()] = Array.isArray(value) ? (value[0] ?? "") : value;
  }
  return out;
}

function matchesEndpoint(parsed: URL, endpoint: TrustedEndpoint): boolean {
  let expected: URL;
  try {
    expected = new URL(endpoint.url);
  } catch {
    return false;
  }
  if (parsed.origin !== expected.origin) return false;
  if (endpoint.match === "origin") return true;
  if (endpoint.match === "prefix") return parsed.pathname.startsWith(expected.pathname);
  return normalizePath(parsed.pathname) === normalizePath(expected.pathname);
}

function normalizePath(pathname: string): string {
  return pathname.length > 1 && pathname.endsWith("/") ? pathname.slice(0, -1) : pathname;
}

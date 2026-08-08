/**
 * A2A adapter config loader (§E.13).
 */

import type { AuthMode } from "./types.js";
import { IDEMPOTENCY_RETENTION_MS } from "./types.js";

/** Normative minimum retention for adapter dedup (§A.12.4). */
export const IDEMPOTENCY_MIN_RETENTION_MS = IDEMPOTENCY_RETENTION_MS;

export interface A2AAuthConfig {
  mode: AuthMode;
  token?: string;
  token_file?: string;
  header_name?: string;
}

export interface TrustedEndpoint {
  url: string;
  /** exact (default) | origin | prefix */
  match?: "exact" | "origin" | "prefix";
  auth?: A2AAuthConfig;
}

export interface A2ARateLimitConfig {
  enabled: boolean;
  capacity?: number;
  refill_per_sec?: number;
}

export interface A2AAdapterConfig {
  enabled: boolean;
  inbound_enabled: boolean;
  outbound_enabled: boolean;
  a2a_url?: string;
  listen_host: string;
  listen_port?: number;
  public_card_path: string;
  jsonrpc_path: string;
  sse_enabled: boolean;
  poll_max_ms: number;
  auth: A2AAuthConfig;
  rate_limit: A2ARateLimitConfig;
  idempotency_store_path?: string;
  /** Operator-declared trusted A2A endpoint identities (§A.13.3.1). */
  trusted_endpoints: Array<string | TrustedEndpoint>;
  allow_public_unauthenticated?: boolean;
  task_id_map_path?: string;
  event_log_path?: string;
}

const DEFAULTS: A2AAdapterConfig = {
  enabled: false,
  inbound_enabled: false,
  outbound_enabled: false,
  listen_host: "127.0.0.1",
  public_card_path: "/.well-known/agent.json",
  jsonrpc_path: "/a2a",
  sse_enabled: true,
  poll_max_ms: 15_000,
  auth: { mode: "none", header_name: "Authorization" },
  rate_limit: { enabled: true },
  trusted_endpoints: [],
  allow_public_unauthenticated: false,
};

function envBool(env: NodeJS.ProcessEnv, key: string): boolean | undefined {
  const v = env[key];
  if (v == null || v === "") return undefined;
  return /^(1|true|yes|on)$/i.test(v);
}

function envInt(env: NodeJS.ProcessEnv, key: string): number | undefined {
  const v = env[key];
  if (v == null || v === "") return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}

export function normalizeTrustedEndpoints(
  entries: ReadonlyArray<string | TrustedEndpoint>,
): TrustedEndpoint[] {
  return entries.map((e) => (typeof e === "string" ? { url: e, match: "exact" } : e));
}

export function loadA2AAdapterConfig(
  env: NodeJS.ProcessEnv = process.env,
  overrides: Partial<A2AAdapterConfig> = {},
): A2AAdapterConfig {
  const authMode = (env.POLYMESH_A2A_AUTH_MODE as AuthMode | undefined) ?? "none";
  const token = env.POLYMESH_A2A_AUTH_TOKEN ?? env.A2A_AUTH_TOKEN;
  const tokenFile = env.POLYMESH_A2A_AUTH_TOKEN_FILE ?? env.A2A_AUTH_TOKEN_FILE;
  const a2aUrl = env.POLYMESH_A2A_URL ?? env.A2A_URL;
  const trustedRaw = env.POLYMESH_A2A_TRUSTED_ENDPOINTS;
  const trustedFromEnv = trustedRaw
    ? trustedRaw.split(",").map((s) => s.trim()).filter(Boolean)
    : [];

  const base: A2AAdapterConfig = {
    ...DEFAULTS,
    enabled: envBool(env, "POLYMESH_A2A_ENABLED") ?? DEFAULTS.enabled,
    inbound_enabled: envBool(env, "POLYMESH_A2A_INBOUND_ENABLED") ?? DEFAULTS.inbound_enabled,
    outbound_enabled: envBool(env, "POLYMESH_A2A_OUTBOUND_ENABLED") ?? DEFAULTS.outbound_enabled,
    a2a_url: a2aUrl,
    listen_host: env.POLYMESH_A2A_LISTEN_HOST ?? DEFAULTS.listen_host,
    listen_port: envInt(env, "POLYMESH_A2A_LISTEN_PORT"),
    public_card_path: env.POLYMESH_A2A_CARD_PATH ?? DEFAULTS.public_card_path,
    jsonrpc_path: env.POLYMESH_A2A_JSONRPC_PATH ?? DEFAULTS.jsonrpc_path,
    sse_enabled: envBool(env, "POLYMESH_A2A_SSE_ENABLED") ?? DEFAULTS.sse_enabled,
    poll_max_ms: envInt(env, "POLYMESH_A2A_POLL_MAX_MS") ?? DEFAULTS.poll_max_ms,
    auth: {
      mode: authMode,
      token,
      token_file: tokenFile,
      header_name: env.POLYMESH_A2A_AUTH_HEADER ?? "Authorization",
    },
    rate_limit: {
      enabled: envBool(env, "POLYMESH_A2A_RATE_LIMIT") ?? true,
    },
    idempotency_store_path: env.POLYMESH_A2A_IDEMPOTENCY_STORE,
    trusted_endpoints: trustedFromEnv,
  };

  return {
    ...base,
    ...overrides,
    auth: { ...base.auth, ...(overrides.auth ?? {}) },
    rate_limit: { ...base.rate_limit, ...(overrides.rate_limit ?? {}) },
    trusted_endpoints: overrides.trusted_endpoints ?? base.trusted_endpoints,
  };
}

export function assertSafeToLogConfig(config: A2AAdapterConfig): Record<string, unknown> {
  return {
    enabled: config.enabled,
    inbound_enabled: config.inbound_enabled,
    outbound_enabled: config.outbound_enabled,
    a2a_url: config.a2a_url,
    listen_host: config.listen_host,
    listen_port: config.listen_port,
    public_card_path: config.public_card_path,
    jsonrpc_path: config.jsonrpc_path,
    sse_enabled: config.sse_enabled,
    poll_max_ms: config.poll_max_ms,
    auth: {
      mode: config.auth.mode,
      token: config.auth.token ? "[REDACTED]" : undefined,
      token_file: config.auth.token_file,
      header_name: config.auth.header_name,
    },
    rate_limit: { ...config.rate_limit },
    idempotency_store_path: config.idempotency_store_path,
    trusted_endpoints: config.trusted_endpoints.map((e) =>
      typeof e === "string" ? e : { url: e.url, match: e.match },
    ),
  };
}

/**
 * Strict, local-only configuration for the TypeScript CLI.
 *
 * Configuration deliberately contains credential *paths*, never raw runtime
 * tokens.  Wire configuration belongs in the SDK; this module only resolves
 * operational defaults before the CLI constructs a broker or client.
 */
import { homedir } from "node:os";
import { join } from "node:path";
import { readFile as nodeReadFile } from "node:fs/promises";
import { isIP } from "node:net";

import { parse as parseToml } from "@iarna/toml";

export type CliEnvironment = Record<string, string | undefined>;

export interface BrokerCliConfig {
  host: string;
  port: number;
  /** Owner-readable runtime token file path. Never a raw runtime token. */
  token?: string;
}

export interface ClientCliConfig {
  /** Milliseconds, matching the CLI's --timeout flag. */
  default_timeout: number;
  /** Reserved for a reconnecting CLI session; retained in effective config. */
  reconnect: boolean;
}

export interface DiscoveryCliConfig {
  mdns_enabled: boolean;
  /** Discovery observation interval in milliseconds. Zero is non-blocking. */
  mdns_interval: number;
}

export interface CliConfig {
  broker: BrokerCliConfig;
  client: ClientCliConfig;
  discovery: DiscoveryCliConfig;
}

export interface CliConfigOverrides {
  broker?: Partial<BrokerCliConfig>;
  client?: Partial<ClientCliConfig>;
  discovery?: Partial<DiscoveryCliConfig>;
}

export interface LoadedCliConfig {
  config: CliConfig;
  /** The selected path, whether or not the optional default file exists. */
  configPath: string;
  configFileLoaded: boolean;
}

export interface LoadCliConfigOptions {
  /** Explicit --config path. It wins over POLYMESH_CONFIG. */
  configPath?: string;
  env?: CliEnvironment;
  /** Values already parsed from command-line flags. */
  overrides?: CliConfigOverrides;
  readFile?: (path: string, encoding: BufferEncoding) => Promise<string>;
  homeDir?: () => string;
}

/** Bounded configuration errors that are safe to print on the CLI. */
export class CliConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CliConfigError";
  }
}

const MAX_CONFIG_BYTES = 1_048_576;
const MAX_TIMEOUT_MS = 86_400_000;
const MAX_MDNS_INTERVAL_MS = 86_400_000;
const RAW_SECRET_ENVIRONMENT_NAMES = [
  "POLYMESH_TOKEN",
  "POLYMESH_PRIVATE_KEY",
  "POLYMESH_TLS_KEY",
  "POLYMESH_IDENTITY_KEY",
] as const;

export const DEFAULT_CLI_CONFIG: Readonly<CliConfig> = Object.freeze({
  broker: Object.freeze({ host: "127.0.0.1", port: 7337 }),
  client: Object.freeze({ default_timeout: 60_000, reconnect: false }),
  discovery: Object.freeze({ mdns_enabled: false, mdns_interval: 0 }),
});

function cloneDefaults(): CliConfig {
  return {
    broker: { ...DEFAULT_CLI_CONFIG.broker },
    client: { ...DEFAULT_CLI_CONFIG.client },
    discovery: { ...DEFAULT_CLI_CONFIG.discovery },
  };
}

/** The stable, user-scoped configuration path used when no override is set. */
export function defaultConfigPath(home = homedir()): string {
  return join(home, ".config", "polymesh", "config.toml");
}

function expandHome(path: string, home: string): string {
  if (path === "~") return home;
  if (path.startsWith("~/")) return join(home, path.slice(2));
  return path;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function fail(message: string): never {
  throw new CliConfigError(message);
}

function assertAllowedKeys(value: Record<string, unknown>, allowed: readonly string[], location: string): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) fail(`Unknown configuration key: ${location}.${key}`);
  }
}

function optionalString(value: unknown, location: string, options: { allowEmpty?: boolean } = {}): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || (!options.allowEmpty && value.trim().length === 0) || value.includes("\0")) {
    fail(`${location} must be a non-empty string`);
  }
  return value;
}

function integer(value: unknown, location: string, minimum: number, maximum: number): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${location} must be an integer between ${minimum} and ${maximum}`);
  }
  return value as number;
}

function boolean(value: unknown, location: string): boolean | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "boolean") fail(`${location} must be true or false`);
  return value;
}

/**
 * `broker.token` is intentionally a file path despite the compact TOML name.
 * Reject token-shaped values here so a copied credential cannot silently turn
 * into a configuration value (or later be displayed by an operational tool).
 */
function tokenFilePath(value: unknown, location: string, home: string): string | undefined {
  const path = optionalString(value, location);
  if (path === undefined) return undefined;
  const trimmed = path.trim();
  if (/^[A-Za-z0-9_-]{43}$/.test(trimmed)) {
    fail(`${location} must be a runtime token file path; raw tokens are not supported`);
  }
  return expandHome(path, home);
}

function validateBrokerHost(host: string): void {
  // Broker host is later used both as a listen address and, when no explicit
  // URL is supplied, to construct a local WebSocket URL. Do not allow URL
  // punctuation to change that latter meaning.
  if (host.trim() !== host || host.length > 255 || /[\\/?#@\[\]]/.test(host)) {
    fail("broker.host must be a non-empty host name or address");
  }
  if (isIP(host) !== 0) return;
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(host) || host.includes("..")) {
    fail("broker.host must be a non-empty host name or address");
  }
}

function parsePartialConfig(value: unknown, source: string, home: string): CliConfigOverrides {
  if (!isPlainObject(value)) fail(`${source} must be a TOML table`);
  assertAllowedKeys(value, ["broker", "client", "discovery"], source);
  const result: CliConfigOverrides = {};

  const broker = value.broker;
  if (broker !== undefined) {
    if (!isPlainObject(broker)) fail(`${source}.broker must be a TOML table`);
    assertAllowedKeys(broker, ["host", "port", "token"], `${source}.broker`);
    const host = optionalString(broker.host, "broker.host");
    if (host !== undefined) validateBrokerHost(host);
    const port = integer(broker.port, "broker.port", 1, 65_535);
    const token = tokenFilePath(broker.token, "broker.token", home);
    result.broker = {
      ...(host === undefined ? {} : { host }),
      ...(port === undefined ? {} : { port }),
      ...(token === undefined ? {} : { token }),
    };
  }

  const client = value.client;
  if (client !== undefined) {
    if (!isPlainObject(client)) fail(`${source}.client must be a TOML table`);
    assertAllowedKeys(client, ["default_timeout", "reconnect"], `${source}.client`);
    const defaultTimeout = integer(client.default_timeout, "client.default_timeout", 1, MAX_TIMEOUT_MS);
    const reconnect = boolean(client.reconnect, "client.reconnect");
    result.client = {
      ...(defaultTimeout === undefined ? {} : { default_timeout: defaultTimeout }),
      ...(reconnect === undefined ? {} : { reconnect }),
    };
  }

  const discovery = value.discovery;
  if (discovery !== undefined) {
    if (!isPlainObject(discovery)) fail(`${source}.discovery must be a TOML table`);
    assertAllowedKeys(discovery, ["mdns_enabled", "mdns_interval"], `${source}.discovery`);
    const enabled = boolean(discovery.mdns_enabled, "discovery.mdns_enabled");
    const interval = integer(discovery.mdns_interval, "discovery.mdns_interval", 0, MAX_MDNS_INTERVAL_MS);
    result.discovery = {
      ...(enabled === undefined ? {} : { mdns_enabled: enabled }),
      ...(interval === undefined ? {} : { mdns_interval: interval }),
    };
  }

  return result;
}

function mergeConfig(base: CliConfig, override: CliConfigOverrides): CliConfig {
  return {
    broker: { ...base.broker, ...override.broker },
    client: { ...base.client, ...override.client },
    discovery: { ...base.discovery, ...override.discovery },
  };
}

function parseBooleanEnvironment(value: string, name: string): boolean {
  switch (value.toLowerCase()) {
    case "true":
    case "1":
      return true;
    case "false":
    case "0":
      return false;
    default:
      fail(`${name} must be true, false, 1, or 0`);
  }
}

function parseIntegerEnvironment(value: string, name: string, minimum: number, maximum: number): number {
  if (!/^(?:0|[1-9][0-9]*)$/.test(value)) fail(`${name} must be an integer between ${minimum} and ${maximum}`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    fail(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return parsed;
}

function firstEnvironmentValue(env: CliEnvironment, names: readonly string[]): string | undefined {
  const values = names
    .map((name) => ({ name, value: env[name] }))
    .filter((entry): entry is { name: string; value: string } => entry.value !== undefined);
  if (values.length === 0) return undefined;
  if (values.some((entry) => entry.value !== values[0]!.value)) {
    fail(`Conflicting environment settings: ${values.map((entry) => entry.name).join(", ")}`);
  }
  return values[0]!.value;
}

/** Safe environment overrides. Raw secret values are explicitly rejected. */
export function environmentConfigOverrides(env: CliEnvironment = process.env, home = homedir()): CliConfigOverrides {
  for (const name of RAW_SECRET_ENVIRONMENT_NAMES) {
    if (env[name] !== undefined) fail(`${name} is not supported; use a runtime token file path`);
  }

  const broker: Partial<BrokerCliConfig> = {};
  const client: Partial<ClientCliConfig> = {};
  const discovery: Partial<DiscoveryCliConfig> = {};
  const host = firstEnvironmentValue(env, ["POLYMESH_HOST", "POLYMESH_BROKER_HOST"]);
  const port = firstEnvironmentValue(env, ["POLYMESH_PORT", "POLYMESH_BROKER_PORT"]);
  const token = env.POLYMESH_TOKEN_FILE;
  const timeout = firstEnvironmentValue(env, ["POLYMESH_TIMEOUT_MS", "POLYMESH_DEFAULT_TIMEOUT"]);
  const reconnect = env.POLYMESH_RECONNECT;
  const mdnsEnabled = firstEnvironmentValue(env, ["POLYMESH_MDNS", "POLYMESH_MDNS_ENABLED"]);
  const mdnsInterval = env.POLYMESH_MDNS_INTERVAL;

  if (host !== undefined) broker.host = host;
  if (port !== undefined) broker.port = parseIntegerEnvironment(port, "POLYMESH_PORT", 1, 65_535);
  if (token !== undefined) broker.token = token;
  if (timeout !== undefined) client.default_timeout = parseIntegerEnvironment(timeout, "POLYMESH_TIMEOUT_MS", 1, MAX_TIMEOUT_MS);
  if (reconnect !== undefined) client.reconnect = parseBooleanEnvironment(reconnect, "POLYMESH_RECONNECT");
  if (mdnsEnabled !== undefined) discovery.mdns_enabled = parseBooleanEnvironment(mdnsEnabled, "POLYMESH_MDNS");
  if (mdnsInterval !== undefined) {
    discovery.mdns_interval = parseIntegerEnvironment(mdnsInterval, "POLYMESH_MDNS_INTERVAL", 0, MAX_MDNS_INTERVAL_MS);
  }

  // Validate paths/host strings and ensure aliases cannot bypass the same
  // strict validation as TOML.  TOML parsing itself is not involved here.
  return parsePartialConfig({
    ...(Object.keys(broker).length === 0 ? {} : { broker }),
    ...(Object.keys(client).length === 0 ? {} : { client }),
    ...(Object.keys(discovery).length === 0 ? {} : { discovery }),
  }, "environment", home);
}

/** Parse a TOML document into a validated partial CLI configuration. */
export function parseCliToml(value: string, home = homedir()): CliConfigOverrides {
  if (Buffer.byteLength(value, "utf8") > MAX_CONFIG_BYTES) fail("Configuration file exceeds 1 MiB");
  let parsed: unknown;
  try {
    parsed = parseToml(value);
  } catch {
    fail("Invalid TOML configuration");
  }
  return parsePartialConfig(parsed, "configuration", home);
}

function selectedConfigPath(options: LoadCliConfigOptions, env: CliEnvironment, home: string): { path: string; explicit: boolean } {
  if (options.configPath !== undefined) {
    if (options.configPath.trim().length === 0) fail("--config requires a non-empty TOML file path");
    return { path: expandHome(options.configPath, home), explicit: true };
  }
  if (env.POLYMESH_CONFIG !== undefined) {
    if (env.POLYMESH_CONFIG.trim().length === 0) fail("POLYMESH_CONFIG must be a non-empty TOML file path");
    return { path: expandHome(env.POLYMESH_CONFIG, home), explicit: true };
  }
  return { path: defaultConfigPath(home), explicit: false };
}

function validateConfigFileName(path: string): void {
  if (!path.toLowerCase().endsWith(".toml")) fail("Only TOML configuration files are supported");
}

function isMissingFile(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && (error as { code?: unknown }).code === "ENOENT";
}

/**
 * Merge defaults < TOML file < environment < CLI flags. The selected default
 * path is optional, while an explicit --config/POLYMESH_CONFIG path must be
 * readable so a typo cannot silently select surprising defaults.
 */
export async function loadCliConfig(options: LoadCliConfigOptions = {}): Promise<LoadedCliConfig> {
  const env = options.env ?? process.env;
  const home = (options.homeDir ?? homedir)();
  const selected = selectedConfigPath(options, env, home);
  validateConfigFileName(selected.path);
  let config = cloneDefaults();
  let configFileLoaded = false;

  try {
    const source = await (options.readFile ?? nodeReadFile)(selected.path, "utf8");
    config = mergeConfig(config, parseCliToml(source, home));
    configFileLoaded = true;
  } catch (error) {
    if (!selected.explicit && isMissingFile(error)) {
      // A first-run installation should work before a user config exists.
    } else if (error instanceof CliConfigError) {
      throw error;
    } else if (isMissingFile(error)) {
      fail(`Configuration file does not exist: ${selected.path}`);
    } else {
      fail(`Cannot read configuration file: ${selected.path}`);
    }
  }

  config = mergeConfig(config, environmentConfigOverrides(env, home));
  // This validates programmatic callers too, rather than trusting the CLI's
  // flag parser to be the only entry point.
  config = mergeConfig(config, parsePartialConfig(options.overrides ?? {}, "command-line flags", home));
  return { config, configPath: selected.path, configFileLoaded };
}

/** Return a copy suitable for `polymesh config show` and diagnostics. */
export function redactCliConfig(config: CliConfig): CliConfig {
  return {
    broker: {
      host: config.broker.host,
      port: config.broker.port,
      ...(config.broker.token === undefined ? {} : { token: "[redacted]" }),
    },
    client: { ...config.client },
    discovery: { ...config.discovery },
  };
}

/** Backwards-friendly concise name for callers that only need the merge. */
export const loadConfig = loadCliConfig;

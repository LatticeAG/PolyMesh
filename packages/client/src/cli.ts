#!/usr/bin/env node
/** Testable implementation behind the `polymesh` command-line interface. */
import { realpathSync } from "node:fs";
import { readFile as nodeReadFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

import {
  MAX_CARD_BYTES,
  Broker,
  createAgentCard,
  decodeRuntimeToken,
  isAgentCard,
  parseStrictJson,
  type AgentCard,
} from "@latticeag/polymesh-broker";
import { PolyMeshClient, type ClientOptions } from "./client.js";
import { loadCliConfig, redactCliConfig, type CliConfigOverrides } from "./config.js";
import { advertiseMdns, discoverMdns, type MdnsHandle, type MdnsPeer } from "./mdns.js";

export interface CliIo {
  stdout: { write(chunk: string): unknown };
  stderr: { write(chunk: string): unknown };
}

export interface CliDeps {
  env?: Record<string, string | undefined>;
  io?: CliIo;
  readFile?: (path: string, encoding: BufferEncoding) => Promise<string>;
  /** Dedicated config reader; named configs fall back to readFile for legacy embedders. */
  readConfigFile?: (path: string, encoding: BufferEncoding) => Promise<string>;
  /** Lets tests select the default ~/.config path without touching $HOME. */
  homeDir?: () => string;
  createBroker?: (options: ConstructorParameters<typeof Broker>[0]) => Broker;
  createClient?: (options: ClientOptions) => PolyMeshClient;
  advertiseMdns?: typeof advertiseMdns;
  discoverMdns?: typeof discoverMdns;
  /** Opt in to process-lifetime behavior in a real command wrapper. */
  waitForSignal?: () => Promise<void>;
  discoverWindowMs?: number;
}

interface ParsedArgs {
  command?: string;
  positionals: string[];
  flags: Map<string, string | true>;
}

const usage = `Usage:
  polymesh config show [--config FILE]
  polymesh start [--config FILE] [--port 7337] [--host 127.0.0.1] [--token-file FILE] [--insecure-loopback-dev] [--mdns]
  polymesh connect [<wss-url>] [--config FILE] [--card FILE] [--token-file FILE] [--insecure-loopback-dev]
  polymesh peers [--config FILE] [--mdns | --no-mdns]
  polymesh capabilities [--card FILE]
  polymesh call <agent> <capability> <json-input> [--config FILE] [--url URL] [--timeout MS] [--token-file FILE] [--insecure-loopback-dev]
`;

function parseArgs(argv: string[]): ParsedArgs {
  const flags = new Map<string, string | true>();
  const positionals: string[] = [];
  let command: string | undefined;
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index]!;
    if (value.startsWith("--")) {
      const equals = value.indexOf("=");
      if (equals > 2) flags.set(value.slice(2, equals), value.slice(equals + 1));
      else if (argv[index + 1] && !argv[index + 1]!.startsWith("--")) flags.set(value.slice(2), argv[++index]!);
      else flags.set(value.slice(2), true);
    } else if (!command) command = value;
    else positionals.push(value);
  }
  return { command, positionals, flags };
}

function flag(parsed: ParsedArgs, name: string): string | undefined {
  const value = parsed.flags.get(name);
  return typeof value === "string" ? value : undefined;
}

function hasFlag(parsed: ParsedArgs, name: string): boolean {
  return parsed.flags.has(name);
}

function defaultCard(): AgentCard {
  return createAgentCard({ agent_id: "org.polymesh.cli" });
}

async function loadCard(path: string | undefined, deps: CliDeps): Promise<AgentCard> {
  if (!path) return defaultCard();
  const content = await (deps.readFile ?? nodeReadFile)(path, "utf8");
  const parsed = parseStrictJson(content, { maxBytes: MAX_CARD_BYTES });
  if (!parsed.ok || !isAgentCard(parsed.value)) throw new Error(`Invalid PolyMesh Agent Card: ${path}`);
  return parsed.value;
}

async function loadRuntimeToken(path: string | undefined, deps: CliDeps): Promise<string | undefined> {
  if (!path) return undefined;
  const token = await (deps.readFile ?? nodeReadFile)(path, "utf8");
  if (!decodeRuntimeToken(token)) throw new Error("Runtime token file does not contain a valid PolyMesh token");
  return token;
}

function rejectInlineToken(parsed: ParsedArgs, env: Record<string, string | undefined>): void {
  if (hasFlag(parsed, "token") || env.POLYMESH_TOKEN !== undefined) {
    throw new Error("Inline runtime tokens are not supported; use --token-file or POLYMESH_TOKEN_FILE");
  }
}

function requiredFlagValue(parsed: ParsedArgs, name: string): string | undefined {
  const value = parsed.flags.get(name);
  if (value === true) throw new Error(`--${name} requires a value`);
  return typeof value === "string" ? value : undefined;
}

function numericFlagValue(parsed: ParsedArgs, name: string): number | undefined {
  const value = requiredFlagValue(parsed, name);
  if (value === undefined) return undefined;
  const parsedValue = Number(value);
  if (!Number.isSafeInteger(parsedValue)) throw new Error(`--${name} must be an integer`);
  return parsedValue;
}

/** Extract only the configuration-backed flags, preserving the documented precedence. */
function configOverridesFromFlags(parsed: ParsedArgs): CliConfigOverrides {
  if (hasFlag(parsed, "mdns") && hasFlag(parsed, "no-mdns")) {
    throw new Error("--mdns and --no-mdns cannot be used together");
  }
  for (const booleanFlag of ["mdns", "no-mdns"]) {
    const value = parsed.flags.get(booleanFlag);
    if (typeof value === "string") throw new Error(`--${booleanFlag} does not take a value`);
  }
  const host = requiredFlagValue(parsed, "host");
  const port = numericFlagValue(parsed, "port");
  const token = requiredFlagValue(parsed, "token-file");
  const timeout = numericFlagValue(parsed, "timeout");
  const mdnsInterval = numericFlagValue(parsed, "mdns-interval");
  return {
    ...(host === undefined && port === undefined && token === undefined ? {} : {
      broker: {
        ...(host === undefined ? {} : { host }),
        ...(port === undefined ? {} : { port }),
        ...(token === undefined ? {} : { token }),
      },
    }),
    ...(timeout === undefined ? {} : { client: { default_timeout: timeout } }),
    ...(!hasFlag(parsed, "mdns") && !hasFlag(parsed, "no-mdns") && mdnsInterval === undefined ? {} : {
      discovery: {
        ...(hasFlag(parsed, "mdns") ? { mdns_enabled: true } : {}),
        ...(hasFlag(parsed, "no-mdns") ? { mdns_enabled: false } : {}),
        ...(mdnsInterval === undefined ? {} : { mdns_interval: mdnsInterval }),
      },
    }),
  };
}

function configuredBrokerUrl(config: { host: string; port: number }): string {
  const host = config.host.includes(":") && !config.host.startsWith("[") ? `[${config.host}]` : config.host;
  return `ws://${host}:${config.port}/polymesh`;
}

function write(io: CliIo, value: unknown): void {
  io.stdout.write(`${typeof value === "string" ? value : JSON.stringify(value, null, 2)}\n`);
}

/**
 * Run a command without invoking process.exit or spawning subprocesses.  This
 * makes CLI behavior straightforward to test and useful to embedded callers.
 */
export async function main(argv: string[] = process.argv.slice(2), deps: CliDeps = {}): Promise<number> {
  const env = deps.env ?? process.env;
  const io = deps.io ?? { stdout: process.stdout, stderr: process.stderr };
  const parsed = parseArgs(argv);
  if (!parsed.command || parsed.command === "help" || hasFlag(parsed, "help")) {
    write(io, usage.trimEnd());
    return 0;
  }
  const createBroker = deps.createBroker ?? ((options) => new Broker(options));
  const createClient = deps.createClient ?? ((options) => new PolyMeshClient(options));

  try {
    rejectInlineToken(parsed, env);
    const configPath = requiredFlagValue(parsed, "config");
    const loadedConfig = await loadCliConfig({
      ...(configPath === undefined ? {} : { configPath }),
      env,
      overrides: configOverridesFromFlags(parsed),
      // Existing embedded callers commonly provide `readFile` for a named
      // card/token fixture. Reuse it for an explicitly named config file,
      // while keeping automatic first-run config discovery independent.
      readFile: deps.readConfigFile ?? (configPath !== undefined || env.POLYMESH_CONFIG !== undefined ? deps.readFile : undefined),
      homeDir: deps.homeDir,
    });
    const config = loadedConfig.config;
    const cardPath = flag(parsed, "card") ?? env.POLYMESH_CARD;
    const tokenFile = config.broker.token;
    switch (parsed.command) {
      case "config": {
        if (parsed.positionals.length !== 1 || parsed.positionals[0] !== "show") {
          throw new Error("config requires the show subcommand");
        }
        write(io, {
          config_path: loadedConfig.configPath,
          config_file_loaded: loadedConfig.configFileLoaded,
          ...redactCliConfig(config),
        });
        return 0;
      }
      case "start": {
        const { port, host } = config.broker;
        const token = await loadRuntimeToken(tokenFile, deps);
        const broker = createBroker({
          port,
          host,
          token,
          // Plain ws:// is an explicitly named development posture.  The
          // broker independently verifies that the host is numeric loopback
          // and that a valid runtime token is present.
          allowInsecureLoopbackDevelopment: hasFlag(parsed, "insecure-loopback-dev"),
        });
        await broker.start();
        let advertisement: MdnsHandle | undefined;
        if (config.discovery.mdns_enabled) {
          if (!broker.url?.startsWith("wss://")) {
            throw new Error("mDNS advertising requires a WSS endpoint");
          }
          advertisement = (deps.advertiseMdns ?? advertiseMdns)({
            agentId: broker.card.agent_id,
            port: broker.port ?? port,
          });
        }
        write(io, { url: broker.url, port: broker.port, agent_id: broker.card.agent_id });
        if (deps.waitForSignal) {
          try {
            await deps.waitForSignal();
          } finally {
            advertisement?.stop();
            await broker.close();
          }
        }
        return 0;
      }
      case "connect": {
        const url = parsed.positionals[0] ?? flag(parsed, "url") ?? env.POLYMESH_URL ?? configuredBrokerUrl(config.broker);
        const card = await loadCard(cardPath, deps);
        const token = await loadRuntimeToken(tokenFile, deps);
        const client = createClient({
          card,
          url,
          token,
          defaultTimeoutMs: config.client.default_timeout,
          allowInsecureLoopbackDevelopment: hasFlag(parsed, "insecure-loopback-dev"),
        });
        await client.connect();
        write(io, { connected: true, peer: client.brokerIdentity, card: client.brokerCard });
        client.close();
        return 0;
      }
      case "capabilities": {
        const card = await loadCard(cardPath, deps);
        write(io, card.capabilities);
        return 0;
      }
      case "peers": {
        if (!config.discovery.mdns_enabled) {
          write(io, []);
          return 0;
        }
        const peers: MdnsPeer[] = [];
        const browser = (deps.discoverMdns ?? discoverMdns)((peer) => peers.push(peer));
        const windowMs = deps.discoverWindowMs ?? config.discovery.mdns_interval;
        if (windowMs > 0) await new Promise<void>((resolve) => setTimeout(resolve, windowMs));
        browser.stop();
        write(io, peers);
        return 0;
      }
      case "call": {
        const [agent, capability, jsonInput] = parsed.positionals;
        const url = flag(parsed, "url") ?? env.POLYMESH_URL ?? configuredBrokerUrl(config.broker);
        if (!agent || !capability || jsonInput === undefined) throw new Error("call requires <agent> <capability> <json-input>");
        const parsedInput = parseStrictJson(jsonInput, { maxBytes: 256 * 1_024 });
        if (!parsedInput.ok || typeof parsedInput.value !== "object" || parsedInput.value === null || Array.isArray(parsedInput.value)) {
          throw new Error("json-input must be a bounded JSON object without duplicate keys");
        }
        const card = await loadCard(cardPath, deps);
        const token = await loadRuntimeToken(tokenFile, deps);
        const client = createClient({
          card,
          url,
          token,
          defaultTimeoutMs: config.client.default_timeout,
          allowInsecureLoopbackDevelopment: hasFlag(parsed, "insecure-loopback-dev"),
        });
        const timeoutMs = config.client.default_timeout;
        try {
          const result = await client.call(agent, capability, parsedInput.value as Record<string, never>, { timeoutMs });
          write(io, result);
        } finally {
          client.close();
        }
        return 0;
      }
      default:
        throw new Error(`Unknown command: ${parsed.command}`);
    }
  } catch (error) {
    io.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
}

export const parseCliArgs = parseArgs;

function waitForTerminationSignal(): Promise<void> {
  return new Promise((resolve) => {
    const done = () => {
      process.off("SIGINT", done);
      process.off("SIGTERM", done);
      resolve();
    };
    process.once("SIGINT", done);
    process.once("SIGTERM", done);
  });
}

/**
 * npm exposes package binaries as symlinks in `node_modules/.bin`.  Resolve
 * that link before comparing it with `import.meta.url`; otherwise the packed
 * CLI silently imports without ever running its command handler.
 */
function isExecutableEntrypoint(): boolean {
  const executable = process.argv[1];
  if (!executable) return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(executable)).href;
  } catch {
    return import.meta.url === pathToFileURL(executable).href;
  }
}

// Imports remain side-effect free.  The command only takes ownership of the
// process lifetime when this file is the executable entrypoint.
if (isExecutableEntrypoint()) {
  void main(process.argv.slice(2), { waitForSignal: waitForTerminationSignal })
    .then((code) => { process.exitCode = code; })
    .catch((error) => {
      process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
      process.exitCode = 1;
    });
}

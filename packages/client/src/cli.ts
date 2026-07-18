#!/usr/bin/env node
/** Testable implementation behind the `polymesh` command-line interface. */
import { readFile as nodeReadFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

import { Broker, createAgentCard, isAgentCard, type AgentCard } from "@polymesh/broker";
import { PolyMeshClient, type ClientOptions } from "./client.js";
import { advertiseMdns, discoverMdns, type MdnsHandle, type MdnsPeer } from "./mdns.js";

export interface CliIo {
  stdout: { write(chunk: string): unknown };
  stderr: { write(chunk: string): unknown };
}

export interface CliDeps {
  env?: Record<string, string | undefined>;
  io?: CliIo;
  readFile?: (path: string, encoding: BufferEncoding) => Promise<string>;
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
  polymesh start [--port 7337] [--host 127.0.0.1] [--token TOKEN] [--mdns]
  polymesh connect <ws-url> [--card FILE] [--token TOKEN]
  polymesh peers [--url URL] [--card FILE] [--mdns]
  polymesh capabilities [--card FILE]
  polymesh call <agent> <capability> <json-input> [--url URL] [--timeout MS]
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

function positiveInt(value: string | undefined, fallback: number, name: string): number {
  if (value === undefined) return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) throw new Error(`${name} must be a positive integer`);
  return parsed;
}

function defaultCard(): AgentCard {
  return createAgentCard({ agent_id: "org.polymesh.cli" });
}

async function loadCard(path: string | undefined, deps: CliDeps): Promise<AgentCard> {
  if (!path) return defaultCard();
  const content = await (deps.readFile ?? nodeReadFile)(path, "utf8");
  const parsed = JSON.parse(content) as unknown;
  if (!isAgentCard(parsed)) throw new Error(`Invalid PolyMesh Agent Card: ${path}`);
  return parsed;
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
  const cardPath = flag(parsed, "card") ?? env.POLYMESH_CARD;
  const token = flag(parsed, "token") ?? env.POLYMESH_TOKEN;
  const createBroker = deps.createBroker ?? ((options) => new Broker(options));
  const createClient = deps.createClient ?? ((options) => new PolyMeshClient(options));

  try {
    switch (parsed.command) {
      case "start": {
        const port = positiveInt(flag(parsed, "port"), 7337, "port");
        const host = flag(parsed, "host") ?? "127.0.0.1";
        const broker = createBroker({ port, host, token });
        await broker.start();
        let advertisement: MdnsHandle | undefined;
        if (hasFlag(parsed, "mdns")) {
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
        const url = parsed.positionals[0] ?? flag(parsed, "url") ?? env.POLYMESH_URL;
        if (!url) throw new Error("connect requires a WebSocket URL");
        const card = await loadCard(cardPath, deps);
        const client = createClient({ card, url, token });
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
        if (!hasFlag(parsed, "mdns")) {
          write(io, []);
          return 0;
        }
        const peers: MdnsPeer[] = [];
        const browser = (deps.discoverMdns ?? discoverMdns)((peer) => peers.push(peer));
        const windowMs = deps.discoverWindowMs ?? 0;
        if (windowMs > 0) await new Promise<void>((resolve) => setTimeout(resolve, windowMs));
        browser.stop();
        write(io, peers);
        return 0;
      }
      case "call": {
        const [agent, capability, jsonInput] = parsed.positionals;
        const url = flag(parsed, "url") ?? env.POLYMESH_URL;
        if (!agent || !capability || jsonInput === undefined) throw new Error("call requires <agent> <capability> <json-input>");
        if (!url) throw new Error("call requires --url or POLYMESH_URL");
        const input = JSON.parse(jsonInput) as unknown;
        if (typeof input !== "object" || input === null || Array.isArray(input)) throw new Error("json-input must be a JSON object");
        const card = await loadCard(cardPath, deps);
        const client = createClient({ card, url, token });
        const timeoutMs = positiveInt(flag(parsed, "timeout"), 60_000, "timeout");
        try {
          const result = await client.call(agent, capability, input as Record<string, never>, { timeoutMs });
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

// Imports remain side-effect free.  The command only takes ownership of the
// process lifetime when this file is the executable entrypoint.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  void main(process.argv.slice(2), { waitForSignal: waitForTerminationSignal })
    .then((code) => { process.exitCode = code; })
    .catch((error) => {
      process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
      process.exitCode = 1;
    });
}

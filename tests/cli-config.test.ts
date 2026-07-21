import { describe, expect, it, vi } from "vitest";

import { createAgentCard } from "@latticeag/polymesh-broker";
import {
  CliConfigError,
  defaultConfigPath,
  loadCliConfig,
  main,
  parseCliToml,
} from "@latticeag/polymesh-client";

function missingFile(): Error & { code: string } {
  return Object.assign(new Error("missing"), { code: "ENOENT" });
}

function ioCapture() {
  const stdout: string[] = [];
  const stderr: string[] = [];
  return {
    stdout,
    stderr,
    io: {
      stdout: { write: (chunk: string) => stdout.push(chunk) },
      stderr: { write: (chunk: string) => stderr.push(chunk) },
    },
  };
}

const FILE_CONFIG = `
[broker]
host = "file-broker"
port = 7444
token = "~/.config/polymesh/runtime-token"

[client]
default_timeout = 1200
reconnect = true

[discovery]
mdns_enabled = true
mdns_interval = 250
`;

describe("TypeScript CLI TOML configuration", () => {
  it("uses the stable default path and makes an absent automatic file optional", async () => {
    expect(defaultConfigPath("/home/alice")).toBe("/home/alice/.config/polymesh/config.toml");
    const readFile = vi.fn(async () => { throw missingFile(); });

    const loaded = await loadCliConfig({
      homeDir: () => "/home/alice",
      readFile,
      env: {},
    });

    expect(readFile).toHaveBeenCalledWith("/home/alice/.config/polymesh/config.toml", "utf8");
    expect(loaded.configFileLoaded).toBe(false);
    expect(loaded.config).toMatchObject({
      broker: { host: "127.0.0.1", port: 7337 },
      client: { default_timeout: 60_000, reconnect: false },
      discovery: { mdns_enabled: false, mdns_interval: 0 },
    });
  });

  it("merges file, environment, and CLI values in precedence order", async () => {
    const readFile = vi.fn(async () => FILE_CONFIG);
    const loaded = await loadCliConfig({
      configPath: "/tmp/explicit.toml",
      homeDir: () => "/home/alice",
      readFile,
      env: {
        POLYMESH_CONFIG: "/tmp/ignored-by-flag.toml",
        POLYMESH_HOST: "environment-broker",
        POLYMESH_PORT: "7555",
        POLYMESH_TOKEN_FILE: "/environment/token",
        POLYMESH_TIMEOUT_MS: "2200",
        POLYMESH_RECONNECT: "false",
        POLYMESH_MDNS: "false",
        POLYMESH_MDNS_INTERVAL: "500",
      },
      overrides: {
        broker: { host: "flag-broker", port: 7666, token: "/flag/token" },
        client: { default_timeout: 3300 },
        discovery: { mdns_enabled: true, mdns_interval: 750 },
      },
    });

    expect(readFile).toHaveBeenCalledWith("/tmp/explicit.toml", "utf8");
    expect(loaded.config).toEqual({
      broker: { host: "flag-broker", port: 7666, token: "/flag/token" },
      client: { default_timeout: 3300, reconnect: false },
      discovery: { mdns_enabled: true, mdns_interval: 750 },
    });
  });

  it("rejects unknown keys and raw tokens instead of treating them as safe configuration", () => {
    expect(() => parseCliToml("[broker]\nunknown = true")).toThrow(CliConfigError);
    const rawToken = Buffer.alloc(32, 1).toString("base64url");
    expect(() => parseCliToml(`[broker]\ntoken = "${rawToken}"`)).toThrow(/token file path/i);
  });

  it("applies config-backed host, port, token, timeout, and mDNS settings to CLI commands", async () => {
    const capture = ioCapture();
    const token = Buffer.alloc(32, 7).toString("base64url");
    const broker = {
      card: createAgentCard({ agent_id: "config-broker" }),
      port: 7666,
      url: "ws://127.0.0.1:7666/polymesh",
      start: vi.fn(async () => undefined),
      close: vi.fn(async () => undefined),
    };
    const createBroker = vi.fn(() => broker);
    const call = vi.fn(async () => ({ configured: true }));
    const close = vi.fn();
    const createClient = vi.fn(() => ({ call, close }));
    const discover = vi.fn(() => ({ stop: vi.fn() }));
    const config = `
[broker]
host = "file-host"
port = 7444
token = "/file/token"

[client]
default_timeout = 1234

[discovery]
mdns_enabled = true
mdns_interval = 100
`;
    const commonDeps = {
      io: capture.io,
      readConfigFile: async () => config,
      readFile: async () => token,
    };

    await expect(main([
      "start", "--config", "/tmp/config.toml", "--host", "127.0.0.1", "--port", "7666", "--token-file", "/flag/token", "--insecure-loopback-dev", "--no-mdns",
    ], {
      ...commonDeps,
      createBroker: createBroker as never,
    })).resolves.toBe(0);
    expect(createBroker).toHaveBeenCalledWith(expect.objectContaining({
      host: "127.0.0.1",
      port: 7666,
      token,
    }));

    await expect(main([
      "call", "bob", "org.example.echo", "{}", "--config", "/tmp/config.toml", "--url", "ws://127.0.0.1:7444/polymesh", "--insecure-loopback-dev",
    ], {
      ...commonDeps,
      createClient: createClient as never,
    })).resolves.toBe(0);
    expect(createClient).toHaveBeenCalledWith(expect.objectContaining({ defaultTimeoutMs: 1234 }));
    expect(call).toHaveBeenCalledWith("bob", "org.example.echo", {}, { timeoutMs: 1234 });

    await expect(main(["peers", "--config", "/tmp/config.toml"], {
      ...commonDeps,
      discoverMdns: discover as never,
      discoverWindowMs: 0,
    })).resolves.toBe(0);
    expect(discover).toHaveBeenCalledOnce();
  });

  it("selects POLYMESH_CONFIG and redacts the configured token in config show", async () => {
    const capture = ioCapture();
    const tokenPath = "/private/runtime-token";
    const code = await main(["config", "show"], {
      io: capture.io,
      env: { POLYMESH_CONFIG: "/tmp/from-environment.toml" },
      readConfigFile: async () => `[broker]\ntoken = "${tokenPath}"`,
    });

    expect(code).toBe(0);
    const shown = JSON.parse(capture.stdout.join(""));
    expect(shown.config_path).toBe("/tmp/from-environment.toml");
    expect(shown.broker.token).toBe("[redacted]");
    expect(capture.stdout.join("")).not.toContain(tokenPath);
    expect(capture.stderr).toEqual([]);
  });
});

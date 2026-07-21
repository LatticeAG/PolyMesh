import { describe, expect, it, vi } from "vitest";

import { createAgentCard } from "@latticeag/polymesh-broker";
import { main } from "@latticeag/polymesh-client";

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

describe("polymesh CLI", () => {
  it("prints capabilities from an injected card file without spawning a process", async () => {
    const capture = ioCapture();
    const card = createAgentCard({
      agent_id: "cli-agent",
      capabilities: [{ id: "org.example.echo", version: "1.0.0" }],
    });
    const code = await main(["capabilities", "--card", "agent-card.json"], {
      io: capture.io,
      readFile: async () => JSON.stringify(card),
    });

    expect(code).toBe(0);
    expect(JSON.parse(capture.stdout.join("")).some((capability: { id: string }) => capability.id === "org.example.echo")).toBe(true);
    expect(capture.stderr).toEqual([]);
  });

  it("uses injected broker, mDNS, and client dependencies", async () => {
    const capture = ioCapture();
    const brokerCard = createAgentCard({ agent_id: "broker-agent" });
    const broker = {
      card: brokerCard,
      port: 7444,
      url: "wss://127.0.0.1:7444/polymesh",
      start: vi.fn(async () => broker),
      close: vi.fn(async () => undefined),
    };
    const advertise = vi.fn(() => ({ stop: vi.fn() }));
    const createBroker = vi.fn(() => broker);

    await expect(main(["start", "--port", "7444", "--mdns"], {
      io: capture.io,
      createBroker: createBroker as never,
      advertiseMdns: advertise as never,
    })).resolves.toBe(0);
    expect(createBroker).toHaveBeenCalledWith(expect.objectContaining({ port: 7444, host: "127.0.0.1" }));
    expect(advertise).toHaveBeenCalledWith(expect.objectContaining({ agentId: "broker-agent", port: 7444 }));

    const call = vi.fn(async () => ({ echoed: true }));
    const close = vi.fn();
    const createClient = vi.fn(() => ({ call, close }));
    await expect(main([
      "call", "bob", "org.example.echo", '{"value":1}', "--url", "ws://example.test/polymesh", "--timeout", "50",
    ], {
      io: capture.io,
      createClient: createClient as never,
    })).resolves.toBe(0);
    expect(call).toHaveBeenCalledWith("bob", "org.example.echo", { value: 1 }, { timeoutMs: 50 });
    expect(close).toHaveBeenCalledOnce();

    const discover = vi.fn((onPeer: (peer: unknown) => void) => {
      onPeer({ agentId: "nearby", host: "localhost", port: 7337, addresses: ["127.0.0.1"], tls: false, name: "nearby" });
      return { stop: vi.fn() };
    });
    await expect(main(["peers", "--mdns"], { io: capture.io, discoverMdns: discover as never })).resolves.toBe(0);
    expect(capture.stdout.join("")).toContain("nearby");
  });

  it("returns a nonzero status and reports bad command input", async () => {
    const capture = ioCapture();
    await expect(main(["call", "only-agent"], { io: capture.io })).resolves.toBe(1);
    expect(capture.stderr.join("")).toContain("call requires");
  });
});

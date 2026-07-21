import { describe, expect, it } from "vitest";

import { advertiseMdns, discoverMdns, type BonjourLike } from "@latticeag/polymesh-client";

function fakeBonjour() {
  let onUp: ((service: Record<string, unknown>) => void) | undefined;
  const published: Record<string, unknown>[] = [];
  let stopCalls = 0;
  let destroyCalls = 0;
  const instance: BonjourLike = {
    publish(options) {
      published.push(options);
      return { stop: () => { stopCalls += 1; } };
    },
    find(_options, callback) {
      onUp = callback;
      return { stop: () => { stopCalls += 1; } };
    },
    destroy() { destroyCalls += 1; },
  };
  return {
    instance,
    published,
    emit(service: Record<string, unknown>) { onUp?.(service); },
    get stopCalls() { return stopCalls; },
    get destroyCalls() { return destroyCalls; },
  };
}

describe("mDNS security boundary", () => {
  it("publishes only minimal WSS hints and refuses plaintext discovery", () => {
    const fake = fakeBonjour();
    const handle = advertiseMdns({ agentId: "com.example.agent", port: 7443 }, {
      createBonjour: () => fake.instance,
    });
    expect(fake.published).toEqual([expect.objectContaining({
      type: "polymesh",
      protocol: "tcp",
      port: 7443,
      txt: { v: "0.1", id: "com.example.agent" },
    })]);
    expect((fake.published[0]!.txt as Record<string, unknown>).tls).toBeUndefined();
    expect(() => advertiseMdns({ agentId: "com.example.agent", port: 7443, tls: false }, {
      createBonjour: () => fake.instance,
    })).toThrow(/requires WSS/);
    handle.stop();
    handle.stop();
    expect(fake.stopCalls).toBe(1);
    expect(fake.destroyCalls).toBe(1);
  });

  it("accepts only minimal TXT records with bounded private-LAN literal addresses", () => {
    const fake = fakeBonjour();
    const peers: unknown[] = [];
    const handle = discoverMdns((peer) => peers.push(peer), {}, { createBonjour: () => fake.instance });

    fake.emit({
      name: "nearby",
      host: "attacker.example",
      port: 7443,
      txt: { v: "0.1", id: "com.example.nearby" },
      addresses: ["127.0.0.1", "8.8.8.8", "10.8.0.4", "fd12:3456::1"],
      interfaceIndex: 3,
    });
    fake.emit({
      name: "bad-extra-txt",
      port: 7443,
      txt: { v: "0.1", id: "com.example.bad", tls: "1" },
      addresses: ["10.8.0.5"],
    });
    fake.emit({
      name: "bad-public-address",
      port: 7443,
      txt: { v: "0.1", id: "com.example.bad" },
      addresses: ["169.254.169.254", "fe80::1", "::ffff:127.0.0.1"],
    });

    expect(peers).toEqual([{
      agentId: "com.example.nearby",
      host: "10.8.0.4",
      port: 7443,
      addresses: ["10.8.0.4", "fd12:3456::1"],
      tls: true,
      name: "nearby",
    }]);
    handle.stop();
  });

  it("deduplicates and rate-limits discovery callbacks without auto-connecting", () => {
    const fake = fakeBonjour();
    let now = 1_000;
    const peers: string[] = [];
    const handle = discoverMdns((peer) => peers.push(peer.host), { minCallbackIntervalMs: 500 }, {
      createBonjour: () => fake.instance,
      now: () => now,
    });
    const base = {
      name: "nearby",
      port: 7443,
      txt: { v: "0.1", id: "com.example.nearby" },
      interfaceIndex: 3,
    };

    fake.emit({ ...base, addresses: ["10.8.0.4"] });
    fake.emit({ ...base, addresses: ["10.8.0.4"] });
    fake.emit({ ...base, addresses: ["10.8.0.5"] });
    now += 500;
    fake.emit({ ...base, addresses: ["10.8.0.6"] });

    expect(peers).toEqual(["10.8.0.4", "10.8.0.6"]);
    handle.stop();
  });
});

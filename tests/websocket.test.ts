import { afterEach, describe, expect, it } from "vitest";

import { Broker, createAgentCard, generateRuntimeToken } from "@latticeag/polymesh-broker";
import { PolyMeshClient } from "@latticeag/polymesh-client";

const brokers: Broker[] = [];
const clients: PolyMeshClient[] = [];

function allow() {
  return { effect: "allow" as const, ruleId: "test", policyGeneration: 1, leaseId: "test-lease" };
}

afterEach(async () => {
  for (const client of clients.splice(0)) client.close();
  await Promise.all(brokers.splice(0).map((broker) => broker.close()));
});

describe("WebSocket transport", () => {
  it("uses the polymesh.0.1 subprotocol and routes a task through an OS-assigned port", async () => {
    const token = generateRuntimeToken();
    const broker = new Broker({
      port: 0,
      host: "127.0.0.1",
      token,
      allowInsecureLoopbackDevelopment: true,
    });
    brokers.push(broker);
    await broker.start();
    const alice = new PolyMeshClient({
      card: createAgentCard({ agent_id: "alice" }),
      url: broker.url,
      token,
      allowInsecureLoopbackDevelopment: true,
    });
    const bob = new PolyMeshClient({
      card: createAgentCard({ agent_id: "bob", capabilities: [{ id: "org.example.add", version: "1.0.0" }] }),
      url: broker.url,
      token,
      allowInsecureLoopbackDevelopment: true,
      handlers: { "org.example.add": ({ left, right }) => ({ sum: Number(left) + Number(right) }) },
      authorize: () => allow(),
    });
    clients.push(alice, bob);

    await Promise.all([alice.connect(), bob.connect()]);
    await expect(alice.call("bob", "org.example.add", { left: 2, right: 3 })).resolves.toEqual({ sum: 5 });
  });

  it("rejects a bad loopback token before the session becomes active", async () => {
    const broker = new Broker({
      port: 0,
      host: "127.0.0.1",
      token: generateRuntimeToken(),
      allowInsecureLoopbackDevelopment: true,
    });
    brokers.push(broker);
    await broker.start();
    const client = new PolyMeshClient({
      card: createAgentCard({ agent_id: "alice" }),
      url: broker.url,
      token: generateRuntimeToken(),
      allowInsecureLoopbackDevelopment: true,
    });
    clients.push(client);

    await expect(client.connect()).rejects.toMatchObject({ code: "TRANSPORT_CLOSED" });
    expect(client.connected).toBe(false);
  });

  it("rejects plaintext endpoints without an explicit numeric-loopback development opt-in", async () => {
    const card = createAgentCard({ agent_id: "alice" });
    const disabled = new PolyMeshClient({ card, url: "ws://127.0.0.1:7337/polymesh", token: generateRuntimeToken() });
    const nonLoopback = new PolyMeshClient({
      card,
      url: "ws://192.168.1.10:7337/polymesh",
      token: generateRuntimeToken(),
      allowInsecureLoopbackDevelopment: true,
    });
    clients.push(disabled, nonLoopback);

    await expect(disabled.connect()).rejects.toMatchObject({ code: "INSECURE_TRANSPORT_DISABLED" });
    await expect(nonLoopback.connect()).rejects.toMatchObject({ code: "INSECURE_TRANSPORT_DISABLED" });
  });
});

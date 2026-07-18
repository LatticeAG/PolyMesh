import { afterEach, describe, expect, it } from "vitest";

import { Broker, createAgentCard } from "@polymesh/broker";
import { PolyMeshClient } from "@polymesh/client";

const brokers: Broker[] = [];
const clients: PolyMeshClient[] = [];

afterEach(async () => {
  for (const client of clients.splice(0)) client.close();
  await Promise.all(brokers.splice(0).map((broker) => broker.close()));
});

describe("WebSocket transport", () => {
  it("uses the polymesh.0.1 subprotocol and routes a task through an OS-assigned port", async () => {
    const broker = new Broker({ port: 0, host: "127.0.0.1", token: "websocket-token" });
    brokers.push(broker);
    await broker.start();
    const alice = new PolyMeshClient({ card: createAgentCard({ agent_id: "alice" }), url: broker.url, token: "websocket-token" });
    const bob = new PolyMeshClient({
      card: createAgentCard({ agent_id: "bob", capabilities: [{ id: "org.example.add", version: "1.0.0" }] }),
      url: broker.url,
      token: "websocket-token",
      handlers: { "org.example.add": ({ left, right }) => ({ sum: Number(left) + Number(right) }) },
      authorize: () => true,
    });
    clients.push(alice, bob);

    await Promise.all([alice.connect(), bob.connect()]);
    await expect(alice.call("bob", "org.example.add", { left: 2, right: 3 })).resolves.toEqual({ sum: 5 });
  });

  it("rejects a bad loopback token before the session becomes active", async () => {
    const broker = new Broker({ port: 0, host: "127.0.0.1", token: "right-token" });
    brokers.push(broker);
    await broker.start();
    const client = new PolyMeshClient({ card: createAgentCard({ agent_id: "alice" }), url: broker.url, token: "wrong-token" });
    clients.push(client);

    await expect(client.connect()).rejects.toMatchObject({ code: "TRANSPORT_CLOSED" });
    expect(client.connected).toBe(false);
  });
});

import { afterEach, describe, expect, it } from "vitest";

import {
  Broker,
  V2_PROFILE,
  createAgentCard,
  createWirePair,
  generateRuntimeToken,
  isUuidV7,
  uuidv7,
} from "@latticeag/polymesh-broker";
import { PolyMeshClient } from "@latticeag/polymesh-client";

const brokers: Broker[] = [];

afterEach(async () => {
  await Promise.all(brokers.splice(0).map((broker) => broker.close()));
});

function collect(wire: ReturnType<typeof createWirePair>[0]): unknown[] {
  const frames: unknown[] = [];
  wire.on("message", (data) => frames.push(JSON.parse(data)));
  return frames;
}

async function eventually<T>(read: () => T | undefined, message: string): Promise<T> {
  const deadline = Date.now() + 1_000;
  while (Date.now() < deadline) {
    const value = read();
    if (value !== undefined) return value;
    await new Promise<void>((resolve) => setTimeout(resolve, 1));
  }
  throw new Error(message);
}

describe("Broker native polymesh.0.2 profile", () => {
  it("connects the native TypeScript client without a legacy downgrade", async () => {
    const token = generateRuntimeToken();
    const broker = new Broker({ token, allowZstdCompression: false });
    brokers.push(broker);
    const client = new PolyMeshClient({
      card: createAgentCard({ agent_id: "com.example.native-client" }),
      profile: V2_PROFILE,
      compression: ["none"],
    });
    const [clientWire, brokerWire] = createWirePair();
    const brokerFrames = collect(clientWire);
    const clientFrames = collect(brokerWire);
    broker.attach(brokerWire, { token, profile: "native-v2" });
    try {
      const connecting = client.connectTransport(clientWire);
      await eventually(
        () => client.connected ? true : undefined,
        `native client did not become ready; broker=${JSON.stringify(brokerFrames)} client=${JSON.stringify(clientFrames)}`,
      );
      await connecting;
      expect(client.connected).toBe(true);
      const result = await Promise.race([
        client.call("org.polymesh.broker", "org.polymesh.agent.ping", {}),
        new Promise<never>((_, reject) => setTimeout(() => reject(new Error(
          `native broker/client call did not settle; broker=${JSON.stringify(brokerFrames)} client=${JSON.stringify(clientFrames)}`,
        )), 1_000)),
      ]);
      expect(result).toEqual({});
    } finally {
      client.close();
    }
  });

  it("selects a broker UUIDv7 mesh and completes a native standard task", async () => {
    const token = generateRuntimeToken();
    const broker = new Broker({ token, allowZstdCompression: false });
    brokers.push(broker);
    const [clientWire, brokerWire] = createWirePair();
    const frames = collect(clientWire);
    const card = createAgentCard({ agent_id: "com.example.native" });
    broker.attach(brokerWire, { token, profile: "native-v2" });

    clientWire.send(JSON.stringify({
      type: "v2.init",
      protocol: V2_PROFILE,
      profile: V2_PROFILE,
      agent_id: card.agent_id,
      instance_id: card.instance_id,
      nonce: uuidv7(),
      supported_profiles: [V2_PROFILE],
      compression: ["none"],
    }));

    const ack = await eventually(() => frames.find((frame): frame is Record<string, unknown> =>
      typeof frame === "object" && frame !== null && (frame as Record<string, unknown>).type === "v2.ack",
    ), "native v2 ack was not received");
    expect(ack.profile).toBe(V2_PROFILE);
    expect(ack.compression).toBe("none");
    expect(isUuidV7(ack.mesh_id)).toBe(true);
    expect(isUuidV7(ack.session_id)).toBe(true);
    expect(ack.mesh_id).toBe(broker.nativeMeshId);

    const taskId = uuidv7();
    const messageId = uuidv7();
    const deadline = new Date(Date.now() + 10_000).toISOString();
    clientWire.send(JSON.stringify({
      protocol: V2_PROFILE,
      profile: V2_PROFILE,
      mesh_id: ack.mesh_id,
      type: "task.submit",
      message_id: messageId,
      timestamp: new Date().toISOString(),
      source: { agent_id: card.agent_id, instance_id: card.instance_id },
      target: { agent_id: "org.polymesh.broker" },
      delivery: {
        delivery_id: uuidv7(),
        mode: "at_least_once",
        idempotency_key: `submit:${taskId}`,
        deadline,
      },
      params: {
        task_id: taskId,
        capability: "org.polymesh.agent.ping",
        input: {},
        deadline,
      },
    }));

    const accepted = await eventually(() => frames.find((frame): frame is Record<string, unknown> =>
      typeof frame === "object" && frame !== null && (frame as Record<string, unknown>).type === "task.accepted",
    ), "native task.accepted was not received");
    expect(accepted.in_reply_to).toBe(messageId);
    const completed = await eventually(() => frames.find((frame): frame is Record<string, unknown> =>
      typeof frame === "object" && frame !== null && (frame as Record<string, unknown>).type === "task.completed",
    ), "native task.completed was not received");
    expect((completed.params as Record<string, unknown>).task_id).toBe(taskId);
    expect((completed.params as Record<string, unknown>).terminal).toMatchObject({ outcome: "succeeded", result: {} });
  });

  it("returns a mesh-scoped native handshake error before session activation", async () => {
    const token = generateRuntimeToken();
    const broker = new Broker({ token });
    brokers.push(broker);
    const [clientWire, brokerWire] = createWirePair();
    const frames = collect(clientWire);
    broker.attach(brokerWire, { token, profile: "native-v2" });
    clientWire.send(JSON.stringify({ type: "v2.init", profile: "not-polymesh" }));

    const error = await eventually(() => frames.find((frame): frame is Record<string, unknown> =>
      typeof frame === "object" && frame !== null && (frame as Record<string, unknown>).type === "v2.error",
    ), "native v2 error was not received");
    expect(error.profile).toBe(V2_PROFILE);
    expect(error.code).toBe("PMX.SESSION.HANDSHAKE");
    expect(error.mesh_id).toBe(broker.nativeMeshId);
  });
});

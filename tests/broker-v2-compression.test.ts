import { afterEach, describe, expect, it } from "vitest";

// zstd is unavailable on Node < 22.  The describe block skips itself when the
// runtime codec is absent so the suite is not restricted to a specific version.
const zstdAvailable: boolean = (() => {
  try {
    const zlib = require("node:zlib") as {
      zstdCompressSync?: (input: Uint8Array) => Uint8Array;
    };
    return typeof zlib.zstdCompressSync === "function";
  } catch {
    return false;
  }
})();

import {
  Broker,
  InMemoryDurableStore,
  V2_HANDSHAKE_VERSION,
  V2_PROTOCOL_VERSION,
  capabilityContractTuple,
  cardDigest,
  createAgentCard,
  createWirePair,
  deriveV2SessionId,
  generateRuntimeToken,
  randomNonce,
  uuidv7,
  type AgentCard,
  type Capability,
} from "@polymesh/broker";

const brokers: Broker[] = [];
const meshId = "msh-compression-wire";
const echo: Capability = { id: "org.example.echo", version: "1.0.0" };
const compressionLimits = {
  maxCompressedBytes: 64 * 1024,
  maxUncompressedBytes: 64 * 1024,
  maxExpansionRatio: 16,
} as const;

type JsonRecord = Record<string, unknown>;

afterEach(async () => {
  await Promise.all(brokers.splice(0).map((broker) => broker.close()));
});

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function eventually<T>(read: () => T | undefined | Promise<T | undefined>, message: string): Promise<T> {
  const until = Date.now() + 1_000;
  while (Date.now() < until) {
    const value = await read();
    if (value !== undefined) return value;
    await new Promise<void>((resolve) => setTimeout(resolve, 1));
  }
  throw new Error(message);
}

function collect(wire: ReturnType<typeof createWirePair>[0]): unknown[] {
  const frames: unknown[] = [];
  wire.on("message", (data) => frames.push(JSON.parse(data)));
  return frames;
}

async function connectV2(
  wire: ReturnType<typeof createWirePair>[0],
  frames: unknown[],
  card: AgentCard,
): Promise<void> {
  const nonce = randomNonce();
  wire.send(JSON.stringify({
    type: "hello",
    v: V2_HANDSHAKE_VERSION,
    role: "initiator",
    agent_id: card.agent_id,
    instance_id: card.instance_id,
    nonce,
    mesh_id: meshId,
  }));
  const responder = await eventually(() => frames.find((frame): frame is JsonRecord =>
    isRecord(frame) && frame.type === "hello" && frame.v === V2_HANDSHAKE_VERSION,
  ), "v0.2 responder hello was not received");
  const responderNonce = String(responder.nonce);
  const sid = deriveV2SessionId(nonce, responderNonce);
  expect(responder.sid).toBe(sid);
  wire.send(JSON.stringify({
    type: "card",
    sid,
    for_nonce: responderNonce,
    digest: cardDigest(card),
    card,
  }));
  const brokerCard = await eventually(() => frames.find((frame): frame is JsonRecord =>
    isRecord(frame) && frame.type === "card",
  ), "broker Card was not received");
  wire.send(JSON.stringify({
    type: "ready",
    sid,
    self_card: cardDigest(card),
    peer_card: String(brokerCard.digest),
  }));
  await eventually(() => frames.find((frame): frame is JsonRecord =>
    isRecord(frame) && frame.type === "ready",
  ), "v0.2 ready was not received");
}

function zstdOffer(): JsonRecord {
  return {
    type: "compression.offer",
    v: V2_HANDSHAKE_VERSION,
    algorithms: ["none", "zstd"],
    limits: compressionLimits,
  };
}

async function negotiateZstd(
  wire: ReturnType<typeof createWirePair>[0],
  frames: unknown[],
): Promise<JsonRecord> {
  const start = frames.length;
  wire.send(JSON.stringify(zstdOffer()));
  const selected = await eventually(() => frames.slice(start).find((frame): frame is JsonRecord =>
    isRecord(frame) && frame.type === "compression.selected" && frame.algorithm === "zstd",
  ), "broker did not select zstd after the READY boundary");
  expect(selected.v).toBe(V2_HANDSHAKE_VERSION);
  expect(selected.limits).toEqual(compressionLimits);
  return selected;
}

// zstd runtime — resolved lazily so the file can be loaded on Node < 22 where
// zstdCompressSync is absent.  The describe block skips itself unconditionally
// when the codec is unavailable.
function zstdCompressSync(input: Uint8Array): Uint8Array {
  return require("node:zlib").zstdCompressSync(input);
}
function zstdDecompressSync(input: Uint8Array): Uint8Array {
  return require("node:zlib").zstdDecompressSync(input);
}

function zstdFrame(recordType: string, record: unknown): JsonRecord {
  const uncompressed = Buffer.from(JSON.stringify(record), "utf8");
  const payload = zstdCompressSync(uncompressed);
  return {
    type: "compression.frame",
    v: V2_HANDSHAKE_VERSION,
    algorithm: "zstd",
    record_type: recordType,
    compressed_bytes: payload.byteLength,
    uncompressed_bytes: uncompressed.byteLength,
    payload: payload.toString("base64url"),
  };
}

function decodeZstdFrame(frame: JsonRecord): JsonRecord {
  if (frame.type !== "compression.frame" || typeof frame.payload !== "string") {
    throw new TypeError("Expected a compressed v0.2 transport record");
  }
  const compressed = Buffer.from(frame.payload, "base64url");
  if (compressed.byteLength !== frame.compressed_bytes) {
    throw new TypeError("Compressed frame byte count is not bound to its payload");
  }
  const decoded = zstdDecompressSync(compressed);
  if (decoded.byteLength !== frame.uncompressed_bytes) {
    throw new TypeError("Compressed frame uncompressed byte count is not bound to its payload");
  }
  const record: unknown = JSON.parse(decoded.toString("utf8"));
  if (!isRecord(record)) throw new TypeError("Compressed payload was not a JSON object");
  return record;
}

function applicationRecords(frames: readonly unknown[]): JsonRecord[] {
  const records: JsonRecord[] = [];
  for (const frame of frames) {
    if (!isRecord(frame)) continue;
    if (frame.protocol === V2_PROTOCOL_VERSION) {
      records.push(frame);
    } else if (frame.type === "compression.frame") {
      records.push(decodeZstdFrame(frame));
    }
  }
  return records;
}

describe("Broker v0.2 zstd transport integration", () => {
  (zstdAvailable ? it : it.skip)("selects zstd post-READY, accepts a compressed submit, and delivers a compressed envelope", async () => {
    const token = generateRuntimeToken();
    const store = new InMemoryDurableStore();
    const broker = new Broker({
      token,
      meshId,
      multiInstanceRouting: true,
      allowInsecureMultiInstanceDevelopment: true,
      durableStore: store,
      durableNodeId: "compression-wire-node",
      compressionOffer: { algorithms: ["none", "zstd"], limits: compressionLimits },
      allowZstdCompression: true,
    });
    brokers.push(broker);

    const sourceCard = createAgentCard({ agent_id: "com.example.compressed-source" });
    const targetCard = createAgentCard({ agent_id: "com.example.compressed-target", capabilities: [echo] });
    const [sourceWire, brokerSourceWire] = createWirePair();
    const [targetWire, brokerTargetWire] = createWirePair();
    const sourceFrames = collect(sourceWire);
    const targetFrames = collect(targetWire);
    broker.attach(brokerSourceWire, { token, profile: "v2" });
    broker.attach(brokerTargetWire, { token, profile: "v2" });

    await Promise.all([
      connectV2(sourceWire, sourceFrames, sourceCard),
      connectV2(targetWire, targetFrames, targetCard),
    ]);
    await Promise.all([
      negotiateZstd(sourceWire, sourceFrames),
      negotiateZstd(targetWire, targetFrames),
    ]);

    const taskId = uuidv7();
    const messageId = uuidv7();
    const deadline = new Date(Date.now() + 10_000).toISOString();
    const contract = capabilityContractTuple(echo);
    const submit = {
      protocol: V2_PROTOCOL_VERSION,
      type: "task.submit",
      message_id: messageId,
      timestamp: new Date().toISOString(),
      source: { mesh_id: meshId, agent_id: sourceCard.agent_id, instance_id: sourceCard.instance_id },
      target: { mesh_id: meshId, agent_id: targetCard.agent_id },
      delivery: { mode: "at_least_once", idempotency_key: "zstd-submit", deadline },
      params: {
        task_id: taskId,
        method: echo.id,
        capability_version: contract.capability_version,
        capability_contract_digest: contract.capability_contract_digest,
        params: {},
        deadline,
      },
    };
    sourceWire.send(JSON.stringify(zstdFrame("task.submit", submit)));

    const stored = await eventually(() => sourceFrames.find((frame): frame is JsonRecord =>
      isRecord(frame) && frame.type === "delivery.receipt" && frame.state === "stored",
    ), "compressed ingress did not receive an uncompressed stored receipt");
    expect(stored.message_id).toBe(messageId);
    expect(sourceFrames.some((frame) => isRecord(frame) && frame.type === "compression.frame" && frame.record_type === "delivery.receipt")).toBe(false);

    const deliveredFrame = await eventually(() => targetFrames.find((frame): frame is JsonRecord =>
      isRecord(frame) && frame.type === "compression.frame" && frame.record_type === "task.submit",
    ), "durable task was not delivered through a zstd frame");
    expect(deliveredFrame.algorithm).toBe("zstd");
    const delivered = decodeZstdFrame(deliveredFrame);
    expect(delivered).toMatchObject({
      protocol: V2_PROTOCOL_VERSION,
      type: "task.submit",
      message_id: messageId,
      target: {
        mesh_id: meshId,
        agent_id: targetCard.agent_id,
        instance_id: targetCard.instance_id,
      },
    });
    expect(delivered.delivery_id).toBe(stored.delivery_id);
    if (typeof delivered.delivery_id !== "string") throw new Error("delivered v0.2 task has no broker delivery_id");
    await expect(store.getOutbox(delivered.delivery_id)).resolves.toMatchObject({ state: "SENT_AWAITING_RECEIPT" });
  });

  (zstdAvailable ? it : it.skip)("rejects a compressed delivery receipt without settling its outbox record", async () => {
    const token = generateRuntimeToken();
    const store = new InMemoryDurableStore();
    const broker = new Broker({
      token,
      meshId,
      multiInstanceRouting: true,
      allowInsecureMultiInstanceDevelopment: true,
      durableStore: store,
      durableNodeId: "compression-receipt-node",
      compressionOffer: { algorithms: ["none", "zstd"], limits: compressionLimits },
      allowZstdCompression: true,
    });
    brokers.push(broker);

    const sourceCard = createAgentCard({ agent_id: "com.example.receipt-source" });
    const targetCard = createAgentCard({ agent_id: "com.example.receipt-target", capabilities: [echo] });
    const [sourceWire, brokerSourceWire] = createWirePair();
    const [targetWire, brokerTargetWire] = createWirePair();
    const sourceFrames = collect(sourceWire);
    const targetFrames = collect(targetWire);
    broker.attach(brokerSourceWire, { token, profile: "v2" });
    broker.attach(brokerTargetWire, { token, profile: "v2" });
    await Promise.all([
      connectV2(sourceWire, sourceFrames, sourceCard),
      connectV2(targetWire, targetFrames, targetCard),
    ]);
    await Promise.all([
      negotiateZstd(sourceWire, sourceFrames),
      negotiateZstd(targetWire, targetFrames),
    ]);

    const taskId = uuidv7();
    const messageId = uuidv7();
    const deadline = new Date(Date.now() + 10_000).toISOString();
    const contract = capabilityContractTuple(echo);
    sourceWire.send(JSON.stringify(zstdFrame("task.submit", {
      protocol: V2_PROTOCOL_VERSION,
      type: "task.submit",
      message_id: messageId,
      timestamp: new Date().toISOString(),
      source: { mesh_id: meshId, agent_id: sourceCard.agent_id, instance_id: sourceCard.instance_id },
      target: { mesh_id: meshId, agent_id: targetCard.agent_id },
      delivery: { mode: "at_least_once", idempotency_key: "compressed-receipt-submit", deadline },
      params: {
        task_id: taskId,
        method: echo.id,
        capability_version: contract.capability_version,
        capability_contract_digest: contract.capability_contract_digest,
        params: {},
        deadline,
      },
    })));

    const deliveredFrame = await eventually(() => targetFrames.find((frame): frame is JsonRecord =>
      isRecord(frame) && frame.type === "compression.frame" && frame.record_type === "task.submit",
    ), "target did not receive the compressed v0.2 task");
    const delivered = decodeZstdFrame(deliveredFrame);
    const deliveryId = delivered.delivery_id;
    if (typeof deliveryId !== "string") throw new Error("delivered v0.2 task has no broker delivery_id");
    await expect(store.getOutbox(deliveryId)).resolves.toMatchObject({ state: "SENT_AWAITING_RECEIPT" });

    targetWire.send(JSON.stringify(zstdFrame("delivery.receipt", {
      type: "delivery.receipt",
      v: V2_HANDSHAKE_VERSION,
      delivery_id: deliveryId,
      message_id: messageId,
      state: "stored",
    })));
    const error = await eventually(() => applicationRecords(targetFrames).find((record) =>
      record.type === "error" && isRecord(record.params) && record.params.code === "COMPRESSION_FORBIDDEN_RECORD",
    ), "broker did not reject compressed delivery receipt");
    expect((error.params as JsonRecord).code).toBe("COMPRESSION_FORBIDDEN_RECORD");
    await expect(store.getOutbox(deliveryId)).resolves.toMatchObject({ state: "SENT_AWAITING_RECEIPT" });

    // A normal transport receipt remains valid after the rejected compressed
    // wrapper and is the only action that may settle the durable outbox row.
    targetWire.send(JSON.stringify({
      type: "delivery.receipt",
      v: V2_HANDSHAKE_VERSION,
      delivery_id: deliveryId,
      message_id: messageId,
      state: "stored",
    }));
    await eventually(async () => {
      const outbox = await store.getOutbox(deliveryId);
      return outbox?.state === "DELIVERED" ? outbox : undefined;
    }, "uncompressed delivery receipt did not settle durable outbox");
  });
});

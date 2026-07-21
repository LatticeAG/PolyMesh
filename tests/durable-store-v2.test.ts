import { describe, expect, it } from "vitest";

import { SqliteV2DurableStore, V2DurableConflictError } from "../packages/broker/src/durable-store-v2.js";
import { uuidv7 } from "../packages/broker/src/protocol.js";

describe("native v2 durable store", () => {
  it("atomically persists an envelope and a replayable inbox record", async () => {
    let now = 10_000;
    const store = new SqliteV2DurableStore({ clock: () => now });
    const id = uuidv7(now);
    const meshId = uuidv7(now + 1);
    const envelope = { type: "task.submit", message_id: id, params: { value: "hello" } };

    await expect(store.persistEnvelopeAndInbox({
      id,
      mesh_id: meshId,
      envelope,
      target: "com.example.executor",
    })).resolves.toMatchObject({
      disposition: "stored",
      envelope: { id, mesh_id: meshId, profile: "polymesh.0.2", created_at: now },
      inbox: { target: "com.example.executor", envelope_id: id, status: "pending" },
    });

    const replay = await store.replayInbox({ target: "com.example.executor" });
    expect(replay.deliveries).toHaveLength(1);
    expect(replay.next_cursor).toBe(replay.deliveries[0]!.cursor);
    expect(replay.deliveries[0]!.envelope.envelope).toEqual(envelope);

    now += 1;
    await expect(store.persistEnvelopeAndInbox({
      id,
      mesh_id: meshId,
      envelope,
      target: "com.example.executor",
    })).resolves.toMatchObject({ disposition: "duplicate" });

    await expect(store.markDelivered("com.example.executor", id, now)).resolves.toMatchObject({
      status: "delivered",
      delivered_at: now,
    });
    await expect(store.acknowledgeInbox("com.example.executor", id, now + 1)).resolves.toMatchObject({
      status: "acknowledged",
      delivered_at: now,
    });
    await expect(store.compactAcknowledged(now + 1)).resolves.toBe(1);
    await expect(store.replayInbox({ target: "com.example.executor" })).resolves.toEqual({ deliveries: [] });

    store.close();
  });

  it("rejects an immutable envelope-id collision", async () => {
    const store = new SqliteV2DurableStore();
    const id = uuidv7();
    const meshId = uuidv7();
    await store.persistEnvelopeAndInbox({ id, mesh_id: meshId, envelope: { value: 1 }, target: "a" });

    await expect(store.persistEnvelopeAndInbox({
      id,
      mesh_id: meshId,
      envelope: { value: 2 },
      target: "a",
    })).rejects.toBeInstanceOf(V2DurableConflictError);
    store.close();
  });
});

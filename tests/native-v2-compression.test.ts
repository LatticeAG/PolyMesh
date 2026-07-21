import { describe, expect, it } from "vitest";

import {
  V2_TRANSPORT_FLAG_ZSTD,
  V2ZstdStateMachine,
  decodeV2TransportFrame,
  encodeV2TransportFrame,
} from "../packages/broker/src/compression.js";
import { uuidv7 } from "../packages/broker/src/protocol.js";

describe("native v2 zstd transport", () => {
  it("round-trips known plaintext through the portable zstd codec and length framing", async () => {
    const plaintext = Buffer.from("known plaintext → zstd → known plaintext", "utf8");
    const frame = await encodeV2TransportFrame(plaintext, { compression: "zstd" });

    expect(frame[4]).toBe(V2_TRANSPORT_FLAG_ZSTD);
    const decoded = await decodeV2TransportFrame(frame);
    expect(decoded.compressed).toBe(true);
    expect(Buffer.from(decoded.payload).toString("utf8")).toBe(plaintext.toString("utf8"));
  });

  it("requires propose then mutual ready before a zstd wrapper can carry bytes", async () => {
    const session = { meshId: uuidv7(1), sessionId: uuidv7(2) };
    const initiator = new V2ZstdStateMachine(session, "initiator");
    const responder = new V2ZstdStateMachine(session, "responder");

    const propose = initiator.createPropose();
    responder.receivePropose(propose);
    const responderReady = responder.createReady();
    initiator.receiveReady(responderReady);
    const initiatorReady = initiator.createReady();
    responder.receiveReady(initiatorReady);

    expect(initiator.active).toBe(true);
    expect(responder.active).toBe(true);
    const wrapper = await initiator.wrap(Buffer.from("native v2 payload", "utf8"));
    expect(Buffer.from(await responder.unwrap(wrapper)).toString("utf8")).toBe("native v2 payload");
  });
});

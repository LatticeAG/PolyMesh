import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";
import { deriveV2SessionId as publicDeriveV2SessionId } from "@latticeag/polymesh-broker";

import {
  CARD_VERSION,
  HANDSHAKE_VERSION,
  PROTOCOL_PROFILE_SELECTIONS,
  PROTOCOL_VERSION,
  V2_AGENT_CARD_SCHEMA,
  V2_CARD_VERSION,
  V2_DELIVERY_RECEIPT_SCHEMA,
  V2_HANDSHAKE_SCHEMA,
  V2_HANDSHAKE_VERSION,
  V2_MESH_ID_PATTERN,
  V2_PROTOCOL_VERSION,
  V2_REMOTE_ADDRESSES_SCHEMA,
  V2_SID_DOMAIN,
  V2_SUBPROTOCOL,
  deriveV2SessionId,
  isV2MeshId,
  isV2ProtocolProfile,
  isV2SessionId,
} from "../packages/broker/src/protocol.js";

const meshId = "msh_01J9YJP3QXA73AGWT2J71D8TQR";

describe("v2 wire-format primitives", () => {
  it("keeps v0.1 and v0.2 profile selections disjoint and explicit", () => {
    expect(PROTOCOL_PROFILE_SELECTIONS.v0_1).toEqual({
      protocol: PROTOCOL_VERSION,
      handshake_version: HANDSHAKE_VERSION,
      card_version: CARD_VERSION,
    });
    expect(PROTOCOL_PROFILE_SELECTIONS.v0_2).toEqual({
      protocol: V2_PROTOCOL_VERSION,
      handshake_version: V2_HANDSHAKE_VERSION,
      card_version: V2_CARD_VERSION,
    });
    expect(V2_SUBPROTOCOL).toBe("polymesh.0.2");

    expect(isV2ProtocolProfile(PROTOCOL_PROFILE_SELECTIONS.v0_2)).toBe(true);
    expect(isV2ProtocolProfile({
      protocol: V2_PROTOCOL_VERSION,
      handshake_version: HANDSHAKE_VERSION,
      card_version: V2_CARD_VERSION,
    })).toBe(false);
    expect(isV2ProtocolProfile({
      protocol: PROTOCOL_VERSION,
      handshake_version: V2_HANDSHAKE_VERSION,
      card_version: V2_CARD_VERSION,
    })).toBe(false);
  });

  it("accepts only canonical v2 mesh IDs and requires serialized mesh scope remotely", () => {
    expect(meshId).toHaveLength(30);
    expect(new RegExp(V2_MESH_ID_PATTERN).test(meshId)).toBe(true);
    expect(isV2MeshId(meshId)).toBe(true);
    expect(isV2MeshId("msh_01j9YJP3QXA73AGWT2J71D8TQR")).toBe(false);
    expect(isV2MeshId("msh_01J9YJP3QXA73AGWT2J71D8TQO")).toBe(false);
    expect(isV2MeshId("msh_local")).toBe(false);
    expect(isV2MeshId("msh_01J9YJP3QXA73AGWT2J71D8TQ")).toBe(false);

    expect(V2_REMOTE_ADDRESSES_SCHEMA.$defs.RemoteSourceAddress.required).toEqual([
      "mesh_id", "agent_id", "instance_id",
    ]);
    expect(V2_REMOTE_ADDRESSES_SCHEMA.$defs.RemoteTargetAddress.required).toEqual([
      "mesh_id", "agent_id",
    ]);
    expect(V2_AGENT_CARD_SCHEMA.required).toContain("mesh_id");
    expect(V2_AGENT_CARD_SCHEMA.properties.card_version.const).toBe(V2_CARD_VERSION);
  });

  it("derives a channel-bound 43-character v2 session correlation value", () => {
    const initiatorNonce = Buffer.alloc(32, 0x11).toString("base64url");
    const responderNonce = Buffer.alloc(32, 0x22).toString("base64url");
    const channelBinding = Buffer.alloc(32, 0x33).toString("base64url");
    const sid = deriveV2SessionId(initiatorNonce, responderNonce, channelBinding);
    const expected = createHash("sha256")
      .update(V2_SID_DOMAIN, "utf8")
      .update(Buffer.from(initiatorNonce, "base64url"))
      .update(Buffer.from(responderNonce, "base64url"))
      .update(V2_PROTOCOL_VERSION, "utf8")
      .update(Buffer.from(channelBinding, "base64url"))
      .digest("base64url");

    expect(sid).toBe(expected);
    expect(publicDeriveV2SessionId(initiatorNonce, responderNonce, channelBinding)).toBe(sid);
    expect(sid).toHaveLength(43);
    expect(isV2SessionId(sid)).toBe(true);
    expect(deriveV2SessionId(initiatorNonce, responderNonce, Buffer.alloc(32, 0x34))).not.toBe(sid);
    expect(isV2SessionId("not-a-session-id")).toBe(false);
  });

  it("publishes closed v2 hello and durable delivery-receipt schemas", () => {
    const hello = V2_HANDSHAKE_SCHEMA.$defs.HelloInitiator.allOf[0] as {
      required: readonly string[];
      properties: { profile: { const: string }; v: { const: string } };
    };
    const receipt = V2_HANDSHAKE_SCHEMA.$defs.DeliveryReceipt.allOf[1] as {
      required: readonly string[];
      properties: { type: { const: string }; state: { enum: readonly string[] } };
    };

    expect(hello.required).toEqual(expect.arrayContaining([
      "type", "v", "profile", "role", "agent_id", "instance_id", "nonce",
      "transport_profile", "receive_limits", "extensions",
    ]));
    expect(hello.properties.v.const).toBe(V2_HANDSHAKE_VERSION);
    expect(hello.properties.profile.const).toBe(V2_PROTOCOL_VERSION);
    expect(V2_HANDSHAKE_SCHEMA.$defs.HelloInitiator.unevaluatedProperties).toBe(false);

    expect(receipt.required).toEqual(expect.arrayContaining([
      "sid", "mesh_id", "delivery_id", "message_id", "record_digest", "semantic_digest", "state",
    ]));
    expect(receipt.properties.type.const).toBe("delivery.receipt");
    expect(receipt.properties.state.enum).toEqual(["stored", "duplicate", "rejected"]);
    expect(V2_DELIVERY_RECEIPT_SCHEMA.$id).toBe("https://polymesh.dev/schemas/v2/delivery-receipt.json");
  });
});

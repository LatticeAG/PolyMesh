import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  canonicalize,
  cardDigest,
  createEnvelope,
  deriveSessionId,
  encodeRecordText,
  validateAgentCard,
  validateEnvelope,
  validateHandshakeFrame,
  type AgentCard,
  type AgentIdentity,
  type AgentRef,
  type JsonObject,
  type MessageType,
} from "@latticeag/polymesh-broker/protocol";

type JsonRecord = Record<string, unknown>;

interface EnvelopeVector {
  name: string;
  input: JsonRecord;
  expected: {
    envelope: JsonRecord;
    canonical_json: string;
  };
}

interface EnvelopeVectorsFile {
  profile: string;
  vectors: EnvelopeVector[];
  negative: Array<{ name: string; wire: JsonRecord; accepted: boolean }>;
}

interface CardVector {
  name: string;
  card: JsonRecord;
  expected: {
    digest: string;
    canonical_json: string;
  };
}

interface CardVectorsFile {
  profile: string;
  vectors: CardVector[];
  negative: Array<{ name: string; card: JsonRecord; accepted: boolean }>;
}

interface HandshakeFlowFrame {
  name: string;
  direction: string;
  frame: JsonRecord;
}

interface HandshakeFlow {
  name: string;
  initiator_nonce: string;
  responder_nonce: string;
  expected_session_id: string;
  frames: HandshakeFlowFrame[];
}

interface HandshakeVectorsFile {
  profile: string;
  flows: HandshakeFlow[];
  negative: Array<{ name: string; frame: JsonRecord; accepted: boolean }>;
}

function fixture<T>(name: string): T {
  return JSON.parse(readFileSync(fileURLToPath(new URL(`./${name}`, import.meta.url)), "utf8")) as T;
}

function record(value: unknown, label: string): JsonRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${label} must be a JSON object`);
  }
  return value as JsonRecord;
}

const envelopeVectors = fixture<EnvelopeVectorsFile>("envelope-vectors.json");
const cardVectors = fixture<CardVectorsFile>("card-vectors.json");
const handshakeVectors = fixture<HandshakeVectorsFile>("handshake-vectors.json");
const cardsByName = new Map(cardVectors.vectors.map((vector) => [vector.name, vector]));

function createVectorEnvelope(input: JsonRecord) {
  return createEnvelope({
    type: input.type as MessageType,
    source: input.source as AgentIdentity,
    target: input.target as AgentRef,
    params: input.params as JsonObject,
    idempotency_key: input.idempotency_key as string,
    deadline: input.deadline as string,
    message_id: input.message_id as string,
    timestamp: input.timestamp as string,
  });
}

/** Resolve a card fixture reference without permitting it on the wire. */
function materializeHandshakeFrame(template: JsonRecord): JsonRecord {
  const frame = { ...template };
  const cardName = frame.card_vector;
  if (cardName === undefined) return frame;
  if (typeof cardName !== "string") throw new TypeError("card_vector must name a card fixture");
  const card = cardsByName.get(cardName);
  if (!card) throw new TypeError(`Unknown card fixture: ${cardName}`);
  delete frame.card_vector;
  frame.card = card.card;
  return frame;
}

describe("shared v0.1 compatibility vectors", () => {
  it("declares one advertised wire profile across fixture families", () => {
    expect(envelopeVectors.profile).toBe("polymesh.0.1");
    expect(cardVectors.profile).toBe(envelopeVectors.profile);
    expect(handshakeVectors.profile).toBe(envelopeVectors.profile);
  });

  it.each(envelopeVectors.vectors)("encodes $name exactly", (vector) => {
    const produced = createVectorEnvelope(vector.input);
    expect(produced).toStrictEqual(vector.expected.envelope);
    expect(validateEnvelope(produced).ok).toBe(true);
    expect(encodeRecordText(produced)).toBe(vector.expected.canonical_json);
    expect(encodeRecordText(vector.expected.envelope)).toBe(vector.expected.canonical_json);
  });

  it.each(envelopeVectors.negative)("rejects invalid envelope vector $name", (vector) => {
    expect(validateEnvelope(vector.wire).ok).toBe(vector.accepted);
  });

  it.each(cardVectors.vectors)("matches the $name card digest", (vector) => {
    const validation = validateAgentCard(vector.card);
    expect(validation.ok).toBe(true);
    if (!validation.ok) throw new Error(validation.error);
    expect(cardDigest(validation.value)).toBe(vector.expected.digest);
    expect(canonicalize(validation.value as unknown as JsonObject)).toBe(vector.expected.canonical_json);
  });

  it.each(cardVectors.negative)("rejects invalid card vector $name", (vector) => {
    expect(validateAgentCard(vector.card).ok).toBe(vector.accepted);
  });

  it.each(handshakeVectors.flows)("validates and correlates $name", (flow) => {
    const sid = deriveSessionId(flow.initiator_nonce, flow.responder_nonce);
    expect(sid).toBe(flow.expected_session_id);

    const frames = flow.frames.map(({ frame }) => materializeHandshakeFrame(frame));
    expect(frames.map((frame) => frame.type)).toEqual([
      "hello", "hello", "card", "card", "auth", "auth", "ready", "ready",
    ]);
    for (const frame of frames) {
      expect(validateHandshakeFrame(frame).ok).toBe(true);
      // The shared canonical encoder must accept every record in the flow.
      expect(encodeRecordText(frame)).toBe(canonicalize(frame as JsonObject));
    }

    const initiatorHello = record(frames[0], "initiator hello");
    const responderHello = record(frames[1], "responder hello");
    expect(responderHello.echo).toBe(initiatorHello.nonce);
    expect(responderHello.sid).toBe(sid);

    const cardFrames = frames.slice(2, 4).map((frame) => record(frame, "card frame"));
    for (const frame of cardFrames) {
      expect(frame.sid).toBe(sid);
      const card = record(frame.card, "handshake card") as unknown as AgentCard;
      expect(cardDigest(card)).toBe(frame.digest);
    }

    for (const frame of frames.slice(2)) {
      expect(record(frame, "session frame").sid).toBe(sid);
    }

    const initiatorReady = record(frames[6], "initiator ready");
    const responderReady = record(frames[7], "responder ready");
    expect(initiatorReady.self_card).toBe(cardFrames[0]!.digest);
    expect(initiatorReady.peer_card).toBe(cardFrames[1]!.digest);
    expect(responderReady.self_card).toBe(cardFrames[1]!.digest);
    expect(responderReady.peer_card).toBe(cardFrames[0]!.digest);
  });

  it.each(handshakeVectors.negative)("rejects invalid handshake vector $name", (vector) => {
    expect(validateHandshakeFrame(vector.frame).ok).toBe(vector.accepted);
  });
});

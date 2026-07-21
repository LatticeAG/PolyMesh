#!/usr/bin/env python3
"""Verify released Python and TypeScript artifacts against shared v0.1 vectors.

The script intentionally runs outside both source package directories.  It
maps the installed Python schemas to public declarations in the packed
``@latticeag/polymesh-broker`` tarball, then evaluates every checked-in
envelope, card, and handshake fixture through both installed artifacts.  A
release fails unless each implementation produces the vector's expected wire
bytes, digests, validation decisions, and handshake session IDs.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from importlib import resources
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from polymesh.errors import ProtocolError
from polymesh.protocol import (
    canonical_json,
    card_digest,
    create_envelope,
    derive_session_id,
    encode_record_text,
    validate_envelope,
    validate_handshake_frame,
)
from polymesh.types import AgentCard


class VerificationError(RuntimeError):
    """Raised when a release artifact does not expose the advertised profile."""


SCHEMA_TYPE_BRIDGE = {
    "envelope.json": ("interface Envelope", "function validateEnvelope"),
    "card.json": ("interface AgentCard", "function validateAgentCard", "function cardDigest"),
    "handshake.json": ("type HandshakeFrame", "function validateHandshakeFrame"),
}

VECTOR_FILENAMES = (
    "envelope-vectors.json",
    "card-vectors.json",
    "handshake-vectors.json",
)

NODE_VECTOR_RUNNER = r"""
import fs from "node:fs";
import {
  canonicalize,
  cardDigest,
  createEnvelope,
  deriveSessionId,
  encodeRecordText,
  validateAgentCard,
  validateEnvelope,
  validateHandshakeFrame,
} from "@latticeag/polymesh-broker";

const corpus = JSON.parse(fs.readFileSync(0, "utf8"));
const cardsByName = new Map(corpus.cards.vectors.map((vector) => [vector.name, vector]));

function materializeHandshakeFrame(template) {
  const frame = { ...template };
  const cardName = frame.card_vector;
  if (cardName === undefined) return frame;
  const card = cardsByName.get(cardName);
  if (!card) throw new Error(`Unknown card fixture: ${String(cardName)}`);
  delete frame.card_vector;
  frame.card = card.card;
  return frame;
}

function createVectorEnvelope(input) {
  return createEnvelope({
    type: input.type,
    source: input.source,
    target: input.target,
    params: input.params,
    idempotency_key: input.idempotency_key,
    deadline: input.deadline,
    message_id: input.message_id,
    timestamp: input.timestamp,
  });
}

const envelopes = {
  positive: corpus.envelopes.vectors.map((vector) => {
    const wire = createVectorEnvelope(vector.input);
    return {
      name: vector.name,
      wire,
      canonical: encodeRecordText(wire),
      accepted: validateEnvelope(wire).ok === true,
    };
  }),
  negative: corpus.envelopes.negative.map((vector) => ({
    name: vector.name,
    accepted: validateEnvelope(vector.wire).ok === true,
  })),
};

const cards = {
  positive: corpus.cards.vectors.map((vector) => {
    const validation = validateAgentCard(vector.card);
    return {
      name: vector.name,
      accepted: validation.ok === true,
      digest: validation.ok ? cardDigest(validation.value) : null,
      canonical: validation.ok ? canonicalize(validation.value) : null,
    };
  }),
  negative: corpus.cards.negative.map((vector) => ({
    name: vector.name,
    accepted: validateAgentCard(vector.card).ok === true,
  })),
};

const handshakes = {
  flows: corpus.handshakes.flows.map((flow) => {
    const frames = flow.frames.map(({ frame }) => materializeHandshakeFrame(frame));
    return {
      name: flow.name,
      sid: deriveSessionId(flow.initiator_nonce, flow.responder_nonce),
      frame_types: frames.map((frame) => frame.type),
      frame_accepted: frames.map((frame) => validateHandshakeFrame(frame).ok === true),
      canonical: frames.map((frame) => encodeRecordText(frame)),
      card_digests: frames.slice(2, 4).map((frame) => cardDigest(frame.card)),
    };
  }),
  negative: corpus.handshakes.negative.map((vector) => ({
    name: vector.name,
    accepted: validateHandshakeFrame(vector.frame).ok === true,
  })),
};

process.stdout.write(JSON.stringify({ envelopes, cards, handshakes }));
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--npm-root",
        type=Path,
        required=True,
        help="node_modules directory belonging to the clean npm tarball install",
    )
    parser.add_argument(
        "--vectors-dir",
        type=Path,
        required=True,
        help="directory containing the shared compatibility vector corpus",
    )
    return parser.parse_args()


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"{label} must be a JSON object")
    return value


def require_objects(value: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise VerificationError(f"{label} must be a non-empty JSON array")
    return [require_object(item, f"{label}[{index}]") for index, item in enumerate(value)]


def load_vector_corpus(vectors_dir: Path) -> dict[str, dict[str, Any]]:
    """Load and structurally validate the one shared v0.1 fixture corpus."""

    if not vectors_dir.is_dir():
        raise VerificationError(f"shared vector directory is missing: {vectors_dir}")
    documents: dict[str, dict[str, Any]] = {}
    for filename in VECTOR_FILENAMES:
        path = vectors_dir / filename
        if not path.is_file():
            raise VerificationError(f"required shared vector file is missing: {path}")
        try:
            documents[filename] = require_object(json.loads(path.read_text(encoding="utf-8")), filename)
        except json.JSONDecodeError as exc:
            raise VerificationError(f"invalid JSON in shared vector file {path}: {exc}") from exc

    envelopes = documents["envelope-vectors.json"]
    cards = documents["card-vectors.json"]
    handshakes = documents["handshake-vectors.json"]
    for label, document in (("envelope", envelopes), ("card", cards), ("handshake", handshakes)):
        if document.get("profile") != "polymesh.0.1":
            raise VerificationError(f"{label} vectors do not declare the polymesh.0.1 profile")
    require_objects(envelopes.get("vectors"), "envelope vectors")
    require_objects(envelopes.get("negative"), "negative envelope vectors")
    require_objects(cards.get("vectors"), "card vectors")
    require_objects(cards.get("negative"), "negative card vectors")
    require_objects(handshakes.get("flows"), "handshake flows")
    require_objects(handshakes.get("negative"), "negative handshake vectors")
    return {"envelopes": envelopes, "cards": cards, "handshakes": handshakes}


def verify_packed_type_surface(npm_root: Path) -> None:
    """Link installed Python schemas to declarations published in the npm tarball."""

    declaration = npm_root / "@latticeag" / "polymesh-broker" / "dist" / "protocol.d.ts"
    if not declaration.is_file():
        raise VerificationError(f"packed TypeScript protocol declarations are missing: {declaration}")
    declaration_text = declaration.read_text(encoding="utf-8")

    schema_root = resources.files("polymesh").joinpath("schemas")
    for schema_name, required_declarations in SCHEMA_TYPE_BRIDGE.items():
        try:
            schema = json.loads(schema_root.joinpath(schema_name).read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            raise VerificationError(f"installed Python wheel is missing a valid {schema_name} schema") from exc
        if not isinstance(schema, dict) or not isinstance(schema.get("$id"), str):
            raise VerificationError(f"installed Python schema has no stable $id: {schema_name}")
        missing = [item for item in required_declarations if item not in declaration_text]
        if missing:
            raise VerificationError(
                f"packed TypeScript declarations no longer cover {schema_name}: {', '.join(missing)}"
            )


def materialize_handshake_frame(template: dict[str, Any], cards_by_name: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Resolve a fixture-only card reference before it is sent to a parser."""

    frame = dict(template)
    card_name = frame.pop("card_vector", None)
    if card_name is not None:
        if not isinstance(card_name, str) or card_name not in cards_by_name:
            raise VerificationError("handshake card_vector must name a known card fixture")
        frame["card"] = cards_by_name[card_name]["card"]
    return frame


def vector_envelope(input_value: dict[str, Any]) -> dict[str, Any]:
    """Create one fixed envelope from a vector without generating any fields."""

    try:
        envelope = create_envelope(
            type=input_value["type"],
            source=input_value["source"],
            target=input_value["target"],
            params=input_value["params"],
            idempotency_key=input_value["idempotency_key"],
            deadline=input_value["deadline"],
            message_id=input_value["message_id"],
            timestamp=input_value["timestamp"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise VerificationError("envelope vector input is malformed") from exc
    return envelope.model_dump(mode="json", exclude_none=True)


def accepts_envelope(value: dict[str, Any]) -> bool:
    try:
        validate_envelope(value)
        return True
    except ProtocolError:
        return False


def validate_card(value: dict[str, Any]) -> AgentCard | None:
    try:
        return AgentCard.model_validate(value, context={"polymesh.strict_wire": True})
    except ValidationError:
        return None


def accepts_handshake(value: dict[str, Any]) -> bool:
    try:
        validate_handshake_frame(value)
        return True
    except ProtocolError:
        return False


def expected_results(corpus: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Project fixture expectations into the same normalized result shape."""

    envelope_vectors = require_objects(corpus["envelopes"].get("vectors"), "envelope vectors")
    card_vectors = require_objects(corpus["cards"].get("vectors"), "card vectors")
    cards_by_name = {str(vector["name"]): vector for vector in card_vectors}
    handshake_flows = require_objects(corpus["handshakes"].get("flows"), "handshake flows")

    return {
        "envelopes": {
            "positive": [
                {
                    "name": vector["name"],
                    "wire": require_object(vector["expected"], "envelope expected")["envelope"],
                    "canonical": require_object(vector["expected"], "envelope expected")["canonical_json"],
                    "accepted": True,
                }
                for vector in envelope_vectors
            ],
            "negative": [
                {"name": vector["name"], "accepted": vector["accepted"]}
                for vector in require_objects(corpus["envelopes"].get("negative"), "negative envelope vectors")
            ],
        },
        "cards": {
            "positive": [
                {
                    "name": vector["name"],
                    "accepted": True,
                    "digest": require_object(vector["expected"], "card expected")["digest"],
                    "canonical": require_object(vector["expected"], "card expected")["canonical_json"],
                }
                for vector in card_vectors
            ],
            "negative": [
                {"name": vector["name"], "accepted": vector["accepted"]}
                for vector in require_objects(corpus["cards"].get("negative"), "negative card vectors")
            ],
        },
        "handshakes": {
            "flows": [
                {
                    "name": flow["name"],
                    "sid": flow["expected_session_id"],
                    "frame_types": [frame["frame"]["type"] for frame in require_objects(flow.get("frames"), "handshake frames")],
                    "frame_accepted": [True] * len(require_objects(flow.get("frames"), "handshake frames")),
                    "canonical": [
                        canonical_json(materialize_handshake_frame(require_object(frame["frame"], "handshake frame"), cards_by_name))
                        for frame in require_objects(flow.get("frames"), "handshake frames")
                    ],
                    "card_digests": [
                        materialize_handshake_frame(require_object(frame["frame"], "handshake frame"), cards_by_name)["digest"]
                        for frame in require_objects(flow.get("frames"), "handshake frames")[2:4]
                    ],
                }
                for flow in handshake_flows
            ],
            "negative": [
                {"name": vector["name"], "accepted": vector["accepted"]}
                for vector in require_objects(corpus["handshakes"].get("negative"), "negative handshake vectors")
            ],
        },
    }


def python_results(corpus: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Evaluate every shared vector through the installed Python wheel."""

    envelope_vectors = require_objects(corpus["envelopes"].get("vectors"), "envelope vectors")
    card_vectors = require_objects(corpus["cards"].get("vectors"), "card vectors")
    cards_by_name = {str(vector["name"]): vector for vector in card_vectors}
    handshake_flows = require_objects(corpus["handshakes"].get("flows"), "handshake flows")

    envelope_positive: list[dict[str, Any]] = []
    for vector in envelope_vectors:
        wire = vector_envelope(require_object(vector["input"], "envelope input"))
        envelope_positive.append(
            {
                "name": vector["name"],
                "wire": wire,
                "canonical": encode_record_text(wire),
                "accepted": accepts_envelope(wire),
            }
        )

    card_positive: list[dict[str, Any]] = []
    for vector in card_vectors:
        card = validate_card(require_object(vector["card"], "card vector"))
        card_positive.append(
            {
                "name": vector["name"],
                "accepted": card is not None,
                "digest": card_digest(card) if card is not None else None,
                "canonical": canonical_json(card) if card is not None else None,
            }
        )

    handshake_positive: list[dict[str, Any]] = []
    for flow in handshake_flows:
        frames = [
            materialize_handshake_frame(require_object(item["frame"], "handshake frame"), cards_by_name)
            for item in require_objects(flow.get("frames"), "handshake frames")
        ]
        card_digests = []
        for frame in frames[2:4]:
            card = validate_card(require_object(frame["card"], "handshake card"))
            card_digests.append(card_digest(card) if card is not None else None)
        handshake_positive.append(
            {
                "name": flow["name"],
                "sid": derive_session_id(flow["initiator_nonce"], flow["responder_nonce"]),
                "frame_types": [frame["type"] for frame in frames],
                "frame_accepted": [accepts_handshake(frame) for frame in frames],
                "canonical": [encode_record_text(frame) for frame in frames],
                "card_digests": card_digests,
            }
        )

    return {
        "envelopes": {
            "positive": envelope_positive,
            "negative": [
                {"name": vector["name"], "accepted": accepts_envelope(require_object(vector["wire"], "negative envelope"))}
                for vector in require_objects(corpus["envelopes"].get("negative"), "negative envelope vectors")
            ],
        },
        "cards": {
            "positive": card_positive,
            "negative": [
                {"name": vector["name"], "accepted": validate_card(require_object(vector["card"], "negative card")) is not None}
                for vector in require_objects(corpus["cards"].get("negative"), "negative card vectors")
            ],
        },
        "handshakes": {
            "flows": handshake_positive,
            "negative": [
                {"name": vector["name"], "accepted": accepts_handshake(require_object(vector["frame"], "negative handshake"))}
                for vector in require_objects(corpus["handshakes"].get("negative"), "negative handshake vectors")
            ],
        },
    }


def typescript_results(npm_root: Path, corpus: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Evaluate the same corpus through the packed npm artifact, not source files."""

    process = subprocess.run(
        ["node", "--input-type=module", "--eval", NODE_VECTOR_RUNNER],
        cwd=npm_root.parent,
        input=json.dumps(corpus, ensure_ascii=False),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        detail = process.stderr.strip() or process.stdout.strip() or "Node vector runner failed without output"
        raise VerificationError(f"packed TypeScript artifact could not run shared vectors: {detail}")
    try:
        result = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise VerificationError("packed TypeScript vector runner did not return JSON") from exc
    return require_object(result, "packed TypeScript vector result")


def assert_equal(label: str, actual: dict[str, Any], expected: dict[str, Any]) -> None:
    if actual != expected:
        raise VerificationError(
            f"{label} disagrees with the shared vector corpus\n"
            f"Expected: {json.dumps(expected, ensure_ascii=False, sort_keys=True)}\n"
            f"Actual: {json.dumps(actual, ensure_ascii=False, sort_keys=True)}"
        )


def main() -> int:
    args = parse_args()
    corpus = load_vector_corpus(args.vectors_dir)
    verify_packed_type_surface(args.npm_root)
    expected = expected_results(corpus)
    python_actual = python_results(corpus)
    typescript_actual = typescript_results(args.npm_root, corpus)
    assert_equal("installed Python wheel", python_actual, expected)
    assert_equal("packed TypeScript tarball", typescript_actual, expected)
    assert_equal("published Python and TypeScript artifacts", typescript_actual, python_actual)
    print("cross-language packaged vector verification passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as exc:
        print(f"cross-language packaged vector verification failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

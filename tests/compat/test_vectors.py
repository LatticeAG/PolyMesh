"""Shared v0.1 fixture consumers.

The TypeScript companion lives beside these JSON documents.  Keep every
expected byte/string assertion here: the fixtures are the compatibility
contract, not language-specific snapshots.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
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


COMPAT_DIR = Path(__file__).parent


def _fixture(name: str) -> dict[str, Any]:
    return json.loads((COMPAT_DIR / name).read_text(encoding="utf-8"))


ENVELOPE_VECTORS = _fixture("envelope-vectors.json")
CARD_VECTORS = _fixture("card-vectors.json")
HANDSHAKE_VECTORS = _fixture("handshake-vectors.json")
CARDS_BY_NAME = {vector["name"]: vector for vector in CARD_VECTORS["vectors"]}


def _create_vector_envelope(input_value: dict[str, Any]) -> Any:
    return create_envelope(
        type=input_value["type"],
        source=input_value["source"],
        target=input_value["target"],
        params=input_value["params"],
        idempotency_key=input_value["idempotency_key"],
        deadline=input_value["deadline"],
        message_id=input_value["message_id"],
        timestamp=input_value["timestamp"],
    )


def _materialize_handshake_frame(template: dict[str, Any]) -> dict[str, Any]:
    """Resolve a fixture-only card reference before it reaches the parser."""

    frame = dict(template)
    card_name = frame.pop("card_vector", None)
    if card_name is not None:
        assert isinstance(card_name, str)
        frame["card"] = CARDS_BY_NAME[card_name]["card"]
    return frame


def test_fixture_families_declare_one_profile() -> None:
    assert ENVELOPE_VECTORS["profile"] == "polymesh.0.1"
    assert CARD_VECTORS["profile"] == ENVELOPE_VECTORS["profile"]
    assert HANDSHAKE_VECTORS["profile"] == ENVELOPE_VECTORS["profile"]


@pytest.mark.parametrize("vector", ENVELOPE_VECTORS["vectors"], ids=lambda item: item["name"])
def test_envelope_vectors_encode_exactly(vector: dict[str, Any]) -> None:
    produced = _create_vector_envelope(vector["input"])
    expected = vector["expected"]
    wire = produced.model_dump(mode="json", exclude_none=True)

    assert wire == expected["envelope"]
    assert validate_envelope(wire).model_dump(mode="json", exclude_none=True) == expected["envelope"]
    assert encode_record_text(produced) == expected["canonical_json"]
    assert encode_record_text(expected["envelope"]) == expected["canonical_json"]


@pytest.mark.parametrize("vector", ENVELOPE_VECTORS["negative"], ids=lambda item: item["name"])
def test_negative_envelope_vectors_are_rejected(vector: dict[str, Any]) -> None:
    assert vector["accepted"] is False
    with pytest.raises(ProtocolError):
        validate_envelope(vector["wire"])


@pytest.mark.parametrize("vector", CARD_VECTORS["vectors"], ids=lambda item: item["name"])
def test_card_vectors_match_known_digests(vector: dict[str, Any]) -> None:
    card = AgentCard.model_validate(vector["card"], context={"polymesh.strict_wire": True})
    expected = vector["expected"]

    assert card_digest(card) == expected["digest"]
    assert canonical_json(card) == expected["canonical_json"]


@pytest.mark.parametrize("vector", CARD_VECTORS["negative"], ids=lambda item: item["name"])
def test_negative_card_vectors_are_rejected(vector: dict[str, Any]) -> None:
    assert vector["accepted"] is False
    with pytest.raises(ValidationError):
        AgentCard.model_validate(vector["card"], context={"polymesh.strict_wire": True})


@pytest.mark.parametrize("flow", HANDSHAKE_VECTORS["flows"], ids=lambda item: item["name"])
def test_handshake_flows_validate_and_correlate(flow: dict[str, Any]) -> None:
    sid = derive_session_id(flow["initiator_nonce"], flow["responder_nonce"])
    assert sid == flow["expected_session_id"]

    frames = [_materialize_handshake_frame(item["frame"]) for item in flow["frames"]]
    assert [frame["type"] for frame in frames] == ["hello", "hello", "card", "card", "auth", "auth", "ready", "ready"]
    for frame in frames:
        validate_handshake_frame(frame)
        assert encode_record_text(frame) == canonical_json(frame)

    initiator_hello, responder_hello = frames[0], frames[1]
    assert responder_hello["echo"] == initiator_hello["nonce"]
    assert responder_hello["sid"] == sid

    card_frames = frames[2:4]
    for frame in card_frames:
        assert frame["sid"] == sid
        assert card_digest(AgentCard.model_validate(frame["card"], context={"polymesh.strict_wire": True})) == frame["digest"]

    for frame in frames[2:]:
        assert frame["sid"] == sid

    initiator_ready, responder_ready = frames[6], frames[7]
    assert initiator_ready["self_card"] == card_frames[0]["digest"]
    assert initiator_ready["peer_card"] == card_frames[1]["digest"]
    assert responder_ready["self_card"] == card_frames[1]["digest"]
    assert responder_ready["peer_card"] == card_frames[0]["digest"]


@pytest.mark.parametrize("vector", HANDSHAKE_VECTORS["negative"], ids=lambda item: item["name"])
def test_negative_handshake_vectors_are_rejected(vector: dict[str, Any]) -> None:
    assert vector["accepted"] is False
    with pytest.raises(ProtocolError):
        validate_handshake_frame(vector["frame"])

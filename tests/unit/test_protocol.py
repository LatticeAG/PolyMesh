from __future__ import annotations

import base64
import hashlib

import pytest
from pydantic import ValidationError

from polymesh.errors import (
    AuthenticationError,
    DeliveryError,
    DuplicateMemberError,
    LifecycleError,
    MalformedJsonError,
    ResourceError,
    SchemaValidationError,
    TaskTimeoutError,
    TransportError,
    error_from_structured,
)
from polymesh.protocol import (
    UnixFrameDecoder,
    auth_transcript,
    card_digest,
    canonical_json,
    create_envelope,
    decode_unix_frames,
    derive_session_id,
    encode_record,
    encode_record_text,
    encode_unix_frame,
    envelope_semantic_digest,
    parse_strict_json,
    random_instance_id,
    random_nonce,
    uuidv7,
    validate_envelope,
    validate_handshake_frame,
)
from polymesh.types import (
    AgentCard,
    AgentCardBuilder,
    AgentIdentity,
    AgentRef,
    Capability,
    CapabilityBuilder,
    CardMetadata,
    CardFrame,
    Delivery,
    DeliveryMode,
    Endpoint,
    Envelope,
    InitiatorHello,
    MAX_SAFE_INTEGER,
    ReceiptParams,
    StructuredError,
    ResponderHello,
    SECURE_IDENTITY_PROFILE,
    TaskCancelParams,
    TaskRejectedParams,
    base64url_decode_exact,
    parse_timestamp,
    utc_now_millis,
)


def _identity(agent_id: str) -> AgentIdentity:
    return AgentIdentity(agent_id=agent_id, instance_id=random_instance_id())


def test_strict_json_rejects_duplicate_nonfinite_and_unpaired_unicode() -> None:
    assert parse_strict_json('{"nested":{"ok":[true,null,3]}}') == {"nested": {"ok": [True, None, 3]}}

    with pytest.raises(DuplicateMemberError):
        parse_strict_json('{"a": 1, "a": 2}')
    with pytest.raises(DuplicateMemberError):
        parse_strict_json('{"outer":{"a": 1, "a": 2}}')
    with pytest.raises(MalformedJsonError):
        parse_strict_json('{"number": NaN}')
    with pytest.raises(MalformedJsonError):
        parse_strict_json('{"text": "\\ud800"}')
    with pytest.raises(MalformedJsonError):
        parse_strict_json(b'{"text":"\xff"}')


@pytest.mark.parametrize(
    ("category", "code", "expected"),
    [
        ("resource", "OVERLOADED", ResourceError),
        ("identity", "AUTHORIZATION_DENIED", AuthenticationError),
        ("delivery", "PMX.DELIVERY.MESSAGE_ID_CONFLICT", DeliveryError),
        ("task", "PMX.TASK.EVENT_CONFLICT", LifecycleError),
        ("task", "PMX.TASK.DEADLINE_EXCEEDED", TaskTimeoutError),
        ("protocol", "INSECURE_TRANSPORT_DISABLED", TransportError),
    ],
)
def test_remote_error_code_mapping_preserves_explicit_v01_classes(
    category: str, code: str, expected: type[BaseException]
) -> None:
    error = error_from_structured(category=category, code=code, message="bounded")
    assert isinstance(error, expected)
    assert error.code == code


def test_canonical_json_uses_ecmascript_number_and_utf16_key_order() -> None:
    assert canonical_json({"b": 1.0, "a": [0.000001, 1e21]}) == '{"a":[0.000001,1e+21],"b":1}'

    # U+10000 sorts before U+FFFD in ECMAScript because its first UTF-16 code
    # unit is a high surrogate. Python's ordinary code-point ordering differs.
    assert canonical_json({"\ufffd": 1, "\U00010000": 2}) == '{"\U00010000":2,"\ufffd":1}'

    # JSON.parse in the TypeScript reference stores every number as an
    # IEEE-754 Number. Python must not hash an arbitrary-precision integer
    # differently after strict parsing or outbound canonicalization.
    rounded = parse_strict_json('{"n":9007199254740993}')
    assert canonical_json(rounded) == '{"n":9007199254740992}'
    assert canonical_json({"n": 9007199254740993}) == '{"n":9007199254740992}'


def test_canonical_json_rejects_non_json_python_containers() -> None:
    # Canonicalization is a protocol boundary, not a best-effort serializer:
    # coercing either case changes the security-relevant bytes being hashed.
    with pytest.raises(TypeError):
        canonical_json({1: "not a JSON member name"})
    with pytest.raises(TypeError):
        canonical_json(("not", "a JSON array"))
    with pytest.raises(TypeError):
        canonical_json({"too_large_for_javascript": 10**10_000})


def test_wire_validation_normalizes_safe_integral_json_floats_like_javascript() -> None:
    source = _identity("example.numeric-source")
    ping = create_envelope(
        type="ping",
        source=source,
        target=AgentRef(agent_id="example.numeric-target"),
        params={"n": 1},
    ).model_dump(mode="json", exclude_none=True)
    ping["params"]["n"] = 1.0

    assert validate_envelope(ping).params == {"n": 1}

    card_wire = AgentCardBuilder("example.numeric-card").build().model_dump(mode="json", exclude_none=True)
    card_wire["revision"] = 1.0
    assert AgentCard.model_validate(card_wire).revision == 1

    ping["params"]["n"] = float(MAX_SAFE_INTEGER + 1)
    with pytest.raises(SchemaValidationError):
        validate_envelope(ping)


def test_wire_bounded_strings_use_utf8_bytes_not_python_characters() -> None:
    with pytest.raises(ValidationError):
        Capability(id="org.example.byte-test", version="1.0.0", description="é" * 32_769)
    with pytest.raises(ValidationError):
        Endpoint(transport="websocket", url="ws://example.test/" + "é" * 1_020, scope="loopback")
    with pytest.raises(ValidationError):
        TaskRejectedParams(task_id=uuidv7(), event_seq=1, code="é" * 65, message="rejected")
    with pytest.raises(ValidationError):
        TaskCancelParams(task_id=uuidv7(), reason="é" * 4_097)


def test_strict_wire_null_rules_preserve_only_semantic_json_nulls() -> None:
    source = _identity("example.null-source")
    target = AgentRef(agent_id="example.null-target")
    ping = create_envelope(type="ping", source=source, target=target, params={"n": 1}).model_dump(
        mode="json", exclude_none=True
    )
    ping["in_reply_to"] = None
    with pytest.raises(SchemaValidationError):
        validate_envelope(ping)

    hello = InitiatorHello(
        type="hello",
        role="initiator",
        agent_id="example.null-hello",
        instance_id=random_instance_id(),
        nonce=random_nonce(),
    ).model_dump(mode="json", exclude_none=True)
    hello["security_profile"] = None
    with pytest.raises(SchemaValidationError):
        validate_handshake_frame(hello)

    with pytest.raises(ValidationError):
        create_envelope(
            type="error",
            source=source,
            target=target,
            params={"category": "routing", "code": "TARGET_UNAVAILABLE", "message": "no peer", "retryable": False},
        )
    with pytest.raises(ValidationError):
        create_envelope(
            type="error",
            source=source,
            target=target,
            params={
                "category": "routing",
                "code": "TARGET_UNAVAILABLE",
                "message": "no peer",
                "retryable": False,
                "retry_after_ms": None,
                "details": None,
            },
        )

    error = create_envelope(
        type="error",
        source=source,
        target=target,
        params={
            "category": "routing",
            "code": "TARGET_UNAVAILABLE",
            "message": "no peer",
            "retryable": False,
            "retry_after_ms": None,
        },
    )
    assert error.model_dump(mode="json", exclude_none=True)["params"]["retry_after_ms"] is None
    assert StructuredError(
        category="routing", code="TARGET_UNAVAILABLE", message="no peer", retryable=False
    ).model_dump(mode="json", exclude_none=True)["retry_after_ms"] is None

    task_id = uuidv7()
    completed = create_envelope(
        type="task.completed",
        source=source,
        target=target,
        params={
            "task_id": task_id,
            "event_seq": 2,
            "capability_id": "org.example.null-result",
            "capability_version": "1.0.0",
            "capability_contract_digest": "a" * 64,
            "terminal": {"outcome": "succeeded", "result": None, "completed_at": "2031-01-02T03:04:05.006Z"},
        },
    )
    assert completed.model_dump(mode="json", exclude_none=True)["params"]["terminal"]["result"] is None

    snapshot = create_envelope(
        type="task.status",
        source=source,
        target=target,
        params={
            "kind": "snapshot",
            "task_id": task_id,
            "observed_at": "2031-01-02T03:04:05.006Z",
            "state": None,
            "event_seq": None,
            "terminal": None,
            "progress": None,
        },
    )
    snapshot_params = snapshot.model_dump(mode="json", exclude_none=True)["params"]
    assert {key for key, value in snapshot_params.items() if value is None} == {
        "state",
        "event_seq",
        "terminal",
        "progress",
    }

    card = AgentCardBuilder("example.null-metadata").metadata(CardMetadata.model_validate({"context": None})).build()
    assert card.model_dump(mode="json", exclude_none=True)["metadata"] == {"context": None}
    frame = CardFrame(
        type="card",
        sid=random_nonce(),
        for_nonce=random_nonce(),
        digest=card_digest(card),
        card=card,
    )
    assert validate_handshake_frame(parse_strict_json(encode_record_text(frame))).card.metadata.model_extra == {
        "context": None
    }


def test_uuidv7_layout_and_monotonicity_when_clock_moves_backwards(monkeypatch: pytest.MonkeyPatch) -> None:
    import polymesh.protocol as protocol

    monkeypatch.setattr(protocol, "_last_uuid_ms", -1)
    monkeypatch.setattr(protocol, "_last_uuid_random", 0)
    timestamp = 1_900_000_000_000
    first = uuidv7(timestamp)
    second = uuidv7(timestamp)
    backward = uuidv7(timestamp - 1)

    assert first < second < backward
    for value in (first, second, backward):
        raw = bytes.fromhex(value.replace("-", ""))
        assert int.from_bytes(raw[:6], "big") == timestamp
        assert raw[6] >> 4 == 7
        assert raw[8] >> 6 == 0b10


def test_session_id_derivation_uses_exact_domain_and_nonce_bytes() -> None:
    initiator = base64.urlsafe_b64encode(b"i" * 32).decode().rstrip("=")
    responder = base64.urlsafe_b64encode(b"r" * 32).decode().rstrip("=")
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(b"polymesh.0.1\x00" + b"i" * 32 + b"r" * 32).digest()
    ).decode().rstrip("=")

    assert derive_session_id(initiator, responder) == expected


def test_timestamp_validation_keeps_four_digit_years_before_1000() -> None:
    assert parse_timestamp("0001-01-01T00:00:00.000Z").year == 1


def test_auth_transcript_rejects_non_hex_card_digests() -> None:
    initiator = InitiatorHello(
        type="hello",
        role="initiator",
        agent_id="example.initiator",
        instance_id=random_instance_id(),
        nonce=random_nonce(),
        security_profile=SECURE_IDENTITY_PROFILE,
    )
    responder_nonce = random_nonce()
    responder = ResponderHello(
        type="hello",
        role="responder",
        agent_id="example.responder",
        instance_id=random_instance_id(),
        nonce=responder_nonce,
        echo=initiator.nonce,
        sid=derive_session_id(initiator.nonce, responder_nonce),
        security_profile=SECURE_IDENTITY_PROFILE,
    )

    with pytest.raises(AuthenticationError):
        auth_transcript(
            initiator_hello=initiator,
            responder_hello=responder,
            initiator_card_digest="x" * 64,
            responder_card_digest="a" * 64,
            tls_channel_binding=random_nonce(),
        )


def test_card_builder_and_random_identifier_wire_encoding() -> None:
    instance_id = random_instance_id()
    nonce = random_nonce()
    assert len(instance_id) == 22
    assert len(nonce) == 43
    assert len(base64url_decode_exact(instance_id, 16)) == 16
    assert len(base64url_decode_exact(nonce, 32)) == 32

    card = (
        AgentCardBuilder("example.typed-agent")
        .capability(
            CapabilityBuilder("org.example.echo")
            .schemas(input_schema={"type": "object"}, result_schema={"type": "object"})
            .execution(idempotency="idempotent", side_effects="read")
            .build()
        )
        .build()
    )
    dumped = card.model_dump(mode="json", exclude_none=True)
    assert dumped["card_version"] == "1.0"
    assert {item["id"] for item in dumped["capabilities"]} >= {
        "org.polymesh.agent.ping",
        "org.polymesh.agent.info",
        "org.polymesh.capabilities.list",
        "org.example.echo",
    }
    assert Delivery(mode=DeliveryMode.AT_LEAST_ONCE, idempotency_key="test", deadline="2031-01-02T03:04:05.006Z").mode == DeliveryMode.AT_LEAST_ONCE


def test_envelope_round_trip_and_semantic_digest_ignore_transport_fields() -> None:
    source = _identity("example.owner")
    target = AgentRef(agent_id="example.target")
    task_id = uuidv7()
    deadline = "2031-01-02T03:04:05.006Z"
    envelope = create_envelope(
        type="task.submit",
        source=source,
        target=target,
        deadline=deadline,
        idempotency_key=f"submit:{task_id}",
        params={
            "task_id": task_id,
            "method": "org.example.weather.read",
            "capability_version": "1.2.3",
            "capability_contract_digest": "a" * 64,
            "params": {"city": "London"},
            "deadline": deadline,
        },
    )

    encoded = encode_record_text(envelope)
    decoded = validate_envelope(parse_strict_json(encoded))
    assert decoded == envelope
    assert envelope_semantic_digest(decoded) == envelope_semantic_digest(
        decoded.model_copy(update={"message_id": uuidv7(), "timestamp": utc_now_millis()})
    )

    with pytest.raises(ValidationError):
        Envelope(
            type="task.submit",
            message_id=uuidv7(),
            timestamp=utc_now_millis(),
            source=source,
            target=target,
            delivery=Delivery(mode="at_least_once", idempotency_key="submit:bad", deadline=deadline),
            params={
                "task_id": uuidv7(),
                "method": "org.example.weather.read",
                "capability_version": "1.2.3",
                "capability_contract_digest": "a" * 64,
                "params": {},
                "deadline": "2031-01-02T03:04:05.007Z",
            },
        )


def test_receipt_correlation_and_handshake_card_digest_are_closed_shapes() -> None:
    source = _identity("example.owner")
    target = AgentRef(agent_id="example.target")
    received_message_id = uuidv7()
    with pytest.raises(ValidationError):
        Envelope(
            type="receipt",
            message_id=uuidv7(),
            timestamp=utc_now_millis(),
            source=source,
            target=target,
            delivery=Delivery(
                mode="at_least_once",
                idempotency_key="receipt:bad",
                deadline="2031-01-02T03:04:05.006Z",
            ),
            in_reply_to=uuidv7(),
            params=ReceiptParams(
                received_message_id=received_message_id,
                semantic_digest="b" * 64,
                disposition="accepted",
            ).model_dump(mode="json"),
        )

    card = AgentCardBuilder("example.card").build()
    nonce = random_nonce()
    hello = InitiatorHello(
        type="hello",
        role="initiator",
        agent_id=card.agent_id,
        instance_id=card.instance_id,
        nonce=nonce,
    )
    assert validate_handshake_frame(hello.model_dump(mode="json", exclude_none=True)) == hello

    with pytest.raises(SchemaValidationError):
        validate_handshake_frame({**hello.model_dump(mode="json", exclude_none=True), "extra": True})
    with pytest.raises(ValidationError):
        CardFrame(type="card", sid=random_nonce(), for_nonce=nonce, digest="0" * 64, card=card)


def test_unix_frame_decoder_preserves_partial_stream_records() -> None:
    source = _identity("example.sender")
    envelope = create_envelope(
        type="ping",
        source=source,
        target=AgentRef(agent_id="example.target"),
        params={"n": 7},
    )
    framed = encode_unix_frame(envelope)
    decoder = UnixFrameDecoder()

    assert decode_unix_frames(framed[:3], decoder) == []
    assert decode_unix_frames(framed[3:11], decoder) == []
    assert decode_unix_frames(framed[11:], decoder) == [encode_record(envelope)]
    assert decoder.remainder == b""


@pytest.mark.parametrize(
    "record_type",
    [
        "card",
        "task.accepted",
        "task.rejected",
        "task.progress",
        "task.completed",
        "task.cancel",
        "task.status",
        "ping",
        "pong",
        "receipt",
        "error",
    ],
)
def test_every_non_submission_envelope_shape_encodes_and_decodes(record_type: str) -> None:
    source = _identity("example.source")
    target = AgentRef(agent_id="example.target")
    task_id = uuidv7()
    correlation = uuidv7()
    now = "2031-01-02T03:04:05.006Z"
    contract = {
        "capability_id": "org.example.echo",
        "capability_version": "1.0.0",
        "capability_contract_digest": "c" * 64,
    }
    card = AgentCardBuilder("example.card-record").build()
    params_by_type = {
        "card": {"card": card.model_dump(mode="json", exclude_none=True), "digest": card_digest(card)},
        "task.accepted": {"task_id": task_id, "event_seq": 1, "accepted_at": now, **contract},
        "task.rejected": {"task_id": task_id, "event_seq": 1, "code": "REJECTED", "message": "not now"},
        "task.progress": {"task_id": task_id, "event_seq": 2, "progress": {"state": "running"}},
        "task.completed": {
            "task_id": task_id,
            "event_seq": 2,
            **contract,
            "terminal": {"outcome": "succeeded", "result": {}, "completed_at": now},
        },
        "task.cancel": {"task_id": task_id, "reason": "no longer needed"},
        "task.status": {"kind": "snapshot", "task_id": task_id, "observed_at": now, "state": "running"},
        "ping": {"n": 1},
        "pong": {"n": 1},
        "receipt": {"received_message_id": correlation, "semantic_digest": "d" * 64, "disposition": "accepted"},
        "error": {
            "category": "routing",
            "code": "TARGET_UNAVAILABLE",
            "message": "target unavailable",
            "retryable": True,
            "retry_after_ms": None,
        },
    }
    envelope = create_envelope(
        type=record_type,  # type: ignore[arg-type]
        source=source,
        target=target,
        params=params_by_type[record_type],
        in_reply_to=correlation if record_type == "receipt" else None,
    )

    decoded = validate_envelope(parse_strict_json(encode_record_text(envelope)))
    assert decoded.type == record_type
    assert decoded.params == envelope.params

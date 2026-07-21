"""Strict PolyMesh v0.1 protocol primitives.

The functions in this module form the boundary between an untrusted carrier
record and typed SDK objects.  They intentionally do not perform routing or
task lifecycle authorization; those checks require a live client session.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import re
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

from pydantic import BaseModel, ValidationError

from .errors import (
    AuthenticationError,
    DuplicateMemberError,
    FrameTooLargeError,
    HandshakeError,
    MalformedJsonError,
    ProtocolError,
    ResourceExhaustedError,
    SchemaValidationError,
)
from .types import (
    MAX_FRAME_BYTES,
    MAX_JSON_ARRAY_ITEMS,
    MAX_JSON_DEPTH,
    MAX_JSON_NODES,
    MAX_JSON_OBJECT_MEMBERS,
    MAX_JSON_STRING_BYTES,
    MAX_SAFE_INTEGER,
    PROTOCOL_VERSION,
    V2_HANDSHAKE_VERSION,
    V2_PROTOCOL_VERSION,
    ROUTED_PROVENANCE_VERSION,
    SECURE_IDENTITY_PROFILE,
    AgentCard,
    AgentIdentity,
    AgentRef,
    AuthFrame,
    Capability,
    CapabilityContractTuple,
    CardFrame,
    CardIdentity,
    DeliveryMode,
    Ed25519PublicKey,
    Enrollment,
    Envelope,
    EnvelopeType,
    HandshakeFrame,
    InitiatorHello,
    JsonObject,
    JsonValue,
    ReadyFrame,
    ResponderHello,
    RoutedProvenance,
    VerifiedPrincipal,
    WireModel,
    base64url_decode_exact,
    base64url_encode,
    format_timestamp,
    key_id_from_raw_ed25519_public_key,
    parse_timestamp,
    random_instance_id as _random_instance_id,
    random_nonce as _random_nonce,
    utc_now_millis,
)


try:  # cryptography is a required package dependency, but imports stay clear.
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
except ImportError:  # pragma: no cover - only relevant to deliberately partial installations
    InvalidSignature = Exception  # type: ignore[assignment,misc]
    serialization = None  # type: ignore[assignment]
    Ed25519PrivateKey = Any  # type: ignore[misc,assignment]
    Ed25519PublicKey = Any  # type: ignore[misc,assignment]


@dataclass(frozen=True, slots=True)
class JsonParseLimits:
    max_bytes: int = MAX_FRAME_BYTES
    max_depth: int = MAX_JSON_DEPTH
    max_nodes: int = MAX_JSON_NODES
    max_object_members: int = MAX_JSON_OBJECT_MEMBERS
    max_array_items: int = MAX_JSON_ARRAY_ITEMS
    max_string_bytes: int = MAX_JSON_STRING_BYTES

    def __post_init__(self) -> None:
        for name in (
            "max_bytes",
            "max_depth",
            "max_nodes",
            "max_object_members",
            "max_array_items",
            "max_string_bytes",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


def _limits(
    value: JsonParseLimits | Mapping[str, int] | None = None, *, max_bytes: int | None = None
) -> JsonParseLimits:
    if value is None:
        result = JsonParseLimits()
    elif isinstance(value, JsonParseLimits):
        result = value
    elif isinstance(value, Mapping):
        translated = {
            "max_bytes": value.get("max_bytes", value.get("maxBytes", MAX_FRAME_BYTES)),
            "max_depth": value.get("max_depth", value.get("maxDepth", MAX_JSON_DEPTH)),
            "max_nodes": value.get("max_nodes", value.get("maxNodes", MAX_JSON_NODES)),
            "max_object_members": value.get(
                "max_object_members", value.get("maxObjectMembers", MAX_JSON_OBJECT_MEMBERS)
            ),
            "max_array_items": value.get("max_array_items", value.get("maxArrayItems", MAX_JSON_ARRAY_ITEMS)),
            "max_string_bytes": value.get("max_string_bytes", value.get("maxStringBytes", MAX_JSON_STRING_BYTES)),
        }
        result = JsonParseLimits(**translated)
    else:
        raise TypeError("limits must be JsonParseLimits, a mapping, or None")
    if max_bytes is not None:
        result = JsonParseLimits(
            max_bytes=max_bytes,
            max_depth=result.max_depth,
            max_nodes=result.max_nodes,
            max_object_members=result.max_object_members,
            max_array_items=result.max_array_items,
            max_string_bytes=result.max_string_bytes,
        )
    return result


def _reject_duplicate_members(pairs: Sequence[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateMemberError("duplicate JSON member")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> float:
    raise ValueError(f"non-finite JSON value is forbidden: {value}")


def _parse_ecmascript_integer(value: str) -> int | float:
    """Mirror ``JSON.parse``'s IEEE-754 number boundary for large ints.

    Python's ``json`` parser retains arbitrary precision integers, whereas
    the TypeScript reference has already rounded every JSON number into a
    JavaScript ``Number``.  Preserve ordinary integers for strict Pydantic
    integer fields, but represent out-of-safe-range literals as ``float`` so
    canonicalization and semantic digests agree with the reference.
    """

    parsed = int(value)
    return parsed if -MAX_SAFE_INTEGER <= parsed <= MAX_SAFE_INTEGER else float(value)


def _valid_unicode_scalar_sequence(value: str) -> bool:
    # Python strings can carry unpaired UTF-16 surrogate code points.  They
    # are not Unicode scalar values and cannot appear in a strict wire record.
    return not any(0xD800 <= ord(character) <= 0xDFFF for character in value)


def _require_text_bytes(value: str) -> bytes:
    if not _valid_unicode_scalar_sequence(value):
        raise MalformedJsonError("input contains invalid Unicode")
    try:
        return value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:  # defensive; surrogate check covers it
        raise MalformedJsonError("input contains invalid Unicode") from exc


def validate_json_tree(value: Any, limits: JsonParseLimits | Mapping[str, int] | None = None) -> None:
    """Reject an out-of-budget or non-JSON-compatible object graph.

    This is used for both inbound parsed JSON and outbound objects.  ``active``
    only tracks the current recursion path, so an acyclic object reused in two
    places remains serializable while a true cycle is rejected.
    """

    chosen = _limits(limits)
    nodes = 0
    active: set[int] = set()

    def visit(entry: Any, depth: int) -> None:
        nonlocal nodes
        if depth > chosen.max_depth:
            raise ResourceExhaustedError("JSON nesting depth exceeds the configured limit")
        nodes += 1
        if nodes > chosen.max_nodes:
            raise ResourceExhaustedError("JSON node count exceeds the configured limit")
        if entry is None or isinstance(entry, bool):
            return
        if isinstance(entry, str):
            if not _valid_unicode_scalar_sequence(entry):
                raise MalformedJsonError("JSON string contains an unpaired surrogate")
            if len(_require_text_bytes(entry)) > chosen.max_string_bytes:
                raise ResourceExhaustedError("JSON string exceeds the configured limit")
            return
        if isinstance(entry, (int, float)) and not isinstance(entry, bool):
            if isinstance(entry, float) and not math.isfinite(entry):
                raise MalformedJsonError("non-finite JSON number is forbidden")
            return
        if isinstance(entry, list):
            if len(entry) > chosen.max_array_items:
                raise ResourceExhaustedError("JSON array has too many items")
            object_id = id(entry)
            if object_id in active:
                raise MalformedJsonError("JSON value contains a cycle")
            active.add(object_id)
            try:
                for item in entry:
                    visit(item, depth + 1)
            finally:
                active.remove(object_id)
            return
        if isinstance(entry, dict):
            if len(entry) > chosen.max_object_members:
                raise ResourceExhaustedError("JSON object has too many members")
            object_id = id(entry)
            if object_id in active:
                raise MalformedJsonError("JSON value contains a cycle")
            active.add(object_id)
            try:
                for key, item in entry.items():
                    if not isinstance(key, str):
                        raise MalformedJsonError("JSON object keys must be strings")
                    if not _valid_unicode_scalar_sequence(key):
                        raise MalformedJsonError("JSON object key contains an unpaired surrogate")
                    if len(_require_text_bytes(key)) > chosen.max_string_bytes:
                        raise ResourceExhaustedError("JSON object key exceeds the configured limit")
                    visit(item, depth + 1)
            finally:
                active.remove(object_id)
            return
        raise MalformedJsonError("value is not JSON-compatible")

    visit(value, 1)


def parse_strict_json(
    payload: str | bytes | bytearray | memoryview,
    limits: JsonParseLimits | Mapping[str, int] | None = None,
    *,
    max_bytes: int | None = None,
) -> JsonValue:
    """Parse one complete strict UTF-8 JSON value.

    Default ``json.loads`` accepts duplicate object members and non-finite
    constants.  Both are rejected here before Pydantic receives a value.
    """

    chosen = _limits(limits, max_bytes=max_bytes)
    if isinstance(payload, str):
        raw = _require_text_bytes(payload)
        text = payload
    elif isinstance(payload, (bytes, bytearray, memoryview)):
        raw = bytes(payload)
        try:
            text = raw.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise MalformedJsonError("input is not valid UTF-8") from exc
        if not _valid_unicode_scalar_sequence(text):
            raise MalformedJsonError("input contains invalid Unicode")
    else:
        raise TypeError("payload must be text or bytes")
    if len(raw) > chosen.max_bytes:
        raise ResourceExhaustedError("JSON input exceeds configured byte limit")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_members,
            parse_constant=_reject_nonfinite,
            parse_int=_parse_ecmascript_integer,
        )
    except DuplicateMemberError:
        raise
    except RecursionError as exc:
        raise ResourceExhaustedError("JSON nesting depth exceeds the configured limit") from exc
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise MalformedJsonError("malformed JSON") from exc
    validate_json_tree(value, chosen)
    return value


# Compatibility name used by the TypeScript reference and early Python users.
parse_bounded_json = parse_strict_json


def _normalise_json_value(value: Any) -> JsonValue:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", exclude_none=True)
    if isinstance(value, Mapping):
        # JSON object member names are strings.  Coercing Python keys here
        # would silently change the bytes being hashed (and can collapse
        # distinct keys such as ``1`` and ``"1"``), so canonicalization must
        # fail at the same boundary as strict JSON validation.
        if any(not isinstance(key, str) for key in value):
            raise TypeError("canonical JSON object keys must be strings")
        return {key: _normalise_json_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalise_json_value(item) for item in value]
    if isinstance(value, tuple):
        raise TypeError("canonical JSON does not accept tuples")
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) > MAX_SAFE_INTEGER:
        # A Python arbitrary-precision integer has no exact TypeScript
        # ``number`` counterpart.  Serialize the same rounded IEEE-754 value
        # a peer would have after JSON.parse rather than hashing a byte stream
        # the reference cannot construct.
        try:
            rounded = float(value)
        except OverflowError as exc:
            raise TypeError("canonical JSON integer cannot be represented as a finite JavaScript number") from exc
        if not math.isfinite(rounded):
            raise TypeError("canonical JSON integer cannot be represented as a finite JavaScript number")
        return rounded
    return value


def _quote_string(value: str) -> str:
    # JSON.stringify uses literal non-ASCII scalar characters and the usual
    # short JSON control escapes.  Python's encoder matches that when
    # ensure_ascii=False after surrogate validation.
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _ecmascript_number(value: int | float) -> str:
    """Best-effort ECMAScript/JSON.stringify finite-number spelling.

    CPython and V8 both use shortest round-trip formatting; the observable
    differences are primarily ``1.0``, exponent zero padding, and the fixed
    decimal range [1e-6, 1e21).  The protocol restricts its typed numeric
    fields to safe integers, while this handles arbitrary JSON schema values.
    """

    if isinstance(value, bool):  # bool is a subclass of int
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if not math.isfinite(value):
        raise TypeError("canonical JSON does not allow non-finite numbers")
    if value == 0:
        return "0"
    raw = repr(value)
    # Python's shortest spelling may be fixed or scientific.  Preserve its
    # significant digits, then choose the ECMAScript fixed/scientific range.
    absolute = abs(value)
    if 1e-6 <= absolute < 1e21:
        if "e" in raw.lower():
            fixed = format(Decimal(raw), "f")
        else:
            fixed = raw
        if "." in fixed:
            fixed = fixed.rstrip("0").rstrip(".")
        return fixed
    if "e" not in raw.lower():
        # This is uncommon (large integers arrive as ``int``), but Decimal
        # avoids a lossy ``.15e`` conversion when a float repr is fixed.
        decimal = Decimal(raw).normalize()
        raw = format(decimal, "e")
    mantissa, exponent = raw.lower().split("e", 1)
    if "." in mantissa:
        mantissa = mantissa.rstrip("0").rstrip(".")
    exponent_number = int(exponent)
    sign = "+" if exponent_number >= 0 else "-"
    return f"{mantissa}e{sign}{abs(exponent_number)}"


def canonical_json(value: JsonValue | BaseModel) -> str:
    """Return deterministic JCS-style JSON compatible with the TS helper."""

    normalised = _normalise_json_value(value)
    validate_json_tree(normalised)
    stack: set[int] = set()

    def key_order(key: str) -> bytes:
        # ECMAScript Array.sort compares UTF-16 code units.  Using UTF-16BE
        # makes non-BMP keys agree with Node rather than Python code-point
        # ordering.
        return key.encode("utf-16-be")

    def visit(entry: Any) -> str:
        if entry is None:
            return "null"
        if entry is True:
            return "true"
        if entry is False:
            return "false"
        if isinstance(entry, str):
            return _quote_string(entry)
        if isinstance(entry, (int, float)) and not isinstance(entry, bool):
            return _ecmascript_number(entry)
        if isinstance(entry, list):
            object_id = id(entry)
            if object_id in stack:
                raise TypeError("canonical JSON cannot contain a cycle")
            stack.add(object_id)
            try:
                return "[" + ",".join(visit(item) for item in entry) + "]"
            finally:
                stack.remove(object_id)
        if isinstance(entry, dict):
            object_id = id(entry)
            if object_id in stack:
                raise TypeError("canonical JSON cannot contain a cycle")
            stack.add(object_id)
            try:
                return (
                    "{"
                    + ",".join(_quote_string(key) + ":" + visit(entry[key]) for key in sorted(entry, key=key_order))
                    + "}"
                )
            finally:
                stack.remove(object_id)
        raise TypeError("canonical JSON contains a non-JSON value")

    return visit(normalised)


canonicalize = canonical_json


def encoded_json_bytes(value: JsonValue | BaseModel) -> int:
    return len(canonical_json(value).encode("utf-8"))


def sha256_hex(value: JsonValue | BaseModel | str) -> str:
    text = value if isinstance(value, str) else canonical_json(value)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


sha256 = sha256_hex


_uuid_lock = threading.Lock()
_last_uuid_ms = -1
_last_uuid_random = 0
_MAX_UUID_RANDOM = (1 << 74) - 1


def random_instance_id() -> str:
    """Generate a canonical 16-byte random v0.1 instance ID."""

    return _random_instance_id()


def random_nonce() -> str:
    """Generate a canonical 32-byte random handshake nonce."""

    return _random_nonce()


def uuidv7(now_ms: int | None = None) -> str:
    """Generate a process-monotonic RFC UUIDv7 with the reference bit layout."""

    global _last_uuid_ms, _last_uuid_random
    timestamp = int(time.time() * 1000) if now_ms is None else now_ms
    if not isinstance(timestamp, int) or isinstance(timestamp, bool) or timestamp < 0 or timestamp > 0xFFFF_FFFF_FFFF:
        raise ValueError("UUIDv7 timestamp does not fit in 48 bits")
    with _uuid_lock:
        if timestamp > _last_uuid_ms:
            _last_uuid_ms = timestamp
            _last_uuid_random = int.from_bytes(os.urandom(10), "big") & _MAX_UUID_RANDOM
        elif _last_uuid_random < _MAX_UUID_RANDOM:
            _last_uuid_random += 1
        else:
            _last_uuid_ms += 1
            _last_uuid_random = int.from_bytes(os.urandom(10), "big") & _MAX_UUID_RANDOM
        selected_timestamp = _last_uuid_ms
        random74 = _last_uuid_random
    raw = bytearray(16)
    raw[0:6] = selected_timestamp.to_bytes(6, "big")
    random_a = random74 >> 62
    random_b = random74 & ((1 << 62) - 1)
    raw[6] = 0x70 | (random_a >> 8)
    raw[7] = random_a & 0xFF
    raw[8] = 0x80 | ((random_b >> 56) & 0x3F)
    raw[9:16] = (random_b & ((1 << 56) - 1)).to_bytes(7, "big")
    hex_value = raw.hex()
    return f"{hex_value[0:8]}-{hex_value[8:12]}-{hex_value[12:16]}-{hex_value[16:20]}-{hex_value[20:32]}"


def derive_session_id(initiator_nonce: str, responder_nonce: str) -> str:
    initiator = base64url_decode_exact(initiator_nonce, 32)
    responder = base64url_decode_exact(responder_nonce, 32)
    raw = hashlib.sha256(b"polymesh.0.1\x00" + initiator + responder).digest()
    return base64url_encode(raw)


# v0.2 deliberately keeps a distinct derivation domain.  This helper lives
# next to the legacy derivation rather than replacing it so a caller cannot
# accidentally downgrade or cross-correlate sessions while negotiating a
# profile.
V2_MESH_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
V2_NATIVE_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
V2_NATIVE_AGENT_ID_RE = re.compile(r"^(?:[a-z]|[a-z][a-z0-9._-]*[a-z0-9])$")
V2_NATIVE_INSTANCE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,255}$")
V2_NATIVE_COMPRESSION_ALGORITHMS = frozenset({"zstd", "none"})


def is_v2_native_uuid(value: Any) -> bool:
    """Return whether a compact native-v2 identifier is a lowercase UUIDv7."""

    return isinstance(value, str) and V2_NATIVE_UUID_RE.fullmatch(value) is not None


def _validate_v2_native_identity(value: Any, *, required_instance: bool) -> JsonObject:
    if not isinstance(value, Mapping):
        raise SchemaValidationError("native v0.2 address must be an object")
    allowed = {"agent_id", "instance_id"}
    required = {"agent_id", *( {"instance_id"} if required_instance else set() )}
    if set(value) - allowed or not required.issubset(value):
        raise SchemaValidationError("native v0.2 address has unknown or missing fields")
    agent_id = value.get("agent_id")
    instance_id = value.get("instance_id")
    if not isinstance(agent_id, str) or V2_NATIVE_AGENT_ID_RE.fullmatch(agent_id) is None:
        raise SchemaValidationError("native v0.2 agent_id is invalid")
    if instance_id is not None and (
        not isinstance(instance_id, str) or V2_NATIVE_INSTANCE_ID_RE.fullmatch(instance_id) is None
    ):
        raise SchemaValidationError("native v0.2 instance_id is invalid")
    if "instance_id" in value and instance_id is None:
        raise SchemaValidationError("native v0.2 instance_id must be omitted rather than null")
    result: JsonObject = {"agent_id": agent_id}
    if instance_id is not None:
        result["instance_id"] = instance_id
    return result


def validate_v2_init_frame(value: JsonValue | Mapping[str, Any]) -> JsonObject:
    """Validate the compact native-v2 client profile proposal.

    This is intentionally a separate grammar from the historical v0.2
    ``hello`` frame.  A caller selects one before sending bytes, so a native
    profile proposal cannot be interpreted as a legacy hello extension.
    """

    validate_json_tree(value)
    if not isinstance(value, Mapping):
        raise SchemaValidationError("native v0.2 init must be an object")
    frame = dict(value)
    allowed = {
        "type", "protocol", "profile", "supported_profiles", "mesh_id", "agent_id",
        "instance_id", "nonce", "compression",
    }
    required = {"type", "profile", "agent_id", "instance_id", "nonce"}
    if set(frame) - allowed or not required.issubset(frame) or frame.get("type") != "v2.init":
        raise SchemaValidationError("native v0.2 init has unknown or missing fields")
    if frame.get("protocol") not in {None, V2_PROTOCOL_VERSION} or frame.get("profile") != V2_PROTOCOL_VERSION:
        raise SchemaValidationError("native v0.2 init profile is invalid")
    if "protocol" in frame and frame["protocol"] is None:
        raise SchemaValidationError("native v0.2 init protocol must be omitted rather than null")
    if not is_v2_native_uuid(frame.get("nonce")):
        raise SchemaValidationError("native v0.2 init nonce must be UUIDv7")
    identity = _validate_v2_native_identity(
        {"agent_id": frame.get("agent_id"), "instance_id": frame.get("instance_id")}, required_instance=True
    )
    if "mesh_id" in frame and not is_v2_native_uuid(frame["mesh_id"]):
        raise SchemaValidationError("native v0.2 init mesh_id must be UUIDv7")
    supported = frame.get("supported_profiles")
    if supported is not None:
        if not isinstance(supported, list) or not supported or len(set(supported)) != len(supported) or any(item != V2_PROTOCOL_VERSION for item in supported):
            raise SchemaValidationError("native v0.2 supported_profiles is invalid")
    elif "supported_profiles" in frame:
        raise SchemaValidationError("native v0.2 supported_profiles must be omitted rather than null")
    compression = frame.get("compression")
    if compression is not None:
        if not isinstance(compression, list) or not compression or len(set(compression)) != len(compression) or any(item not in V2_NATIVE_COMPRESSION_ALGORITHMS for item in compression):
            raise SchemaValidationError("native v0.2 compression proposal is invalid")
    elif "compression" in frame:
        raise SchemaValidationError("native v0.2 compression must be omitted rather than null")
    result: JsonObject = {
        "type": "v2.init",
        "profile": V2_PROTOCOL_VERSION,
        "agent_id": identity["agent_id"],
        "instance_id": identity["instance_id"],
        "nonce": frame["nonce"],
    }
    for optional in ("protocol", "supported_profiles", "mesh_id", "compression"):
        if optional in frame:
            result[optional] = frame[optional]
    return result


def validate_v2_ack_frame(value: JsonValue | Mapping[str, Any]) -> JsonObject:
    """Validate a broker's native-v2 profile selection acknowledgement."""

    validate_json_tree(value)
    if not isinstance(value, Mapping):
        raise SchemaValidationError("native v0.2 ack must be an object")
    frame = dict(value)
    allowed = {"type", "protocol", "profile", "mesh_id", "session_id", "agent_id", "instance_id", "compression"}
    required = {"type", "profile", "mesh_id", "session_id", "compression"}
    if set(frame) - allowed or not required.issubset(frame) or frame.get("type") != "v2.ack":
        raise SchemaValidationError("native v0.2 ack has unknown or missing fields")
    if frame.get("protocol") not in {None, V2_PROTOCOL_VERSION} or frame.get("profile") != V2_PROTOCOL_VERSION:
        raise SchemaValidationError("native v0.2 ack profile is invalid")
    if "protocol" in frame and frame["protocol"] is None:
        raise SchemaValidationError("native v0.2 ack protocol must be omitted rather than null")
    if not is_v2_native_uuid(frame.get("mesh_id")) or not is_v2_native_uuid(frame.get("session_id")):
        raise SchemaValidationError("native v0.2 ack mesh_id and session_id must be UUIDv7")
    if frame.get("compression") not in V2_NATIVE_COMPRESSION_ALGORITHMS:
        raise SchemaValidationError("native v0.2 ack compression is invalid")
    identity_keys = {key for key in ("agent_id", "instance_id") if key in frame}
    if identity_keys and identity_keys != {"agent_id", "instance_id"}:
        raise SchemaValidationError("native v0.2 ack broker identity must be complete")
    if identity_keys:
        _validate_v2_native_identity(
            {"agent_id": frame.get("agent_id"), "instance_id": frame.get("instance_id")}, required_instance=True
        )
    result: JsonObject = {
        "type": "v2.ack",
        "profile": V2_PROTOCOL_VERSION,
        "mesh_id": frame["mesh_id"],
        "session_id": frame["session_id"],
        "compression": frame["compression"],
    }
    for optional in ("protocol", "agent_id", "instance_id"):
        if optional in frame:
            result[optional] = frame[optional]
    return result


def validate_v2_error_frame(value: JsonValue | Mapping[str, Any]) -> JsonObject:
    """Validate a bounded native-v2 pre-session error frame."""

    validate_json_tree(value)
    if not isinstance(value, Mapping):
        raise SchemaValidationError("native v0.2 error must be an object")
    frame = dict(value)
    allowed = {"type", "protocol", "profile", "mesh_id", "session_id", "code", "message", "retryable"}
    required = {"type", "profile", "code", "message"}
    if set(frame) - allowed or not required.issubset(frame) or frame.get("type") != "v2.error":
        raise SchemaValidationError("native v0.2 error has unknown or missing fields")
    if frame.get("protocol") not in {None, V2_PROTOCOL_VERSION} or frame.get("profile") != V2_PROTOCOL_VERSION:
        raise SchemaValidationError("native v0.2 error profile is invalid")
    if "protocol" in frame and frame["protocol"] is None:
        raise SchemaValidationError("native v0.2 error protocol must be omitted rather than null")
    if "mesh_id" in frame and not is_v2_native_uuid(frame["mesh_id"]):
        raise SchemaValidationError("native v0.2 error mesh_id must be UUIDv7")
    if "session_id" in frame and not is_v2_native_uuid(frame["session_id"]):
        raise SchemaValidationError("native v0.2 error session_id must be UUIDv7")
    if not isinstance(frame.get("code"), str) or not frame["code"] or len(frame["code"]) > 128:
        raise SchemaValidationError("native v0.2 error code is invalid")
    if not isinstance(frame.get("message"), str) or not frame["message"] or len(frame["message"]) > 1024:
        raise SchemaValidationError("native v0.2 error message is invalid")
    if "retryable" in frame and not isinstance(frame["retryable"], bool):
        raise SchemaValidationError("native v0.2 error retryable is invalid")
    return frame


def validate_v2_native_handshake_frame(value: JsonValue | Mapping[str, Any]) -> JsonObject:
    """Validate one compact native-v2 handshake record by its closed type."""

    if not isinstance(value, Mapping) or not isinstance(value.get("type"), str):
        raise SchemaValidationError("native v0.2 handshake record must be an object")
    if value["type"] == "v2.init":
        return validate_v2_init_frame(value)
    if value["type"] == "v2.ack":
        return validate_v2_ack_frame(value)
    if value["type"] == "v2.error":
        return validate_v2_error_frame(value)
    raise SchemaValidationError("unknown native v0.2 handshake record")


def _native_v2_task_params_to_legacy(envelope_type: str, value: Any) -> JsonObject:
    if not isinstance(value, Mapping):
        raise SchemaValidationError("native v0.2 envelope params must be an object")
    params = dict(value)
    if envelope_type == "task.submit":
        allowed = {"task_id", "capability", "capability_version", "capability_contract_digest", "input", "deadline"}
        required = {"task_id", "capability", "input", "deadline"}
        if set(params) - allowed or not required.issubset(params):
            raise SchemaValidationError("native v0.2 task.submit params are invalid")
        version = params.get("capability_version", "1.0.0")
        if not isinstance(version, str):
            raise SchemaValidationError("native v0.2 task.submit capability_version is invalid")
        digest = params.get("capability_contract_digest")
        if digest is None:
            try:
                digest = capability_contract_tuple(Capability(id=str(params["capability"]), version=version)).capability_contract_digest
            except Exception as exc:
                raise SchemaValidationError("native v0.2 task.submit capability contract is invalid") from exc
        result: JsonObject = {
            "task_id": params["task_id"],
            "method": params["capability"],
            "capability_version": version,
            "capability_contract_digest": digest,
            "params": params["input"],
            "deadline": params["deadline"],
        }
        return result
    if envelope_type in {"task.accepted", "task.completed"}:
        required = {
            "task.accepted": {"task_id", "event_seq", "accepted_at", "capability", "capability_version", "capability_contract_digest"},
            "task.completed": {"task_id", "event_seq", "terminal", "capability", "capability_version", "capability_contract_digest"},
        }[envelope_type]
        if set(params) != required:
            raise SchemaValidationError(f"native v0.2 {envelope_type} params are invalid")
        return {
            **{key: params[key] for key in required if key != "capability"},
            "capability_id": params["capability"],
        }
    if envelope_type == "task.rejected":
        required = {"task_id", "event_seq", "code", "message"}
        if not required.issubset(params):
            raise SchemaValidationError("native v0.2 task.rejected params are invalid")
        return {key: params[key] for key in required}
    if envelope_type == "task.progress":
        required = {"task_id", "event_seq", "progress"}
        if not required.issubset(params):
            raise SchemaValidationError("native v0.2 task.progress params are invalid")
        return {key: params[key] for key in required}
    if envelope_type == "error":
        allowed = {"code", "message", "retryable", "details"}
        required = {"code", "message", "retryable"}
        if set(params) - allowed or not required.issubset(params):
            raise SchemaValidationError("native v0.2 error params are invalid")
        result = {
            "category": "protocol",
            "code": params["code"],
            "message": params["message"],
            "retryable": params["retryable"],
            "retry_after_ms": None,
        }
        if "details" in params:
            result["details"] = params["details"]
        return result
    return params


def _legacy_task_params_to_native(envelope_type: str, value: JsonObject) -> JsonObject:
    params = copy.deepcopy(value)
    if envelope_type == "task.submit":
        return {
            "task_id": params["task_id"],
            "capability": params["method"],
            "input": params["params"],
            "deadline": params["deadline"],
            **({"capability_version": params["capability_version"]} if "capability_version" in params else {}),
            **({"capability_contract_digest": params["capability_contract_digest"]} if "capability_contract_digest" in params else {}),
        }
    if envelope_type == "error":
        result: JsonObject = {
            "code": params["code"],
            "message": params["message"],
            "retryable": params["retryable"],
        }
        if "details" in params:
            result["details"] = params["details"]
        return result
    if envelope_type in {"task.accepted", "task.completed"}:
        capability_id = params.pop("capability_id", None)
        if capability_id is not None:
            params["capability"] = capability_id
    return params


def validate_v2_native_envelope(value: JsonValue | Mapping[str, Any], *, mesh_id: str | None = None) -> JsonObject:
    """Validate and normalize the compact native-v2 application envelope.

    The selected native profile carries mesh scope once at the envelope root,
    and its durable delivery ID is nested below ``delivery``.  A validated
    temporary v0.1 view keeps the shared task lifecycle grammar exact without
    allowing either profile's outer fields to bleed into the other.
    """

    validate_json_tree(value)
    if not isinstance(value, Mapping):
        raise SchemaValidationError("native v0.2 envelope must be an object")
    frame = dict(value)
    allowed = {
        "protocol", "profile", "mesh_id", "type", "message_id", "timestamp", "source", "target",
        "delivery", "in_reply_to", "params",
    }
    required = {"protocol", "profile", "mesh_id", "type", "message_id", "timestamp", "source", "target", "delivery", "params"}
    if set(frame) - allowed or not required.issubset(frame):
        raise SchemaValidationError("native v0.2 envelope has unknown or missing fields")
    if frame.get("protocol") != V2_PROTOCOL_VERSION or frame.get("profile") != V2_PROTOCOL_VERSION:
        raise SchemaValidationError("native v0.2 envelope profile is invalid")
    if not is_v2_native_uuid(frame.get("mesh_id")) or (mesh_id is not None and frame["mesh_id"] != mesh_id):
        raise SchemaValidationError("native v0.2 envelope mesh scope is invalid")
    if not isinstance(frame.get("type"), str) or frame["type"] not in {
        "card", "task.submit", "task.accepted", "task.rejected", "task.progress", "task.completed",
        "task.cancel", "task.status", "ping", "pong", "receipt", "error",
    }:
        raise SchemaValidationError("native v0.2 envelope type is invalid")
    if not is_v2_native_uuid(frame.get("message_id")) or ("in_reply_to" in frame and not is_v2_native_uuid(frame["in_reply_to"])):
        raise SchemaValidationError("native v0.2 envelope message identifier is invalid")
    try:
        parse_timestamp(frame.get("timestamp"))
    except Exception as exc:
        raise SchemaValidationError("native v0.2 envelope timestamp is invalid") from exc
    source = _validate_v2_native_identity(frame.get("source"), required_instance=True)
    target = _validate_v2_native_identity(frame.get("target"), required_instance=False)
    delivery = frame.get("delivery")
    if not isinstance(delivery, Mapping) or set(delivery) != {"delivery_id", "mode", "idempotency_key", "deadline"}:
        raise SchemaValidationError("native v0.2 delivery is invalid")
    if not is_v2_native_uuid(delivery.get("delivery_id")) or delivery.get("mode") != "at_least_once":
        raise SchemaValidationError("native v0.2 delivery identifier or mode is invalid")
    if not isinstance(delivery.get("idempotency_key"), str) or not delivery["idempotency_key"] or len(delivery["idempotency_key"].encode("utf-8")) > 256:
        raise SchemaValidationError("native v0.2 idempotency key is invalid")
    try:
        parse_timestamp(delivery.get("deadline"))
    except Exception as exc:
        raise SchemaValidationError("native v0.2 delivery deadline is invalid") from exc
    params = _native_v2_task_params_to_legacy(str(frame["type"]), frame.get("params"))
    if frame["type"] == "task.submit" and params.get("deadline") != delivery["deadline"]:
        raise SchemaValidationError("native v0.2 task.submit deadline must match delivery deadline")
    legacy: JsonObject = {
        "protocol": PROTOCOL_VERSION,
        "type": frame["type"],
        "message_id": frame["message_id"],
        "timestamp": frame["timestamp"],
        "source": source,
        "target": target,
        "delivery": {
            "mode": "at_least_once",
            "idempotency_key": delivery["idempotency_key"],
            "deadline": delivery["deadline"],
        },
        "params": params,
    }
    if "in_reply_to" in frame:
        legacy["in_reply_to"] = frame["in_reply_to"]
    try:
        checked = validate_envelope(legacy)
    except Exception as exc:
        raise SchemaValidationError("native v0.2 envelope payload is invalid") from exc
    result: JsonObject = {
        "protocol": V2_PROTOCOL_VERSION,
        "profile": V2_PROTOCOL_VERSION,
        "mesh_id": frame["mesh_id"],
        "type": checked.type,
        "message_id": checked.message_id,
        "timestamp": checked.timestamp,
        "source": source,
        "target": target,
        "delivery": {
            "delivery_id": delivery["delivery_id"],
            "mode": "at_least_once",
            "idempotency_key": checked.delivery.idempotency_key,
            "deadline": checked.delivery.deadline,
        },
        "params": _legacy_task_params_to_native(checked.type, checked.params),
    }
    if checked.in_reply_to is not None:
        result["in_reply_to"] = checked.in_reply_to
    return result


def native_v2_envelope_as_legacy(value: JsonValue | Mapping[str, Any], *, mesh_id: str | None = None) -> Envelope:
    """Convert one validated native-v2 envelope to the internal lifecycle view."""

    checked = validate_v2_native_envelope(value, mesh_id=mesh_id)
    delivery = checked["delivery"]
    assert isinstance(delivery, dict)
    legacy: JsonObject = {
        "protocol": PROTOCOL_VERSION,
        "type": checked["type"],
        "message_id": checked["message_id"],
        "timestamp": checked["timestamp"],
        "source": checked["source"],
        "target": checked["target"],
        "delivery": {
            "mode": delivery["mode"],
            "idempotency_key": delivery["idempotency_key"],
            "deadline": delivery["deadline"],
        },
        "params": _native_v2_task_params_to_legacy(str(checked["type"]), checked["params"]),
    }
    if "in_reply_to" in checked:
        legacy["in_reply_to"] = checked["in_reply_to"]
    return validate_envelope(legacy)


def native_v2_envelope_from_legacy(
    envelope: Envelope | Mapping[str, Any], *, mesh_id: str, delivery_id: str | None = None
) -> JsonObject:
    """Encode the internal lifecycle view as a closed native-v2 envelope."""

    if not is_v2_native_uuid(mesh_id):
        raise ValueError("native v0.2 mesh_id must be UUIDv7")
    legacy = envelope if isinstance(envelope, Envelope) else validate_envelope(envelope)
    deadline = legacy.delivery.deadline or format_timestamp(datetime.now(UTC) + timedelta(seconds=60))
    wire: JsonObject = {
        "protocol": V2_PROTOCOL_VERSION,
        "profile": V2_PROTOCOL_VERSION,
        "mesh_id": mesh_id,
        "type": legacy.type,
        "message_id": legacy.message_id,
        "timestamp": legacy.timestamp,
        "source": legacy.source.model_dump(mode="json", exclude_none=True),
        "target": legacy.target.model_dump(mode="json", exclude_none=True),
        "delivery": {
            "delivery_id": delivery_id or uuidv7(),
            "mode": legacy.delivery.mode.value,
            "idempotency_key": legacy.delivery.idempotency_key,
            "deadline": deadline,
        },
        "params": _legacy_task_params_to_native(legacy.type, legacy.params),
    }
    if legacy.in_reply_to is not None:
        wire["in_reply_to"] = legacy.in_reply_to
    return validate_v2_native_envelope(wire, mesh_id=mesh_id)


def is_v2_mesh_id(value: Any) -> bool:
    """Return whether *value* is a bounded v0.2 mesh routing scope."""

    return isinstance(value, str) and V2_MESH_ID_RE.fullmatch(value) is not None


def derive_v2_session_id(initiator_nonce: str, responder_nonce: str) -> str:
    """Derive the profile-domain-separated v0.2 session identifier."""

    initiator = base64url_decode_exact(initiator_nonce, 32)
    responder = base64url_decode_exact(responder_nonce, 32)
    return base64url_encode(hashlib.sha256(b"polymesh.0.2\x00" + initiator + responder).digest())


def validate_v2_hello_frame(value: JsonValue | Mapping[str, Any]) -> JsonObject:
    """Validate one closed v0.2 hello frame without admitting v0.1 fields.

    The current durable TypeScript broker intentionally reuses card/auth/ready
    records after this profile-selecting hello.  Keeping this parser separate
    from :func:`validate_handshake_frame` makes the selection explicit and
    prevents an untrusted ``v`` member from being treated as an optional v0.1
    extension.
    """

    validate_json_tree(value)
    if not isinstance(value, Mapping):
        raise SchemaValidationError("v0.2 hello frame must be an object")
    frame = dict(value)
    role = frame.get("role")
    if frame.get("type") != "hello" or frame.get("v") != V2_HANDSHAKE_VERSION or role not in {"initiator", "responder"}:
        raise SchemaValidationError("invalid v0.2 hello frame")
    common = {"type", "v", "role", "agent_id", "instance_id", "nonce", "mesh_id", "security_profile"}
    responder = common | {"echo", "sid"}
    allowed = common if role == "initiator" else responder
    required = {"type", "v", "role", "agent_id", "instance_id", "nonce"}
    if role == "responder":
        required |= {"echo", "sid"}
    if set(frame) - allowed or not required.issubset(frame):
        raise SchemaValidationError("invalid v0.2 hello frame")
    try:
        # These local models supply the exact bounded agent/instance/nonce
        # grammar used by both profiles.  Do not use InitiatorHello here: its
        # literal v field is intentionally fixed to 0.1.
        AgentIdentity.model_validate({"agent_id": frame["agent_id"], "instance_id": frame["instance_id"]})
        base64url_decode_exact(str(frame["nonce"]), 32)
        if role == "responder":
            base64url_decode_exact(str(frame["echo"]), 32)
            base64url_decode_exact(str(frame["sid"]), 32)
    except Exception as exc:
        raise SchemaValidationError("invalid v0.2 hello frame") from exc
    if frame.get("mesh_id") is not None and not is_v2_mesh_id(frame["mesh_id"]):
        raise SchemaValidationError("invalid v0.2 mesh identity")
    if frame.get("security_profile") is not None and frame["security_profile"] != SECURE_IDENTITY_PROFILE:
        raise SchemaValidationError("unsupported v0.2 security profile")
    # Optional members use omission rather than JSON null, matching v0.1.
    if "mesh_id" in frame and frame["mesh_id"] is None:
        raise SchemaValidationError("v0.2 mesh_id must be omitted rather than null")
    if "security_profile" in frame and frame["security_profile"] is None:
        raise SchemaValidationError("v0.2 security_profile must be omitted rather than null")
    return frame


def is_v2_hello_frame(value: Any) -> bool:
    try:
        validate_v2_hello_frame(value)
        return True
    except ProtocolError:
        return False


def validate_v2_envelope(value: JsonValue | Mapping[str, Any], *, mesh_id: str | None = None) -> JsonObject:
    """Validate a legacy-broker-compatible v0.2 application envelope.

    v0.2 adds mesh-scoped addresses and optional relay-owned ``delivery_id``
    metadata while retaining the closed v0.1 task/control payload grammar.
    The latter is validated through a temporary v0.1 view so both SDKs make
    the same lifecycle decisions without allowing v0.2 fields into v0.1.
    """

    validate_json_tree(value)
    if not isinstance(value, Mapping):
        raise SchemaValidationError("v0.2 envelope must be an object")
    frame = dict(value)
    allowed = {
        "protocol", "type", "message_id", "timestamp", "source", "target", "delivery",
        "delivery_id", "in_reply_to", "params",
    }
    required = {"protocol", "type", "message_id", "timestamp", "source", "target", "delivery", "params"}
    if frame.get("protocol") != V2_PROTOCOL_VERSION or set(frame) - allowed or not required.issubset(frame):
        raise SchemaValidationError("invalid v0.2 envelope")
    source = frame.get("source")
    target = frame.get("target")
    if not isinstance(source, Mapping) or not isinstance(target, Mapping):
        raise SchemaValidationError("v0.2 envelope addresses are invalid")
    if set(source) != {"mesh_id", "agent_id", "instance_id"} or set(target) - {"mesh_id", "agent_id", "instance_id"} or not {"mesh_id", "agent_id"}.issubset(target):
        raise SchemaValidationError("v0.2 envelope addresses are invalid")
    if not is_v2_mesh_id(source.get("mesh_id")) or not is_v2_mesh_id(target.get("mesh_id")):
        raise SchemaValidationError("v0.2 envelope mesh identities are invalid")
    if mesh_id is not None and (source["mesh_id"] != mesh_id or target["mesh_id"] != mesh_id):
        raise SchemaValidationError("v0.2 envelope mesh scope does not match session")
    if "delivery_id" in frame:
        try:
            # UUIDv7 is accepted by the legacy model's message_id field.
            Envelope.model_validate({
                "protocol": PROTOCOL_VERSION,
                "type": "ping",
                "message_id": frame["delivery_id"],
                "timestamp": frame["timestamp"],
                "source": {"agent_id": source.get("agent_id"), "instance_id": source.get("instance_id")},
                "target": {"agent_id": target.get("agent_id")},
                "delivery": {"mode": "at_least_once", "idempotency_key": "v2-delivery-id", "deadline": frame["timestamp"]},
                "params": {"n": 0},
            }, context={"polymesh.strict_wire": True})
        except Exception as exc:
            raise SchemaValidationError("v0.2 delivery_id must be UUIDv7") from exc
    legacy = {
        **{key: item for key, item in frame.items() if key != "delivery_id"},
        "protocol": PROTOCOL_VERSION,
        "source": {"agent_id": source.get("agent_id"), "instance_id": source.get("instance_id")},
        "target": ({"agent_id": target.get("agent_id")} if target.get("instance_id") is None else {"agent_id": target.get("agent_id"), "instance_id": target.get("instance_id")}),
    }
    try:
        checked = validate_envelope(legacy)
    except Exception as exc:
        raise SchemaValidationError("invalid v0.2 envelope") from exc
    normalized = checked.model_dump(mode="json", exclude_none=True)
    normalized["protocol"] = V2_PROTOCOL_VERSION
    normalized["source"] = {"mesh_id": source["mesh_id"], **normalized["source"]}
    normalized["target"] = {"mesh_id": target["mesh_id"], **normalized["target"]}
    if "delivery_id" in frame:
        normalized["delivery_id"] = frame["delivery_id"]
    return normalized


def is_v2_envelope(value: Any, *, mesh_id: str | None = None) -> bool:
    try:
        validate_v2_envelope(value, mesh_id=mesh_id)
        return True
    except ProtocolError:
        return False


def v2_envelope_as_legacy(value: JsonValue | Mapping[str, Any], *, mesh_id: str | None = None) -> Envelope:
    """Return the validated v0.1 lifecycle view of one v0.2 envelope."""

    checked = validate_v2_envelope(value, mesh_id=mesh_id)
    source = checked["source"]
    target = checked["target"]
    assert isinstance(source, dict) and isinstance(target, dict)
    legacy = {
        **{key: item for key, item in checked.items() if key != "delivery_id"},
        "protocol": PROTOCOL_VERSION,
        "source": {"agent_id": source["agent_id"], "instance_id": source["instance_id"]},
        "target": {key: item for key, item in target.items() if key != "mesh_id"},
    }
    return validate_envelope(legacy)


def v2_envelope_from_legacy(envelope: Envelope | Mapping[str, Any], *, mesh_id: str, delivery_id: str | None = None) -> JsonObject:
    """Create a mesh-scoped v0.2 wire view from a validated v0.1 envelope."""

    if not is_v2_mesh_id(mesh_id):
        raise ValueError("mesh_id is invalid")
    legacy = envelope if isinstance(envelope, Envelope) else validate_envelope(envelope)
    result: JsonObject = legacy.model_dump(mode="json", exclude_none=True)
    result["protocol"] = V2_PROTOCOL_VERSION
    result["source"] = {"mesh_id": mesh_id, **result["source"]}
    result["target"] = {"mesh_id": mesh_id, **result["target"]}
    if delivery_id is not None:
        result["delivery_id"] = delivery_id
    return validate_v2_envelope(result, mesh_id=mesh_id)


def _model_json(model: BaseModel | Mapping[str, Any]) -> JsonObject:
    if isinstance(model, BaseModel):
        return model.model_dump(mode="json", exclude_none=True)
    return dict(model)


def card_digest(card: AgentCard | Mapping[str, Any]) -> str:
    return sha256_hex(_model_json(card))


digest_card = card_digest
canonical_card_digest = card_digest


def capability_contract_payload(capability: Capability | Mapping[str, Any]) -> JsonObject:
    item = capability if isinstance(capability, Capability) else Capability.model_validate(capability)
    return {
        "id": item.id,
        "version": item.version,
        "input_schema": item.input_schema,
        "result_schema": item.result_schema,
        "idempotency": item.idempotency or "idempotent",
        "side_effects": item.side_effects or "none",
        "approval": item.approval or "never",
        "cancellation": item.cancellation or "none",
        "timeout_ceiling_seconds": item.timeout_ceiling_seconds or 300,
    }


def capability_contract_digest(capability: Capability | Mapping[str, Any]) -> str:
    return sha256_hex(capability_contract_payload(capability))


def capability_contract_tuple(capability: Capability | Mapping[str, Any]) -> CapabilityContractTuple:
    item = capability if isinstance(capability, Capability) else Capability.model_validate(capability)
    return CapabilityContractTuple(
        capability_id=item.id,
        capability_version=item.version,
        capability_contract_digest=capability_contract_digest(item),
    )


def matches_capability_contract(
    tuple_value: CapabilityContractTuple | Mapping[str, Any], capability: Capability | Mapping[str, Any]
) -> bool:
    expected = capability_contract_tuple(capability)
    candidate = (
        tuple_value
        if isinstance(tuple_value, CapabilityContractTuple)
        else CapabilityContractTuple.model_validate(tuple_value)
    )
    return candidate == expected


def envelope_semantic_digest(envelope: Envelope | Mapping[str, Any]) -> str:
    value = _model_json(envelope)
    value.pop("message_id", None)
    value.pop("timestamp", None)
    return sha256_hex(value)


def routed_envelope_digest(envelope: Envelope | Mapping[str, Any]) -> str:
    value = _model_json(envelope)
    value.pop("provenance", None)
    value.pop("message_id", None)
    value.pop("timestamp", None)
    return sha256_hex(value)


RESTRICTED_SCHEMA_PROFILE = "polymesh.restricted-json-schema/1"
_RESTRICTED_SCHEMA_TYPES = {"object", "array", "string", "number", "integer", "boolean", "null"}
_RESTRICTED_SCHEMA_FIELDS = {
    "$schema",
    "type",
    "const",
    "enum",
    "anyOf",
    "oneOf",
    "allOf",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "minLength",
    "maxLength",
    "minimum",
    "maximum",
    "minItems",
    "maxItems",
}


def validate_restricted_schema(value: JsonObject | Mapping[str, Any]) -> JsonObject:
    """Validate the closed, non-executable PolyMesh schema profile."""

    budget = 0

    def finite_integer(candidate: Any, minimum: int = 0) -> bool:
        return isinstance(candidate, int) and not isinstance(candidate, bool) and candidate >= minimum

    def finite_number(candidate: Any) -> bool:
        return isinstance(candidate, (int, float)) and not isinstance(candidate, bool) and math.isfinite(candidate)

    def check(schema: Any, depth: int) -> None:
        nonlocal budget
        budget += 1
        if budget > 4_096 or depth > MAX_JSON_DEPTH:
            raise SchemaValidationError("schema exceeds structural limits")
        if not isinstance(schema, dict):
            raise SchemaValidationError("schema must be a JSON object")
        validate_json_tree(schema)
        unknown = set(schema) - _RESTRICTED_SCHEMA_FIELDS
        if unknown:
            raise SchemaValidationError("schema contains an unsupported keyword")
        if "$schema" in schema and schema["$schema"] != RESTRICTED_SCHEMA_PROFILE:
            raise SchemaValidationError("schema declares an unsupported profile")
        if "type" in schema:
            types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
            if (
                not types
                or len(types) > len(_RESTRICTED_SCHEMA_TYPES)
                or any(item not in _RESTRICTED_SCHEMA_TYPES for item in types)
                or len(set(types)) != len(types)
            ):
                raise SchemaValidationError("schema type is invalid")
        if "const" in schema:
            validate_json_tree(schema["const"])
        if "enum" in schema:
            enum = schema["enum"]
            if not isinstance(enum, list) or not enum or len(enum) > 64:
                raise SchemaValidationError("schema enum is invalid")
            for item in enum:
                validate_json_tree(item)
        for name in ("anyOf", "oneOf", "allOf"):
            if name not in schema:
                continue
            children = schema[name]
            if not isinstance(children, list) or not children or len(children) > 32:
                raise SchemaValidationError(f"schema {name} is invalid")
            for child in children:
                check(child, depth + 1)
        if "properties" in schema:
            properties = schema["properties"]
            if not isinstance(properties, dict) or len(properties) > MAX_JSON_OBJECT_MEMBERS:
                raise SchemaValidationError("schema properties is invalid")
            for name, child in properties.items():
                if not isinstance(name, str) or not name or len(name.encode("utf-8")) > 255:
                    raise SchemaValidationError("schema property name is invalid")
                check(child, depth + 1)
        if "required" in schema:
            required = schema["required"]
            if (
                not isinstance(required, list)
                or len(required) > MAX_JSON_OBJECT_MEMBERS
                or any(not isinstance(item, str) or not item or len(item.encode("utf-8")) > 255 for item in required)
                or len(set(required)) != len(required)
            ):
                raise SchemaValidationError("schema required is invalid")
        if "additionalProperties" in schema and not isinstance(schema["additionalProperties"], bool):
            raise SchemaValidationError("schema additionalProperties is invalid")
        if "items" in schema:
            check(schema["items"], depth + 1)
        for name in ("minLength", "maxLength", "minItems", "maxItems"):
            if name in schema and not finite_integer(schema[name]):
                raise SchemaValidationError(f"schema {name} is invalid")
        for lower, upper, label in (("minLength", "maxLength", "string"), ("minItems", "maxItems", "array")):
            if lower in schema and upper in schema and schema[lower] > schema[upper]:
                raise SchemaValidationError(f"schema {label} bounds are invalid")
        for name in ("minimum", "maximum"):
            if name in schema and not finite_number(schema[name]):
                raise SchemaValidationError(f"schema {name} is invalid")
        if "minimum" in schema and "maximum" in schema and schema["minimum"] > schema["maximum"]:
            raise SchemaValidationError("schema numeric bounds are invalid")

    check(value, 1)
    return dict(value)


def _json_equal(left: Any, right: Any) -> bool:
    try:
        return canonical_json(left) == canonical_json(right)
    except Exception:
        return False


def validate_restricted_schema_instance(value: JsonValue, schema: JsonObject | Mapping[str, Any]) -> None:
    """Validate a JSON value against the deliberately small schema profile."""

    validated = validate_restricted_schema(schema)
    validate_json_tree(value)

    def expected_type_matches(entry: Any, kind: str) -> bool:
        if kind == "null":
            return entry is None
        if kind == "boolean":
            return isinstance(entry, bool)
        if kind == "object":
            return isinstance(entry, dict)
        if kind == "array":
            return isinstance(entry, list)
        if kind == "string":
            return isinstance(entry, str)
        if kind == "number":
            return isinstance(entry, (int, float)) and not isinstance(entry, bool) and math.isfinite(entry)
        if kind == "integer":
            return isinstance(entry, int) and not isinstance(entry, bool)
        return False

    def fail(path: str, message: str) -> None:
        label = path or "$"
        raise SchemaValidationError(f"{label}: {message}")

    def check(entry: Any, current: Mapping[str, Any], path: str) -> None:
        if "const" in current and not _json_equal(entry, current["const"]):
            fail(path, "does not equal const")
        if "enum" in current and not any(_json_equal(entry, allowed) for allowed in current["enum"]):
            fail(path, "is not in enum")
        if "allOf" in current:
            for child in current["allOf"]:
                check(entry, child, path)
        if "anyOf" in current:
            valid = False
            for child in current["anyOf"]:
                try:
                    check(entry, child, path)
                    valid = True
                    break
                except SchemaValidationError:
                    pass
            if not valid:
                fail(path, "does not match anyOf")
        if "oneOf" in current:
            count = 0
            for child in current["oneOf"]:
                try:
                    check(entry, child, path)
                    count += 1
                except SchemaValidationError:
                    pass
            if count != 1:
                fail(path, "does not match exactly one oneOf branch")
        if "type" in current:
            kinds = current["type"] if isinstance(current["type"], list) else [current["type"]]
            if not any(expected_type_matches(entry, kind) for kind in kinds):
                fail(path, "has the wrong type")
        if isinstance(entry, str):
            length = len(entry)
            if "minLength" in current and length < current["minLength"]:
                fail(path, "is shorter than minLength")
            if "maxLength" in current and length > current["maxLength"]:
                fail(path, "is longer than maxLength")
        if isinstance(entry, (int, float)) and not isinstance(entry, bool):
            if "minimum" in current and entry < current["minimum"]:
                fail(path, "is below minimum")
            if "maximum" in current and entry > current["maximum"]:
                fail(path, "is above maximum")
        if isinstance(entry, list):
            if "minItems" in current and len(entry) < current["minItems"]:
                fail(path, "has fewer than minItems")
            if "maxItems" in current and len(entry) > current["maxItems"]:
                fail(path, "has more than maxItems")
            if "items" in current:
                for index, child in enumerate(entry):
                    check(child, current["items"], f"{path}/{index}")
        if isinstance(entry, dict):
            properties = current.get("properties", {})
            required = current.get("required", [])
            for name in required:
                if name not in entry:
                    fail(path, f"is missing required property {name!r}")
            for name, child in entry.items():
                if name in properties:
                    check(child, properties[name], f"{path}/{name}")
                elif current.get("additionalProperties") is False:
                    fail(path, f"has unexpected property {name!r}")

    check(value, validated, "$")


validate_schema_instance = validate_restricted_schema_instance


def _raw_public_key(value: str | bytes | bytearray) -> bytes:
    raw = base64url_decode_exact(value, 32) if isinstance(value, str) else bytes(value)
    if len(raw) != 32:
        raise ValueError("Ed25519 public key must be 32 raw bytes")
    return raw


def create_card_identity(public_key: Any) -> CardIdentity:
    """Create the self-contained card identity for an Ed25519 public key."""

    if serialization is None:
        raise RuntimeError("cryptography is required for Ed25519 operations")
    if isinstance(public_key, (str, bytes, bytearray)):
        raw = _raw_public_key(public_key)
    elif hasattr(public_key, "public_key"):
        public = public_key.public_key()
        raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    elif hasattr(public_key, "public_bytes"):
        raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    else:
        raise TypeError("an Ed25519 public key is required")
    return CardIdentity(key_id=key_id_from_raw_ed25519_public_key(raw), public_key=base64url_encode(raw))


def create_card_identity_from_private_key(private_key: Any) -> CardIdentity:
    return create_card_identity(private_key)


def card_signing_payload(card: AgentCard | Mapping[str, Any]) -> bytes:
    unsigned = _model_json(card)
    unsigned.pop("signature", None)
    return b"PMX-CARD/0.1\x00" + canonical_json(unsigned).encode("utf-8")


def _coerce_private_key(private_key: Any) -> Any:
    if serialization is None:
        raise RuntimeError("cryptography is required for Ed25519 operations")
    if hasattr(private_key, "sign") and hasattr(private_key, "public_key"):
        return private_key
    if isinstance(private_key, (bytes, bytearray, str)):
        data = private_key.encode() if isinstance(private_key, str) else bytes(private_key)
        return serialization.load_pem_private_key(data, password=None)
    raise TypeError("an Ed25519 private key is required")


def sign_agent_card(card: AgentCard | Mapping[str, Any], private_key: Any) -> AgentCard:
    key = _coerce_private_key(private_key)
    identity = create_card_identity(key)
    data = _model_json(card)
    existing = data.get("identity")
    if existing is not None and (
        existing.get("key_id") != identity.key_id or existing.get("public_key") != identity.public_key
    ):
        raise ValueError("card identity does not match the signing key")
    data["identity"] = identity.model_dump(mode="json")
    data.pop("signature", None)
    signature = key.sign(b"PMX-CARD/0.1\x00" + canonical_json(data).encode("utf-8"))
    data["signature"] = base64url_encode(signature)
    return AgentCard.model_validate(data)


def verify_agent_card_signature(card: AgentCard | Mapping[str, Any]) -> bool:
    try:
        item = card if isinstance(card, AgentCard) else AgentCard.model_validate(card)
        if item.identity is None or item.signature is None:
            return False
        public = Ed25519PublicKey.from_public_bytes(base64url_decode_exact(item.identity.public_key, 32))
        public.verify(base64url_decode_exact(item.signature, 64), card_signing_payload(item))
        return True
    except (ValueError, InvalidSignature, TypeError, AttributeError):
        return False


class EnrollmentStore:
    """Small in-memory enrollment map; it never learns keys from peers."""

    def __init__(self, enrollments: Sequence[Enrollment | Mapping[str, Any]] = ()) -> None:
        self._records: dict[tuple[str, str], Enrollment] = {}
        for enrollment in enrollments:
            self.enroll(enrollment)

    def enroll(self, value: Enrollment | Mapping[str, Any]) -> Enrollment:
        enrollment = value if isinstance(value, Enrollment) else Enrollment.model_validate(value)
        key = (enrollment.agent_id, enrollment.key_id)
        prior = self._records.get(key)
        if prior is not None and prior.public_key != enrollment.public_key:
            raise ValueError("enrollment key collision")
        self._records[key] = enrollment
        return enrollment

    def resolve(self, agent_id: str, key_id: str, now: datetime | float | None = None) -> Enrollment | None:
        record = self._records.get((agent_id, key_id))
        if record is None or record.enabled is False:
            return None
        now_dt = _as_utc_datetime(now)
        if record.expires_at is not None and parse_timestamp(record.expires_at) <= now_dt:
            return None
        return record

    def verify_card(
        self, card: AgentCard | Mapping[str, Any], now: datetime | float | None = None
    ) -> VerifiedPrincipal | None:
        try:
            item = card if isinstance(card, AgentCard) else AgentCard.model_validate(card)
        except ValidationError:
            return None
        if item.identity is None or not verify_agent_card_signature(item):
            return None
        enrollment = self.resolve(item.agent_id, item.identity.key_id, now)
        if enrollment is None or enrollment.public_key != item.identity.public_key:
            return None
        return VerifiedPrincipal(
            principal_id=f"key:{enrollment.key_id}",
            agent_id=enrollment.agent_id,
            key_id=enrollment.key_id,
            public_key=enrollment.public_key,
        )


def verify_enrolled_card(
    card: AgentCard | Mapping[str, Any],
    enrollments: EnrollmentStore | Sequence[Enrollment | Mapping[str, Any]],
    now: datetime | float | None = None,
) -> VerifiedPrincipal | None:
    store = enrollments if isinstance(enrollments, EnrollmentStore) else EnrollmentStore(enrollments)
    return store.verify_card(card, now)


def _as_utc_datetime(value: datetime | float | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("clock time must be timezone-aware")
        return value.astimezone(UTC)
    return datetime.fromtimestamp(value / 1000 if value > 10_000_000_000 else value, UTC)


def auth_transcript(
    *,
    initiator_hello: InitiatorHello | Mapping[str, Any],
    responder_hello: ResponderHello | Mapping[str, Any],
    initiator_card_digest: str,
    responder_card_digest: str,
    tls_channel_binding: str,
) -> bytes:
    initiator = (
        initiator_hello
        if isinstance(initiator_hello, InitiatorHello)
        else InitiatorHello.model_validate(initiator_hello)
    )
    responder = (
        responder_hello
        if isinstance(responder_hello, ResponderHello)
        else ResponderHello.model_validate(responder_hello)
    )
    if (
        initiator.security_profile != SECURE_IDENTITY_PROFILE
        or responder.security_profile != SECURE_IDENTITY_PROFILE
        or responder.echo != initiator.nonce
        or responder.sid != derive_session_id(initiator.nonce, responder.nonce)
    ):
        raise AuthenticationError("invalid secure handshake transcript")
    if (
        not isinstance(initiator_card_digest, str)
        or not isinstance(responder_card_digest, str)
        or re.fullmatch(r"[0-9a-fA-F]{64}", initiator_card_digest) is None
        or re.fullmatch(r"[0-9a-fA-F]{64}", responder_card_digest) is None
    ):
        raise AuthenticationError("invalid secure card digest")
    base64url_decode_exact(tls_channel_binding, 32)
    value: JsonObject = {
        "protocol": PROTOCOL_VERSION,
        "handshake_version": "0.1",
        "security_profile": SECURE_IDENTITY_PROFILE,
        "initiator_hello": initiator.model_dump(mode="json", exclude_none=True),
        "responder_hello": responder.model_dump(mode="json", exclude_none=True),
        "initiator_card_digest": initiator_card_digest,
        "responder_card_digest": responder_card_digest,
        "tls_channel_binding": tls_channel_binding,
    }
    return b"PMX-AUTH/0.1\x00" + canonical_json(value).encode("utf-8")


def v2_auth_transcript(
    *,
    initiator_hello: Mapping[str, Any],
    responder_hello: Mapping[str, Any],
    initiator_card_digest: str,
    responder_card_digest: str,
    tls_channel_binding: str,
) -> bytes:
    """Build the TLS-bound, domain-separated secure v0.2 transcript.

    v0.2 deliberately reuses the concrete ``auth`` record shape, but not the
    proof bytes.  The profile/version domain and v2 hello objects make a proof
    from a v0.1 connection unusable here.
    """

    initiator = validate_v2_hello_frame(initiator_hello)
    responder = validate_v2_hello_frame(responder_hello)
    if initiator.get("role") != "initiator" or responder.get("role") != "responder":
        raise AuthenticationError("invalid v0.2 secure handshake transcript")
    if responder.get("echo") != initiator.get("nonce") or responder.get("sid") != derive_v2_session_id(str(initiator["nonce"]), str(responder["nonce"])):
        raise AuthenticationError("invalid v0.2 secure handshake transcript")
    if not isinstance(initiator_card_digest, str) or not isinstance(responder_card_digest, str) or (
        re.fullmatch(r"[0-9a-fA-F]{64}", initiator_card_digest) is None
        or re.fullmatch(r"[0-9a-fA-F]{64}", responder_card_digest) is None
    ):
        raise AuthenticationError("invalid v0.2 secure card digest")
    base64url_decode_exact(tls_channel_binding, 32)
    value: JsonObject = {
        "protocol": V2_PROTOCOL_VERSION,
        "handshake_version": V2_HANDSHAKE_VERSION,
        "initiator_hello": initiator,
        "responder_hello": responder,
        "initiator_card_digest": initiator_card_digest,
        "responder_card_digest": responder_card_digest,
        "tls_channel_binding": tls_channel_binding,
    }
    return b"PMX-AUTH/0.2\x00" + canonical_json(value).encode("utf-8")


def create_v2_auth_proof(
    identity: CardIdentity,
    agent_id: str,
    sid: str,
    transcript: bytes,
    private_key: Any,
) -> AuthFrame:
    """Sign an already domain-separated v0.2 transcript."""

    return create_auth_proof(identity, agent_id, sid, transcript, private_key)


def verify_v2_auth_proof(
    proof: AuthFrame | Mapping[str, Any],
    transcript: bytes,
    enrollments: EnrollmentStore | Sequence[Enrollment | Mapping[str, Any]],
    now: datetime | float | None = None,
) -> VerifiedPrincipal | None:
    """Verify v0.2 proof possession against a preconfigured enrollment store."""

    return verify_auth_proof(proof, transcript, enrollments, now)


def create_auth_proof(
    identity: CardIdentity,
    agent_id: str,
    sid: str,
    transcript: bytes,
    private_key: Any,
) -> AuthFrame:
    key = _coerce_private_key(private_key)
    expected = create_card_identity(key)
    if expected != identity:
        raise ValueError("handshake identity does not match proof key")
    return AuthFrame(
        type="auth",
        sid=sid,
        agent_id=agent_id,
        key_id=identity.key_id,
        signature=base64url_encode(key.sign(bytes(transcript))),
    )


def verify_auth_proof(
    proof: AuthFrame | Mapping[str, Any],
    transcript: bytes,
    enrollments: EnrollmentStore | Sequence[Enrollment | Mapping[str, Any]],
    now: datetime | float | None = None,
) -> VerifiedPrincipal | None:
    try:
        item = proof if isinstance(proof, AuthFrame) else AuthFrame.model_validate(proof)
        store = enrollments if isinstance(enrollments, EnrollmentStore) else EnrollmentStore(enrollments)
        enrollment = store.resolve(item.agent_id, item.key_id, now)
        if enrollment is None:
            return None
        public = Ed25519PublicKey.from_public_bytes(base64url_decode_exact(enrollment.public_key, 32))
        public.verify(base64url_decode_exact(item.signature, 64), bytes(transcript))
        return VerifiedPrincipal(
            principal_id=f"key:{enrollment.key_id}",
            agent_id=enrollment.agent_id,
            key_id=enrollment.key_id,
            public_key=enrollment.public_key,
        )
    except (ValueError, ValidationError, InvalidSignature, TypeError):
        return None


def routed_provenance_signing_payload(provenance: RoutedProvenance | Mapping[str, Any]) -> bytes:
    value = _model_json(provenance)
    value.pop("signature", None)
    return b"PMX-ROUTED-PROVENANCE/1\x00" + canonical_json(value).encode("utf-8")


def verify_routed_provenance_signature(
    provenance: RoutedProvenance | Mapping[str, Any], public_key: str | bytes
) -> bool:
    try:
        item = provenance if isinstance(provenance, RoutedProvenance) else RoutedProvenance.model_validate(provenance)
        public = Ed25519PublicKey.from_public_bytes(_raw_public_key(public_key))
        public.verify(base64url_decode_exact(item.signature, 64), routed_provenance_signing_payload(item))
        return True
    except (ValueError, ValidationError, InvalidSignature, TypeError):
        return False


def create_routed_provenance(
    *,
    envelope: Envelope,
    broker: Mapping[str, Any],
    source_principal: VerifiedPrincipal,
    source_session_id: str,
    target_session_id: str,
    expires_at: str,
    private_key: Any,
    issued_at: str | None = None,
) -> RoutedProvenance:
    """Create the broker-only secure routed provenance attachment.

    Applications must call this only after authenticating the source session
    and choosing the target session.  A sender-supplied provenance object is
    rejected rather than nested or overwritten.
    """

    if envelope.provenance is not None:
        raise AuthenticationError("a routed envelope cannot carry sender-supplied provenance")
    broker_value = dict(broker)
    if not {"agent_id", "instance_id", "key_id"}.issubset(broker_value):
        raise ValueError("broker provenance identity is incomplete")
    if (
        source_principal.principal_id != f"key:{source_principal.key_id}"
        or source_principal.agent_id != envelope.source.agent_id
    ):
        raise AuthenticationError("source principal does not match routed envelope")
    selected_issued = issued_at or utc_now_millis()
    issued = parse_timestamp(selected_issued)
    expires = parse_timestamp(expires_at)
    deadline = parse_timestamp(envelope.delivery.deadline)
    if expires <= issued or expires - issued > timedelta(seconds=60) or expires > deadline:
        raise ValueError("routed provenance lifetime is invalid")
    key = _coerce_private_key(private_key)
    identity = create_card_identity(key)
    if broker_value["key_id"] != identity.key_id:
        raise ValueError("broker provenance key does not match signing key")
    unsigned: JsonObject = {
        "version": ROUTED_PROVENANCE_VERSION,
        "broker": {
            "agent_id": broker_value["agent_id"],
            "instance_id": broker_value["instance_id"],
            "key_id": broker_value["key_id"],
        },
        "source_principal": {
            "principal_id": source_principal.principal_id,
            "agent_id": source_principal.agent_id,
            "key_id": source_principal.key_id,
        },
        "source": envelope.source.model_dump(mode="json"),
        "target": envelope.target.model_dump(mode="json", exclude_none=True),
        "source_session_id": source_session_id,
        "target_session_id": target_session_id,
        "envelope_digest": routed_envelope_digest(envelope),
        "issued_at": selected_issued,
        "expires_at": expires_at,
    }
    signature = key.sign(b"PMX-ROUTED-PROVENANCE/1\x00" + canonical_json(unsigned).encode("utf-8"))
    unsigned["signature"] = base64url_encode(signature)
    return RoutedProvenance.model_validate(unsigned)


def verify_routed_provenance(
    envelope: Envelope,
    *,
    broker_principal: VerifiedPrincipal,
    broker_identity: AgentIdentity,
    target_session_id: str,
    now: datetime | float | None = None,
) -> bool:
    """Verify all session-bound provenance invariants for a secure recipient."""

    provenance = envelope.provenance
    if provenance is None:
        return False
    try:
        current = _as_utc_datetime(now)
        if parse_timestamp(provenance.issued_at) > current or parse_timestamp(provenance.expires_at) <= current:
            return False
        if (
            provenance.broker.agent_id != broker_principal.agent_id
            or provenance.broker.agent_id != broker_identity.agent_id
            or provenance.broker.instance_id != broker_identity.instance_id
            or provenance.broker.key_id != broker_principal.key_id
            or broker_principal.principal_id != f"key:{broker_principal.key_id}"
            or provenance.target_session_id != target_session_id
            or provenance.source_principal.principal_id != f"key:{provenance.source_principal.key_id}"
            or provenance.source_principal.agent_id != envelope.source.agent_id
            or provenance.source != envelope.source
            or provenance.target != envelope.target
            or provenance.envelope_digest != routed_envelope_digest(envelope)
        ):
            return False
        return verify_routed_provenance_signature(provenance, broker_principal.public_key)
    except (ValueError, TypeError):
        return False


def create_envelope(
    *,
    type: EnvelopeType,
    source: AgentIdentity | Mapping[str, Any],
    target: AgentRef | Mapping[str, Any],
    params: JsonObject | None = None,
    idempotency_key: str | None = None,
    deadline: str | None = None,
    in_reply_to: str | None = None,
    message_id: str | None = None,
    timestamp: str | None = None,
) -> Envelope:
    source_value = source if isinstance(source, AgentIdentity) else AgentIdentity.model_validate(source)
    target_value = target if isinstance(target, AgentRef) else AgentRef.model_validate(target)
    parameter_value: JsonObject = {} if params is None else copy.deepcopy(params)
    validate_json_tree(parameter_value)
    chosen_message_id = message_id or uuidv7()
    chosen_deadline = deadline or format_timestamp(datetime.now(UTC) + timedelta(seconds=60))
    wire_value: JsonObject = {
        "type": type,
        "message_id": chosen_message_id,
        "timestamp": timestamp or utc_now_millis(),
        "source": source_value.model_dump(mode="json", exclude_none=True),
        "target": target_value.model_dump(mode="json", exclude_none=True),
        "delivery": {
            "mode": DeliveryMode.AT_LEAST_ONCE.value,
            "idempotency_key": idempotency_key or f"{type}:{chosen_message_id}",
            "deadline": chosen_deadline,
        },
        "params": parameter_value,
    }
    if in_reply_to is not None:
        wire_value["in_reply_to"] = in_reply_to
    return Envelope.model_validate(
        wire_value,
        context={"polymesh.strict_wire": True},
    )


def validate_envelope(value: JsonValue | Mapping[str, Any]) -> Envelope:
    validate_json_tree(value)
    if not isinstance(value, dict):
        raise SchemaValidationError("envelope must be an object")
    try:
        return Envelope.model_validate(value, context={"polymesh.strict_wire": True})
    except ValidationError as exc:
        raise SchemaValidationError("invalid PolyMesh envelope") from exc


def is_envelope(value: Any) -> bool:
    try:
        validate_envelope(value)
        return True
    except ProtocolError:
        return False


def validate_handshake_frame(
    value: JsonValue | Mapping[str, Any],
    expected_type: str | type[WireModel] | None = None,
) -> HandshakeFrame:
    validate_json_tree(value)
    if not isinstance(value, dict) or not isinstance(value.get("type"), str):
        raise SchemaValidationError("handshake frame must be an object")
    name = value["type"]
    model_type: type[WireModel]
    if name == "hello":
        role = value.get("role")
        model_type = (
            InitiatorHello if role == "initiator" else ResponderHello if role == "responder" else InitiatorHello
        )
    elif name == "card":
        model_type = CardFrame
    elif name == "auth":
        model_type = AuthFrame
    elif name == "ready":
        model_type = ReadyFrame
    else:
        raise SchemaValidationError("unknown handshake frame type")
    try:
        frame = model_type.model_validate(value, context={"polymesh.strict_wire": True})
    except ValidationError as exc:
        raise SchemaValidationError("invalid handshake frame") from exc
    if expected_type is not None:
        expected_name = expected_type if isinstance(expected_type, str) else getattr(expected_type, "__name__", "")
        matches = frame.type == expected_name or type(frame) is expected_type
        if not matches:
            raise HandshakeError("unexpected handshake frame")
    return frame  # type: ignore[return-value]


def is_handshake_frame(value: Any) -> bool:
    try:
        validate_handshake_frame(value)
        return True
    except ProtocolError:
        return False


def encode_record_text(record: HandshakeFrame | Envelope | Mapping[str, Any]) -> str:
    """Encode one validated record for one WebSocket text message."""

    if isinstance(record, Envelope):
        value = validate_envelope(record.model_dump(mode="json", exclude_none=True)).model_dump(
            mode="json", exclude_none=True
        )
    elif isinstance(record, (InitiatorHello, ResponderHello, CardFrame, AuthFrame, ReadyFrame)):
        value = validate_handshake_frame(record.model_dump(mode="json", exclude_none=True)).model_dump(
            mode="json", exclude_none=True
        )
    elif isinstance(record, BaseModel):
        raise TypeError("record must be a PolyMesh handshake frame or envelope")
    elif isinstance(record, Mapping):
        value = dict(record)
        # Calling code that creates a raw dict should get exactly the same
        # outbound validation boundary as calling code that uses a model.
        if "protocol" in value:
            value = validate_envelope(value).model_dump(mode="json", exclude_none=True)
        else:
            value = validate_handshake_frame(value).model_dump(mode="json", exclude_none=True)
    else:
        raise TypeError("record must be a handshake frame or envelope")
    encoded = canonical_json(value)
    if len(encoded.encode("utf-8")) > MAX_FRAME_BYTES:
        raise FrameTooLargeError("outbound record exceeds 1 MiB")
    return encoded


def encode_record(record: HandshakeFrame | Envelope | Mapping[str, Any]) -> bytes:
    return encode_record_text(record).encode("utf-8")


def encode_unix_frame(record: HandshakeFrame | Envelope | Mapping[str, Any]) -> bytes:
    payload = encode_record(record)
    if len(payload) + 4 > MAX_FRAME_BYTES:
        raise FrameTooLargeError("outbound Unix frame exceeds 1 MiB")
    return len(payload).to_bytes(4, "big") + payload


class UnixFrameDecoder:
    """Incremental four-byte-big-endian Unix stream frame decoder."""

    def __init__(self) -> None:
        self._remainder = bytearray()

    @property
    def remainder(self) -> bytes:
        return bytes(self._remainder)

    def feed(self, data: bytes | bytearray | memoryview) -> list[bytes]:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("Unix frame data must be bytes")
        self._remainder.extend(data)
        records: list[bytes] = []
        while len(self._remainder) >= 4:
            size = int.from_bytes(self._remainder[:4], "big")
            if size + 4 > MAX_FRAME_BYTES:
                self._remainder.clear()
                raise FrameTooLargeError("inbound Unix frame exceeds 1 MiB")
            if len(self._remainder) < size + 4:
                break
            payload = bytes(self._remainder[4 : 4 + size])
            # Validate UTF-8 here, before a caller has a chance to treat this
            # stream payload as text/JSON.
            try:
                payload.decode("utf-8", "strict")
            except UnicodeDecodeError as exc:
                del self._remainder[: 4 + size]
                raise MalformedJsonError("Unix frame is not valid UTF-8") from exc
            records.append(payload)
            del self._remainder[: 4 + size]
        # A remainder can contain only a prefix plus a bounded body.  A large
        # short prefix is impossible after the size check, but this protects
        # direct mutation/subclassing too.
        if len(self._remainder) > MAX_FRAME_BYTES:
            self._remainder.clear()
            raise FrameTooLargeError("Unix frame remainder exceeds 1 MiB")
        return records


def decode_unix_frames(data: bytes | bytearray | memoryview, decoder: UnixFrameDecoder) -> list[bytes]:
    return decoder.feed(data)


__all__ = [
    "EnrollmentStore",
    "JsonParseLimits",
    "RESTRICTED_SCHEMA_PROFILE",
    "UnixFrameDecoder",
    "auth_transcript",
    "canonical_card_digest",
    "canonical_json",
    "canonicalize",
    "capability_contract_digest",
    "capability_contract_payload",
    "capability_contract_tuple",
    "card_digest",
    "card_signing_payload",
    "create_auth_proof",
    "create_card_identity",
    "create_card_identity_from_private_key",
    "create_envelope",
    "create_routed_provenance",
    "decode_unix_frames",
    "derive_session_id",
    "digest_card",
    "encode_record",
    "encode_record_text",
    "encode_unix_frame",
    "encoded_json_bytes",
    "envelope_semantic_digest",
    "is_envelope",
    "is_handshake_frame",
    "matches_capability_contract",
    "parse_bounded_json",
    "parse_strict_json",
    "random_instance_id",
    "random_nonce",
    "routed_envelope_digest",
    "routed_provenance_signing_payload",
    "sha256",
    "sha256_hex",
    "sign_agent_card",
    "uuidv7",
    "validate_envelope",
    "validate_handshake_frame",
    "validate_json_tree",
    "validate_restricted_schema",
    "validate_restricted_schema_instance",
    "validate_schema_instance",
    "verify_agent_card_signature",
    "verify_auth_proof",
    "verify_enrolled_card",
    "verify_routed_provenance",
    "verify_routed_provenance_signature",
]

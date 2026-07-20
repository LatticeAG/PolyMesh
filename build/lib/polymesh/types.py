"""Closed PolyMesh v0.1 wire and public SDK models.

This module intentionally contains data definitions rather than transport
state.  The parser in :mod:`polymesh.protocol` validates raw JSON before any
of these Pydantic models are constructed.
"""

from __future__ import annotations

import base64
import hashlib
import math
import os
import re
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any, Annotated, ClassVar, Final, Literal, Self, TypeAlias
from urllib.parse import urlsplit

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationInfo,
    field_validator,
    model_validator,
)


# Pydantic 2.13 on Python 3.11/3.12 recursively expands an implicit alias of
# the form ``list["JsonValue"] | dict[str, "JsonValue"]`` while building each
# wire model and can hit its own recursion limit.  Wire values are instead
# bounded explicitly by ``validate_json_tree`` before model construction (and
# before serialization), which is stricter than Pydantic's generic JSON type.
# Keeping the runtime aliases broad avoids a framework-specific schema loop.
JsonPrimitive: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = Any
JsonObject: TypeAlias = dict[str, Any]

PROTOCOL_VERSION: Final = "polymesh.0.1"
HANDSHAKE_VERSION: Final = "0.1"
CARD_VERSION: Final = "1.0"
SECURE_IDENTITY_PROFILE: Final = "enrolled-ed25519-tls-1.3"
ROUTED_PROVENANCE_VERSION: Final = "pmx.broker-provenance/1"

MAX_FRAME_BYTES: Final = 1_048_576
MAX_JSON_DEPTH: Final = 32
MAX_JSON_NODES: Final = 10_000
MAX_JSON_OBJECT_MEMBERS: Final = 1_024
MAX_JSON_ARRAY_ITEMS: Final = 4_096
MAX_JSON_STRING_BYTES: Final = 65_536
MAX_CARD_BYTES: Final = 64 * 1024
MAX_PUBLIC_CARD_BYTES: Final = 8 * 1024
MAX_CAPABILITIES_PER_CARD: Final = 64
MAX_ENDPOINTS_PER_CARD: Final = 8
MAX_SCHEMA_BYTES_PER_CAPABILITY: Final = 16 * 1024
MAX_IDEMPOTENCY_KEY_BYTES: Final = 256
MAX_SAFE_INTEGER: Final = 9_007_199_254_740_991


AgentId = Annotated[
    str,
    StringConstraints(min_length=1, max_length=255, pattern=r"^[a-zA-Z][a-zA-Z0-9._-]*$"),
]
CapabilityId = Annotated[
    str,
    StringConstraints(
        min_length=3,
        max_length=255,
        pattern=r"^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)*\.[a-z](?:[a-z0-9-]*[a-z0-9])?$",
    ),
]
SemVer = Annotated[str, StringConstraints(max_length=32, pattern=r"^\d+\.\d+\.\d+$")]
UuidV7 = Annotated[
    str,
    StringConstraints(
        pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
    ),
]
HexDigest = Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F]{64}$")]
Base64Url = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]+$")]


def _require_utf8_bytes(value: str, maximum: int, *, label: str = "string") -> str:
    """Require a scalar string to fit the wire's UTF-8 byte ceiling."""

    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{label} contains invalid Unicode") from exc
    if len(encoded) > maximum:
        raise ValueError(f"{label} exceeds {maximum} UTF-8 bytes")
    return value


def _bounded_error_code(value: str) -> str:
    return _require_utf8_bytes(value, 128, label="error code")


def _bounded_message(value: str) -> str:
    return _require_utf8_bytes(value, 8_192, label="message")


def _bounded_reason(value: str) -> str:
    return _require_utf8_bytes(value, 8_192, label="reason")


# The character constraints keep Pydantic's generated schemas descriptive,
# while these validators enforce the actual v0.1 byte limits used by the
# TypeScript reference.
ErrorCode = Annotated[
    str,
    StringConstraints(min_length=1, max_length=128),
    AfterValidator(_bounded_error_code),
]
BoundedMessage = Annotated[
    str,
    StringConstraints(min_length=1, max_length=8_192),
    AfterValidator(_bounded_message),
]
BoundedReason = Annotated[
    str,
    StringConstraints(max_length=8_192),
    AfterValidator(_bounded_reason),
]


def _normalise_safe_integral_wire_numbers(value: Any) -> Any:
    """Mirror JavaScript's one numeric type before strict model validation.

    JSON ``1.0`` is a Number in the reference implementation and therefore
    satisfies ``Number.isSafeInteger`` for integer wire fields.  Python's
    strict Pydantic ``int`` fields distinguish it from ``1`` unless the raw
    record is normalized at this boundary.
    """

    if isinstance(value, float) and math.isfinite(value) and value.is_integer() and -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
        return int(value)
    return value


def _strict_wire_context(info: ValidationInfo) -> bool:
    """Whether validation is processing an untrusted v0.1 wire record."""

    return bool(info.context and info.context.get("polymesh.strict_wire"))


def _require_canonical_base64url(value: str, bytes_required: int) -> str:
    """Require unpadded, canonical URL-safe base64 of one exact length."""

    if not isinstance(value, str) or not value or "=" in value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("invalid base64url")
    if len(value) % 4 == 1:
        raise ValueError("invalid base64url")
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except Exception as exc:  # pragma: no cover - implementation-specific decoder error
        raise ValueError("invalid base64url") from exc
    if len(raw) != bytes_required:
        raise ValueError(f"base64url value must encode {bytes_required} bytes")
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        raise ValueError("base64url value is not canonical")
    return value


def base64url_decode_exact(value: str, bytes_required: int) -> bytes:
    _require_canonical_base64url(value, bytes_required)
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def base64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _require_utc_millis(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", value):
        raise ValueError("timestamp must be RFC 3339 UTC with milliseconds")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("timestamp is invalid") from exc
    if parsed.utcoffset() != timedelta(0) or format_timestamp(parsed) != value:
        raise ValueError("timestamp is not canonical UTC milliseconds")
    return value


def parse_timestamp(value: str) -> datetime:
    _require_utc_millis(value)
    return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(UTC)


def format_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    value = value.astimezone(UTC)
    milliseconds = value.microsecond // 1_000
    # ``strftime('%Y')`` is not consistently zero-padded for years below
    # 1000 on POSIX platforms, whereas the v0.1 wire format always has four
    # year digits.
    return (
        f"{value.year:04d}-{value.month:02d}-{value.day:02d}"
        f"T{value.hour:02d}:{value.minute:02d}:{value.second:02d}.{milliseconds:03d}Z"
    )


def utc_now_millis() -> str:
    return format_timestamp(datetime.now(UTC))


InstanceId = Annotated[Base64Url, AfterValidator(lambda value: _require_canonical_base64url(value, 16))]
Nonce = Annotated[Base64Url, AfterValidator(lambda value: _require_canonical_base64url(value, 32))]
SessionId = Annotated[Base64Url, AfterValidator(lambda value: _require_canonical_base64url(value, 32))]
Ed25519PublicKey = Annotated[Base64Url, AfterValidator(lambda value: _require_canonical_base64url(value, 32))]
Ed25519KeyId = Annotated[Base64Url, AfterValidator(lambda value: _require_canonical_base64url(value, 32))]
Ed25519Signature = Annotated[Base64Url, AfterValidator(lambda value: _require_canonical_base64url(value, 64))]
Timestamp = Annotated[str, AfterValidator(_require_utc_millis)]


class WireModel(BaseModel):
    """Strict, closed model used for every v0.1 record shape."""

    model_config = ConfigDict(extra="forbid", strict=True, populate_by_name=True)

    # Pydantic's ``T | None = None`` is useful for ergonomic local builders,
    # but JSON ``null`` is not interchangeable with an omitted optional v0.1
    # member.  Strict parser entry points set a validation context so models
    # can retain that distinction without making local construction awkward.
    _wire_allowed_null_fields: ClassVar[frozenset[str]] = frozenset()
    _wire_required_fields: ClassVar[frozenset[str]] = frozenset()
    _wire_preserved_null_fields: ClassVar[frozenset[str]] = frozenset()

    @model_validator(mode="before")
    @classmethod
    def validate_wire_scalars(cls, value: Any, info: ValidationInfo) -> Any:
        # Do this only one object level deep.  Nested wire models run the
        # same boundary themselves, which avoids walking attacker-controlled
        # cyclic local Python objects before Pydantic can reject them.
        if isinstance(value, dict):
            if _strict_wire_context(info):
                missing = cls._wire_required_fields.difference(value)
                if missing:
                    raise ValueError(f"missing required wire member: {sorted(missing)[0]}")
                for key, item in value.items():
                    if item is None and key not in cls._wire_allowed_null_fields:
                        raise ValueError(f"wire member {key} must be omitted rather than null")
            return {key: _normalise_safe_integral_wire_numbers(item) for key, item in value.items()}
        return value

    def model_dump(self, *args: Any, **kwargs: Any) -> dict[str, Any]:  # type: ignore[override]
        """Keep explicitly supplied semantic JSON nulls under ``exclude_none``."""

        dumped = super().model_dump(*args, **kwargs)
        if kwargs.get("exclude_none") and isinstance(dumped, dict):
            excluded = kwargs.get("exclude")
            for field in self._wire_preserved_null_fields:
                if (
                    (field in self.model_fields_set or field in self._wire_required_fields)
                    and getattr(self, field, object()) is None
                ):
                    if not isinstance(excluded, set | frozenset | list | tuple | dict) or field not in excluded:
                        dumped[field] = None
        return dumped


class DeliveryMode(str, Enum):
    AT_LEAST_ONCE = "at_least_once"


class TaskStatus(str, Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    REJECTED = "rejected"
    RECOVERY_REQUIRED = "recovery_required"


class ClientPhase(str, Enum):
    IDLE = "idle"
    AWAIT_HELLO = "await_hello"
    AWAIT_CARD = "await_card"
    AWAIT_AUTH = "await_auth"
    AWAIT_READY = "await_ready"
    ACTIVE = "active"
    CLOSED = "closed"


class ErrorCategory(str, Enum):
    PARSE = "parse"
    PROTOCOL = "protocol"
    IDENTITY = "identity"
    ROUTING = "routing"
    DELIVERY = "delivery"
    RESOURCE = "resource"
    TASK = "task"
    EXECUTION = "execution"
    INTERNAL = "internal"


class AgentRef(WireModel):
    agent_id: AgentId
    instance_id: InstanceId | None = None


class AgentIdentity(AgentRef):
    instance_id: InstanceId


class Delivery(WireModel):
    mode: DeliveryMode = DeliveryMode.AT_LEAST_ONCE
    idempotency_key: Annotated[str, StringConstraints(min_length=1, max_length=MAX_IDEMPOTENCY_KEY_BYTES)]
    deadline: Timestamp

    @field_validator("mode", mode="before")
    @classmethod
    def parse_delivery_mode(cls, value: DeliveryMode | str) -> DeliveryMode:
        try:
            return value if isinstance(value, DeliveryMode) else DeliveryMode(value)
        except ValueError as exc:
            raise ValueError("delivery mode is invalid") from exc

    @field_validator("idempotency_key")
    @classmethod
    def validate_idempotency_key_bytes(cls, value: str) -> str:
        if len(value.encode("utf-8")) > MAX_IDEMPOTENCY_KEY_BYTES:
            raise ValueError("idempotency key exceeds 256 UTF-8 bytes")
        return value


class CapabilityContractTuple(WireModel):
    capability_id: CapabilityId
    capability_version: SemVer
    capability_contract_digest: HexDigest


class Endpoint(WireModel):
    transport: Literal["websocket", "unix"]
    url: Annotated[str, StringConstraints(min_length=1, max_length=2_048)]
    scope: Literal["loopback", "lan", "remote"]
    security: Literal["none", "token", "mutual"] | None = None

    @field_validator("url")
    @classmethod
    def validate_url_bytes(cls, value: str) -> str:
        return _require_utf8_bytes(value, 2_048, label="endpoint URL")

    @model_validator(mode="after")
    def validate_transport_url(self) -> Self:
        parsed = urlsplit(self.url)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("endpoint URL has forbidden components")
        if self.transport == "websocket":
            if parsed.scheme not in {"ws", "wss"} or not parsed.hostname:
                raise ValueError("websocket endpoint URL is invalid")
            if self.scope != "loopback" and parsed.scheme != "wss":
                raise ValueError("LAN and remote WebSocket endpoints require WSS")
        elif parsed.scheme != "unix" or parsed.netloc or not parsed.path.startswith("/") or "/../" in parsed.path:
            raise ValueError("unix endpoint URL is invalid")
        return self


class Limits(WireModel):
    max_task_timeout_ms: int | None = Field(default=None, ge=0, le=MAX_SAFE_INTEGER)
    max_tasks_per_principal: int | None = Field(default=None, ge=0, le=MAX_SAFE_INTEGER)
    max_input_bytes: int | None = Field(default=None, ge=0, le=MAX_SAFE_INTEGER)
    max_result_bytes: int | None = Field(default=None, ge=0, le=MAX_SAFE_INTEGER)


class CardMetadata(BaseModel):
    model_config = ConfigDict(extra="allow", strict=True)

    description: str | None = Field(default=None, max_length=MAX_JSON_STRING_BYTES)
    tags: list[str] | None = None
    icon: str | None = Field(default=None, max_length=2_048)

    @model_validator(mode="before")
    @classmethod
    def reject_known_null_wire_fields(cls, value: Any, info: ValidationInfo) -> Any:
        if _strict_wire_context(info) and isinstance(value, dict):
            for field in ("description", "tags", "icon"):
                if field in value and value[field] is None:
                    raise ValueError(f"wire member {field} must be omitted rather than null")
        return value

    def model_dump(self, *args: Any, **kwargs: Any) -> dict[str, Any]:  # type: ignore[override]
        dumped = super().model_dump(*args, **kwargs)
        if kwargs.get("exclude_none") and isinstance(dumped, dict):
            # Metadata extras are arbitrary JSON values, so an explicit null
            # is meaningful and must survive card canonicalization.
            for field, value in (self.model_extra or {}).items():
                if value is None:
                    dumped[field] = None
        return dumped

    @field_validator("description")
    @classmethod
    def validate_description_bytes(cls, value: str | None) -> str | None:
        return None if value is None else _require_utf8_bytes(value, MAX_JSON_STRING_BYTES, label="metadata description")

    @field_validator("icon")
    @classmethod
    def validate_icon_bytes(cls, value: str | None) -> str | None:
        return None if value is None else _require_utf8_bytes(value, 2_048, label="metadata icon")

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return value
        if len(value) > 32 or len(set(value)) != len(value):
            raise ValueError("tags must be unique and bounded")
        if any(not item for item in value):
            raise ValueError("tags contain an invalid value")
        for item in value:
            _require_utf8_bytes(item, 64, label="metadata tag")
        return value

    @model_validator(mode="after")
    def validate_extra_values(self) -> Self:
        # Deferred import avoids a protocol/types import cycle.
        from .protocol import validate_json_tree

        for value in (self.model_extra or {}).values():
            validate_json_tree(value)
        return self


class Capability(WireModel):
    id: CapabilityId
    version: SemVer
    description: str | None = Field(default=None, max_length=MAX_JSON_STRING_BYTES)
    input_schema: JsonObject | None = None
    result_schema: JsonObject | None = None
    idempotency: Literal["pure", "idempotent", "sensitive"] | None = None
    side_effects: Literal["none", "read", "write", "network", "approval"] | None = None
    approval: Literal["never", "always", "threshold"] | None = None
    cancellation: Literal["none", "best_effort", "supported"] | None = None
    timeout_ceiling_seconds: int | None = Field(default=None, ge=1, le=MAX_SAFE_INTEGER)

    @field_validator("description")
    @classmethod
    def validate_description_bytes(cls, value: str | None) -> str | None:
        return None if value is None else _require_utf8_bytes(value, MAX_JSON_STRING_BYTES, label="capability description")

    @field_validator("input_schema", "result_schema")
    @classmethod
    def validate_schema(cls, value: JsonObject | None) -> JsonObject | None:
        if value is None:
            return value
        from .protocol import encoded_json_bytes, validate_json_tree, validate_restricted_schema

        validate_json_tree(value)
        if encoded_json_bytes(value) > MAX_SCHEMA_BYTES_PER_CAPABILITY:
            raise ValueError("capability schema exceeds 16 KiB")
        validate_restricted_schema(value)
        return value


class CardIdentity(WireModel):
    alg: Literal["Ed25519"] = "Ed25519"
    key_id: Ed25519KeyId
    public_key: Ed25519PublicKey

    @model_validator(mode="after")
    def validate_key_id(self) -> Self:
        if key_id_from_raw_ed25519_public_key(self.public_key) != self.key_id:
            raise ValueError("key_id does not hash the public key")
        return self


class AgentCard(WireModel):
    card_version: Literal["1.0"] = CARD_VERSION
    agent_id: AgentId
    instance_id: InstanceId
    display_name: str | None = Field(default=None, max_length=MAX_JSON_STRING_BYTES)
    issued_at: Timestamp
    expires_at: Timestamp
    revision: int = Field(ge=1, le=MAX_SAFE_INTEGER)
    endpoints: list[Endpoint] | None = None
    capabilities: list[Capability] = Field(min_length=1, max_length=MAX_CAPABILITIES_PER_CARD)
    limits: Limits | None = None
    metadata: CardMetadata | None = None
    identity: CardIdentity | None = None
    signature: Ed25519Signature | None = None

    @field_validator("display_name")
    @classmethod
    def validate_display_name_bytes(cls, value: str | None) -> str | None:
        return None if value is None else _require_utf8_bytes(value, MAX_JSON_STRING_BYTES, label="card display name")

    def model_dump(self, *args: Any, **kwargs: Any) -> dict[str, Any]:  # type: ignore[override]
        dumped = super().model_dump(*args, **kwargs)
        if self.metadata is not None:
            # See CardMetadata.model_dump: arbitrary metadata permits JSON
            # null, and Pydantic's outer serializer otherwise elides it.
            dumped["metadata"] = self.metadata.model_dump(*args, **kwargs)
        return dumped

    @field_validator("endpoints")
    @classmethod
    def validate_endpoints(cls, value: list[Endpoint] | None) -> list[Endpoint] | None:
        if value is not None and len(value) > MAX_ENDPOINTS_PER_CARD:
            raise ValueError("too many card endpoints")
        return value

    @model_validator(mode="after")
    def validate_card(self) -> Self:
        if parse_timestamp(self.expires_at) <= parse_timestamp(self.issued_at):
            raise ValueError("expires_at must follow issued_at")
        capability_ids = [capability.id for capability in self.capabilities]
        if len(set(capability_ids)) != len(capability_ids):
            raise ValueError("duplicate capability ID")
        required = {
            "org.polymesh.agent.ping",
            "org.polymesh.agent.info",
            "org.polymesh.capabilities.list",
        }
        if not required.issubset(capability_ids):
            raise ValueError("card lacks mandatory standard capabilities")
        if (self.identity is None) != (self.signature is None):
            raise ValueError("identity and signature must occur together")
        from .protocol import encoded_json_bytes, verify_agent_card_signature

        if encoded_json_bytes(self.model_dump(mode="json", exclude_none=True)) > MAX_CARD_BYTES:
            raise ValueError("card exceeds 64 KiB")
        if self.identity is not None and not verify_agent_card_signature(self):
            raise ValueError("card signature is invalid")
        return self


STANDARD_CAPABILITIES: tuple[Capability, ...] = (
    Capability(id="org.polymesh.agent.ping", version="1.0.0", idempotency="pure", side_effects="none"),
    Capability(id="org.polymesh.agent.info", version="1.0.0", idempotency="pure", side_effects="none"),
    Capability(id="org.polymesh.capabilities.list", version="1.0.0", idempotency="pure", side_effects="none"),
)


class CapabilityBuilder:
    def __init__(self, capability_id: str, version: str = "1.0.0") -> None:
        self._values: dict[str, object] = {"id": capability_id, "version": version}

    def schemas(
        self,
        *,
        input_schema: JsonObject | None = None,
        result_schema: JsonObject | None = None,
    ) -> Self:
        self._values["input_schema"] = input_schema
        self._values["result_schema"] = result_schema
        return self

    def execution(
        self,
        *,
        idempotency: Literal["pure", "idempotent", "sensitive"] = "idempotent",
        side_effects: Literal["none", "read", "write", "network", "approval"] = "none",
        approval: Literal["never", "always", "threshold"] = "never",
        cancellation: Literal["none", "best_effort", "supported"] = "none",
        timeout_ceiling_seconds: int = 300,
    ) -> Self:
        self._values.update(
            idempotency=idempotency,
            side_effects=side_effects,
            approval=approval,
            cancellation=cancellation,
            timeout_ceiling_seconds=timeout_ceiling_seconds,
        )
        return self

    def describe(self, text: str) -> Self:
        self._values["description"] = text
        return self

    def build(self) -> Capability:
        return Capability.model_validate(self._values)


class AgentCardBuilder:
    def __init__(self, agent_id: str) -> None:
        self._agent_id = agent_id
        self._display_name: str | None = None
        self._instance_id: str | None = None
        self._issued_at: str | None = None
        self._expires_at: str | None = None
        self._revision = 1
        self._capabilities: list[Capability] = []
        self._endpoints: list[Endpoint] = []
        self._limits: Limits | None = None
        self._metadata: CardMetadata | None = None
        self._include_standard = True

    def display_name(self, value: str) -> Self:
        self._display_name = value
        return self

    def instance_id(self, value: str) -> Self:
        self._instance_id = value
        return self

    def revision(self, value: int) -> Self:
        self._revision = value
        return self

    def issued_at(self, value: str) -> Self:
        self._issued_at = value
        return self

    def expires_at(self, value: str) -> Self:
        self._expires_at = value
        return self

    def valid_for(self, duration: timedelta) -> Self:
        if duration.total_seconds() <= 0:
            raise ValueError("card validity must be positive")
        issued = utc_now_millis()
        self._issued_at = issued
        self._expires_at = format_timestamp(parse_timestamp(issued) + duration)
        return self

    def capability(self, value: Capability) -> Self:
        if any(existing.id == value.id for existing in self._capabilities):
            raise ValueError(f"duplicate capability: {value.id}")
        self._capabilities.append(value)
        return self

    def endpoint(self, value: Endpoint) -> Self:
        self._endpoints.append(value)
        return self

    def limits(self, value: Limits) -> Self:
        self._limits = value
        return self

    def metadata(self, value: CardMetadata) -> Self:
        self._metadata = value
        return self

    def include_standard_capabilities(self, enabled: bool) -> Self:
        self._include_standard = enabled
        return self

    def build(self) -> AgentCard:
        issued_at = self._issued_at or utc_now_millis()
        expires_at = self._expires_at or format_timestamp(parse_timestamp(issued_at) + timedelta(hours=1))
        supplied = list(self._capabilities)
        if self._include_standard:
            # The reference's canonical baseline entries win if a caller tries
            # to redefine one of them in the builder.
            capabilities = [
                *(item.model_copy(deep=True) for item in STANDARD_CAPABILITIES),
                *(item for item in supplied if item.id not in {base.id for base in STANDARD_CAPABILITIES}),
            ]
        else:
            capabilities = supplied
        return AgentCard(
            agent_id=self._agent_id,
            instance_id=self._instance_id or random_instance_id(),
            display_name=self._display_name,
            issued_at=issued_at,
            expires_at=expires_at,
            revision=self._revision,
            endpoints=self._endpoints or None,
            capabilities=capabilities,
            limits=self._limits,
            metadata=self._metadata,
        )


class Enrollment(WireModel):
    agent_id: AgentId
    key_id: Ed25519KeyId
    public_key: Ed25519PublicKey
    enabled: bool | None = None
    expires_at: Timestamp | None = None

    @model_validator(mode="after")
    def validate_key_binding(self) -> Self:
        CardIdentity(key_id=self.key_id, public_key=self.public_key)
        return self


class VerifiedPrincipal(WireModel):
    principal_id: str
    agent_id: AgentId
    key_id: Ed25519KeyId
    public_key: Ed25519PublicKey
    auth_strength: Literal["enrolled-key"] = "enrolled-key"

    @model_validator(mode="after")
    def validate_principal(self) -> Self:
        if self.principal_id != f"key:{self.key_id}":
            raise ValueError("principal ID is not key-bound")
        CardIdentity(key_id=self.key_id, public_key=self.public_key)
        return self


class RoutedProvenanceBroker(WireModel):
    agent_id: AgentId
    instance_id: InstanceId
    key_id: Ed25519KeyId


class RoutedProvenancePrincipal(WireModel):
    principal_id: str
    agent_id: AgentId
    key_id: Ed25519KeyId

    @model_validator(mode="after")
    def validate_principal(self) -> Self:
        if self.principal_id != f"key:{self.key_id}":
            raise ValueError("source principal is not key-bound")
        return self


class RoutedProvenance(WireModel):
    version: Literal["pmx.broker-provenance/1"] = ROUTED_PROVENANCE_VERSION
    broker: RoutedProvenanceBroker
    source_principal: RoutedProvenancePrincipal
    source: AgentIdentity
    target: AgentRef
    source_session_id: SessionId
    target_session_id: SessionId
    envelope_digest: HexDigest
    issued_at: Timestamp
    expires_at: Timestamp
    signature: Ed25519Signature

    @model_validator(mode="after")
    def validate_lifetime(self) -> Self:
        issued = parse_timestamp(self.issued_at)
        expires = parse_timestamp(self.expires_at)
        if expires <= issued or expires - issued > timedelta(seconds=60):
            raise ValueError("provenance lifetime is invalid")
        if self.source.agent_id != self.source_principal.agent_id:
            raise ValueError("provenance source principal mismatch")
        return self


class StructuredError(WireModel):
    _wire_allowed_null_fields: ClassVar[frozenset[str]] = frozenset({"retry_after_ms"})
    _wire_required_fields: ClassVar[frozenset[str]] = frozenset({"retry_after_ms"})
    _wire_preserved_null_fields: ClassVar[frozenset[str]] = frozenset({"retry_after_ms"})

    category: ErrorCategory
    code: ErrorCode
    message: BoundedMessage
    retryable: bool
    retry_after_ms: int | None = Field(default=None, ge=0, le=MAX_SAFE_INTEGER)
    details: JsonObject | None = None

    @field_validator("category", mode="before")
    @classmethod
    def parse_category(cls, value: ErrorCategory | str) -> ErrorCategory:
        # ``strict=True`` correctly protects ordinary scalar coercion, but a
        # JSON wire string is the canonical representation of an Enum.
        try:
            return value if isinstance(value, ErrorCategory) else ErrorCategory(value)
        except ValueError as exc:
            raise ValueError("error category is invalid") from exc

    @field_validator("details")
    @classmethod
    def validate_details(cls, value: JsonObject | None) -> JsonObject | None:
        if value is not None:
            from .protocol import validate_json_tree

            validate_json_tree(value)
        return value


class Cancellation(WireModel):
    code: ErrorCode
    message: BoundedReason | None = None


class TerminalSucceeded(WireModel):
    _wire_allowed_null_fields: ClassVar[frozenset[str]] = frozenset({"result"})
    _wire_preserved_null_fields: ClassVar[frozenset[str]] = frozenset({"result"})

    outcome: Literal["succeeded"]
    result: JsonValue
    completed_at: Timestamp

    @field_validator("result")
    @classmethod
    def validate_result(cls, value: JsonValue) -> JsonValue:
        from .protocol import validate_json_tree

        validate_json_tree(value)
        return value


class TerminalFailure(WireModel):
    code: ErrorCode
    message: BoundedMessage
    details: JsonObject | None = None

    @field_validator("details")
    @classmethod
    def validate_details(cls, value: JsonObject | None) -> JsonObject | None:
        if value is not None:
            from .protocol import validate_json_tree

            validate_json_tree(value)
        return value


class TerminalFailed(WireModel):
    outcome: Literal["failed"]
    error: TerminalFailure
    completed_at: Timestamp


class TerminalCancelled(WireModel):
    outcome: Literal["cancelled"]
    cancellation: Cancellation
    completed_at: Timestamp


Terminal: TypeAlias = TerminalSucceeded | TerminalFailed | TerminalCancelled


class CardParams(WireModel):
    card: AgentCard
    digest: HexDigest

    def model_dump(self, *args: Any, **kwargs: Any) -> dict[str, Any]:  # type: ignore[override]
        dumped = super().model_dump(*args, **kwargs)
        dumped["card"] = self.card.model_dump(*args, **kwargs)
        return dumped

    @model_validator(mode="after")
    def verify_digest(self) -> Self:
        from .protocol import card_digest

        if card_digest(self.card) != self.digest:
            raise ValueError("card digest mismatch")
        return self


class TaskSubmitParams(WireModel):
    task_id: UuidV7
    method: CapabilityId
    capability_version: SemVer
    capability_contract_digest: HexDigest
    params: JsonObject
    deadline: Timestamp

    @field_validator("params")
    @classmethod
    def validate_params_tree(cls, value: JsonObject) -> JsonObject:
        from .protocol import validate_json_tree

        validate_json_tree(value)
        return value


class TaskAcceptedParams(CapabilityContractTuple):
    task_id: UuidV7
    event_seq: Literal[1]
    accepted_at: Timestamp


class TaskRejectedParams(WireModel):
    task_id: UuidV7
    event_seq: Literal[1]
    code: ErrorCode
    message: BoundedMessage


class TaskProgressParams(WireModel):
    task_id: UuidV7
    event_seq: int = Field(ge=2, le=MAX_SAFE_INTEGER)
    progress: JsonObject

    @field_validator("progress")
    @classmethod
    def validate_progress_tree(cls, value: JsonObject) -> JsonObject:
        from .protocol import validate_json_tree

        validate_json_tree(value)
        return value


class TaskCompletedParams(CapabilityContractTuple):
    task_id: UuidV7
    event_seq: int = Field(ge=2, le=MAX_SAFE_INTEGER)
    terminal: Terminal

    def model_dump(self, *args: Any, **kwargs: Any) -> dict[str, Any]:  # type: ignore[override]
        dumped = super().model_dump(*args, **kwargs)
        # Pydantic's compiled nested serializer bypasses the child model's
        # Python ``model_dump`` override.  Reinsert a succeeded null result,
        # which is valid JSON semantics rather than an omitted optional field.
        if isinstance(self.terminal, TerminalSucceeded):
            dumped["terminal"] = self.terminal.model_dump(*args, **kwargs)
        return dumped


class TaskCancelParams(WireModel):
    task_id: UuidV7
    reason: BoundedReason | None = None


class TaskStatusQueryParams(WireModel):
    kind: Literal["query"]
    task_id: UuidV7


class TaskStatusSnapshotParams(WireModel):
    _wire_allowed_null_fields: ClassVar[frozenset[str]] = frozenset({"state", "event_seq", "terminal", "progress"})
    _wire_preserved_null_fields: ClassVar[frozenset[str]] = frozenset({"state", "event_seq", "terminal", "progress"})

    kind: Literal["snapshot"]
    task_id: UuidV7
    observed_at: Timestamp
    state: JsonValue | None = None
    event_seq: JsonValue | None = None
    terminal: JsonValue | None = None
    progress: JsonValue | None = None

    @model_validator(mode="after")
    def validate_optional_json_fields(self) -> Self:
        from .protocol import validate_json_tree

        for value in (self.state, self.event_seq, self.terminal, self.progress):
            if value is not None:
                validate_json_tree(value)
        return self


TaskStatusSnapshotWire: TypeAlias = TaskStatusSnapshotParams
TaskStatusParams: TypeAlias = TaskStatusQueryParams | TaskStatusSnapshotParams


class PingParams(WireModel):
    n: int = Field(ge=0, le=MAX_SAFE_INTEGER)


class ReceiptParams(WireModel):
    received_message_id: UuidV7
    semantic_digest: HexDigest
    disposition: Literal["accepted", "duplicate", "rejected"]


Receipt = ReceiptParams

EnvelopeType: TypeAlias = Literal[
    "card",
    "task.submit",
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
]

PARAM_MODEL_BY_TYPE: dict[str, type[WireModel]] = {
    "card": CardParams,
    "task.submit": TaskSubmitParams,
    "task.accepted": TaskAcceptedParams,
    "task.rejected": TaskRejectedParams,
    "task.progress": TaskProgressParams,
    "task.completed": TaskCompletedParams,
    "task.cancel": TaskCancelParams,
    "task.status": TaskStatusQueryParams,
    "ping": PingParams,
    "pong": PingParams,
    "receipt": ReceiptParams,
    "error": StructuredError,
}


class Envelope(WireModel):
    protocol: Literal["polymesh.0.1"] = PROTOCOL_VERSION
    type: EnvelopeType
    message_id: UuidV7
    timestamp: Timestamp
    source: AgentIdentity
    target: AgentRef
    delivery: Delivery
    in_reply_to: UuidV7 | None = None
    provenance: RoutedProvenance | None = None
    params: JsonObject

    @field_validator("params")
    @classmethod
    def validate_params_tree(cls, value: JsonObject) -> JsonObject:
        from .protocol import validate_json_tree

        validate_json_tree(value)
        return value

    @model_validator(mode="after")
    def validate_type_specific_params(self, info: ValidationInfo) -> Self:
        model_type: type[WireModel]
        if self.type == "task.status":
            kind = self.params.get("kind")
            model_type = TaskStatusQueryParams if kind == "query" else TaskStatusSnapshotParams
        else:
            model_type = PARAM_MODEL_BY_TYPE[self.type]
        try:
            parameter_model = model_type.model_validate(self.params, context=info.context)
        except Exception as exc:
            raise ValueError(f"invalid {self.type} params") from exc
        self.params = parameter_model.model_dump(mode="json", exclude_none=True)
        if self.type == "task.submit" and self.params["deadline"] != self.delivery.deadline:
            raise ValueError("task.submit deadline must equal delivery deadline")
        if self.type == "receipt" and self.in_reply_to != self.params["received_message_id"]:
            raise ValueError("receipt in_reply_to must equal received_message_id")
        return self


class InitiatorHello(WireModel):
    type: Literal["hello"]
    v: Literal["0.1"] = HANDSHAKE_VERSION
    role: Literal["initiator"]
    agent_id: AgentId
    instance_id: InstanceId
    nonce: Nonce
    security_profile: Literal["enrolled-ed25519-tls-1.3"] | None = None


class ResponderHello(WireModel):
    type: Literal["hello"]
    v: Literal["0.1"] = HANDSHAKE_VERSION
    role: Literal["responder"]
    agent_id: AgentId
    instance_id: InstanceId
    nonce: Nonce
    echo: Nonce
    sid: SessionId
    security_profile: Literal["enrolled-ed25519-tls-1.3"] | None = None


class CardFrame(WireModel):
    type: Literal["card"]
    sid: SessionId
    for_nonce: Nonce
    digest: HexDigest
    card: AgentCard

    def model_dump(self, *args: Any, **kwargs: Any) -> dict[str, Any]:  # type: ignore[override]
        dumped = super().model_dump(*args, **kwargs)
        dumped["card"] = self.card.model_dump(*args, **kwargs)
        return dumped

    @model_validator(mode="after")
    def validate_digest(self) -> Self:
        from .protocol import card_digest

        if card_digest(self.card) != self.digest:
            raise ValueError("card digest mismatch")
        return self


class AuthFrame(WireModel):
    type: Literal["auth"]
    sid: SessionId
    agent_id: AgentId
    key_id: Ed25519KeyId
    signature: Ed25519Signature


class ReadyFrame(WireModel):
    type: Literal["ready"]
    sid: SessionId
    self_card: HexDigest
    peer_card: HexDigest


HandshakeFrame: TypeAlias = InitiatorHello | ResponderHello | CardFrame | AuthFrame | ReadyFrame


class ReconnectPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    enabled: bool = True
    initial_delay: float = Field(default=1.0, gt=0.0, le=60.0)
    maximum_delay: float = Field(default=60.0, gt=0.0, le=300.0)
    multiplier: float = Field(default=2.0, ge=1.0, le=10.0)
    jitter: float = Field(default=0.20, ge=0.0, le=1.0)
    reset_after_active: float = Field(default=90.0, gt=0.0)
    resend_pending: Literal[False] = False


class ClientLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    default_timeout: float = Field(default=60.0, gt=0.0)
    max_task_timeout: float = Field(default=300.0, gt=0.0, le=86_400.0)
    max_task_input_bytes: int = Field(default=256 * 1024, ge=1, le=MAX_FRAME_BYTES)
    max_result_bytes: int = Field(default=MAX_FRAME_BYTES, ge=1, le=MAX_FRAME_BYTES)
    max_pending_calls: int = Field(default=128, ge=1)
    max_local_tasks: int = Field(default=128, ge=1)
    max_inbound_dedupe_entries: int = Field(default=256, ge=1)
    max_progress_events_per_task: int = Field(default=256, ge=1)
    idempotency_retention: timedelta = Field(default=timedelta(hours=24))
    heartbeat_interval: float = Field(default=30.0, gt=0.0)
    pong_timeout: float = Field(default=5.0, gt=0.0)
    inbound_timeout: float = Field(default=90.0, gt=0.0)

    @field_validator("idempotency_retention")
    @classmethod
    def require_minimum_retention(cls, value: timedelta) -> timedelta:
        if value < timedelta(hours=24):
            raise ValueError("idempotency retention must be at least 24 hours")
        return value


class TLSOptions(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    ca_file: str | None = None
    cert_file: str | None = None
    key_file: str | None = None
    server_hostname: str | None = None


class SecureIdentityOptions(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    private_key: object
    enrollments: tuple[Enrollment, ...] | object
    tls: TLSOptions


class TaskSnapshot(BaseModel):
    """Local immutable-ish observation used by :class:`TaskHandle`."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    task_id: str
    submit_message_id: str
    status: TaskStatus
    last_event_seq: int = 0
    receipt: ReceiptParams | None = None


def random_instance_id() -> str:
    return base64url_encode(os.urandom(16))


def random_nonce() -> str:
    return base64url_encode(os.urandom(32))


def key_id_from_raw_ed25519_public_key(public_key: str | bytes) -> str:
    raw = base64url_decode_exact(public_key, 32) if isinstance(public_key, str) else bytes(public_key)
    if len(raw) != 32:
        raise ValueError("Ed25519 public key must contain 32 bytes")
    return base64url_encode(hashlib.sha256(raw).digest())


__all__ = [
    "AgentCard",
    "AgentCardBuilder",
    "AgentId",
    "AgentIdentity",
    "AgentRef",
    "AuthFrame",
    "Base64Url",
    "BoundedMessage",
    "BoundedReason",
    "CARD_VERSION",
    "Capability",
    "CapabilityBuilder",
    "CapabilityContractTuple",
    "CapabilityId",
    "CardFrame",
    "CardIdentity",
    "CardMetadata",
    "CardParams",
    "Cancellation",
    "ClientLimits",
    "ClientPhase",
    "Delivery",
    "DeliveryMode",
    "Ed25519KeyId",
    "Ed25519PublicKey",
    "Ed25519Signature",
    "Enrollment",
    "Endpoint",
    "Envelope",
    "EnvelopeType",
    "ErrorCategory",
    "ErrorCode",
    "HANDSHAKE_VERSION",
    "HandshakeFrame",
    "HexDigest",
    "InitiatorHello",
    "InstanceId",
    "JsonObject",
    "JsonPrimitive",
    "JsonValue",
    "Limits",
    "MAX_CAPABILITIES_PER_CARD",
    "MAX_CARD_BYTES",
    "MAX_ENDPOINTS_PER_CARD",
    "MAX_FRAME_BYTES",
    "MAX_IDEMPOTENCY_KEY_BYTES",
    "MAX_JSON_ARRAY_ITEMS",
    "MAX_JSON_DEPTH",
    "MAX_JSON_NODES",
    "MAX_JSON_OBJECT_MEMBERS",
    "MAX_JSON_STRING_BYTES",
    "MAX_SAFE_INTEGER",
    "MAX_SCHEMA_BYTES_PER_CAPABILITY",
    "Nonce",
    "PARAM_MODEL_BY_TYPE",
    "PROTOCOL_VERSION",
    "PingParams",
    "ReadyFrame",
    "Receipt",
    "ReceiptParams",
    "ReconnectPolicy",
    "ResponderHello",
    "ROUTED_PROVENANCE_VERSION",
    "RoutedProvenance",
    "RoutedProvenanceBroker",
    "RoutedProvenancePrincipal",
    "SECURE_IDENTITY_PROFILE",
    "STANDARD_CAPABILITIES",
    "SecureIdentityOptions",
    "SemVer",
    "SessionId",
    "StructuredError",
    "TLSOptions",
    "TaskAcceptedParams",
    "TaskCancelParams",
    "TaskCompletedParams",
    "TaskProgressParams",
    "TaskRejectedParams",
    "TaskSnapshot",
    "TaskStatus",
    "TaskStatusParams",
    "TaskStatusQueryParams",
    "TaskStatusSnapshotParams",
    "TaskStatusSnapshotWire",
    "TaskSubmitParams",
    "Terminal",
    "TerminalCancelled",
    "TerminalFailed",
    "TerminalFailure",
    "TerminalSucceeded",
    "Timestamp",
    "UuidV7",
    "VerifiedPrincipal",
    "WireModel",
    "base64url_decode_exact",
    "base64url_encode",
    "format_timestamp",
    "key_id_from_raw_ed25519_public_key",
    "parse_timestamp",
    "random_instance_id",
    "random_nonce",
    "utc_now_millis",
]

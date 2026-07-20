# PolyMesh Python SDK Specification

> **Status:** Internal implementation specification
>
> **Target wire profile:** `polymesh.0.1`
>
> **Reference authority:** the local TypeScript `protocol.ts`, `broker.ts`,
> `client.ts`, and `SPEC.md` reviewed with this document.
>
> **Confidentiality:** This document is governed by the local `AGENTS.md`
> protocol-governance policy. Do not publish or distribute it outside an
> authorized LatticeAG environment.

## 1. Purpose and conformance boundary

This document specifies the Python package named `polymesh`. It defines a
Pythonic, async-first SDK which interoperates with the TypeScript reference
broker and client on the selected PolyMesh v0.1 wire profile.

The words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and
**MAY** are normative.

The source implementation, rather than prose which conflicts with it, is the
wire authority. In particular, the Python SDK MUST follow these resolutions:

| Topic | Python SDK requirement |
|---|---|
| WebSocket framing | One complete UTF-8 JSON value in one WebSocket text message. It is not newline-delimited JSON. |
| Unix framing | A 4-byte big-endian payload length followed by UTF-8 JSON bytes. It is not newline-delimited JSON. |
| Protocol profile | Implement `polymesh.0.1` only for the initial SDK. Reject v0.2 records on a v0.1 connection. |
| Loopback authentication | Send the runtime token only in the HTTP upgrade header `x-polymesh-token`. It is not an `auth` frame credential. |
| Secure handshake order | `hello`, `card`, secure-only `auth`, then `ready`. Cards are exchanged before proof-of-possession. |
| Delivery mode | The sole accepted v0.1 wire value is `at_least_once`. Do not serialize `at_most_once` or `exactly_once`. |
| Capability result field | Use `result_schema`, not `output_schema`. |
| Task identifier | Carry `task_id` in type-specific `params`; it is not an Envelope top-level field. |
| Reconnect | It is a local SDK extension. It cannot transparently resume or resend a live v0.1 task. |

### 1.1 In scope

The v0.1 Python SDK includes:

- strict, bounded JSON parsing and v0.1 protocol validation;
- Pydantic v2 models for wire records and SDK configuration;
- an asyncio `PolyMeshClient` with client calls and inbound handlers;
- loopback WebSocket runtime-token sessions;
- optional Unix-domain support behind an explicit transport adapter;
- conditionally supported enrolled Ed25519/TLS 1.3 sessions;
- a safe reconnect facility for later work, not task resumption;
- a command-line interface, configuration loader, and conformance tests.

### 1.2 Explicitly out of scope for v0.1

The SDK MUST NOT pretend to support any of the following as v0.1 wire
features:

- a `resume`, `close`, or `close_ack` application record;
- v0.2 `delivery_id`, mesh IDs, `delivery.resume`, or v0.2 compression;
- automatic retry of an in-flight task after its broker session changes;
- exactly-once execution across a process crash;
- unverified WSS, WSS-to-WS downgrade, or raw-token WSS authentication;
- token placement in a URL, query string, card, envelope, logging field, or
  command-line argument.

### 1.3 Profile selection

The Python package MUST select a profile before processing the first record.
For this document, the only selected profile is:

```text
WebSocket subprotocol: polymesh.0.1
Envelope protocol:     polymesh.0.1
Handshake version:     0.1
Card version:          1.0
```

`polymesh.0.2` is a distinct profile with mesh-scoped addresses, distinct
handshake records, delivery identifiers, and fencing semantics. A future
`polymesh.v2` module MAY implement it, but it MUST not be represented by
optional fields on these v0.1 models.

## 2. Package, runtime, and dependency contract

### 2.1 Supported runtime

The package targets Python 3.11 and later. Python 3.11 is required for the
standard-library `asyncio.TaskGroup`, precise type syntax, and dependable
`ExceptionGroup` handling. Implementations MAY support Python 3.10 using a
compatibility layer, but such support is non-normative.

The primary public API is asyncio-native. No blocking network operation may
occur on the event-loop thread.

### 2.2 Required dependencies

| Dependency | Version policy | Use |
|---|---|---|
| `pydantic` | `>=2.7,<3` | closed wire/config models and generated JSON schemas |
| `websockets` | `>=13,<16` | loopback WebSocket carrier and standard async transport |
| `cryptography` | `>=42,<46` | Ed25519 cards, signatures, and secure-profile verification |
| `platformdirs` | `>=4,<5` | optional platform-safe config-location discovery |

Optional extras are:

| Extra | Dependency | Scope |
|---|---|---|
| `polymesh[http]` | `httpx` | an explicitly separate REST gateway adapter |
| `polymesh[mdns]` | `zeroconf` | future local discovery support |
| `polymesh[yaml]` | `PyYAML` | YAML config input; TOML works with the standard library |
| `polymesh[secure-carrier]` | carrier-specific package | exact TLS exporter capability for the enrolled profile |

`websockets` alone is sufficient for token-authenticated numeric-loopback
sessions. It is not by itself proof that an enrolled secure session can expose
the reference TLS exporter binding; see [Security](#10-security-and-identity).

### 2.3 Package layout

```text
polymesh/
├── pyproject.toml
├── README.md
├── src/
│   └── polymesh/
│       ├── __init__.py
│       ├── client.py
│       ├── types.py
│       ├── protocol.py
│       ├── transport.py
│       ├── auth.py
│       ├── errors.py
│       ├── discovery.py
│       ├── cli.py
│       ├── config.py
│       ├── _json.py
│       └── py.typed
└── tests/
    ├── unit/
    ├── vectors/
    ├── integration/
    └── security/
```

Responsibilities are deliberately separated:

| Module | Responsibility |
|---|---|
| `types.py` | Pydantic models, enums, local SDK models, builders |
| `protocol.py` | strict parser, IDs, canonical JSON, digests, frame codecs, validators |
| `transport.py` | WebSocket/Unix carriers, queues, connection generation, heartbeats |
| `auth.py` | token store, enrollment store, card/proof/provenance cryptography |
| `client.py` | public client API, handshake orchestration, task/call state, dispatch |
| `errors.py` | exception hierarchy and error-frame mapping |
| `discovery.py` | local card cache and future mDNS implementation |
| `config.py` | TOML/YAML/environment merge and validation |
| `cli.py` | command parsing, presentation, exit mapping |

### 2.4 Public exports

`polymesh.__init__` MUST export only stable, documented names:

```python
from polymesh.client import PolyMeshClient, Client, TaskContext, TaskHandle
from polymesh.errors import PolyMeshError
from polymesh.types import (
    AgentCard,
    AgentCardBuilder,
    AgentIdentity,
    AgentRef,
    Capability,
    CapabilityBuilder,
    Delivery,
    DeliveryMode,
    Envelope,
    TaskStatus,
)

__all__ = [
    "AgentCard",
    "AgentCardBuilder",
    "AgentIdentity",
    "AgentRef",
    "Capability",
    "CapabilityBuilder",
    "Client",
    "Delivery",
    "DeliveryMode",
    "Envelope",
    "PolyMeshClient",
    "PolyMeshError",
    "TaskContext",
    "TaskHandle",
    "TaskStatus",
]
```

The package MUST NOT expose a mutable module-global active client or token.

## 3. Public Python API

### 3.1 Design principles

The Python surface is intentionally more ergonomic than the TypeScript
surface while preserving every wire-relevant invariant. In particular:

- all lifecycle I/O is awaitable;
- the client binds to one asyncio loop;
- handler registration is thread-safe but handler execution happens on the
  owning loop;
- unknown outcomes are explicit exceptions, never silent retries;
- Pydantic model serialization uses `exclude_none=True` and field names
  matching the wire exactly;
- public methods validate before they enqueue bytes for sending.

The TypeScript reference exposes `setHandler`, `removeHandler`, `connect`,
`connectTransport`, `ready`, `call`, `cancel`, and `close`. Python adds
`disconnect`, a decorator-form `handle`, `discover`, and a task-handle form;
these are local API conveniences and do not introduce wire records.

### 3.2 `PolyMeshClient` constructor

```text
class PolyMeshClient:
    def __init__(
        self,
        *,
        card: AgentCard,
        broker_url: str | None = None,
        token: str | None = None,
        token_store: TokenStore | None = None,
        allow_insecure_loopback_development: bool = False,
        identity: SecureIdentityOptions | None = None,
        tls: TLSOptions | None = None,
        handlers: Mapping[str, TaskHandler] | None = None,
        default_timeout: float = 60.0,
        handshake_timeout: float = 5.0,
        reconnect: ReconnectPolicy | None = None,
        limits: ClientLimits | None = None,
        authorization: AuthorizationHook | None = None,
        replay_ledger: ReplayLedger | None = None,
        transport_factory: TransportFactory | None = None,
        clock: Clock | None = None,
    ) -> None
```

The signature block is formal API notation; constructor behavior is fully
specified by the requirements immediately below it.

Arguments have the following meaning:

| Argument | Requirement |
|---|---|
| `card` | A locally valid v0.1 card. Secure mode signs it during construction and requires it to be locally enrolled. |
| `broker_url` | A complete `ws`/`wss` endpoint, normally ending in `/polymesh`; a numeric-loopback origin MAY be normalized to that path. |
| `token` | Optional direct loopback runtime token. It MUST pass 32-byte canonical-base64url validation and MUST NOT be logged. |
| `token_store` | Preferred lazy token source. Default construction uses `~/.polymesh/token` only when explicitly requested by a CLI/default factory. |
| `allow_insecure_loopback_development` | Must be true for `ws://` and the host must be numeric loopback. |
| `identity` | Enables the fail-closed enrolled Ed25519/TLS profile. It cannot be combined with a runtime token. |
| `tls` | CA/client-certificate/key/SNI material used only by secure WSS. It cannot disable certificate or hostname checks. |
| `handlers` | Initial capability-to-handler mapping. Each capability must be declared in `card`. |
| `default_timeout` | Positive seconds; defaults to 60.0 and is capped by local/card capability policy. |
| `handshake_timeout` | Positive seconds; defaults to 5.0, matching the reference client. |
| `reconnect` | Local reconnect policy. Its default MUST have `resend_pending=False`. |
| `limits` | Local safety ceilings. Defaults are specified in [Resource limits](#73-resource-limits). |
| `authorization` | Optional handler-admission hook. A missing hook permits only the standard capabilities unless the application configures its own policy. |
| `replay_ledger` | Durable ledger required for secure side-effecting work. |
| `transport_factory` | Advanced injection point for tests, Unix transport, or a secure exporter-capable carrier. |
| `clock` | Injectable clock for deterministic test vectors. It exposes wall UTC time and monotonic time. |

The constructor MUST reject invalid combinations before opening a socket. For
example, it MUST reject WSS without secure identity, WS without explicit
numeric-loopback development permission, and an `identity` profile paired
with `token`.

### 3.3 Client state and properties

```text
phase -> ClientPhase                         read-only property
connected -> bool                            read-only property
broker_url -> str | None                     read-only property
broker_card -> AgentCard | None              read-only property
broker_identity -> AgentIdentity | None      read-only property
broker_principal -> VerifiedPrincipal | None read-only property
loop -> asyncio.AbstractEventLoop | None     read-only property
```

`phase` uses the wire-aligned values `idle`, `await_hello`, `await_card`,
`await_auth`, `await_ready`, `active`, and `closed`. Local transport state
such as `reconnect_wait` belongs to `connection_state`, not the wire phase.

`connected` is true only when the phase is `active` and the current transport
generation is still live. A TCP connection that has not passed `ready` is not
connected for API purposes.

### 3.4 Connection methods

```text
await connect(url: str | None = None) -> PolyMeshClient
await connect_transport(transport: WireTransport) -> PolyMeshClient
await ready() -> PolyMeshClient
await disconnect(code: int = 1000, reason: str = "client closed", wait: bool = True) -> None
close(code: int = 1000, reason: str = "client closed") -> None
```

`connect()` resolves only after the responder `ready` has been validated.
Concurrent calls share the same connection future. `connect_transport()` is a
test/embedding API; an injected transport must already be open or expose an
open callback. `ready()` returns immediately once active, otherwise delegates
to `connect()`.

`disconnect()` is the awaited, idempotent shutdown API. It cancels reconnect,
fences the current generation, sends a valid native WebSocket close when
possible, aborts local handlers, and completes after background tasks finish
when `wait=True`. `close()` starts the same transition but is safe to call
from synchronous cleanup code and does not wait.

### 3.5 Calling a capability

```text
await call(
    self,
    target: str,
    capability: str,
    input: JsonObject,
    *,
    target_instance_id: str | None = None,
    task_id: str | None = None,
    timeout: float | None = None,
    deadline: datetime | str | None = None,
    idempotency_key: str | None = None,
    capability_contract: Capability | None = None,
    capability_version: str | None = None,
    capability_contract_digest: str | None = None,
    result_schema: JsonObject | None = None,
    on_progress: ProgressCallback | None = None,
) -> JsonValue

await submit(
    self,
    target: str,
    capability: str,
    input: JsonObject,
    **options: Unpack[CallOptions],
) -> TaskHandle
```

`call()` is equivalent to awaiting `submit(target, capability, input)` and
then awaiting its `result()`. It resolves
only with a successful terminal result. A rejected, failed, cancelled,
timed-out, malformed, transport-lost, or recovery-unknown task raises a
typed exception.

The method MUST:

1. await an active session;
2. reject empty target/capability, arbitrary input scalars/arrays, and input
   above the configured byte limit;
3. derive a millisecond UTC deadline from `timeout` or validate an explicit
   deadline;
4. generate/validate UUIDv7 `task_id`;
5. resolve an exact capability contract;
6. validate input against the pinned input schema when present;
7. construct an exact `task.submit` envelope;
8. track causal lifecycle state until terminal completion or failure.

On a directly authenticated broker peer, the client MAY derive the contract
from `broker_card`. A routed secure target has no automatically authenticated
target card in v0.1; callers MUST pass `capability_contract` or an explicit
valid version/digest pair. The SDK MUST NOT guess a secure capability
contract.

### 3.6 `TaskHandle`

```text
TaskHandle.task_id -> str                              read-only property
TaskHandle.submit_message_id -> str                    read-only property
TaskHandle.status -> TaskStatus                        read-only property
TaskHandle.last_event_seq -> int                       read-only property
TaskHandle.receipt -> Receipt | None                   read-only property
await TaskHandle.result() -> JsonValue
await TaskHandle.cancel(reason: str | None = None) -> None
TaskHandle.add_progress_callback(callback: ProgressCallback) -> unsubscribe callable
TaskHandle.snapshot() -> TaskSnapshot
```

`TaskHandle.status` is an SDK-local observation, not a claim that the remote
broker has durably persisted that status. A transition to
`TaskStatus.RECOVERY_REQUIRED` means the session was lost after the task could
possibly have been written or admitted; it MUST NOT be silently changed to
`PENDING` on reconnect.

### 3.7 Cancellation and status

```text
await cancel(task_id: str, reason: str | None = None) -> None

await query_status(
    self,
    target: str,
    task_id: str,
    *,
    target_instance_id: str | None = None,
    timeout: float | None = None,
) -> TaskStatusSnapshotWire
```

`cancel()` sends a normal `task.cancel` envelope only for a locally pending
task by default. It does not resolve its result future. The executor decides
whether the terminal record is cancelled or completed.

`query_status()` sends `task.status` with a query object containing the exact
UUIDv7 task ID.
The reference broker routes this as ordinary target traffic; it does not give
it the pinned-route lifecycle authority of accepted/progress/completed
records. A caller MUST treat a status response as advisory unless its own
application defines stronger persistence semantics.

### 3.8 Handler registration

```text
TaskHandler = Callable[[JsonObject, TaskContext], Awaitable[JsonValue] | JsonValue]

set_handler(capability: str, handler: TaskHandler) -> PolyMeshClient
remove_handler(capability: str) -> bool
handle(capability: str) -> Callable[[TaskHandler], TaskHandler]
```

Decorator use is supported:

```python
client = PolyMeshClient(card=my_card, broker_url="ws://127.0.0.1:7337/polymesh")

@client.handle("org.example.calendar.read")
async def read_calendar(input: JsonObject, context: TaskContext) -> JsonValue:
    context.progress({"state": "running", "current": 1, "total": 2})
    return {"slots": []}
```

`set_handler()` MUST reject an empty capability, a non-callable handler, or a
capability not advertised in the local card. `remove_handler()` returns true
only when an existing registration was removed. A replacement must be atomic:
an inbound task sees either the prior handler or the replacement, never a
partially mutated registry.

### 3.9 `TaskContext`

```text
TaskContext fields:
  task_id: str
  source: AgentIdentity
  deadline: datetime
  result_schema: JsonObject | None
  cancelled: asyncio.Event
  generation: int

TaskContext.progress(progress: TaskProgress) -> None
TaskContext.raise_if_cancelled() -> None
```

`progress()` schedules an outbound `task.progress` only while the task is
active, has capacity, belongs to the current connection generation, and the
deadline has not elapsed. It returns no value so application code cannot
mistake enqueueing for delivery. `raise_if_cancelled()` raises
`TaskCancelledError` when the task was cancelled, timed out, disconnected, or
fenced by a new generation.

Handlers receive an immutable deep clone of the validated input. The SDK MUST
not let a handler mutate the model or a shared inbound JSON object after
admission.

### 3.10 Event subscriptions

The client exposes local event hooks. They do not create protocol event
subscriptions:

```text
on(event: ClientEventName, callback: ClientEventCallback) -> unsubscribe callable
async iterator envelopes() -> Envelope
```

Supported event names are `ready`, `envelope`, `progress`, `receipt`,
`protocol_error`, `close`, `reconnecting`, and `reconnected`. `on()` returns
an unsubscribe function. A callback failure MUST be isolated, reported as a
local callback error, and MUST NOT terminate the receiver task.

### 3.11 Discovery API

```text
await discover(
    self,
    *,
    refresh: bool = False,
    timeout: float = 2.0,
) -> list[AgentCard]
```

v0.1 has no broker discovery envelope. In the initial release,
`discover()` returns cards from an explicitly configured local cache or
configured discovery provider. It returns an empty list when none is enabled.
It MUST NOT fabricate peers from unverified data. mDNS is a v0.2 roadmap
feature; its results are hints and still require a normal authenticated card
exchange before use.

## 4. Complete type system and Pydantic models

### 4.1 Modeling rules

The models below are the normative Python v0.1 model surface. They use
Pydantic v2 and wire-name field spelling. They do **not** replace strict JSON
decoding: parsing first rejects duplicate members, invalid UTF-8, non-finite
numbers, unpaired surrogates, and resource-limit violations before a model is
constructed.

Every wire model has `extra="forbid"`. Optional wire members are omitted when
serialized; callers MUST use `model_dump(mode="json", exclude_none=True)`.
An SDK model may have local-only fields, but it MUST never be serialized by a
wire-model constructor.

```python
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Annotated, Final, Literal, TypeAlias

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

JsonPrimitive: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonPrimitive | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]

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
    StringConstraints(
        min_length=1,
        max_length=255,
        pattern=r"^[a-zA-Z][a-zA-Z0-9._-]*$",
    ),
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
ErrorCode = Annotated[str, StringConstraints(min_length=1, max_length=128)]
BoundedMessage = Annotated[str, StringConstraints(min_length=1, max_length=8_192)]
BoundedReason = Annotated[str, StringConstraints(max_length=8_192)]


class WireModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, populate_by_name=True)


def _require_canonical_base64url(value: str, bytes_required: int) -> str:
    """Decode without padding, require the exact raw length, then re-encode."""
    import base64

    if "=" in value:
        raise ValueError("base64url values are unpadded")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise ValueError("invalid base64url") from exc
    if len(raw) != bytes_required:
        raise ValueError(f"base64url value must encode {bytes_required} bytes")
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        raise ValueError("base64url value is not canonical")
    return value


def _require_utc_millis(value: str) -> str:
    import re

    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", value):
        raise ValueError("timestamp must be RFC 3339 UTC with milliseconds")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp is invalid") from exc
    if parsed.tzinfo != UTC or parsed.strftime("%Y-%m-%dT%H:%M:%S.") + f"{parsed.microsecond // 1000:03d}Z" != value:
        raise ValueError("timestamp is not canonical UTC milliseconds")
    return value


InstanceId = Annotated[Base64Url, AfterValidator(lambda value: _require_canonical_base64url(value, 16))]
Nonce = Annotated[Base64Url, AfterValidator(lambda value: _require_canonical_base64url(value, 32))]
SessionId = Annotated[Base64Url, AfterValidator(lambda value: _require_canonical_base64url(value, 32))]
Ed25519PublicKey = Annotated[Base64Url, AfterValidator(lambda value: _require_canonical_base64url(value, 32))]
Ed25519KeyId = Annotated[Base64Url, AfterValidator(lambda value: _require_canonical_base64url(value, 32))]
Ed25519Signature = Annotated[Base64Url, AfterValidator(lambda value: _require_canonical_base64url(value, 64))]
Timestamp = Annotated[str, AfterValidator(_require_utc_millis)]
```

The reference validates raw JSON tree size recursively, including values under
arbitrary capability schemas and `metadata`. The Pydantic type alias is
therefore only a type annotation. `parse_strict_json()` and
`validate_json_tree()` are REQUIRED before every `model_validate()` call and
before every canonicalization call.

### 4.2 Enumerations and basic address/delivery models

```python
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
    mode: Literal[DeliveryMode.AT_LEAST_ONCE] = DeliveryMode.AT_LEAST_ONCE
    idempotency_key: Annotated[str, StringConstraints(min_length=1, max_length=MAX_IDEMPOTENCY_KEY_BYTES)]
    deadline: Timestamp


class CapabilityContractTuple(WireModel):
    capability_id: CapabilityId
    capability_version: SemVer
    capability_contract_digest: HexDigest


class Endpoint(WireModel):
    transport: Literal["websocket", "unix"]
    url: Annotated[str, StringConstraints(min_length=1, max_length=2_048)]
    scope: Literal["loopback", "lan", "remote"]
    security: Literal["none", "token", "mutual"] | None = None

    @model_validator(mode="after")
    def validate_transport_url(self) -> Endpoint:
        from urllib.parse import urlsplit

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

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return value
        if len(value) > 32 or len(set(value)) != len(value):
            raise ValueError("tags must be unique and bounded")
        if any(not item or len(item.encode("utf-8")) > 64 for item in value):
            raise ValueError("tags contain an invalid value")
        return value

    @model_validator(mode="after")
    def validate_extra_values(self) -> CardMetadata:
        for value in self.model_extra.values() if self.model_extra else ():
            validate_json_tree(value)
        return self
```

`TaskStatus` is an SDK-local status enum. It is intentionally not used to
narrow the v0.1 wire `task.status` snapshot `state`: the TypeScript v0.1
validator accepts a bounded string there rather than a fixed state enum.

### 4.3 Capability and card models

```python
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

    @field_validator("input_schema", "result_schema")
    @classmethod
    def validate_schema(cls, value: JsonObject | None) -> JsonObject | None:
        if value is None:
            return value
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
    def validate_key_id(self) -> CardIdentity:
        if key_id_from_raw_ed25519_public_key(self.public_key) != self.key_id:
            raise ValueError("key_id does not hash the public key")
        return self


class AgentCard(WireModel):
    card_version: Literal[CARD_VERSION] = CARD_VERSION
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

    @field_validator("endpoints")
    @classmethod
    def validate_endpoints(cls, value: list[Endpoint] | None) -> list[Endpoint] | None:
        if value is not None and len(value) > MAX_ENDPOINTS_PER_CARD:
            raise ValueError("too many card endpoints")
        return value

    @model_validator(mode="after")
    def validate_card(self) -> AgentCard:
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
```

`validate_restricted_schema()` implements the reference secure restricted
schema profile, not arbitrary executable JSON Schema. It accepts only:
`$schema`, `type`, `const`, `enum`, `anyOf`, `oneOf`, `allOf`, `properties`,
`required`, `additionalProperties`, `items`, `minLength`, `maxLength`,
`minimum`, `maximum`, `minItems`, and `maxItems`; `$schema`, if supplied,
must be `polymesh.restricted-json-schema/1`. It MUST reject unsupported
keywords rather than silently ignoring them.

### 4.4 Card builders and factories

The builder API removes boilerplate without allowing an invalid card to be
emitted.

```python
class CapabilityBuilder:
    def __init__(self, capability_id: str, version: str = "1.0.0") -> None:
        self._values: dict[str, object] = {"id": capability_id, "version": version}

    def schemas(self, *, input_schema: JsonObject | None = None, result_schema: JsonObject | None = None) -> CapabilityBuilder:
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
    ) -> CapabilityBuilder:
        self._values.update(
            idempotency=idempotency,
            side_effects=side_effects,
            approval=approval,
            cancellation=cancellation,
            timeout_ceiling_seconds=timeout_ceiling_seconds,
        )
        return self

    def describe(self, text: str) -> CapabilityBuilder:
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

    def display_name(self, value: str) -> AgentCardBuilder:
        self._display_name = value
        return self

    def instance_id(self, value: str) -> AgentCardBuilder:
        self._instance_id = value
        return self

    def valid_for(self, duration: timedelta) -> AgentCardBuilder:
        if duration.total_seconds() <= 0:
            raise ValueError("card validity must be positive")
        issued = utc_now_millis()
        self._issued_at = issued
        self._expires_at = format_timestamp(parse_timestamp(issued) + duration)
        return self

    def capability(self, value: Capability) -> AgentCardBuilder:
        if any(existing.id == value.id for existing in self._capabilities):
            raise ValueError(f"duplicate capability: {value.id}")
        self._capabilities.append(value)
        return self

    def endpoint(self, value: Endpoint) -> AgentCardBuilder:
        self._endpoints.append(value)
        return self

    def limits(self, value: Limits) -> AgentCardBuilder:
        self._limits = value
        return self

    def metadata(self, value: CardMetadata) -> AgentCardBuilder:
        self._metadata = value
        return self

    def include_standard_capabilities(self, enabled: bool) -> AgentCardBuilder:
        self._include_standard = enabled
        return self

    def build(self) -> AgentCard:
        issued_at = self._issued_at or utc_now_millis()
        expires_at = self._expires_at or format_timestamp(parse_timestamp(issued_at) + timedelta(hours=1))
        capabilities = list(self._capabilities)
        if self._include_standard:
            present = {item.id for item in capabilities}
            capabilities = [*STANDARD_CAPABILITIES, *[item for item in capabilities if item.id not in present.intersection({base.id for base in STANDARD_CAPABILITIES})]]
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
```

An implementation MAY simplify the builder internals, but its observable
defaults MUST match the reference: card version `1.0`, random 16-byte
instance ID, current issued timestamp, one-hour expiry, revision `1`, and the
three standard capabilities. Calling `include_standard_capabilities(False)`
is useful only when a caller supplies those capabilities itself; otherwise the
card validator correctly rejects the result.

### 4.5 Enrollment, principal, and routed-provenance models

```python
class Enrollment(WireModel):
    agent_id: AgentId
    key_id: Ed25519KeyId
    public_key: Ed25519PublicKey
    enabled: bool | None = None
    expires_at: Timestamp | None = None

    @model_validator(mode="after")
    def validate_key_binding(self) -> Enrollment:
        identity = CardIdentity(key_id=self.key_id, public_key=self.public_key)
        if identity.alg != "Ed25519":
            raise ValueError("unsupported enrollment algorithm")
        return self


class VerifiedPrincipal(WireModel):
    principal_id: str
    agent_id: AgentId
    key_id: Ed25519KeyId
    public_key: Ed25519PublicKey
    auth_strength: Literal["enrolled-key"] = "enrolled-key"

    @model_validator(mode="after")
    def validate_principal(self) -> VerifiedPrincipal:
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
    def validate_principal(self) -> RoutedProvenancePrincipal:
        if self.principal_id != f"key:{self.key_id}":
            raise ValueError("source principal is not key-bound")
        return self


class RoutedProvenance(WireModel):
    version: Literal[ROUTED_PROVENANCE_VERSION] = ROUTED_PROVENANCE_VERSION
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
    def validate_lifetime(self) -> RoutedProvenance:
        issued = parse_timestamp(self.issued_at)
        expires = parse_timestamp(self.expires_at)
        if expires <= issued or expires - issued > timedelta(seconds=60):
            raise ValueError("provenance lifetime is invalid")
        if self.source.agent_id != self.source_principal.agent_id:
            raise ValueError("provenance source principal mismatch")
        return self
```

`Enrollment` is local trust configuration, not peer data. An Agent Card,
discovery record, hostname, TLS certificate, or presented public key MUST NOT
add or rotate an enrollment.

### 4.6 Terminal and task parameter models

```python
class StructuredError(WireModel):
    category: ErrorCategory
    code: ErrorCode
    message: BoundedMessage
    retryable: bool
    retry_after_ms: int | None = Field(default=None, ge=0, le=MAX_SAFE_INTEGER)
    details: JsonObject | None = None


class Cancellation(WireModel):
    code: ErrorCode
    message: BoundedReason | None = None


class TerminalSucceeded(WireModel):
    outcome: Literal["succeeded"]
    result: JsonValue
    completed_at: Timestamp


class TerminalFailure(WireModel):
    code: ErrorCode
    message: BoundedMessage
    details: JsonObject | None = None


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

    @model_validator(mode="after")
    def verify_digest(self) -> CardParams:
        if card_digest(self.card) != self.digest.lower():
            raise ValueError("card digest mismatch")
        return self


class TaskSubmitParams(WireModel):
    task_id: UuidV7
    method: CapabilityId
    capability_version: SemVer
    capability_contract_digest: HexDigest
    params: JsonObject
    deadline: Timestamp


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


class TaskCompletedParams(CapabilityContractTuple):
    task_id: UuidV7
    event_seq: int = Field(ge=2, le=MAX_SAFE_INTEGER)
    terminal: Terminal


class TaskCancelParams(WireModel):
    task_id: UuidV7
    reason: BoundedReason | None = None


class TaskStatusQueryParams(WireModel):
    kind: Literal["query"]
    task_id: UuidV7


class TaskStatusSnapshotParams(WireModel):
    kind: Literal["snapshot"]
    task_id: UuidV7
    observed_at: Timestamp
    state: JsonValue | None = None
    event_seq: JsonValue | None = None
    terminal: JsonValue | None = None
    progress: JsonValue | None = None


TaskStatusParams: TypeAlias = TaskStatusQueryParams | TaskStatusSnapshotParams


class PingParams(WireModel):
    n: int = Field(ge=0, le=MAX_SAFE_INTEGER)


class ReceiptParams(WireModel):
    received_message_id: UuidV7
    semantic_digest: HexDigest
    disposition: Literal["accepted", "duplicate", "rejected"]
```

The `TaskStatusSnapshotParams` field set exactly matches the permissive v0.1
validator: `kind`, `task_id`, and `observed_at` are required, while `state`,
`event_seq`, `terminal`, and `progress` are optional. It intentionally does
not import the stricter v0.2 snapshot state vocabulary.

### 4.7 Envelope model and type-specific validation

One base envelope model handles the closed common shape. It dispatches `params`
to the exact Pydantic model listed by `type`, then stores the validated JSON
form. This keeps `Envelope` usable for generic event consumers while retaining
closed type-specific validation.

```python
EnvelopeType = Literal[
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
    protocol: Literal[PROTOCOL_VERSION] = PROTOCOL_VERSION
    type: EnvelopeType
    message_id: UuidV7
    timestamp: Timestamp
    source: AgentIdentity
    target: AgentRef
    delivery: Delivery
    in_reply_to: UuidV7 | None = None
    provenance: RoutedProvenance | None = None
    params: JsonObject

    @model_validator(mode="after")
    def validate_type_specific_params(self) -> Envelope:
        parameter_model: WireModel
        if self.type == "task.status":
            kind = self.params.get("kind")
            model_type = TaskStatusQueryParams if kind == "query" else TaskStatusSnapshotParams
            parameter_model = model_type.model_validate(self.params)
        else:
            parameter_model = PARAM_MODEL_BY_TYPE[self.type].model_validate(self.params)
        self.params = parameter_model.model_dump(mode="json", exclude_none=True)
        if self.type == "task.submit" and self.params["deadline"] != self.delivery.deadline:
            raise ValueError("task.submit deadline must equal delivery deadline")
        if self.type == "receipt":
            received = self.params["received_message_id"]
            if self.in_reply_to != received:
                raise ValueError("receipt in_reply_to must equal received_message_id")
        return self
```

The base `Envelope` does not by itself authorize a record. Session state,
addressing, authenticated source identity, provenance, route ownership, and
lifecycle order are checked after structural validation.

### 4.8 Handshake frame models

Handshake frames are not Envelopes. They have no `protocol`, `message_id`,
`timestamp`, `source`, `target`, `delivery`, or `params` members.

```python
class InitiatorHello(WireModel):
    type: Literal["hello"]
    v: Literal[HANDSHAKE_VERSION] = HANDSHAKE_VERSION
    role: Literal["initiator"]
    agent_id: AgentId
    instance_id: InstanceId
    nonce: Nonce
    security_profile: Literal[SECURE_IDENTITY_PROFILE] | None = None


class ResponderHello(WireModel):
    type: Literal["hello"]
    v: Literal[HANDSHAKE_VERSION] = HANDSHAKE_VERSION
    role: Literal["responder"]
    agent_id: AgentId
    instance_id: InstanceId
    nonce: Nonce
    echo: Nonce
    sid: SessionId
    security_profile: Literal[SECURE_IDENTITY_PROFILE] | None = None


class CardFrame(WireModel):
    type: Literal["card"]
    sid: SessionId
    for_nonce: Nonce
    digest: HexDigest
    card: AgentCard


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
```

The session validator selects the allowed concrete class by state and role;
it does not accept any union member merely because it parses structurally.

### 4.9 Local-only configuration models

```python
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
    enrollments: tuple[Enrollment, ...] | EnrollmentStore
    tls: TLSOptions
```

`SecureIdentityOptions` is not a wire object and intentionally permits a
cryptography private-key object. An application may use PEM input in a
separate loader, but it MUST convert it to an Ed25519 key before client
construction.

### 4.10 Required JSON Schemas

Pydantic-generated schemas are useful to Python consumers, but the package
MUST ship checked-in Draft 2020-12 schemas for envelope, card, and handshake
records. The schemas are an interoperability aid, not a replacement for the
semantic/session validators. The complete canonical envelope schema appears
in [Appendix A](#appendix-a-json-schemas); `AgentCard.model_json_schema()`
and each parameter-model schema MUST be tested against its checked-in form.

## 5. Wire protocol binding

### 5.1 Record classes and phase legality

There are exactly two v0.1 record classes.

| Record class | Legal phase | Has Envelope fields? |
|---|---|---:|
| Handshake frame | Before `active` | No |
| Application/control envelope | After both sides validate `ready` | Yes |

Handshake-frame vocabulary:

```text
hello
card
auth
ready
```

Envelope type vocabulary:

```text
card
task.submit
task.accepted
task.rejected
task.progress
task.completed
task.cancel
task.status
ping
pong
receipt
error
```

The `card` name occurs in both vocabularies but describes different shapes.
Handshake card exchange uses `CardFrame`. A post-ready `Envelope` with
`type="card"` is structurally valid but the reference broker rejects it as
non-routable. Python MUST use a handshake `CardFrame` for initial exchange and
MUST NOT use a post-ready card envelope for peer discovery.

### 5.2 WebSocket framing

Each WebSocket text message contains exactly one UTF-8 JSON record:

```text
WebSocket text message payload = UTF-8 encoding of one complete JSON object
```

Requirements:

- Request exactly the `polymesh.0.1` WebSocket subprotocol.
- Reject a peer which does not select that subprotocol.
- Reject binary WebSocket messages.
- Disable WebSocket compression (`permessage-deflate`).
- Reject a text message whose UTF-8 byte length exceeds `1_048_576`.
- Do not concatenate objects into one WebSocket message.
- Do not split one protocol record across WebSocket messages.
- Do not treat newline as a protocol delimiter. Newline may occur only as JSON
  whitespace inside one message.

The Python `websockets` transport should use a bounded receive size and still
perform a byte count itself, because carrier settings alone are not a complete
protocol validation boundary.

### 5.3 Unix stream framing

Unix transport is optional in v0.1 Python but, if exposed, MUST use the same
record serialization and this framing:

```text
0                   31 32
+----------------------+-----------------------------------+
| N, unsigned big endian| N UTF-8 JSON bytes                |
+----------------------+-----------------------------------+
```

`N` is the payload size. The reference maximum applies to the whole wire
frame, so `N + 4 <= 1_048_576`. The decoder keeps incomplete prefix/body bytes
as a per-connection remainder, never treats them as a malformed record merely
because one stream read was short, and rejects an invalid UTF-8 payload before
JSON parsing.

Normative codec interface:

```python
def encode_unix_frame(record: HandshakeFrame | Envelope) -> bytes:
    payload = encode_record(record)
    if len(payload) + 4 > MAX_FRAME_BYTES:
        raise FrameTooLargeError("outbound Unix frame exceeds 1 MiB")
    return len(payload).to_bytes(4, "big") + payload


class UnixFrameDecoder:
    def __init__(self) -> None:
        self._remainder = bytearray()

    def feed(self, data: bytes) -> list[bytes]:
        self._remainder.extend(data)
        records: list[bytes] = []
        while len(self._remainder) >= 4:
            size = int.from_bytes(self._remainder[:4], "big")
            if size + 4 > MAX_FRAME_BYTES:
                raise FrameTooLargeError("inbound Unix frame exceeds 1 MiB")
            if len(self._remainder) < size + 4:
                break
            records.append(bytes(self._remainder[4:4 + size]))
            del self._remainder[:4 + size]
        return records
```

### 5.4 Strict JSON pipeline

The receive pipeline MUST be ordered as follows:

```text
carrier record
  -> encoded-byte limit
  -> text/binary decision
  -> strict UTF-8 decoding
  -> strict JSON syntax parse
  -> duplicate-member detection
  -> JSON depth/node/member/item/string budgets
  -> Pydantic closed-shape validation
  -> phase, session, source, target, provenance, and lifecycle validation
  -> dispatch
```

The parser MUST reject duplicate object members. Python's default
`json.loads()` loses this information unless `object_pairs_hook` is used. A
minimal design is:

```python
import json
from collections.abc import Sequence


class DuplicateMemberError(ValueError):
    """A JSON object contains the same member name more than once."""


def _reject_duplicate_members(pairs: Sequence[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateMemberError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> float:
    raise ValueError(f"non-finite JSON value is forbidden: {value}")


def parse_strict_json(payload: str | bytes, *, max_bytes: int = MAX_FRAME_BYTES) -> JsonValue:
    if isinstance(payload, bytes):
        try:
            text = payload.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise MalformedJsonError("input is not valid UTF-8") from exc
    else:
        text = payload
        try:
            text.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise MalformedJsonError("input contains invalid Unicode") from exc
    if len(text.encode("utf-8")) > max_bytes:
        raise ResourceExhaustedError("JSON input exceeds configured byte limit")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_members,
            parse_constant=_reject_nonfinite,
        )
    except DuplicateMemberError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise MalformedJsonError("malformed JSON") from exc
    validate_json_tree(value)
    return value
```

`validate_json_tree()` MUST recursively enforce the following before a record
is passed to Pydantic:

| Budget | Value |
|---|---:|
| Frame bytes | 1,048,576 |
| JSON depth | 32 |
| JSON nodes | 10,000 |
| Object members | 1,024 |
| Array items | 4,096 |
| UTF-8 bytes per string | 65,536 |
| Card bytes | 65,536 |
| Public-card bytes | 8,192 |
| Capabilities/card | 64 |
| Endpoints/card | 8 |
| Schema bytes/capability | 16,384 |
| Idempotency-key bytes | 256 |

It also rejects unpaired UTF-16 surrogate code points, JSON values which are
not finite numbers, cyclic outbound objects, and values that exceed any
budget. A parser error before `active` fails the session. A malformed
application record after `active` is reported locally and ignored; it MUST
never reach a task handler or alter pending-call state.

### 5.5 Primitive encoding constraints

| Name | Exact v0.1 constraint |
|---|---|
| `agent_id` | `^[a-zA-Z][a-zA-Z0-9._-]*$`, maximum 255 characters |
| `instance_id` | Canonical unpadded base64url encoding of 16 random bytes |
| `nonce` | Canonical unpadded base64url encoding of 32 random bytes |
| `sid` | Canonical unpadded base64url encoding of 32 SHA-256 bytes |
| `message_id` / `task_id` | UUIDv7 |
| timestamp | UTC RFC 3339 with exactly 3 fractional digits and a final `Z` |
| capability ID | lower-case dotted grammar defined by `CapabilityId` |
| capability version | exactly `major.minor.patch` decimal components |
| SHA-256 digest | 64 hexadecimal characters; SDK output is lowercase |
| Ed25519 public key/key ID | canonical 32-byte base64url |
| Ed25519 signature | canonical 64-byte base64url |

Although early prose reserves `"*"` for a future broadcast target, it is not
a valid v0.1 `agent_id` in the reference validator. Python MUST reject it.

### 5.6 UUIDv7 and random identifiers

The SDK MUST generate UUIDv7, not UUIDv4, for message IDs and task IDs. It
SHOULD mirror the reference's process-monotonic generator under a lock:

```python
import os
import threading
import time

_uuid_lock = threading.Lock()
_last_uuid_ms = -1
_last_uuid_random = 0
_MAX_UUID_RANDOM = (1 << 74) - 1


def uuidv7(now_ms: int | None = None) -> str:
    global _last_uuid_ms, _last_uuid_random
    timestamp = int(time.time() * 1000) if now_ms is None else now_ms
    if timestamp < 0 or timestamp > 0xFFFF_FFFF_FFFF:
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
        ts = _last_uuid_ms
        random74 = _last_uuid_random
    raw = bytearray(16)
    raw[0:6] = ts.to_bytes(6, "big")
    random_a = random74 >> 62
    random_b = random74 & ((1 << 62) - 1)
    raw[6] = 0x70 | (random_a >> 8)
    raw[7] = random_a & 0xFF
    raw[8] = 0x80 | ((random_b >> 56) & 0x3F)
    raw[9:16] = (random_b & ((1 << 56) - 1)).to_bytes(7, "big")
    hex_value = raw.hex()
    return f"{hex_value[0:8]}-{hex_value[8:12]}-{hex_value[12:16]}-{hex_value[16:20]}-{hex_value[20:32]}"
```

`random_instance_id()` generates 16 random bytes and canonical base64url
encodes them. `random_nonce()` does the same with 32 bytes. The generator must
not use predictable PRNG state or reusable values.

### 5.7 Canonical JSON and digest functions

The TypeScript reference uses a JCS-style canonical JSON function. Python
MUST use a vetted RFC 8785/JCS-compatible encoder or a tested implementation
with TypeScript test vectors. `json.dumps(sort_keys=True)` alone is not a
wire-compatible substitute: Python and JavaScript may differ in number
rendering, escaping, and Unicode behavior.

Canonicalization requirements:

- reject non-JSON values, cycles, non-finite numbers, invalid Unicode, and
  resource-budget violations;
- preserve array order;
- sort object keys lexicographically according to the required canonical
  ordering;
- output compact JSON with no insignificant whitespace;
- use JavaScript/JCS-compatible primitive serializations;
- hash the UTF-8 bytes of canonical JSON.

```python
import hashlib


def sha256_hex(value: JsonValue | str) -> str:
    text = value if isinstance(value, str) else canonical_json(value)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def card_digest(card: AgentCard) -> str:
    return sha256_hex(card.model_dump(mode="json", exclude_none=True))


def capability_contract_payload(capability: Capability) -> JsonObject:
    return {
        "id": capability.id,
        "version": capability.version,
        "input_schema": capability.input_schema,
        "result_schema": capability.result_schema,
        "idempotency": capability.idempotency or "idempotent",
        "side_effects": capability.side_effects or "none",
        "approval": capability.approval or "never",
        "cancellation": capability.cancellation or "none",
        "timeout_ceiling_seconds": capability.timeout_ceiling_seconds or 300,
    }


def capability_contract_digest(capability: Capability) -> str:
    return sha256_hex(capability_contract_payload(capability))


def capability_contract_tuple(capability: Capability) -> CapabilityContractTuple:
    return CapabilityContractTuple(
        capability_id=capability.id,
        capability_version=capability.version,
        capability_contract_digest=capability_contract_digest(capability),
    )


def envelope_semantic_digest(envelope: Envelope) -> str:
    value = envelope.model_dump(mode="json", exclude_none=True)
    value.pop("message_id")
    value.pop("timestamp")
    return sha256_hex(value)


def routed_envelope_digest(envelope: Envelope) -> str:
    value = envelope.model_dump(mode="json", exclude_none=True)
    value.pop("provenance", None)
    value.pop("message_id")
    value.pop("timestamp")
    return sha256_hex(value)
```

The normalized capability contract uses literal JSON `null` for absent input
or result schema. It applies these defaults exactly:

| Contract field | Default |
|---|---|
| `input_schema` | `null` |
| `result_schema` | `null` |
| `idempotency` | `idempotent` |
| `side_effects` | `none` |
| `approval` | `never` |
| `cancellation` | `none` |
| `timeout_ceiling_seconds` | `300` |

The difference between submission `method` and response `capability_id` is
intentional. A Python executor MUST compare the tuple from
`method/capability_version/capability_contract_digest` to the tuple it derives
from its advertised capability before acceptance.

### 5.8 Envelope construction

All outbound envelopes are made by one validated factory. It supplies the
reference-compatible convenience defaults and then calls `Envelope` validation
before serializing:

```python
def create_envelope(
    *,
    type: EnvelopeType,
    source: AgentIdentity,
    target: AgentRef,
    params: JsonObject,
    idempotency_key: str | None = None,
    deadline: str | None = None,
    in_reply_to: str | None = None,
    message_id: str | None = None,
    timestamp: str | None = None,
) -> Envelope:
    chosen_message_id = message_id or uuidv7()
    chosen_deadline = deadline or format_timestamp(datetime.now(UTC) + timedelta(seconds=60))
    return Envelope(
        type=type,
        message_id=chosen_message_id,
        timestamp=timestamp or utc_now_millis(),
        source=source,
        target=target,
        delivery=Delivery(
            mode=DeliveryMode.AT_LEAST_ONCE,
            idempotency_key=idempotency_key or f"{type}:{chosen_message_id}",
            deadline=chosen_deadline,
        ),
        in_reply_to=in_reply_to,
        params=params,
    )
```

Task submission uses a deliberate idempotency key of `submit:{task_id}`;
progress/completion use a key including type, task ID, and event sequence;
cancellation uses `cancel:{task_id}`. These are library defaults, not a
substitute for application-level durable idempotency policy.

### 5.9 Hello, card, auth, and ready flow

The default loopback runtime-token flow is:

```text
Python initiator                                        TypeScript broker
----------------                                        -----------------
HTTP upgrade with x-polymesh-token -------------------> token validation
hello(role=initiator) -------------------------------->
                                     <---------------- hello(role=responder)
card(for_nonce=responder nonce) ---------------------->
                                     <---------------- card(for_nonce=initiator nonce)
ready ------------------------------------------------->
                                     <---------------- ready
ACTIVE                                                   ACTIVE
```

The secure profile is:

```text
Python initiator                                        TypeScript broker
----------------                                        -----------------
TLS 1.3 mutual-authenticated WSS upgrade -------------> TLS validation
hello(security_profile set) -------------------------->
                                     <---------------- hello(security_profile set)
card(signed) ------------------------------------------>
                                     <---------------- card(signed)
auth(initiator Ed25519 proof) ------------------------>
                                     <---------------- auth(responder Ed25519 proof)
ready ------------------------------------------------->
                                     <---------------- ready
ACTIVE                                                   ACTIVE
```

In loopback mode, `security_profile` MUST be absent in both hello records and
no `auth` frame occurs. In secure mode it MUST equal exactly
`enrolled-ed25519-tls-1.3` in both hellos; a missing, changed, or extra
profile is a fail-closed identity error.

### 5.10 Session ID derivation

The initiator creates a 32-byte nonce. The responder creates its own 32-byte
nonce, echoes the initiator nonce, and sends a session ID. Both sides derive
the identical correlation value:

```python
import base64
import hashlib


def derive_session_id(initiator_nonce: str, responder_nonce: str) -> str:
    initiator = base64url_decode_exact(initiator_nonce, 32)
    responder = base64url_decode_exact(responder_nonce, 32)
    raw = hashlib.sha256(b"polymesh.0.1\x00" + initiator + responder).digest()
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
```

The initiator MUST reject a responder hello when its `echo` differs from the
initiator nonce, when `sid` differs from this derivation, or when the peer
agent/instance equals its own agent/instance. A session ID is correlation
material only; it is not a credential, encryption key, or authority grant.

### 5.11 Handshake card checks

Before it sends or accepts `ready`, each side MUST verify:

1. `CardFrame.sid` equals the current derived session ID.
2. `CardFrame.for_nonce` equals the recipient's nonce.
3. card `agent_id` and `instance_id` match the earlier peer hello.
4. card `expires_at` is strictly after the current wall clock.
5. frame `digest` equals canonical `card_digest(card)`.
6. all Agent Card validation rules succeed.
7. in secure mode, card identity/signature matches a prior local enrollment.

The initiator sends:

```json
{
  "type": "ready",
  "sid": "JcGbKiqRJLJ_fGmVHyS3RK7OcSKVffAMiWKvFsPv9uc",
  "self_card": "18c5b4548202152a65ec9fe5f3e5c7ecf0aee5fd55d1bde6e532906408602850",
  "peer_card": "d1ddeb8c25e3aac782bcd744a3efd73ea54c946422f28a6ef28e1b6426fcf3ba"
}
```

where `self_card` is its own sent card digest and `peer_card` is the verified
counterparty digest. The responder validates those values and returns them in
the opposite order. Application traffic before a validated peer ready is a
handshake failure.

### 5.12 Secure `auth` cryptographic binding

The secure auth frame contains no bearer token:

```json
{
  "type": "auth",
  "sid": "JcGbKiqRJLJ_fGmVHyS3RK7OcSKVffAMiWKvFsPv9uc",
  "agent_id": "example.python-agent",
  "key_id": "SItoEaQEOZSizLTrpyyL8rQzWkoqrne8kw6ajP6sktw",
  "signature": "Q3i5msvmeE0OHeVxY4CbnYzY2UHoZ1T7tpF4V_YfJ6NAG1xnlwWVFYgsPqfKeLx7QK0gGHA-NDF8PV0PH_MwCQ"
}
```

The signed bytes are exactly:

```text
UTF8("PMX-AUTH/0.1\\0") ||
UTF8(canonical_json({
  protocol: "polymesh.0.1",
  handshake_version: "0.1",
  security_profile: "enrolled-ed25519-tls-1.3",
  initiator_hello: complete initiator hello object,
  responder_hello: complete responder hello object,
  initiator_card_digest: complete initiator card digest,
  responder_card_digest: complete responder card digest,
  tls_channel_binding: base64url 32-byte channel binding
}))
```

The notation above defines the byte layout; the actual Python implementation
MUST assemble the full objects, not serialize the descriptive labels. It
verifies all of these conditions before ready:

- enrollment resolves the claimed `(agent_id, key_id)` and is enabled/unexpired;
- the peer Card's public key and signature match that enrollment;
- auth `agent_id` and `key_id` match peer hello and Card identity;
- Ed25519 verifies the exact transcript under the enrolled public key;
- the TLS channel binding is exact reference-compatible exporter material.

Card signatures use:

```text
UTF8("PMX-CARD/0.1\\0") || UTF8(canonical_json(card without signature))
```

The secure transport requirements and the exporter caveat appear in
[Section 10](#10-security-and-identity).

### 5.13 Required `protocol.py` surface

The following pure functions form the conformance-tested protocol boundary:

```text
parse_strict_json(payload: str | bytes, limits: JsonParseLimits | None = None) -> JsonValue
validate_handshake_frame(value: JsonValue, expected frame type optional) -> HandshakeFrame
validate_envelope(value: JsonValue) -> Envelope
uuidv7(now_ms: int | None = None) -> str
random_instance_id() -> str
random_nonce() -> str
derive_session_id(initiator_nonce: str, responder_nonce: str) -> str
canonical_json(value: JsonValue) -> str
sha256_hex(value: JsonValue | str) -> str
card_digest(card: AgentCard) -> str
capability_contract_payload(capability: Capability) -> JsonObject
capability_contract_digest(capability: Capability) -> str
capability_contract_tuple(capability: Capability) -> CapabilityContractTuple
envelope_semantic_digest(envelope: Envelope) -> str
routed_envelope_digest(envelope: Envelope) -> str
create_envelope(validated construction options) -> Envelope
encode_unix_frame(record: HandshakeFrame | Envelope) -> bytes
decode_unix_frames(data: bytes, decoder: UnixFrameDecoder) -> list[bytes]
```

Each protocol function has full implementation requirements in Sections 4-6
and needs direct unit tests plus TypeScript-generated cross-language fixtures.

## 6. Task lifecycle, delivery, receipts, and routing

### 6.1 Submission and contract pinning

A `task.submit` creates or retries one logical task. Its exact v0.1 parameter
object is:

```json
{
  "task_id": "0197a1b0-0000-7000-8000-000000000001",
  "method": "org.example.calendar.read",
  "capability_version": "1.2.3",
  "capability_contract_digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "params": {
    "date": "2026-07-20"
  },
  "deadline": "2026-07-20T12:01:00.000Z"
}
```

The owner MUST pin the exact advertised capability contract. It derives the
tuple:

```json
{
  "capability_id": "org.example.calendar.read",
  "capability_version": "1.2.3",
  "capability_contract_digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

from the locally verified capability entry. The executor compares that tuple
with its current card before admitting the handler. A mismatch produces
`CAPABILITY_CONTRACT_MISMATCH`; the handler MUST NOT execute.

The task deadline has two copies and they MUST compare byte-for-byte:

```text
envelope.delivery.deadline == envelope.params.deadline
```

The owner rejects a deadline already elapsed or exceeding its local maximum.
The executor repeats the check before and after potentially asynchronous
authorization. When a capability provides `timeout_ceiling_seconds`, the
effective ceiling is the lower of that ceiling and the configured client
maximum.

### 6.2 Broker route state machine

The TypeScript v0.1 broker keeps an in-memory route logically equivalent to:

```text
TaskRoute
  task_id
  capability contract tuple
  immutable fingerprint
  deadline and retention deadline
  owner fence:    (agent_id, instance_id, session_id)
  executor fence: (agent_id, instance_id, session_id)
  accepted submission message IDs
  lifecycle state
  next expected event sequence
  canonical event digest by sequence
```

The state machine is:

```text
                                  task.submit
                                      |
                                      v
                                [SUBMITTED]
                                /         \
              rejected seq=1  /           \  accepted seq=1, matching contract
                              v             v
                         [REJECTED]     [ACCEPTED]
                                               |
                           progress seq=2..N, contiguous
                                               |
                                               v
                                          [ACCEPTED]
                                               |
                               completed seq=N, contiguous
                                               v
                                         [COMPLETED]

SUBMITTED or ACCEPTED -- deadline or participant disconnect --> [CLOSED]
```

`task.cancel` is a request, rather than a lifecycle terminal record. Only the
exact pinned owner may send it and only to the exact pinned executor. The
executor determines whether the final outcome is `cancelled` or `succeeded`/
`failed` when cancellation races with completion.

### 6.3 New task admission

For a new submission, the broker performs these operations in order:

1. validate the strict Envelope and type-specific params;
2. verify that the actual authenticated transport identity equals
   `envelope.source`;
3. reject sender-supplied routed provenance;
4. reject an expired deadline;
5. derive the submitted contract tuple;
6. canonicalize the immutable fingerprint below;
7. resolve a live eligible target instance;
8. pin owner and executor to their current session IDs;
9. allocate route capacity and retain the submission message ID;
10. forward the submission to the selected executor.

The immutable task fingerprint contains exactly:

```json
{
  "method": "org.example.calendar.read",
  "capability_version": "1.2.3",
  "capability_contract_digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "params": {
    "date": "2026-07-20"
  },
  "deadline": "2026-07-20T12:01:00.000Z"
}
```

The selected executor is not reselected for a retried task. That selection
rule protects ordering and avoids changing execution identity after the owner
has logically submitted work.

### 6.4 Lifecycle envelope requirements

| Envelope | Required route state | Required `event_seq` | Correlation and contract rule |
|---|---|---:|---|
| `task.accepted` | submitted | 1 | `in_reply_to` is a known submission ID; exact contract tuple |
| `task.rejected` | submitted | 1 | `in_reply_to` is a known submission ID |
| `task.progress` | accepted | next contiguous value >= 2 | exact executor fence |
| `task.completed` | accepted | next contiguous value >= 2 | exact executor fence and exact contract tuple |
| `task.cancel` | submitted or accepted | none | exact owner fence, directed to pinned executor |

The v0.1 structural envelope validator does not itself require `in_reply_to`
for accepted/rejected/error types. The state machine MUST require it before a
record is allowed to affect a route. A forged lifecycle record that merely
parses MUST be ignored and reported as a local protocol/task error.

Repeated event sequence values are compared using canonical semantic content:

```json
{
  "type": "task.progress",
  "source": {
    "agent_id": "executor",
    "instance_id": "instance"
  },
  "target": {
    "agent_id": "owner",
    "instance_id": "instance"
  },
  "params": {
    "task_id": "0197a1b0-0000-7000-8000-000000000001",
    "event_seq": 2,
    "progress": {
      "state": "running"
    }
  }
}
```

The same canonical content at the same sequence is a retransmission and is
ignored after optional observability reporting. Different content at the same
sequence is `PMX.TASK.EVENT_CONFLICT`. A stale, skipped, or phase-illegal
sequence is `PMX.TASK.INVALID_LIFECYCLE`.

### 6.5 Client-side pending-call state machine

The Python client keeps a separate local `PendingCall` record:

```text
PendingCall
  task_id
  submit_message_id
  expected target agent and optional instance
  pinned capability tuple
  pinned result schema
  deadline timer
  accepted flag
  last_event_seq
  terminal flag
  receipt observation
  completion future
```

The client MUST apply this logic before completing a `call()` result:

1. filter lifecycle events to a non-terminal pending task whose source equals
   the expected executor target;
2. for accepted/rejected, require an exact `in_reply_to` lookup to a pending
   submission message ID and `event_seq == 1`;
3. for accepted, require the returned tuple to equal the submitted tuple;
4. for progress, require prior acceptance and `event_seq == last_event_seq+1`;
5. for completed, require prior acceptance, causal contiguity, and the exact
   tuple; then validate the terminal result against the pinned result schema;
6. ignore exact known retransmissions; fail the call for conflicting/gapped
   records;
7. settle the future exactly once and remove timers/maps atomically.

A completion outcome maps as follows:

| Terminal outcome | Client behavior |
|---|---|
| `succeeded` | resolve `call()` with validated JSON result |
| `failed` | raise `ExecutionError` using the bounded structured error |
| `cancelled` | raise `TaskCancelledError` |
| absent/malformed | raise `ProtocolError` or `ResultValidationError` |

### 6.6 Executor-side admission and handler behavior

Before it invokes an inbound handler, the Python client MUST:

1. validate source/target/session/provenance;
2. reject unequal delivery/task deadlines;
3. reject expired or over-ceiling deadline;
4. enforce input byte limit;
5. look up a locally advertised capability and handler;
6. compare the submitted and advertised capability tuples;
7. validate input against the capability `input_schema`;
8. enforce authorization policy;
9. admit/replay through the appropriate idempotency/replay ledger;
10. persist durable admission before emitting `task.accepted` when durability
    is required;
11. emit accepted at sequence one;
12. create a deadline/cancellation controller and invoke the handler.

The default standard handlers are:

| Capability | Result |
|---|---|
| `org.polymesh.agent.ping` | `{}` |
| `org.polymesh.agent.info` | the local Agent Card |
| `org.polymesh.capabilities.list` | array of `{id, version}` mappings |

An undeclared, unhandled, rejected, policy-denied, or schema-invalid
submission MUST NOT invoke application code. A handler receives a deep-copied
immutable JSON input. Its result is serialized, re-parsed strictly, bounded,
validated against the result schema, and only then placed in a terminal
envelope.

### 6.7 Terminal object requirements

Each terminal is a closed discriminated object. These are the only valid
forms:

```json
{
  "outcome": "succeeded",
  "result": {
    "slots": []
  },
  "completed_at": "2026-07-20T12:00:01.000Z"
}
```

```json
{
  "outcome": "failed",
  "error": {
    "code": "EXECUTION_FAILED",
    "message": "Task handler failed",
    "details": {}
  },
  "completed_at": "2026-07-20T12:00:01.000Z"
}
```

```json
{
  "outcome": "cancelled",
  "cancellation": {
    "code": "CANCELLED",
    "message": "Cancellation was observed by the executor"
  },
  "completed_at": "2026-07-20T12:00:01.000Z"
}
```

For strict compatibility, failure terminal `error` is the narrower
`{code,message,details?}` object accepted by the reference terminal validator,
not necessarily a full `StructuredError`. The SDK may convert it into a local
`ExecutionError` with category `execution` and `retryable=False`; it MUST NOT
add extra members to the wire terminal.

### 6.8 Delivery semantics

The only v0.1 delivery guarantee is at-least-once delivery. It means a sender
may retransmit and a recipient may see duplicate records. It does **not** mean
exactly-once execution, exactly-once terminal delivery, or durable broker
storage across every crash.

There are two separate deduplication layers:

| Layer | Key | Responsibility |
|---|---|---|
| Broker replay ledger | secure principal plus message ID, or legacy source agent/instance plus message ID | detect a duplicate/conflicting ingress record |
| Executor admission ledger | source, recipient instance, protocol, type, and idempotency key | avoid duplicate handler execution and replay canonical lifecycle events |

The broker semantic digest is:

```text
SHA-256(canonical_json(envelope with message_id and timestamp removed))
```

It handles same-message-ID reuse as follows:

| Reuse | Required broker behavior |
|---|---|
| Same message ID and same semantic digest | duplicate; may forward/replay and receipt disposition is `duplicate` |
| Same message ID and changed semantic digest | reject with `PMX.DELIVERY.MESSAGE_ID_CONFLICT` and a rejected receipt when possible |
| New message ID, same logical task on same live route | valid only if immutable route conditions still hold |
| Same task ID, changed fingerprint | reject with `PMX.TASK.ID_CONFLICT` |

The executor's v0.1 in-memory idempotency scope is a NUL-delimited sequence:

```text
source.agent_id
source.instance_id
recipient.card.instance_id
envelope.protocol
envelope.type
envelope.delivery.idempotency_key
```

Its delivery fingerprint covers protocol, type, source, target, delivery mode,
delivery deadline, and params but excludes message ID and timestamp. A reused
key with changed semantics is `PMX.DELIVERY.IDEMPOTENCY_CONFLICT`.

For a secure side-effecting capability (`sensitive` idempotency or `write`,
`network`, or `approval` side effects), Python MUST require a durable replay
ledger and a verified stable principal before invoking the handler. A process
local dictionary cannot make a restart-safe execution claim.

### 6.9 Receipt protocol

A v0.1 receipt is an ordinary Envelope with non-recursive control semantics.
Its required `params` are `received_message_id`, `semantic_digest`, and a
`disposition` of `accepted`, `duplicate`, or `rejected`.

```json
{
  "protocol": "polymesh.0.1",
  "type": "receipt",
  "message_id": "0197a1b0-0000-7000-8000-000000000099",
  "timestamp": "2026-07-20T12:00:01.000Z",
  "source": {
    "agent_id": "org.polymesh.broker",
    "instance_id": "XBr2H0mJ7xEVN1XNYXqvVQ"
  },
  "target": {
    "agent_id": "example.python-agent",
    "instance_id": "fGqS2M8n2f4u2KO4Bcv0Ow"
  },
  "delivery": {
    "mode": "at_least_once",
    "idempotency_key": "receipt:0197a1b0-0000-7000-8000-000000000099",
    "deadline": "2026-07-20T12:01:01.000Z"
  },
  "in_reply_to": "0197a1b0-0000-7000-8000-000000000001",
  "params": {
    "received_message_id": "0197a1b0-0000-7000-8000-000000000001",
    "semantic_digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "disposition": "accepted"
  }
}
```

Requirements:

- `in_reply_to` MUST exactly equal `params.received_message_id`.
- receipt source is the authenticated broker in a broker-client session.
- receipts are never routed to other agents.
- receipts are never acknowledged with another receipt.
- receipt processing MUST NOT settle a call, alter a route, authorize work, or
  claim executor admission.
- an SDK may expose a receipt callback and retain it for diagnostics/recovery
  evidence only.

The broker emits a receipt after it determines ingress/replay disposition. It
may instead send an error or close when malformed input or resource exhaustion
prevents ordinary receipt emission. Receipt absence therefore does not prove
that a write failed.

### 6.10 Retry guidance

When a sender retransmits a byte-for-byte record after missing a receipt, it
MUST preserve the original message ID, idempotency key, task ID, deadline, and
all semantic fields. The broker can then classify it as a duplicate rather
than a changed message-ID reuse.

Within the same live session and the same route, a logical task retry may have
a new submission `message_id`, but it MUST preserve task ID, method,
capability version, contract digest, input parameters, deadline, target route,
and idempotency semantics.

When an executor replays canonical lifecycle events to a new known submission
message ID, it uses fresh envelope `message_id` and `timestamp` values. For an
admission event it rewrites `in_reply_to` to the current submission message
ID. The semantic task content remains unchanged.

### 6.11 Secure routed provenance

For an enrolled WSS session, a broker appends a signed `provenance` attachment
while forwarding task submissions, cancellations, lifecycle records, and
correlated errors. A sender MUST NOT provide this attachment.

The closed attachment shape is:

```json
{
  "version": "pmx.broker-provenance/1",
  "broker": {
    "agent_id": "org.polymesh.broker",
    "instance_id": "XBr2H0mJ7xEVN1XNYXqvVQ",
    "key_id": "SItoEaQEOZSizLTrpyyL8rQzWkoqrne8kw6ajP6sktw"
  },
  "source_principal": {
    "principal_id": "key:source-key-id",
    "agent_id": "source-agent",
    "key_id": "source-key-id"
  },
  "source": {
    "agent_id": "source-agent",
    "instance_id": "fGqS2M8n2f4u2KO4Bcv0Ow"
  },
  "target": {
    "agent_id": "target-agent",
    "instance_id": "1W5fpkNH2fK31CD3Dr3L0g"
  },
  "source_session_id": "JcGbKiqRJLJ_fGmVHyS3RK7OcSKVffAMiWKvFsPv9uc",
  "target_session_id": "Oy1zDYPs1vV-4xPjUi8ZaNnT8RCu8sI9syUB7CX3yVQ",
  "envelope_digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "issued_at": "2026-07-20T12:00:00.000Z",
  "expires_at": "2026-07-20T12:00:30.000Z",
  "signature": "Q3i5msvmeE0OHeVxY4CbnYzY2UHoZ1T7tpF4V_YfJ6NAG1xnlwWVFYgsPqfKeLx7QK0gGHA-NDF8PV0PH_MwCQ"
}
```

The broker signs domain-separated bytes:

```text
UTF8("PMX-ROUTED-PROVENANCE/1\\0") ||
UTF8(canonical_json(provenance without signature))
```

The attachment expiry is no later than the earlier of the envelope deadline
and issued time plus 60 seconds.

A secure Python recipient MUST verify all of the following before a forwarded
record affects task state, handler admission, authorization, or replay state:

1. current authenticated broker Card/enrollment and broker identity;
2. broker agent ID, instance ID, and key ID in provenance;
3. source-principal `principal_id == "key:" + key_id`;
4. provenance source and target equal the envelope source and target;
5. provenance source principal agent ID equals the envelope source agent ID;
6. `target_session_id` equals the current secure session ID;
7. `envelope_digest` equals `routed_envelope_digest(envelope)`;
8. issued/expiry temporal validity and 60-second lifetime;
9. the Ed25519 signature under the enrolled broker key.

This binds a routed record to the recipient's current session and prevents
cross-session replay after reconnect.

### 6.12 Fencing and disconnect behavior

The two broker route fences are:

```text
owner fence    = (agent_id, instance_id, session_id)
executor fence = (agent_id, instance_id, session_id)
```

Consequences:

- a source reconnecting with the same agent/instance but new SID is not the
  old owner/executor route participant;
- a disconnected executor cannot be silently replaced by another same-ID
  connection for an existing task;
- a stale close callback cannot remove a newer registration;
- an old handler generation cannot emit progress or terminal output after
  deadline, cancellation, disconnect, or replacement;
- a terminal transition is valid only once and releases task capacity once.

The broker closes non-terminal routes when either pinned participant
disconnects; it does not rebind them. The Python client must surface unknown
completion safely rather than infer that no remote execution occurred.

## 7. Async transport, reconnect, and threading

### 7.1 Transport profiles

| Profile | Endpoint form | Upgrade authentication | Python implementation status |
|---|---|---|---|
| Loopback development | `ws://127.0.0.0/8` or `ws://[::1]` | 32-byte runtime token in `x-polymesh-token` | Required |
| Enrolled secure | `wss://` only | TLS 1.3 mutual TLS, enrollment, and Ed25519 proofs | Conditional on exporter-capable carrier |
| Unix socket | `unix:` endpoint | kernel peer credentials supplied by adapter | Optional |

`ws://localhost`, a hostname that happens to resolve locally, arbitrary LAN
`ws://`, and WSS-to-WS fallback are forbidden. The reference checks numeric
IPv4 loopback (`127/8`) or literal IPv6 `::1` and an explicit insecure
development flag.

Before opening any WebSocket, the client MUST validate:

- scheme is `ws` or `wss`;
- no userinfo, fragment, or query parameters exist;
- an origin may be normalized to the reference `/polymesh` path, but a final
  endpoint has that exact path;
- redirects are disabled;
- WS has explicit numeric-loopback development mode and a valid token source;
- WSS has a secure identity configuration and no runtime token;
- WebSocket compression is disabled;
- the carrier requests `polymesh.0.1` and verifies selection.

### 7.2 Session ownership

`PolyMeshClient` is async-first and attaches to exactly one event loop for its
active lifetime. The owner loop is captured when `connect()` begins. Calls
from another loop MUST fail with `WrongEventLoopError`; the library MUST NOT
try to drive a foreign loop with `run_until_complete`.

Each connection attempt owns one `TransportSession`:

```text
TransportSession
  generation: integer
  websocket: carrier-specific object
  wire phase
  ready future
  reader task
  writer task
  handshake timeout task
  heartbeat task
  reconnect task
  bounded control queue
  bounded application queue
  current SID
  peer identity/card/principal
  current pending-call and local-task fences
```

There MUST be one reader coroutine and one writer coroutine per active
generation. Only the writer calls `websocket.send()`. This serializes writes,
provides one backpressure boundary, and lets heartbeat start a pong timeout
after a ping was accepted by the writer.

The control queue is bounded but reserved for `pong`, heartbeat `ping`,
cancel, and close/error traffic. The application queue is separately bounded.
When it cannot be drained before a configured write deadline, the session
fails with a retryable slow-consumer/transport error rather than retaining
unbounded in-memory records.

### 7.3 Connection state machine

Wire phase is one of the reference values:

| Wire phase | Allowed inbound record | Allowed outbound record |
|---|---|---|
| `idle` | none | none |
| `await_hello` | responder hello | initiator hello |
| `await_card` | peer CardFrame | local CardFrame |
| `await_auth` | peer AuthFrame in secure mode | local AuthFrame in secure mode |
| `await_ready` | peer ReadyFrame | local ReadyFrame |
| `active` | validated Envelopes | validated Envelopes |
| `closed` | none | none |

The Python transport layer may additionally expose local state:

```text
NEW
  -> CONNECTING
  -> HANDSHAKING
  -> ACTIVE
ACTIVE -> CLOSING -> CLOSED
ACTIVE -> RECONNECT_WAIT -> CONNECTING
ACTIVE -> CLOSED
```

`CONNECTING`, `HANDSHAKING`, `RECONNECT_WAIT`, and `CLOSING` are local
observability states; they MUST NOT be emitted as a wire frame or confused
with the TypeScript `ClientPhase` values.

The default handshake timer is five seconds and starts with initiator hello.
It is cancelled only after validated peer ready. Partial card/auth state from
a failed generation MUST never be reused by a new generation.

### 7.4 Generation fencing

Each connection attempt gets a monotonically increasing integer generation.
Every reader, writer, heartbeat callback, handshake timeout, close callback,
and reconnect coroutine captures both:

1. the generation integer; and
2. the specific transport object.

Before it changes state, writes bytes, completes a future, aborts a task, or
schedules reconnect, it checks both values still identify the active session.

```python
async def is_current(self, generation: int, transport: WireTransport) -> bool:
    async with self._state_lock:
        return (
            self._session is not None
            and self._session.generation == generation
            and self._session.transport is transport
        )
```

This is not an optimization. It prevents an old socket's delayed close or
message from closing a newly established connection, removing its peer card,
or completing the wrong pending call.

### 7.5 Heartbeat

Heartbeat begins after `active`. Default timing matches the reference:

| Parameter | Default |
|---|---:|
| Protocol-ping interval | 30 seconds |
| Matching pong deadline | 5 seconds |
| Valid-inbound inactivity deadline | 90 seconds |

Use monotonic time for heartbeat/reconnect timers. Use UTC wall time only for
wire timestamps and absolute task/card deadlines.

Heartbeat behavior:

1. start `n` at zero for each new connection generation;
2. enqueue an Envelope `ping` addressed to the authenticated broker;
3. record its exact `n` and pong deadline after writer acceptance;
4. accept `pong` only from the broker with exactly the outstanding `n`;
5. reply to a valid broker `ping` with a `pong` of the same `n`;
6. refresh valid-inbound time only after full framing, parsing, validation,
   addressing, and required provenance checks;
7. fail current generation with `HEARTBEAT_TIMEOUT` if matching pong is late,
   a ping cannot be written, or valid inbound traffic is absent for 90 seconds.

Native WebSocket ping/pong controls may exist for carrier health but cannot
satisfy PolyMesh protocol heartbeat requirements.

### 7.6 Reconnect policy

Python provides an explicit local extension:

```python
ReconnectPolicy(
    enabled=True,
    initial_delay=1.0,
    maximum_delay=60.0,
    multiplier=2.0,
    jitter=0.20,
    reset_after_active=90.0,
    resend_pending=False,
)
```

For failed reconnect attempt `k`:

```text
base = min(60 seconds, 1 second * 2^k)
delay = min(60 seconds, base * uniform(0.80, 1.20))
```

The counter resets only after 90 continuous active seconds. A reconnect always
creates a new transport, nonces, SID, handshake timeout, heartbeat sequence,
and peer validation state. It reruns the full handshake.

Reconnect is allowed only for locally classified transient failures such as a
carrier loss, heartbeat timeout, or bounded local setup failure. It MUST NOT
run after:

- explicit `disconnect()`;
- malformed JSON or duplicate-member input;
- profile mismatch, card/provenance/signature failure, identity collision, or
  authentication/enrollment/TLS failure;
- a peer close reason alone, without local retry classification;
- non-retryable remote error, task rejection, authorization denial, or handler
  failure.

### 7.7 In-flight work after disconnect

The TypeScript v0.1 client stops heartbeats, aborts local tasks, and rejects
pending calls on transport loss. Python follows this default. It may reconnect
for future work, but it MUST NOT silently retry a pending task.

| Observed condition at failure | Required safe result |
|---|---|
| Task not yet written | caller may submit after reconnect |
| Write outcome unknown, no receipt | `TaskRecoveryRequiredError` |
| Receipt observed, no terminal | `TaskRecoveryRequiredError` |
| Accepted task loses session | `TaskRecoveryRequiredError` |
| Pure/idempotent task with explicit application decision | caller may submit a new logical attempt |
| Sensitive/write/network task | require explicit recovery decision and durable policy |

The broker pins routes to the original SID. A reconnect with the same
instance ID is not the old owner/executor session, and v0.1 has no resume
cursor or `resume` message. `resend_pending=False` is therefore mandatory for
reference-compatible safety.

The SDK MAY persist an opaque recovery record with task ID, submit message ID,
deadline, contract tuple, input fingerprint, receipt evidence, and last event
sequence. It MUST call this recovery metadata, not interoperable resumption.

### 7.8 Multithreading safety

The handler registry, subscriptions, and externally callable close operations
are safe to invoke from non-owner threads, but no mutable protocol state may
be modified directly outside the owner loop.

Required pattern:

```python
def set_handler_threadsafe(self, capability: str, handler: TaskHandler) -> None:
    with self._registry_lock:
        self._handlers = {**self._handlers, capability: handler}


def close_from_thread(self, code: int = 1000, reason: str = "client closed") -> None:
    loop = self._owner_loop
    if loop is None or loop.is_closed():
        return
    loop.call_soon_threadsafe(self._begin_close, code, reason)
```

Rules:

- use `threading.RLock` only for small synchronous registry/subscription
  snapshots;
- use `asyncio.Lock` for session, pending-call, and task-state transitions on
  the owner loop;
- snapshot a handler under the registry lock at task admission, then release
  the lock before running user code;
- event callbacks are invoked outside state locks;
- never await while holding a `threading.RLock`;
- never access an asyncio primitive from an unrelated event loop;
- use `loop.call_soon_threadsafe` or `run_coroutine_threadsafe` for cross-
  thread ingress, with bounded queue admission.

### 7.9 Race table

| Race | Required handling |
|---|---|
| Old socket closes after new active socket | ignore callback when generation/transport mismatches |
| Old reader yields a delayed message | discard before parsing/dispatch when stale |
| Heartbeat fires after replacement | check generation/phase and return without effect |
| Handshake timeout fires after ready | timer is cancelled and generation-fenced |
| Two `connect()` calls overlap | share one readiness future; never create two active sessions |
| `disconnect()` during reconnect delay | mark reconnect disabled and fence/cancel retry task |
| Handler returns after cancellation | task terminal/generation check blocks late envelope |
| Cancel and handler completion race | single async terminal lock chooses one terminal emission |
| Duplicate lifecycle event races completion | terminal/pending maps use one atomic completion path |
| Registry reload during admission | task pins callable/registry generation before handler starts |

## 8. Errors, exceptions, and failure mapping

### 8.1 Design

Every surfaced Python failure is a `PolyMeshError` or a standard local input
exception (`TypeError`, `ValueError`) documented at the API boundary. Remote
error details are bounded and treated as untrusted. They are never rendered as
format strings, log fields containing secrets, or raw tracebacks.

The base exception retains machine-readable wire information:

```python
class PolyMeshError(Exception):
    def __init__(
        self,
        code: str,
        message: str | None = None,
        *,
        category: ErrorCategory | Literal["transport", "timeout"] = ErrorCategory.PROTOCOL,
        retryable: bool = False,
        retry_after_ms: int | None = None,
        details: JsonObject | None = None,
        task_id: str | None = None,
        envelope: Envelope | None = None,
    ) -> None:
        super().__init__(message or code)
        self.code = code
        self.category = category
        self.retryable = retryable
        self.retry_after_ms = retry_after_ms
        self.details = details
        self.task_id = task_id
        self.envelope = envelope
```

The exception message is safe for a human-facing bounded diagnostic. It MUST
NOT contain runtime tokens, private key material, TLS exporter bytes, raw card
credential fields, unbounded peer text, or unredacted arbitrary task input.

### 8.2 Exception hierarchy

```text
PolyMeshError
├── ProtocolError
│   ├── ParseError
│   │   ├── MalformedJsonError
│   │   ├── DuplicateMemberError
│   │   └── FrameTooLargeError
│   ├── HandshakeError
│   ├── SchemaValidationError
│   └── LifecycleError
├── AuthenticationError
│   ├── AuthError
│   ├── TokenError
│   ├── TLSVerificationError
│   ├── EnrollmentError
│   ├── CardSignatureError
│   ├── ProvenanceError
│   └── SecureProfileUnsupportedError
├── RoutingError
├── DeliveryError
├── ResourceError
├── TaskError
│   ├── TaskRejectedError
│   ├── TaskNotFoundError
│   ├── TaskCancelledError
│   ├── TaskRecoveryRequiredError
│   └── ContractMismatchError
├── ExecutionError
│   └── ResultValidationError
├── TransportError
│   ├── TransportClosedError
│   ├── SlowConsumerError
│   ├── ReconnectExhaustedError
│   └── WrongEventLoopError
└── TimeoutError
    ├── HandshakeTimeoutError
    ├── HeartbeatTimeoutError
    └── TaskTimeoutError
```

`AuthError` is a public alias/subclass retained for users who expect that
common name. `TimeoutError` here is `polymesh.errors.TimeoutError`; code should
not accidentally catch it as a standard-library timeout without importing the
qualified class.

### 8.3 Remote category mapping

Map a remote `StructuredError.category` to a Python subclass without changing
its code, retryability, or retry-after value:

| Wire category | Python exception |
|---|---|
| `parse` | `ParseError` |
| `protocol` | `ProtocolError` |
| `identity` | `AuthenticationError` |
| `routing` | `RoutingError` |
| `delivery` | `DeliveryError` |
| `resource` | `ResourceError` |
| `task` | `TaskError` |
| `execution` | `ExecutionError` |
| `internal` | `PolyMeshError` |

The SDK must use the peer's explicit `retryable` boolean as a diagnostic field
only. Local reconnect policy still determines whether a transport attempt is
eligible to retry. It MUST NOT infer retryability from an error code string or
human message.

### 8.4 Important code mapping

| Code | Required Python result |
|---|---|
| `MALFORMED_JSON` | `MalformedJsonError` |
| `DUPLICATE_MEMBER` | `DuplicateMemberError` |
| `RESOURCE_EXHAUSTED` | `ResourceError` |
| `FRAME_TOO_LARGE` | `FrameTooLargeError` |
| `HANDSHAKE_TIMEOUT` | `HandshakeTimeoutError` |
| `HEARTBEAT_TIMEOUT` | `HeartbeatTimeoutError` |
| `AUTHENTICATION_FAILED` | `AuthenticationError` |
| `SECURITY_PROFILE_MISMATCH` | `AuthenticationError` |
| `ROUTED_PROVENANCE_INVALID` | `ProvenanceError` |
| `INSECURE_TRANSPORT_DISABLED` | `TransportError` |
| `TRANSPORT_CLOSED` | `TransportClosedError` |
| `TARGET_UNAVAILABLE` | `RoutingError` |
| `PMX.ROUTING.PINNED_INSTANCE_UNAVAILABLE` | `RoutingError` |
| `PMX.DELIVERY.MESSAGE_ID_CONFLICT` | `DeliveryError` |
| `PMX.DELIVERY.IDEMPOTENCY_CONFLICT` | `DeliveryError` |
| `PMX.TASK.NOT_FOUND` | `TaskNotFoundError` |
| `PMX.TASK.DEADLINE_EXCEEDED` | `TaskTimeoutError` or `TaskError` according to local timer origin |
| `PMX.TASK.EVENT_CONFLICT` | `LifecycleError` |
| `PMX.TASK.INVALID_LIFECYCLE` | `LifecycleError` |
| `CAPABILITY_CONTRACT_MISMATCH` | `ContractMismatchError` |
| `PMX.TASK.CONTRACT_MISMATCH` | `ContractMismatchError` |
| `TASK_CANCELLED` | `TaskCancelledError` |
| `RESULT_SCHEMA_INVALID` | `ResultValidationError` |
| `RESULT_TOO_LARGE` | `ResultValidationError` |
| `OVERLOADED` | `ResourceError` |
| `AUTHORIZATION_DENIED` | `AuthenticationError` or application-policy error, with no fallback allow |

### 8.5 Error-envelope correlation

An `error` Envelope may affect a pending call only when all conditions hold:

1. it has an `in_reply_to` equal to a current submission message ID;
2. it comes from the expected executor or the authenticated broker;
3. its source/target/session/provenance checks pass;
4. the associated pending call is not terminal.

`details.task_id`, an arbitrary error string, or a matching task ID is not
enough to select a pending call. This blocks a peer from terminating unrelated
calls through a forged or stale diagnostic record.

### 8.6 Failure observability

The SDK emits a local `protocol_error` event for ignored malformed post-ready
records and a `close` event for transport closure. It does not leak a stack
trace across the wire. Implementations SHOULD give the application a bounded
error object with `code`, `category`, `retryable`, `task_id`, and a redacted
diagnostic summary.

## 9. CLI and operational configuration

### 9.1 Compatibility contract

The reference TypeScript CLI implements:

```text
polymesh start
polymesh connect
polymesh call
polymesh peers
polymesh capabilities
```

It prints successful values as indented JSON, writes usage/errors to stderr,
returns `0` on success and `1` for caught errors, and rejects raw `--token` or
`POLYMESH_TOKEN`.

The Python CLI includes all of those commands plus `listen`, format selection,
configuration files, and stable exit codes. Those are local UX extensions;
they do not change the v0.1 wire protocol.

### 9.2 Grammar and global options

```text
polymesh [GLOBAL OPTIONS] start [START OPTIONS]
polymesh [GLOBAL OPTIONS] listen [LISTEN OPTIONS]
polymesh [GLOBAL OPTIONS] connect URL [CONNECT OPTIONS]
polymesh [GLOBAL OPTIONS] call AGENT CAPABILITY JSON_INPUT [CALL OPTIONS]
polymesh [GLOBAL OPTIONS] peers [PEERS OPTIONS]
polymesh [GLOBAL OPTIONS] capabilities [CAPABILITIES OPTIONS]
```

Global options are:

```text
--config PATH
--format json|table|plain
--card PATH
--token-file PATH
--url URL
--timeout MS
--insecure-loopback-dev
--quiet
--help
```

The CLI MUST reject raw credential flags including `--token`, `--private-key`
with an inline value, and `--tls-key` with an inline value. It accepts only
credential file paths, validates their permissions, and redacts them from
diagnostics.

### 9.3 Commands

| Command | Reference behavior | Python v0.1 behavior |
|---|---|---|
| `start` | Start local broker | Required broker start command |
| `listen` | absent | alias for `start`; not a direct-agent wire listener |
| `connect` | connect, print broker, close | same probe with richer output |
| `call` | one call, print result, close | same with structured errors/output |
| `peers` | empty unless mDNS | discovery snapshot only, never broker administration |
| `capabilities` | inspect local card | local inspection; optional constrained standard-capability remote query |

#### `polymesh start`

```text
polymesh start [--host HOST] [--port PORT] [--token-file PATH]
               [--insecure-loopback-dev] [--mdns]
```

Defaults are host `127.0.0.1`, port `7337`, and token path
`~/.polymesh/token`. Plaintext operation requires all of numeric-loopback
host, a token file, and `--insecure-loopback-dev`. The process stays in the
foreground until SIGINT/SIGTERM and closes the broker cleanly.

`--mdns` requires a WSS listener; it is rejected for a plaintext loopback
broker. Python may permit `--port 0` as an explicit extension only if it
prints the resolved bound endpoint.

```bash
polymesh start --host 127.0.0.1 --port 7337 \
  --token-file ~/.polymesh/token --insecure-loopback-dev
```

#### `polymesh listen`

```text
polymesh listen [start options]
```

`listen` is an exact alias for `start` in initial Python v0.1. It MUST NOT
claim a new direct peer-listener protocol. A future handler-serving command
requires a separate explicit design such as `polymesh serve`; it is not
defined here.

#### `polymesh connect`

```text
polymesh connect URL [--card PATH] [--token-file PATH]
                  [--insecure-loopback-dev]
```

It loads/validates a local card, resolves safe credentials, validates endpoint
policy, completes handshake, prints authenticated broker identity/card, then
closes. The positional URL is canonical; `--url` and `POLYMESH_URL` are
compatibility inputs. WSS requires enrolled TLS/Ed25519 configuration. Numeric
loopback WS requires explicit flag and token file.

#### `polymesh call`

```text
polymesh call AGENT CAPABILITY JSON_INPUT --url URL [--card PATH]
              [--token-file PATH] [--timeout MS] [--insecure-loopback-dev]
```

It strictly parses `JSON_INPUT` as a JSON object, connects, submits, waits for
terminal state, prints the raw successful result, and closes. Timeout defaults
to `60000` milliseconds. A remote error writes a bounded diagnostic to stderr
and exits nonzero.

#### `polymesh peers`

```text
polymesh peers [--mdns] [--wait MS]
```

This reports a discovery snapshot. Without mDNS/another configured provider,
it returns `[]`. It MUST NOT auto-connect to a discovery result, send it a
runtime token, or treat discovery metadata as enrollment. `--wait 0` performs
immediate polling; a Python default of 2000 ms is acceptable when mDNS is
enabled.

#### `polymesh capabilities`

```text
polymesh capabilities [--card PATH]
polymesh capabilities --url URL --agent AGENT [connection options]
```

The first form prints the local/default card's capabilities. The optional
remote form may call `org.polymesh.capabilities.list` after normal
authentication; it returns only the target's declared ID/version list and
MUST NOT be described as a verified full remote Card.

### 9.4 Output contract

`--format json|table|plain` selects output rendering. The default is `json`
for machine-readable continuity with the TypeScript CLI.

| Format | Requirement |
|---|---|
| `json` | One complete indented JSON document on stdout followed by LF |
| `table` | Stable headings and deterministic row order; fallback to pretty JSON for non-tabular result |
| `plain` | One stable scalar or one line per collection item |

Rules:

- stdout contains results only, never logs, progress, tracebacks, or secrets;
- stderr contains bounded diagnostics;
- `call --format json` writes the raw successful terminal result, not a CLI
  wrapper object;
- empty lists render as `[]`, heading-only table, or no plain rows;
- ANSI color is disabled for non-TTY output and never required for parsing.

Example JSON result from `connect`:

```json
{
  "connected": true,
  "peer": {
    "agent_id": "org.polymesh.broker",
    "instance_id": "XBr2H0mJ7xEVN1XNYXqvVQ"
  },
  "card": {
    "card_version": "1.0",
    "agent_id": "org.polymesh.broker"
  }
}
```

Suggested table headings are `Agent`, `Instance`, `Host`, `Port`, `Security`
for peers and `Capability`, `Version`, `Idempotency`, `Side effects`,
`Cancellation` for capabilities.

### 9.5 Configuration files

The CLI supports TOML and optionally safe YAML. Precedence is:

1. explicit command-line option;
2. environment variable;
3. explicit `--config PATH` file;
4. project `polymesh.toml` or `polymesh.yaml`;
5. user config under the platform configuration directory;
6. built-in default.

An explicit `--config` disables automatic configuration discovery but does not
override flags or environment values. Configuration has closed Pydantic models:
unknown fields, inline secrets, unsafe WSS choices, invalid URLs, and invalid
timeouts are errors. Agent cards remain strict JSON wire objects even when
operational configuration is TOML/YAML.

```toml
[client]
url = "ws://127.0.0.1:7337/polymesh"
card_file = "~/.polymesh/card.json"
token_file = "~/.polymesh/token"
timeout_ms = 60000
insecure_loopback_dev = true

[broker]
host = "127.0.0.1"
port = 7337
token_file = "~/.polymesh/token"
insecure_loopback_dev = true
mdns = false

[output]
format = "json"

[security]
ca_file = "/etc/polymesh/ca.pem"
cert_file = "/etc/polymesh/client.pem"
key_file = "/etc/polymesh/client-key.pem"
identity_key_file = "/etc/polymesh/identity-ed25519.pem"
enrollments_file = "/etc/polymesh/enrollments.json"
```

Equivalent YAML uses the same nested names:

```yaml
client:
  url: ws://127.0.0.1:7337/polymesh
  token_file: ~/.polymesh/token
  timeout_ms: 60000
  insecure_loopback_dev: true
broker:
  host: 127.0.0.1
  port: 7337
  insecure_loopback_dev: true
output:
  format: json
```

YAML loaders MUST use safe loading, reject custom tags and duplicate keys, and
apply the same bounded structural parsing rules appropriate to configuration.

### 9.6 Environment variables

The Python CLI preserves the reference variables and adds file/path-oriented
ones:

| Variable | Meaning |
|---|---|
| `POLYMESH_CARD` | Card file path |
| `POLYMESH_TOKEN_FILE` | Runtime token file path |
| `POLYMESH_URL` | Broker URL |
| `POLYMESH_CONFIG` | Configuration file path |
| `POLYMESH_FORMAT` | `json`, `table`, or `plain` |
| `POLYMESH_PORT` | Broker port |
| `POLYMESH_HOST` | Broker host |
| `POLYMESH_TIMEOUT_MS` | Default call timeout |
| `POLYMESH_INSECURE_LOOPBACK_DEV` | Explicit boolean WS opt-in |
| `POLYMESH_MDNS` | Explicit boolean discovery opt-in |
| `POLYMESH_CA_FILE` | TLS CA file path |
| `POLYMESH_CERT_FILE` | TLS client certificate file path |
| `POLYMESH_KEY_FILE` | TLS client private-key file path |
| `POLYMESH_IDENTITY_KEY_FILE` | Ed25519 identity-key path |
| `POLYMESH_ENROLLMENTS_FILE` | Local enrollment file path |

`POLYMESH_TOKEN`, `POLYMESH_PRIVATE_KEY`, and variables carrying raw secret
values are rejected. Boolean parsing accepts only `true`, `false`, `1`, or
`0`; ambiguous spellings fail configuration validation.

### 9.7 Exit codes

| Exit code | Meaning |
|---:|---|
| `0` | Success |
| `1` | Unexpected internal failure |
| `2` | Usage error or invalid flag |
| `3` | Configuration, file, Card, or JSON-input validation failure |
| `4` | Authentication, credential, TLS, enrollment, or security-policy failure |
| `5` | Connection, handshake, or transport failure |
| `6` | Protocol validation or compatibility failure |
| `7` | Remote task rejection or execution failure |
| `8` | Call, handshake, or heartbeat timeout |
| `130` | SIGINT interruption |

With JSON output selected, errors use a bounded stderr object:

```json
{
  "ok": false,
  "code": "AUTHENTICATION_FAILED",
  "category": "identity",
  "message": "Runtime token file does not contain a valid PolyMesh token",
  "retryable": false
}
```

## 10. Security and identity

### 10.1 Runtime-token file management

The default token-store location is:

```text
~/.polymesh/token
```

This is an SDK storage convention and does not change the TypeScript wire
protocol. Deployments may configure another explicit absolute path.

A runtime token is exactly 32 cryptographically random bytes encoded in
canonical unpadded base64url. It normally has 43 ASCII characters. `TokenStore`
MUST reject empty data, internal whitespace, padding, malformed base64url, and
values that decode to a length other than 32 bytes.

```python
class TokenStore:
    @classmethod
    def default_path(cls) -> Path:
        return Path.home() / ".polymesh" / "token"

    def read(self) -> str:
        """Read one safe token file and return canonical base64url text."""

    def write_new(self) -> str:
        """Generate, atomically persist, and return a new token."""
```

POSIX requirements:

- create `~/.polymesh` with mode `0700`;
- create token file with mode `0600`;
- reject symlink directory and symlink token file;
- verify both are owned by the current effective UID;
- reject group/world readable or writable files/directories;
- write a same-directory temporary file with restrictive mode before writing;
- `fsync` file, atomically replace, then `fsync` the parent directory;
- accept only token bytes, optionally followed by one terminal LF written by
  the store; do not broadly strip whitespace.

On non-POSIX systems the implementation MUST apply an equivalent current-user
ACL policy or fail closed. It must not claim a world-readable credential is
protected.

The token is sent only in the loopback WebSocket HTTP upgrade header:

```http
x-polymesh-token: canonical-base64url-runtime-token
```

It MUST NOT occur in a URL, query string, fragment, userinfo, card, envelope,
auth frame, mDNS record, raw CLI flag, raw environment variable, error, log,
or trace event. A reconnect reads the token file immediately before opening a
new upgrade so normal token rotation can take effect.

Possession of this token authenticates loopback connection admission. It does
not by itself authenticate the self-declared `agent_id` as a durable principal.
Sensitive authorization therefore needs stronger local policy or the enrolled
secure profile.

### 10.2 WSS and certificate verification

The only secure identity profile in the reference is:

```text
enrolled-ed25519-tls-1.3
```

Secure WSS is fail-closed. It requires:

- `wss://` endpoint only;
- TLS 1.3 or later;
- certificate-chain and hostname verification enabled;
- mutual TLS client certificate/key support;
- an enrolled local Ed25519 private key;
- a pre-existing local EnrollmentStore for the peer;
- a carrier capable of exporting the exact reference TLS channel binding;
- no runtime token and no downgrade to `ws://`.

The SDK MUST NOT set `CERT_NONE`, disable hostname checking, accept a custom
callback that bypasses normal verification, or silently fall back to plain WS.
Caller-provided CA, client-cert, key, and SNI files can add trust material but
cannot weaken these checks.

### 10.3 Enrollment and Ed25519 identity

An enrollment is a local trust decision binding `agent_id`, `key_id`, and raw
Ed25519 public key. It is immutable to peer presentation. On secure setup the
SDK:

1. derives local Card identity from the configured private key;
2. verifies an existing local Card identity, if present, matches the key;
3. signs the local Card;
4. verifies the local signed card against local enrollment;
5. verifies peer card signature, expiry, agent ID, key ID, and public key
   against the local EnrollmentStore;
6. derives/verifies the auth proof over complete hello/card/TLS transcript;
7. permits ready only after both sides prove key possession.

An enrollment can be disabled or expire. A disabled/expired record is not a
fallback candidate. A Card, hostname, discovery hint, TLS certificate, or
unknown key MUST NOT create, rotate, or replace enrollment data.

### 10.4 TLS exporter compatibility gate

The TypeScript reference binds secure auth to exact TLS exporter material.
Many ordinary Python WebSocket stacks expose an SSL socket but not the required
exporter. `SSLSocket.get_channel_binding("tls-unique")`, a certificate
fingerprint, a finished-message hash, or an invented hash is not equivalent.

The secure transport abstraction MUST expose:

```python
class SecureWireTransport(WireTransport, Protocol):
    def export_tls_channel_binding(self) -> bytes:
        """Return exactly 32 reference-compatible exporter bytes."""
```

Before it sends secure protocol records, the SDK verifies the method exists,
returns exactly 32 bytes, and is integration-tested against the TypeScript
broker. If it cannot do so, client creation or connect MUST raise
`SecureProfileUnsupportedError`. Token-authenticated loopback remains usable
with the standard carrier; the SDK simply cannot claim secure-profile wire
compatibility without this capability.

### 10.5 Authorization and replay protection

The default client handler policy permits only the standard capabilities.
Applications enabling other capabilities supply an explicit authorization
hook or policy engine. An allow decision must be structurally valid and
positive; an exception, malformed return, resolver failure, or missing policy
is deny-by-default.

For secure/policy deployments, stable principal resolution MUST come from
verified provenance, an authenticated direct peer, or an explicitly trusted
bridge. It MUST NOT manufacture a principal merely from `source.agent_id` or
`source.instance_id`.

For sensitive/side-effecting work, durable replay admission occurs before
handler execution. Persist recipient-visible lifecycle artifacts before their
send when the ledger requires durability. If persistence fails, abort work and
emit a bounded rejection/error rather than run without promised protection.

### 10.6 Input/output hardening

The SDK must:

- enforce strict JSON and size budgets before Pydantic/model construction;
- freeze/deep-copy handler input;
- validate capability input/result schema using the restricted profile only;
- limit progress records and pending/local tasks;
- avoid compiling attacker-controlled regex/schema references;
- parse endpoint URLs with userinfo/query/fragment prohibition;
- sanitize native close code/reason before reusing it locally;
- log only bounded/redacted metadata;
- keep application exception messages local and emit generic wire failure
  messages by default.

### 10.7 Secret and log-redaction checklist

Never log or emit in CLI output:

- runtime tokens;
- private keys or PEM contents;
- raw TLS exporter material;
- unredacted certificate/private-key paths when policy treats paths as secret;
- task inputs/results by default;
- raw authorization decisions, provider responses, or application exception
  stack traces;
- full session IDs in normal logs; use a stable redacted hash if correlation is
  necessary.

## 11. Testing and conformance strategy

### 11.1 Test layers

| Layer | Scope | Required outcome |
|---|---|---|
| Unit | IDs, parser, models, schemas, digests, token store | deterministic local correctness |
| Property | bounded parser/encoder/model inputs | no crash, no acceptance of malformed shape |
| Vector | TypeScript-generated bytes/digests/signatures | byte-for-byte compatibility |
| Transport | fake WebSocket/Unix transport | phase, queue, heartbeat, race behavior |
| Integration | Python and TypeScript broker/client processes | actual protocol interoperability |
| Security | malformed inputs, credentials, TLS/provenance | fail-closed behavior and no leakage |
| CLI | subprocess/config/output tests | stable automation contract |

All tests use an injectable UTC/monotonic clock where timing matters. No test
may depend on an external network or web search.

### 11.2 Unit and vector fixtures

The repository MUST include checked-in TypeScript-produced fixtures for:

1. UUIDv7 bit layout and monotonic same-millisecond/backward-clock cases;
2. random instance ID and nonce canonical base64url validation;
3. SID derivation from fixed initiator/responder nonce bytes;
4. canonical JSON with reordered keys, arrays, Unicode, escaping, and number
   edge cases;
5. Card digest for unsigned and signed cards;
6. capability contract normalized payload/digest/tuple;
7. envelope semantic and routed-envelope digest;
8. Ed25519 Card signature, auth proof, and routed provenance signature;
9. every handshake frame and every envelope parameter family;
10. valid and invalid JSON Schema restricted-profile samples.

The vector test should assert both serialized canonical bytes and final digest,
not only digest equality. That catches accidental encoder differences which
could otherwise collide only in a small fixture set.

### 11.3 Parser/model negative cases

Test rejection of:

- invalid UTF-8 and binary WebSocket frames;
- duplicate JSON names at root and nested depth;
- trailing JSON content and malformed escape sequences;
- `NaN`, `Infinity`, `-Infinity`, non-finite outbound floats, cycles, and
  unpaired Unicode surrogates;
- frame/depth/node/member/array/string/card/schema limits;
- unknown fields in each closed wire object;
- invalid UUIDv7, timestamp, base64url length/canonical padding, agent ID,
  capability ID, semver, endpoint URL, and idempotency key;
- unequal submit/dependency deadlines;
- invalid terminal branch field combinations;
- invalid receipt correlation;
- invalid Card identity/signature/enrollment/provenance lifetimes.

### 11.4 Handshake and transport tests

The suite must exercise both normal and negative traces:

```text
Python client -> TypeScript broker: loopback token hello/card/ready
Python client -> TypeScript broker: secure hello/card/auth/ready when exporter carrier exists
Python handler client <- TypeScript client: submit/accepted/progress/completed
TypeScript client <- Python interoperability harness: structural vector coverage
```

Required failures include wrong subprotocol, WS host not numeric loopback,
missing token, WSS token attempt, wrong SID, wrong hello echo, self connection,
expired/mismatched card, profile downgrade, invalid auth proof, late ready,
binary record, and pre-ready Envelope.

### 11.5 Task, receipt, and reconnect tests

Test these execution cases:

- accepted/rejected admission correlation;
- progress/completed contiguous sequence success;
- duplicate lifecycle retransmission and conflicting same sequence;
- wrong source/target/contract/result schema;
- timeout, cancel, completion, and disconnect races;
- receipt accepted/duplicate/rejected behavior without lifecycle mutation;
- broker task-ID and idempotency conflict paths;
- durable replay-ledger required/available/failing cases;
- handler late result after cancellation/deadline/generation replacement;
- heartbeat ping/pong mismatch, inactivity, and timer fencing;
- old socket message/close callback after a new generation becomes active;
- reconnect backoff/reset and explicit proof that no pending task is silently
  resent across a new v0.1 SID.

### 11.6 CLI and security tests

CLI tests run subprocesses with isolated temporary homes/config directories.
They verify JSON/table/plain determinism, config precedence, exit codes, raw
secret flag/environment rejection, redaction, unsafe token-file permissions,
symlink rejection, token rotation, SIGINT exit, and safe default endpoints.

Security integration tests must assert WSS certificate/hostname failure,
enrollment revocation/expiry, provenance substitution/cross-session replay,
malformed mDNS hint handling, no WS fallback, and no credential data in logs.

## 12. SDK roadmap

### 12.1 Version axes

Python package version and selected wire profile are independent:

| Axis | Example | Meaning |
|---|---|---|
| Python SDK release | `polymesh==0.2.0` | Python API, packaging, and local features |
| v0.1 wire profile | `polymesh.0.1` | current TypeScript-compatible profile |
| v0.2 wire profile | `polymesh.0.2` | separate selected protocol, not a v0.1 extension |
| Card version | `1.0` or `2.0` | profile-specific card schema |

Upgrading Python SDK package version MUST NOT change the default v0.1 profile,
authentication strength, or replay semantics. A future `protocol_profile`
option fails for v0.2 until a dedicated tested v0.2 client exists.

### 12.2 SDK v0.1: core client, types, basic CLI

Goal: a production-quality selected-v0.1 client implementation.

Included:

- complete Pydantic models, strict parser, canonical/digest/crypto helpers;
- loopback WebSocket transport, optional Unix adapter, heartbeat, explicit
  safe reconnect, token management, errors, and task API;
- secure profile only when the carrier meets the exact exporter requirement;
- `start`, `connect`, `call`, `listen`, `peers`, `capabilities` CLI commands;
- JSON/table/plain output, token-safe config/environment support;
- TypeScript vector, unit, integration, and security suite.

Excluded: mDNS, hot reload, generic sender-envelope signing, new streaming
records, remote event subscription records, and any v0.1 resume claim.

Release gates are all vector tests, loopback integration, handler interop,
lifecycle/receipt/replay/race coverage, no raw-token CLI path, deterministic
output, and no transparent SID-crossing task retry.

### 12.3 SDK v0.2: discovery, hot reload, structured logging

This is a Python package feature release, not automatic support for the
`polymesh.0.2` wire profile.

#### mDNS discovery

Expose an optional `polymesh[mdns]` extra and an opt-in `MdnsDiscovery` API.
It publishes/consumes minimal endpoint hints only. Hints never enroll keys,
grant authorization, select a weaker transport, or receive loopback tokens.
Each candidate passes endpoint policy and a normal authenticated handshake
before its Card is trusted. Discovery defaults off.

#### Handler hot reload

Expose explicit `await client.reload_handlers(mapping)`. Build and validate a
new immutable registry, atomically swap it under an async lock, and pin each
accepted task to the callable/registry generation it saw at admission. Existing
tasks continue under their original callable. A failed reload preserves the old
registry; a reload cannot silently change a Card contract.

#### Structured logging

Use the standard `logging` module with optional JSON formatter. Event fields
may include event name, timestamp, local/peer identity, hashed SID, generation,
message/task IDs, capability, outcome, error code, retryability, and duration.
Never log tokens, keys, exporter material, or task input/result by default.

Release gates: all v0.1 tests still pass unchanged; discovery spoof/policy/no-
auto-connect tests; reload-race tests; logging redaction tests; optional extras
install independently without blocking core installation.

### 12.4 SDK v0.3: advanced capabilities behind selected profiles

#### Envelope signing

Generic sender envelope signing cannot be inserted into v0.1 because its
Envelope objects are closed. Do not smuggle signature fields through params,
metadata, or delivery. A future selected profile needs explicit algorithm/key
ID fields, domain-separated canonical signing payload, enrollment/key rotation,
replay rules, downgrade resistance, vectors, and independent security review.
Existing broker provenance remains v0.1-specific and is not generic signing.

#### Streaming tasks

The SDK may expose a local async iterator over existing v0.1 progress events;
that is not a new streaming wire protocol. True streaming requires future
closed records with per-stream sequencing, bounded backpressure/credits,
terminal relationship, cancellation/deadline/replay/fencing behavior, and
cross-language fixtures. It MUST NOT invent `task.chunk` in v0.1.

#### Event subscriptions

Local event callbacks/iterators are valid SDK conveniences. Remote
subscriptions require a selected future profile with subscribe/unsubscribe
records, authorization, subscription identity, schema/version, cursor/
retention/replay semantics, bounded queues, acknowledgement, and revocation.
It MUST NOT invent v0.1 `subscribe` or `event` message types.

Advanced release gates require closed schemas, pre-record profile selection,
no downgrade, Python/TypeScript byte-for-byte fixtures, and explicit restart,
replay, fencing, cancellation, overload, streaming-slow-consumer, and
subscription-revocation tests.

### 12.5 Migration policy

- v0.1 remains the default connection profile through all package releases.
- New local SDK features are opt-in and do not auto-connect or alter route
  selection.
- Mixed fleets use separate connections per selected profile; a connection
  never switches profile after hello.
- Unknown config fields fail closed except in an explicit documented migration
  reader.
- Public models, `PolyMeshClient`, error fields, and basic CLI names receive
  documented deprecation before incompatible changes.

## Appendix A. JSON Schemas

The schemas below are Draft 2020-12 artifacts shipped with the package. They
express closed structural shape. Strict parsing, exact timestamp/base64url
canonicality, card signature, restricted-schema validation, task deadline
equality, and lifecycle/session checks remain runtime requirements.

### A.1 v0.1 Envelope schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://polymesh.dev/schemas/envelope.json",
  "title": "PolyMesh v0.1 Envelope",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "protocol",
    "type",
    "message_id",
    "timestamp",
    "source",
    "target",
    "delivery",
    "params"
  ],
  "properties": {
    "protocol": {"const": "polymesh.0.1"},
    "type": {
      "enum": [
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
        "error"
      ]
    },
    "message_id": {"$ref": "#/$defs/uuidv7"},
    "timestamp": {"$ref": "#/$defs/timestamp"},
    "source": {"$ref": "#/$defs/source"},
    "target": {"$ref": "#/$defs/target"},
    "delivery": {"$ref": "#/$defs/delivery"},
    "in_reply_to": {"$ref": "#/$defs/uuidv7"},
    "provenance": {"$ref": "#/$defs/provenance"},
    "params": {"type": "object"}
  },
  "$defs": {
    "uuidv7": {
      "type": "string",
      "pattern": "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
    },
    "timestamp": {
      "type": "string",
      "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$"
    },
    "agent_id": {
      "type": "string",
      "maxLength": 255,
      "pattern": "^[a-zA-Z][a-zA-Z0-9._-]*$"
    },
    "source": {
      "type": "object",
      "additionalProperties": false,
      "required": ["agent_id", "instance_id"],
      "properties": {
        "agent_id": {"$ref": "#/$defs/agent_id"},
        "instance_id": {"type": "string", "pattern": "^[A-Za-z0-9_-]{22}$"}
      }
    },
    "target": {
      "type": "object",
      "additionalProperties": false,
      "required": ["agent_id"],
      "properties": {
        "agent_id": {"$ref": "#/$defs/agent_id"},
        "instance_id": {"type": "string", "pattern": "^[A-Za-z0-9_-]{22}$"}
      }
    },
    "delivery": {
      "type": "object",
      "additionalProperties": false,
      "required": ["mode", "idempotency_key", "deadline"],
      "properties": {
        "mode": {"const": "at_least_once"},
        "idempotency_key": {"type": "string", "minLength": 1, "maxLength": 256},
        "deadline": {"$ref": "#/$defs/timestamp"}
      }
    },
    "provenance": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "version", "broker", "source_principal", "source", "target",
        "source_session_id", "target_session_id", "envelope_digest",
        "issued_at", "expires_at", "signature"
      ],
      "properties": {
        "version": {"const": "pmx.broker-provenance/1"},
        "broker": {"type": "object"},
        "source_principal": {"type": "object"},
        "source": {"$ref": "#/$defs/source"},
        "target": {"$ref": "#/$defs/target"},
        "source_session_id": {"type": "string", "pattern": "^[A-Za-z0-9_-]{43}$"},
        "target_session_id": {"type": "string", "pattern": "^[A-Za-z0-9_-]{43}$"},
        "envelope_digest": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
        "issued_at": {"$ref": "#/$defs/timestamp"},
        "expires_at": {"$ref": "#/$defs/timestamp"},
        "signature": {"type": "string", "pattern": "^[A-Za-z0-9_-]{86}$"}
      }
    }
  }
}
```

`params` is specialized by the model table in Section 4 and the rules in
Section 6. A JSON Schema validator alone cannot ensure the `task.submit`
deadline equals `delivery.deadline`, verify a signature, or enforce route
state.

### A.2 v0.1 Agent Card schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://polymesh.dev/schemas/card.json",
  "title": "PolyMesh v0.1 Agent Card",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "card_version",
    "agent_id",
    "instance_id",
    "issued_at",
    "expires_at",
    "revision",
    "capabilities"
  ],
  "properties": {
    "card_version": {"const": "1.0"},
    "agent_id": {"type": "string", "pattern": "^[a-zA-Z][a-zA-Z0-9._-]*$"},
    "instance_id": {"type": "string", "pattern": "^[A-Za-z0-9_-]{22}$"},
    "display_name": {"type": "string"},
    "issued_at": {"type": "string", "format": "date-time"},
    "expires_at": {"type": "string", "format": "date-time"},
    "revision": {"type": "integer", "minimum": 1},
    "endpoints": {"type": "array", "maxItems": 8, "items": {"$ref": "#/$defs/endpoint"}},
    "capabilities": {"type": "array", "minItems": 1, "maxItems": 64, "items": {"$ref": "#/$defs/capability"}},
    "limits": {"type": "object"},
    "metadata": {"type": "object"},
    "identity": {"$ref": "#/$defs/identity"},
    "signature": {"type": "string", "pattern": "^[A-Za-z0-9_-]{86}$"}
  },
  "$defs": {
    "endpoint": {
      "type": "object",
      "additionalProperties": false,
      "required": ["transport", "url", "scope"],
      "properties": {
        "transport": {"enum": ["websocket", "unix"]},
        "url": {"type": "string", "maxLength": 2048},
        "scope": {"enum": ["loopback", "lan", "remote"]},
        "security": {"enum": ["none", "token", "mutual"]}
      }
    },
    "capability": {
      "type": "object",
      "additionalProperties": false,
      "required": ["id", "version"],
      "properties": {
        "id": {"type": "string"},
        "version": {"type": "string", "pattern": "^\\d+\\.\\d+\\.\\d+$"},
        "description": {"type": "string"},
        "input_schema": {"type": "object"},
        "result_schema": {"type": "object"},
        "idempotency": {"enum": ["pure", "idempotent", "sensitive"]},
        "side_effects": {"enum": ["none", "read", "write", "network", "approval"]},
        "approval": {"enum": ["never", "always", "threshold"]},
        "cancellation": {"enum": ["none", "best_effort", "supported"]},
        "timeout_ceiling_seconds": {"type": "integer", "minimum": 1}
      }
    },
    "identity": {
      "type": "object",
      "additionalProperties": false,
      "required": ["alg", "key_id", "public_key"],
      "properties": {
        "alg": {"const": "Ed25519"},
        "key_id": {"type": "string", "pattern": "^[A-Za-z0-9_-]{43}$"},
        "public_key": {"type": "string", "pattern": "^[A-Za-z0-9_-]{43}$"}
      }
    }
  }
}
```

Runtime card validation additionally requires exact UTC-millisecond timestamps,
minimum standard capabilities, unique capability IDs, endpoint URL rules,
restricted schemas, 64 KiB card budget, paired identity/signature fields, and
Ed25519 verification when signed.

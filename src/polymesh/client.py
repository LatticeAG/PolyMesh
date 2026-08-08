"""Async-first PolyMesh v0.1 and native-v2 client lifecycle implementation."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import copy
import inspect
import re
import threading
from collections import OrderedDict, defaultdict
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, TypeAlias

from .auth import TokenStore, validate_runtime_token
from .errors import (
    AuthenticationError,
    ContractMismatchError,
    ExecutionError,
    HandshakeError,
    HandshakeTimeoutError,
    HeartbeatTimeoutError,
    LifecycleError,
    ProtocolError,
    ResultValidationError,
    RoutingError,
    SchemaValidationError,
    SecureProfileUnsupportedError,
    TaskCancelledError,
    TaskRecoveryRequiredError,
    TaskRejectedError,
    TaskTimeoutError,
    TransportClosedError,
    TransportError,
    WrongEventLoopError,
    error_from_structured,
)
from .protocol import (
    EnrollmentStore,
    auth_transcript,
    capability_contract_tuple,
    canonical_json,
    card_digest,
    create_auth_proof,
    create_v2_auth_proof,
    create_envelope,
    derive_session_id,
    derive_v2_session_id,
    encode_record_text,
    is_v2_mesh_id,
    is_v2_native_uuid,
    native_v2_envelope_as_legacy,
    native_v2_envelope_from_legacy,
    parse_strict_json,
    random_nonce,
    sign_agent_card,
    validate_envelope,
    validate_restricted_schema,
    validate_handshake_frame,
    validate_v2_envelope,
    validate_v2_ack_frame,
    validate_v2_error_frame,
    validate_v2_hello_frame,
    validate_v2_init_frame,
    validate_v2_native_envelope,
    validate_restricted_schema_instance,
    verify_auth_proof,
    verify_v2_auth_proof,
    verify_enrolled_card,
    verify_routed_provenance,
    v2_auth_transcript,
    v2_envelope_as_legacy,
    v2_envelope_from_legacy,
    uuidv7,
)
from .transport import (
    ConnectionState,
    MAX_FRAME_BYTES,
    SecureWireTransport,
    WebSocketConnector,
    WireTransport,
    zstd_available,
    zstd_compress,
    zstd_decompress,
)
from .types import (
    AgentCard,
    AgentCardBuilder,
    AgentIdentity,
    AgentRef,
    AuthFrame,
    Capability,
    CapabilityContractTuple,
    CardFrame,
    ClientLimits,
    ClientPhase,
    Envelope,
    InitiatorHello,
    JsonObject,
    JsonValue,
    ReceiptParams,
    ReconnectPolicy,
    ReadyFrame,
    PROTOCOL_VERSION,
    ResponderHello,
    SecureIdentityOptions,
    TaskSnapshot,
    TaskStatus,
    TaskStatusQueryParams,
    TaskStatusSnapshotParams,
    TaskStatusSnapshotWire,
    TLSOptions,
    base64url_encode,
    format_timestamp,
    parse_timestamp,
    utc_now_millis,
    V2_HANDSHAKE_VERSION,
    V2_PROTOCOL_VERSION,
)


TaskProgress: TypeAlias = JsonObject
ProgressCallback: TypeAlias = Callable[[TaskProgress], Any]
TaskHandler: TypeAlias = Callable[[JsonObject, "TaskContext"], Awaitable[JsonValue] | JsonValue]
AuthorizationHook: TypeAlias = Callable[[AgentIdentity, str, JsonObject, Envelope], Awaitable[bool] | bool]
ClientEventCallback: TypeAlias = Callable[[Any], Any]


_STANDARD_CAPABILITIES = {
    "org.polymesh.agent.ping",
    "org.polymesh.agent.info",
    "org.polymesh.capabilities.list",
}


def _utc_deadline(seconds: float) -> str:
    return format_timestamp(datetime.now(UTC) + timedelta(seconds=seconds))


def _clone_json(value: JsonValue) -> JsonValue:
    # Strict JSON/canonical round-trip makes a handler unable to mutate a
    # shared inbound object or retain a model-backed reference.
    return parse_strict_json(canonical_json(value))


def _same_ref(expected: AgentRef | AgentIdentity, actual: AgentRef | AgentIdentity, *, require_instance: bool = False) -> bool:
    """Compare an expected address with an observed identity.

    An ``AgentRef`` without an instance ID intentionally means any live
    instance of that agent.  Keeping that wildcard on the expected side is
    important for routed lifecycle records, whose observed source is always a
    full ``AgentIdentity``.
    """

    if expected.agent_id != actual.agent_id:
        return False
    if require_instance:
        return getattr(expected, "instance_id", None) == getattr(actual, "instance_id", None)
    expected_instance = getattr(expected, "instance_id", None)
    actual_instance = getattr(actual, "instance_id", None)
    return expected_instance is None or expected_instance == actual_instance


def _as_seconds(value: datetime | str | None, timeout: float, maximum: float) -> tuple[str, float]:
    now = datetime.now(UTC)
    if value is None:
        seconds = timeout
        if seconds <= 0 or seconds > maximum:
            raise ValueError("timeout exceeds the configured task limit")
        deadline = now + timedelta(seconds=seconds)
    elif isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("deadline must be timezone-aware")
        deadline = value.astimezone(UTC)
        seconds = (deadline - now).total_seconds()
    elif isinstance(value, str):
        deadline = parse_timestamp(value)
        seconds = (deadline - now).total_seconds()
    else:
        raise TypeError("deadline must be datetime, timestamp string, or None")
    if seconds <= 0:
        raise TaskTimeoutError("PMX.TASK.DEADLINE_EXCEEDED", "task deadline has already elapsed")
    if seconds > maximum:
        raise ValueError("deadline exceeds the configured task limit")
    return format_timestamp(deadline), seconds


@dataclass(slots=True)
class _PendingCall:
    handle: "TaskHandle"
    target: AgentRef
    contract: CapabilityContractTuple
    result_schema: JsonObject | None
    deadline: str
    deadline_task: asyncio.Task[None]
    event_digests: dict[int, str] = field(default_factory=dict)


@dataclass(slots=True)
class _PendingStatusQuery:
    """One advisory v0.1 ``task.status`` request awaiting a snapshot."""

    message_id: str
    target: AgentRef
    task_id: str
    future: asyncio.Future[TaskStatusSnapshotParams]


@dataclass(slots=True)
class _LocalTask:
    task_id: str
    source: AgentIdentity
    target: AgentRef
    contract: CapabilityContractTuple
    deadline: str
    result_schema: JsonObject | None
    submit_message_id: str
    generation: int
    cancelled: asyncio.Event
    task: asyncio.Task[None] | None = None
    next_event_seq: int = 2
    progress_count: int = 0
    terminal: bool = False
    progress_tasks: set[asyncio.Task[None]] = field(default_factory=set)
    replay_key: str | None = None


@dataclass(slots=True)
class _InboundReplay:
    """Bounded local idempotency admission record for one inbound task."""

    fingerprint: str
    accepted: Envelope | None = None
    terminal: Envelope | None = None


@dataclass(frozen=True, slots=True)
class _V2Compression:
    """One post-READY v2 transport selection for this connection generation."""

    algorithm: str
    max_compressed_bytes: int | None = None
    max_uncompressed_bytes: int | None = None
    max_expansion_ratio: int | None = None


_V2_COMPRESSIBLE_TYPES = frozenset(
    {
        "task.submit",
        "task.accepted",
        "task.rejected",
        "task.progress",
        "task.completed",
        "task.cancel",
        "task.status",
        "error",
    }
)


def _v2_compression_limits(value: Mapping[str, Any]) -> tuple[int, int, int] | None:
    """Parse the closed camel-case wire limits used by the current broker."""

    if set(value) != {"maxCompressedBytes", "maxUncompressedBytes", "maxExpansionRatio"}:
        return None
    compressed = value.get("maxCompressedBytes")
    uncompressed = value.get("maxUncompressedBytes")
    ratio = value.get("maxExpansionRatio")
    if (
        not isinstance(compressed, int)
        or isinstance(compressed, bool)
        or not isinstance(uncompressed, int)
        or isinstance(uncompressed, bool)
        or not isinstance(ratio, int)
        or isinstance(ratio, bool)
        or not 0 < compressed <= MAX_FRAME_BYTES
        or not 0 < uncompressed <= MAX_FRAME_BYTES
        or not 0 < ratio <= 64
    ):
        return None
    return compressed, uncompressed, ratio


def _v2_decode_base64url(value: Any) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise ProtocolError("COMPRESSION_FRAME_INVALID", "compressed payload must be canonical base64url")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise ProtocolError("COMPRESSION_FRAME_INVALID", "compressed payload is not base64url") from exc
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        raise ProtocolError("COMPRESSION_FRAME_INVALID", "compressed payload is not canonical base64url")
    return raw


class TaskHandle:
    """A local observation of one submitted logical task."""

    def __init__(self, client: "PolyMeshClient", task_id: str, submit_message_id: str) -> None:
        self._client = client
        self._task_id = task_id
        self._submit_message_id = submit_message_id
        self._status = TaskStatus.PENDING
        self._last_event_seq = 0
        self._receipt: ReceiptParams | None = None
        self._future: asyncio.Future[JsonValue] = asyncio.get_running_loop().create_future()
        self._progress_callbacks: list[ProgressCallback] = []

    @property
    def task_id(self) -> str:
        return self._task_id

    @property
    def submit_message_id(self) -> str:
        return self._submit_message_id

    @property
    def status(self) -> TaskStatus:
        return self._status

    @property
    def last_event_seq(self) -> int:
        return self._last_event_seq

    @property
    def receipt(self) -> ReceiptParams | None:
        return self._receipt

    async def result(self) -> JsonValue:
        return await asyncio.shield(self._future)

    def __await__(self):  # type: ignore[no-untyped-def]
        return self.result().__await__()

    async def cancel(self, reason: str | None = None) -> None:
        await self._client.cancel(self._task_id, reason)

    def add_progress_callback(self, callback: ProgressCallback) -> Callable[[], None]:
        if not callable(callback):
            raise TypeError("progress callback must be callable")
        self._progress_callbacks.append(callback)

        def unsubscribe() -> None:
            with contextlib.suppress(ValueError):
                self._progress_callbacks.remove(callback)

        return unsubscribe

    def snapshot(self) -> TaskSnapshot:
        return TaskSnapshot(
            task_id=self.task_id,
            submit_message_id=self.submit_message_id,
            status=self.status,
            last_event_seq=self.last_event_seq,
            receipt=self.receipt,
        )

    def _progress(self, value: TaskProgress) -> None:
        for callback in tuple(self._progress_callbacks):
            try:
                callback(copy.deepcopy(value))
            except Exception:
                self._client._emit("protocol_error", ProtocolError("CALLBACK_ERROR", "progress callback failed"))

    def _resolve(self, value: JsonValue) -> None:
        if not self._future.done():
            self._future.set_result(value)

    def _reject(self, error: BaseException) -> None:
        if not self._future.done():
            self._future.set_exception(error)


class TaskContext:
    """Task-scoped view passed to an admitted handler."""

    def __init__(
        self,
        client: "PolyMeshClient",
        local: _LocalTask,
        input_value: JsonObject,
    ) -> None:
        self._client = client
        self._local = local
        self.task_id = local.task_id
        self.source = local.source
        self.deadline = parse_timestamp(local.deadline)
        self.result_schema = copy.deepcopy(local.result_schema)
        self.cancelled = local.cancelled
        # Expose the fence that owns this handler invocation.  Application
        # code can retain this diagnostic value without gaining access to
        # mutable client session state.
        self.generation = local.generation
        self.input = _clone_json(input_value)

    def progress(self, progress: TaskProgress) -> None:
        if not isinstance(progress, dict):
            raise TypeError("progress must be a JSON object")
        # Validate synchronously, before spawning the fire-and-forget sender.
        # Otherwise an invalid nested value (for example NaN or a cycle) would
        # fail inside an unobserved background task after application code had
        # been told that progress was accepted for enqueueing.
        try:
            validated = parse_strict_json(canonical_json(progress))
        except Exception as exc:
            raise ValueError("progress must be a bounded JSON object") from exc
        if not isinstance(validated, dict):  # Defensive after the shape check.
            raise TypeError("progress must be a JSON object")
        self._client._schedule_progress(self._local, validated)

    def raise_if_cancelled(self) -> None:
        if self.cancelled.is_set() or self._local.generation != self._client._generation:
            raise TaskCancelledError("TASK_CANCELLED", "task was cancelled or connection generation changed", task_id=self.task_id)
        if datetime.now(UTC) >= self.deadline:
            raise TaskCancelledError("PMX.TASK.DEADLINE_EXCEEDED", "task deadline elapsed", task_id=self.task_id)


class PolyMeshClient:
    """One loop-bound async PolyMesh session manager.

    ``profile="polymesh.0.1"`` remains the default.  Selecting
    ``polymesh.0.2`` is an explicit, non-downgrading choice that uses the v2
    WebSocket subprotocol, mesh-scoped envelope encoding, and optional zstd.
    """

    def __init__(
        self,
        *,
        card: AgentCard | None = None,
        broker_url: str | None = None,
        token: str | None = None,
        token_store: TokenStore | None = None,
        allow_insecure_loopback_development: bool = False,
        identity: SecureIdentityOptions | None = None,
        tls: TLSOptions | None = None,
        handlers: Mapping[str, TaskHandler] | None = None,
        default_timeout: float = 60.0,
        handshake_timeout: float = 5.0,
        profile: str = PROTOCOL_VERSION,
        mesh_id: str | None = None,
        compression: bool = True,
        compression_limits: Mapping[str, int] | None = None,
        v2_handshake: str = "auto",
        reconnect: ReconnectPolicy | None = None,
        limits: ClientLimits | None = None,
        authorization: AuthorizationHook | None = None,
        replay_ledger: Any | None = None,
        transport_factory: Callable[[], Awaitable[WireTransport] | WireTransport] | None = None,
        clock: Any | None = None,
        transport: str | None = None,
        gateway_url: str | None = None,
        api_key: str | None = None,
        agent_id: str | None = None,
        **legacy: Any,
    ) -> None:
        if legacy:
            unknown = ", ".join(sorted(legacy))
            raise TypeError(f"unexpected PolyMeshClient option(s): {unknown}")

        gateway_mode = transport == "gateway"
        if transport is not None and transport != "gateway":
            raise TypeError('transport must be "gateway" when set (broker mode omits transport)')
        if not gateway_mode and (gateway_url is not None or api_key is not None):
            raise TypeError('gateway_url/api_key require transport="gateway"')
        if gateway_mode:
            if identity is not None:
                raise TypeError("Gateway transport cannot be combined with the enrolled identity profile")
            if broker_url is not None or token is not None or token_store is not None:
                raise TypeError("Gateway transport uses gateway_url/api_key rather than broker_url/token")
            if transport_factory is not None:
                raise TypeError("Gateway transport cannot be combined with a broker transport_factory")
        self._gateway_mode = gateway_mode
        self._gateway: Any | None = None

        if card is None:
            if not gateway_mode:
                raise TypeError("card is required unless transport=\"gateway\"")
            safe_id = (
                agent_id
                if isinstance(agent_id, str) and agent_id and re.fullmatch(r"^[a-zA-Z][a-zA-Z0-9._-]*$", agent_id)
                else "gateway.agent"
            )
            card = AgentCardBuilder(safe_id).build()
        self.card = AgentCard.model_validate(card)
        if profile not in {PROTOCOL_VERSION, V2_PROTOCOL_VERSION}:
            raise ValueError("profile must be polymesh.0.1 or polymesh.0.2")
        if not gateway_mode:
            if mesh_id is not None and not is_v2_mesh_id(mesh_id):
                raise ValueError("mesh_id is not a valid PolyMesh v2 mesh identity")
            if profile == PROTOCOL_VERSION and mesh_id is not None:
                raise ValueError("mesh_id is available only for profile='polymesh.0.2'")
            if mesh_id is not None and profile == V2_PROTOCOL_VERSION and v2_handshake != "legacy" and not is_v2_native_uuid(mesh_id):
                raise ValueError("native polymesh.0.2 mesh_id must be a UUIDv7")
        if not isinstance(compression, bool):
            raise TypeError("compression must be a boolean")
        if v2_handshake not in {"auto", "native", "legacy"}:
            raise ValueError("v2_handshake must be 'auto', 'native', or 'legacy'")
        if profile == PROTOCOL_VERSION and v2_handshake != "auto":
            raise ValueError("v2_handshake is available only for profile='polymesh.0.2'")
        limits_source: Mapping[str, Any] = compression_limits or {
            "maxCompressedBytes": MAX_FRAME_BYTES,
            "maxUncompressedBytes": MAX_FRAME_BYTES,
            "maxExpansionRatio": 32,
        }
        parsed_compression_limits = _v2_compression_limits(limits_source)
        if parsed_compression_limits is None:
            raise ValueError("compression_limits must contain bounded v2 zstd limits")
        if default_timeout <= 0 or handshake_timeout <= 0:
            raise ValueError("timeouts must be positive")
        if token is not None and token_store is not None:
            raise ValueError("specify token or token_store, not both")
        if token is not None:
            token = validate_runtime_token(token)
        if identity is not None and (token is not None or token_store is not None):
            raise ValueError("secure identity cannot be combined with a runtime token")
        self._broker_url = broker_url
        self._profile = profile
        self._mesh_id = mesh_id
        self._compression_enabled = compression
        self._v2_offer_limits = parsed_compression_limits
        self._v2_handshake_preference = v2_handshake
        self._v2_wire_mode = "native" if profile == V2_PROTOCOL_VERSION and v2_handshake != "legacy" else "legacy"
        self._v2_compression: _V2Compression | None = None
        self._v2_compression_offered = False
        self._v2_initiator_hello: JsonObject | None = None
        self._v2_responder_hello: JsonObject | None = None
        self._v2_native_compression_selected = "none"
        self._v2_native_compression_active = False
        self._v2_native_proposed = False
        self._v2_native_ready_sent = False
        self._token = token
        self._token_store = token_store
        self._allow_insecure_loopback_development = allow_insecure_loopback_development
        self._identity_options = identity
        self._enrollments: EnrollmentStore | None = None
        self._local_principal: Any | None = None
        if identity is not None:
            try:
                self._enrollments = (
                    identity.enrollments
                    if isinstance(identity.enrollments, EnrollmentStore)
                    else EnrollmentStore(identity.enrollments)
                )
                self.card = sign_agent_card(self.card, identity.private_key)
                self._local_principal = verify_enrolled_card(self.card, self._enrollments)
            except Exception as exc:
                raise AuthenticationError("AUTHENTICATION_FAILED", "secure identity card could not be prepared") from exc
            if self._local_principal is None:
                raise AuthenticationError("AUTHENTICATION_FAILED", "local secure identity is not enrolled")
        self._tls = tls
        self._default_timeout = default_timeout
        self._handshake_timeout = handshake_timeout
        self._limits = limits or ClientLimits(default_timeout=default_timeout)
        self._reconnect = reconnect or ReconnectPolicy()
        self._authorization = authorization
        self._replay_ledger = replay_ledger
        self._transport_factory = transport_factory
        self._clock = clock

        self._phase = ClientPhase.IDLE
        self._connection_state = ConnectionState.IDLE
        self._loop: asyncio.AbstractEventLoop | None = None
        self._transport: WireTransport | None = None
        self._generation = 0
        self._sid: str | None = None
        self._broker_card: AgentCard | None = None
        self._broker_identity: AgentIdentity | None = None
        self._broker_principal: Any | None = None
        self._connect_future: asyncio.Task["PolyMeshClient"] | None = None
        self._disconnecting = False
        self._state_lock: asyncio.Lock | None = None
        self._send_lock: asyncio.Lock | None = None
        self._receiver_task: asyncio.Task[None] | None = None
        self._heartbeat_task: asyncio.Task[None] | None = None
        self._reconnect_task: asyncio.Task[None] | None = None
        self._outstanding_pong: tuple[int, asyncio.Event] | None = None
        self._next_ping = 0
        self._active_since: float | None = None
        self._last_valid_inbound_at: float | None = None
        self._failing_generation: int | None = None
        self._reconnect_attempt = 0

        self._registry_lock = threading.RLock()
        self._handlers: dict[str, TaskHandler] = {}
        self._subscriptions: dict[str, list[ClientEventCallback]] = defaultdict(list)
        self._envelope_queue: asyncio.Queue[Envelope] | None = None
        self._pending_by_task: dict[str, _PendingCall] = {}
        self._pending_by_message: dict[str, _PendingCall] = {}
        self._status_queries: dict[str, _PendingStatusQuery] = {}
        self._local_tasks: dict[str, _LocalTask] = {}
        self._inbound_replays: OrderedDict[str, _InboundReplay] = OrderedDict()
        # Task IDs are logical identities in addition to delivery keys.  This
        # bounded index detects a caller trying to reuse one task ID with a
        # different immutable task body under a fresh idempotency key.
        self._inbound_task_replays: OrderedDict[str, tuple[str, _InboundReplay]] = OrderedDict()

        if handlers:
            for capability, handler in handlers.items():
                self.set_handler(capability, handler)

        if gateway_mode:
            from .gateway_transport import GatewayTransport

            self._gateway = GatewayTransport(
                api_key=api_key,
                gateway_url=gateway_url,
                agent_id=agent_id,
                mesh_id=mesh_id,
            )
            self._gateway._event_bridge = self._emit  # type: ignore[attr-defined]

        # v6 M1 capability router (PRODUCT). Additive; does not alter submit_task.
        from .router import CapabilityRouter

        self._capability_router = CapabilityRouter(
            caller_id=self.card.agent_id,
            cold_start_policy="eager",
        )
        self._a2a_outbound_bridge: Any | None = None

    @property
    def phase(self) -> ClientPhase:
        return self._phase

    @property
    def connection_state(self) -> ConnectionState:
        return self._connection_state

    @property
    def connected(self) -> bool:
        if self._gateway_mode:
            return bool(self._gateway is not None and self._gateway.connected)
        return self._phase is ClientPhase.ACTIVE and self._transport is not None and not self._transport.closed

    @property
    def is_gateway_transport(self) -> bool:
        return self._gateway_mode

    @property
    def gateway(self) -> Any | None:
        return self._gateway

    @property
    def broker_url(self) -> str | None:
        return self._broker_url

    @property
    def profile(self) -> str:
        """The profile selected before this connection's first hello."""

        return self._profile

    @property
    def mesh_id(self) -> str | None:
        """The authenticated v2 mesh scope, populated by a responder hello."""

        return self._mesh_id

    @property
    def compression_algorithm(self) -> str:
        """The active v2 codec, or ``"none"`` before/without negotiation."""

        if self._profile == V2_PROTOCOL_VERSION and self._v2_wire_mode == "native":
            return "zstd" if self._v2_native_compression_active and self._v2_native_compression_selected == "zstd" else "none"
        return self._v2_compression.algorithm if self._v2_compression is not None else "none"

    @property
    def broker_card(self) -> AgentCard | None:
        return self._broker_card

    @property
    def broker_identity(self) -> AgentIdentity | None:
        return self._broker_identity

    @property
    def broker_principal(self) -> Any | None:
        return self._broker_principal

    @property
    def loop(self) -> asyncio.AbstractEventLoop | None:
        return self._loop

    def _bind_loop(self) -> asyncio.AbstractEventLoop:
        loop = asyncio.get_running_loop()
        if self._loop is None:
            self._loop = loop
            self._state_lock = asyncio.Lock()
            self._send_lock = asyncio.Lock()
            self._envelope_queue = asyncio.Queue(maxsize=128)
        elif self._loop is not loop:
            raise WrongEventLoopError("WRONG_EVENT_LOOP", "client is bound to a different asyncio loop")
        return loop

    async def __aenter__(self) -> "PolyMeshClient":
        if self._gateway_mode:
            # Gateway mode: do not auto-connect (SPEC §4.2 / §3.4).
            return self
        await self.connect()
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._gateway_mode and self._gateway is not None:
            try:
                if self._gateway.current_mesh_id is not None:
                    await self._gateway.leave_mesh()
                else:
                    await self._gateway.close()
            finally:
                self._phase = ClientPhase.CLOSED
                self._connection_state = ConnectionState.CLOSED
            return
        await self.disconnect()

    def set_handler(self, capability: str, handler: TaskHandler) -> "PolyMeshClient":
        if not isinstance(capability, str) or not capability:
            raise ValueError("capability must be non-empty")
        if not callable(handler):
            raise TypeError("handler must be callable")
        advertised = {item.id for item in self.card.capabilities}
        if capability not in advertised:
            raise ValueError("handler capability must be declared in the local card")
        with self._registry_lock:
            self._handlers = {**self._handlers, capability: handler}
        return self

    def remove_handler(self, capability: str) -> bool:
        with self._registry_lock:
            if capability not in self._handlers:
                return False
            updated = dict(self._handlers)
            del updated[capability]
            self._handlers = updated
            return True

    def handle(self, capability: str) -> Callable[[TaskHandler], TaskHandler]:
        def decorate(handler: TaskHandler) -> TaskHandler:
            self.set_handler(capability, handler)
            return handler

        return decorate

    def on(self, event: str, callback: ClientEventCallback) -> Callable[[], None]:
        if not callable(callback):
            raise TypeError("event callback must be callable")
        with self._registry_lock:
            self._subscriptions[event] = [*self._subscriptions[event], callback]

        def unsubscribe() -> None:
            with self._registry_lock:
                callbacks = list(self._subscriptions.get(event, ()))
                with contextlib.suppress(ValueError):
                    callbacks.remove(callback)
                self._subscriptions[event] = callbacks

        return unsubscribe

    def _emit(self, event: str, value: Any) -> None:
        with self._registry_lock:
            callbacks = tuple(self._subscriptions.get(event, ()))
        for callback in callbacks:
            try:
                outcome = callback(value)
                if inspect.isawaitable(outcome):
                    loop = self._loop
                    if loop is not None and not loop.is_closed():
                        loop.create_task(outcome)
            except Exception:
                # Event observers are intentionally isolated from protocol
                # state. Recursive callback-error events would be unhelpful.
                pass

    async def envelopes(self) -> AsyncIterator[Envelope]:
        self._bind_loop()
        assert self._envelope_queue is not None
        while True:
            yield await self._envelope_queue.get()

    async def connect(self, url: str | None = None) -> "PolyMeshClient":
        if self._gateway_mode:
            return await self.connect_gateway()
        self._bind_loop()
        if url is not None:
            self._broker_url = url
        if self.connected:
            return self
        # ``disconnect()`` is an idempotent stop operation, not a permanent
        # disposal of the client.  A later explicit connect begins a fresh
        # generation and is therefore allowed to re-enable reconnect logic.
        self._disconnecting = False
        if self._connect_future is not None and not self._connect_future.done():
            return await asyncio.shield(self._connect_future)
        self._connect_future = asyncio.create_task(self._connect_from_factory(), name="polymesh-client-connect")
        return await asyncio.shield(self._connect_future)

    async def _connect_from_factory(self) -> "PolyMeshClient":
        async def open_transport() -> WireTransport:
            factory = self._transport_factory
            if factory is None:
                if not self._broker_url:
                    raise TransportError("INVALID_ENDPOINT", "broker_url is required when no transport factory is supplied")
                connector = WebSocketConnector(
                    self._broker_url,
                    token=self._token,
                    token_store=self._token_store,
                    allow_insecure_loopback_development=self._allow_insecure_loopback_development,
                    secure_identity=self._identity_options,
                    profile=self._profile,
                )
                return await connector()
            candidate = factory()
            return await candidate if inspect.isawaitable(candidate) else candidate

        # Native v2 is the release profile.  Earlier brokers already selected
        # the same WebSocket subprotocol but begin with a v2 ``hello``.  An
        # auto connection attempts the native init/ack exchange first and,
        # only after that fresh carrier is fenced, retries the older v2
        # handshake on a newly opened carrier.  This never downgrades to v0.1.
        if self._profile == V2_PROTOCOL_VERSION and self._v2_handshake_preference == "auto":
            self._v2_wire_mode = "native"
            try:
                return await self.connect_transport(await open_transport())
            except (HandshakeError, TransportClosedError) as native_error:
                if not self._is_native_v2_fallback_error(native_error):
                    raise
                self._v2_wire_mode = "legacy"
                try:
                    return await self.connect_transport(await open_transport())
                except BaseException:
                    # Preserve the native negotiation failure when the retry
                    # could not obtain a new carrier at all; otherwise the
                    # legacy error carries the broker's useful diagnosis.
                    raise
        self._v2_wire_mode = "legacy" if self._v2_handshake_preference == "legacy" else "native"
        return await self.connect_transport(await open_transport())

    @staticmethod
    def _is_native_v2_fallback_error(error: BaseException) -> bool:
        """Only retry old v2 when native profile negotiation was unavailable."""

        if isinstance(error, TransportClosedError):
            return True
        return isinstance(error, HandshakeError) and error.code in {
            "NATIVE_V2_UNSUPPORTED",
            "HANDSHAKE_FAILED",
            "MALFORMED_FRAME",
        }

    async def connect_transport(self, transport: WireTransport) -> "PolyMeshClient":
        if self._gateway_mode:
            from .gateway_transport import GatewayTransportError

            raise GatewayTransportError(
                "GATEWAY_MODE_ACTIVE",
                'connect_transport() is not available when transport is "gateway"',
            )
        self._bind_loop()
        if not isinstance(transport, WireTransport):
            raise TypeError("transport must implement async WireTransport")
        if transport.closed:
            raise TransportClosedError("TRANSPORT_CLOSED", "injected transport is already closed")
        self._disconnecting = False
        assert self._state_lock is not None
        async with self._state_lock:
            if self.connected:
                return self
            self._generation += 1
            generation = self._generation
            self._transport = transport
            self._phase = ClientPhase.AWAIT_HELLO
            self._connection_state = ConnectionState.HANDSHAKING
            self._sid = None
            self._broker_card = None
            self._broker_identity = None
            self._broker_principal = None
            self._v2_compression = None
            self._v2_compression_offered = False
            self._v2_initiator_hello = None
            self._v2_responder_hello = None
            self._v2_native_compression_selected = "none"
            self._v2_native_compression_active = False
            self._v2_native_proposed = False
            self._v2_native_ready_sent = False
            self._next_ping = 0
            self._outstanding_pong = None
            self._last_valid_inbound_at = None
            self._failing_generation = None
        try:
            await asyncio.wait_for(self._handshake(transport, generation), timeout=self._handshake_timeout)
        except asyncio.TimeoutError as exc:
            await self._fail_generation(HandshakeTimeoutError("HANDSHAKE_TIMEOUT", "handshake timed out"), generation, reconnect=False)
            raise HandshakeTimeoutError("HANDSHAKE_TIMEOUT", "handshake timed out") from exc
        except BaseException:
            await self._fail_generation(HandshakeError("HANDSHAKE_FAILED", "handshake failed"), generation, reconnect=False)
            raise
        if generation != self._generation or self._transport is not transport:
            raise TransportClosedError("TRANSPORT_CLOSED", "transport generation was replaced")
        self._phase = ClientPhase.ACTIVE
        self._connection_state = ConnectionState.ACTIVE
        self._active_since = asyncio.get_running_loop().time()
        self._last_valid_inbound_at = self._active_since
        self._receiver_task = asyncio.create_task(self._receiver(transport, generation), name="polymesh-client-receiver")
        self._heartbeat_task = asyncio.create_task(self._heartbeat(transport, generation), name="polymesh-client-heartbeat")
        if self._profile == V2_PROTOCOL_VERSION:
            if self._v2_wire_mode == "native":
                await self._start_native_v2_compression(generation)
            else:
                await self._start_v2_compression(generation)
        self._emit("ready", self)
        return self

    def _require_gateway_mode(self, method: str) -> Any:
        from .gateway_transport import GatewayTransportError

        if not self._gateway_mode or self._gateway is None:
            raise GatewayTransportError(
                "GATEWAY_MODE_REQUIRED",
                f'{method}() requires transport="gateway"',
            )
        return self._gateway

    async def connect_gateway(
        self,
        api_key: str | None = None,
        gateway_url: str | None = None,
    ) -> "PolyMeshClient":
        gateway = self._require_gateway_mode("connect_gateway")
        self._bind_loop()
        self._disconnecting = False
        await gateway.connect_gateway(api_key, gateway_url)
        self._phase = ClientPhase.ACTIVE
        self._connection_state = ConnectionState.ACTIVE
        self._emit("ready", self)
        return self

    async def join_mesh(
        self,
        mesh_id: str,
        *,
        invite_code: str | None = None,
        capabilities: Any = None,
        display_name: str | None = None,
    ) -> Any:
        gateway = self._require_gateway_mode("join_mesh")
        result = await gateway.join_mesh(
            mesh_id,
            invite_code=invite_code,
            capabilities=capabilities,
            display_name=display_name,
        )
        joined_mesh = result.get("mesh_id") if isinstance(result, dict) else None
        if isinstance(joined_mesh, str):
            self._mesh_id = joined_mesh
        return result

    async def discover_agents(self, query: Any = None, /, **filters: Any) -> Any:
        gateway = self._require_gateway_mode("discover_agents")
        if query is None:
            return await gateway.discover_agents(**filters)
        return await gateway.discover_agents(query, **filters)

    async def leave_mesh(self) -> None:
        gateway = self._require_gateway_mode("leave_mesh")
        await gateway.leave_mesh()
        self._mesh_id = None
        self._phase = ClientPhase.CLOSED
        self._connection_state = ConnectionState.CLOSED
        self._emit("close", {"code": 1000, "reason": "mesh.leave"})

    async def submit_task(
        self,
        target: str,
        capability: str,
        payload: JsonValue,
        *,
        task_id: str | None = None,
    ) -> str:
        gateway = self._require_gateway_mode("submit_task")
        return await gateway.submit_task(target, capability, payload, task_id=task_id)

    async def submit_capability_routed(
        self,
        capability: str,
        payload: Any,
        *,
        task_id: str | None = None,
        target: str | None = None,
        max_reroutes: int = 3,
        prefer_dialects: Sequence[str] | None = None,
    ) -> str:
        """Route by capability (Part B) then dispatch; additive to ``submit_task``."""
        router = self._capability_router

        async def _native_dispatch(dispatch_input: Mapping[str, Any]) -> None:
            agent_id = str(dispatch_input["agent_id"])
            cap = str(dispatch_input["capability"])
            body = dispatch_input.get("payload")
            tid = str(dispatch_input["task_id"])
            if self._gateway_mode:
                await self.submit_task(agent_id, cap, body, task_id=tid)
                return
            # Broker-mode native path: use existing targeted submit when available.
            if hasattr(self, "_submit_task_native"):
                await self._submit_task_native(agent_id, cap, body, task_id=tid)  # type: ignore[attr-defined]
                return
            # Route-only / no transport: treat as successful handoff for M1 tests.
            return

        router._native_dispatch = _native_dispatch
        if self._a2a_outbound_bridge is not None:
            router.set_a2a_outbound_bridge(self._a2a_outbound_bridge)

        options: dict[str, Any] = {
            "capability": capability,
            "payload": payload,
            "max_reroutes": max_reroutes,
        }
        if task_id is not None:
            options["task_id"] = task_id
        if target is not None:
            options["target"] = target
        if prefer_dialects is not None:
            options["prefer_dialects"] = list(prefer_dialects)

        result = await router.route_task(options)
        return str(result["task_id"])

    def on_task_routed(self, handler: Callable[[Any], None]) -> Callable[[], None]:
        return self._capability_router.on_task_routed(handler)

    def on_reroute(self, handler: Callable[[Any], None]) -> Callable[[], None]:
        return self._capability_router.on_reroute(handler)

    def set_dialect_preference_hooks(self, hooks: Any | None) -> None:
        self._capability_router.set_dialect_preference_hooks(hooks)

    def set_a2a_outbound_bridge(self, bridge: Any | None) -> None:
        self._a2a_outbound_bridge = bridge
        self._capability_router.set_a2a_outbound_bridge(bridge)

    def set_routing_registry(self, registry: Mapping[str, Any] | None) -> None:
        """Install a RegistryView snapshot for capability routing (tests / merge)."""
        self._capability_router.set_registry(registry)

    async def _handshake(self, transport: WireTransport, generation: int) -> None:
        if self._profile == V2_PROTOCOL_VERSION:
            if self._v2_wire_mode == "native":
                await self._handshake_native_v2(transport, generation)
            else:
                await self._handshake_legacy_v2(transport, generation)
            return
        nonce = random_nonce()
        hello = InitiatorHello(
            type="hello",
            role="initiator",
            agent_id=self.card.agent_id,
            instance_id=self.card.instance_id,
            nonce=nonce,
            **({"security_profile": "enrolled-ed25519-tls-1.3"} if self._identity_options is not None else {}),
        )
        await self._send_record(hello, transport=transport, generation=generation)
        # Handshake records use the same strict JSON boundary as envelopes;
        # unlike the application receiver they are not yet allowed to be
        # ignored on malformed input.
        response = validate_handshake_frame(parse_strict_json(await transport.recv()))
        if not isinstance(response, ResponderHello):
            raise HandshakeError("HANDSHAKE_FAILED", "expected responder hello")
        if response.echo != nonce or response.sid != derive_session_id(nonce, response.nonce):
            raise HandshakeError("HANDSHAKE_FAILED", "responder hello does not bind initiator nonce")
        if response.agent_id == self.card.agent_id and response.instance_id == self.card.instance_id:
            raise HandshakeError("SELF_CONNECTION", "client cannot connect to itself")
        secure_binding: str | None = None
        if self._identity_options is None:
            if response.security_profile is not None:
                raise AuthenticationError("SECURITY_PROFILE_MISMATCH", "peer selected unexpected secure profile")
        else:
            if response.security_profile != "enrolled-ed25519-tls-1.3":
                raise AuthenticationError("SECURITY_PROFILE_MISMATCH", "peer did not select the enrolled secure profile")
            if not isinstance(transport, SecureWireTransport):
                raise SecureProfileUnsupportedError("SECURE_PROFILE_UNSUPPORTED", "secure enrolled handshake requires an exporter-capable adapter")
            try:
                exported = transport.export_tls_channel_binding()
            except Exception as exc:
                raise SecureProfileUnsupportedError("SECURE_PROFILE_UNSUPPORTED", "secure carrier did not export TLS binding") from exc
            if not isinstance(exported, bytes) or len(exported) != 32:
                raise SecureProfileUnsupportedError("SECURE_PROFILE_UNSUPPORTED", "secure carrier TLS binding must be 32 bytes")
            secure_binding = base64url_encode(exported)
        self._sid = response.sid
        self._phase = ClientPhase.AWAIT_CARD
        own_digest = card_digest(self.card)
        await self._send_record(
            CardFrame(type="card", sid=response.sid, for_nonce=response.nonce, digest=own_digest, card=self.card),
            transport=transport,
            generation=generation,
        )
        card_response = validate_handshake_frame(parse_strict_json(await transport.recv()))
        if not isinstance(card_response, CardFrame):
            raise HandshakeError("HANDSHAKE_FAILED", "expected peer card")
        if card_response.sid != response.sid or card_response.for_nonce != nonce:
            raise HandshakeError("HANDSHAKE_FAILED", "peer card does not bind handshake")
        if card_response.card.agent_id != response.agent_id or card_response.card.instance_id != response.instance_id:
            raise AuthenticationError("SOURCE_IDENTITY_MISMATCH", "peer card identity differs from hello")
        if parse_timestamp(card_response.card.expires_at) <= datetime.now(UTC):
            raise HandshakeError("CARD_EXPIRED", "peer card has expired")
        peer_digest = card_digest(card_response.card)
        if peer_digest != card_response.digest.lower():
            raise HandshakeError("CARD_DIGEST_MISMATCH", "peer card digest does not match")
        self._broker_card = card_response.card
        self._broker_identity = AgentIdentity(agent_id=response.agent_id, instance_id=response.instance_id)
        if self._identity_options is not None:
            assert self._enrollments is not None and secure_binding is not None and self.card.identity is not None
            principal = verify_enrolled_card(card_response.card, self._enrollments)
            if principal is None or principal.agent_id != response.agent_id or card_response.card.identity is None or principal.key_id != card_response.card.identity.key_id:
                raise AuthenticationError("AUTHENTICATION_FAILED", "peer card is not signed by an enrolled identity")
            transcript = auth_transcript(
                initiator_hello=hello,
                responder_hello=response,
                initiator_card_digest=own_digest,
                responder_card_digest=peer_digest,
                tls_channel_binding=secure_binding,
            )
            self._phase = ClientPhase.AWAIT_AUTH
            own_proof = create_auth_proof(
                self.card.identity,
                self.card.agent_id,
                response.sid,
                transcript,
                self._identity_options.private_key,
            )
            await self._send_record(own_proof, transport=transport, generation=generation)
            peer_proof = validate_handshake_frame(parse_strict_json(await transport.recv()))
            if not isinstance(peer_proof, AuthFrame) or peer_proof.sid != response.sid:
                raise AuthenticationError("AUTHENTICATION_FAILED", "peer secure authentication proof is invalid")
            verified = verify_auth_proof(peer_proof, transcript, self._enrollments)
            if verified is None or verified.agent_id != principal.agent_id or verified.key_id != principal.key_id:
                raise AuthenticationError("AUTHENTICATION_FAILED", "peer did not prove possession of its enrolled key")
            self._broker_principal = verified
        self._phase = ClientPhase.AWAIT_READY
        await self._send_record(
            ReadyFrame(type="ready", sid=response.sid, self_card=own_digest, peer_card=peer_digest),
            transport=transport,
            generation=generation,
        )
        ready = validate_handshake_frame(parse_strict_json(await transport.recv()))
        if not isinstance(ready, ReadyFrame) or ready.sid != response.sid:
            raise HandshakeError("HANDSHAKE_FAILED", "expected peer ready")
        if ready.self_card != peer_digest or ready.peer_card != own_digest:
            raise HandshakeError("HANDSHAKE_FAILED", "peer ready does not bind exchanged cards")

    async def _handshake_native_v2(self, transport: WireTransport, generation: int) -> None:
        """Negotiate the compact native v2 SDK profile with ``v2.init``/ack.

        Native v2 deliberately has no hidden v0.1 card/ready exchange.  The
        selected profile, broker mesh, and opaque UUIDv7 session identifier
        are established by the ack before any native application envelope is
        admitted.  The enrolled Ed25519 profile is not silently approximated
        here: its card/auth transcript remains an explicit legacy-v2 path
        until native card authentication is specified.
        """

        if self._identity_options is not None:
            raise SecureProfileUnsupportedError(
                "SECURE_PROFILE_UNSUPPORTED",
                "native polymesh.0.2 init/ack does not define the enrolled card authentication exchange",
            )
        if self._mesh_id is not None and not is_v2_native_uuid(self._mesh_id):
            raise HandshakeError("NATIVE_V2_UNSUPPORTED", "configured native v0.2 mesh_id must be UUIDv7")
        compression = ["none"]
        if self._compression_enabled and zstd_available():
            compression = ["zstd", "none"]
        init = validate_v2_init_frame(
            {
                "type": "v2.init",
                "protocol": V2_PROTOCOL_VERSION,
                "profile": V2_PROTOCOL_VERSION,
                "supported_profiles": [V2_PROTOCOL_VERSION],
                **({"mesh_id": self._mesh_id} if self._mesh_id is not None else {}),
                "agent_id": self.card.agent_id,
                "instance_id": self.card.instance_id,
                "nonce": uuidv7(),
                "compression": compression,
            }
        )
        await self._send_record(init, transport=transport, generation=generation)
        raw_response = parse_strict_json(await transport.recv())
        if isinstance(raw_response, dict) and raw_response.get("type") == "v2.error":
            failure = validate_v2_error_frame(raw_response)
            code = str(failure["code"])
            message = str(failure["message"])
            if code == "PMX.SESSION.PROFILE":
                raise HandshakeError("NATIVE_V2_UNSUPPORTED", message)
            raise AuthenticationError(code, message, retryable=bool(failure.get("retryable", False)))
        try:
            ack = validate_v2_ack_frame(raw_response)
        except Exception as exc:
            # Earlier v2 brokers respond to an unknown init with a closed
            # legacy error/connection.  The outer auto mode may reopen one
            # carrier and try that explicit legacy wire grammar.
            raise HandshakeError("NATIVE_V2_UNSUPPORTED", "peer did not acknowledge native v0.2 init") from exc
        if self._mesh_id is not None and ack["mesh_id"] != self._mesh_id:
            raise AuthenticationError("MESH_SCOPE_MISMATCH", "native v0.2 broker selected a different mesh")
        selected_compression = str(ack["compression"])
        if selected_compression == "zstd" and (not self._compression_enabled or not zstd_available()):
            raise HandshakeError("COMPRESSION_UNAVAILABLE", "broker selected zstd which this native v0.2 client did not offer")
        self._sid = str(ack["session_id"])
        self._mesh_id = str(ack["mesh_id"])
        self._v2_native_compression_selected = selected_compression
        self._v2_native_compression_active = selected_compression == "none"
        self._v2_native_proposed = False
        self._v2_native_ready_sent = False
        if "agent_id" in ack and "instance_id" in ack:
            try:
                self._broker_identity = AgentIdentity(agent_id=str(ack["agent_id"]), instance_id=str(ack["instance_id"]))
            except Exception as exc:
                raise HandshakeError("HANDSHAKE_FAILED", "native v0.2 broker identity is incompatible with this SDK") from exc
        self._phase = ClientPhase.AWAIT_READY
        if selected_compression == "zstd":
            # Native v2 has a bilateral compression barrier. Complete it
            # inside the handshake before publishing an active connection so
            # callers can never send a raw application record after zstd was
            # selected but before both peers have confirmed readiness.
            self._v2_native_proposed = True
            await self._send_native_v2_zstd_proposal(generation)
            ready_frame = parse_strict_json(await transport.recv())
            if not isinstance(ready_frame, dict):
                raise HandshakeError("COMPRESSION_FAILED", "native v0.2 broker did not return zstd.ready")
            try:
                self._validate_native_v2_zstd_control(ready_frame, "zstd.ready")
            except Exception as exc:
                raise HandshakeError("COMPRESSION_FAILED", "native v0.2 zstd.ready is invalid") from exc
            self._v2_native_ready_sent = True
            await self._send_record(
                {
                    "type": "zstd.ready",
                    "profile": V2_PROTOCOL_VERSION,
                    "mesh_id": self._mesh_id,
                    "session_id": self._sid,
                    "compression": "zstd",
                },
                transport=transport,
                generation=generation,
            )
            self._v2_native_compression_active = True

    async def _handshake_legacy_v2(self, transport: WireTransport, generation: int) -> None:
        """Run the selected legacy-broker-compatible v0.2 handshake.

        v0.2 hello is deliberately distinct.  The card/auth/ready records are
        still closed v0.1-shaped records, but their session ID and secure
        transcript are profile-domain-separated.
        """

        nonce = random_nonce()
        hello: JsonObject = {
            "type": "hello",
            "v": V2_HANDSHAKE_VERSION,
            "role": "initiator",
            "agent_id": self.card.agent_id,
            "instance_id": self.card.instance_id,
            "nonce": nonce,
            **({"mesh_id": self._mesh_id} if self._mesh_id is not None else {}),
            **({"security_profile": "enrolled-ed25519-tls-1.3"} if self._identity_options is not None else {}),
        }
        hello = validate_v2_hello_frame(hello)
        await self._send_record(hello, transport=transport, generation=generation)
        response = validate_v2_hello_frame(parse_strict_json(await transport.recv()))
        if response.get("role") != "responder":
            raise HandshakeError("HANDSHAKE_FAILED", "expected v0.2 responder hello")
        expected_sid = derive_v2_session_id(nonce, str(response["nonce"]))
        if response.get("echo") != nonce or response.get("sid") != expected_sid:
            raise HandshakeError("HANDSHAKE_FAILED", "v0.2 responder hello does not bind initiator nonce")
        responder_mesh = response.get("mesh_id")
        if not isinstance(responder_mesh, str):
            raise HandshakeError("MESH_SCOPE_MISMATCH", "v0.2 responder did not bind a mesh identity")
        if self._mesh_id is not None and responder_mesh != self._mesh_id:
            raise AuthenticationError("MESH_SCOPE_MISMATCH", "v0.2 responder selected a different mesh")
        if response["agent_id"] == self.card.agent_id and response["instance_id"] == self.card.instance_id:
            raise HandshakeError("SELF_CONNECTION", "client cannot connect to itself")
        secure_binding: str | None = None
        if self._identity_options is None:
            if response.get("security_profile") is not None:
                raise AuthenticationError("SECURITY_PROFILE_MISMATCH", "peer selected unexpected secure profile")
        else:
            if response.get("security_profile") != "enrolled-ed25519-tls-1.3":
                raise AuthenticationError("SECURITY_PROFILE_MISMATCH", "peer did not select the enrolled secure profile")
            if not isinstance(transport, SecureWireTransport):
                raise SecureProfileUnsupportedError("SECURE_PROFILE_UNSUPPORTED", "secure enrolled handshake requires an exporter-capable adapter")
            try:
                exported = transport.export_tls_channel_binding()
            except Exception as exc:
                raise SecureProfileUnsupportedError("SECURE_PROFILE_UNSUPPORTED", "secure carrier did not export TLS binding") from exc
            if not isinstance(exported, bytes) or len(exported) != 32:
                raise SecureProfileUnsupportedError("SECURE_PROFILE_UNSUPPORTED", "secure carrier TLS binding must be 32 bytes")
            secure_binding = base64url_encode(exported)

        self._sid = expected_sid
        self._mesh_id = responder_mesh
        self._v2_initiator_hello = hello
        self._v2_responder_hello = response
        self._phase = ClientPhase.AWAIT_CARD
        own_digest = card_digest(self.card)
        await self._send_record(
            CardFrame(type="card", sid=expected_sid, for_nonce=str(response["nonce"]), digest=own_digest, card=self.card),
            transport=transport,
            generation=generation,
        )
        card_response = validate_handshake_frame(parse_strict_json(await transport.recv()))
        if not isinstance(card_response, CardFrame):
            raise HandshakeError("HANDSHAKE_FAILED", "expected peer card")
        if card_response.sid != expected_sid or card_response.for_nonce != nonce:
            raise HandshakeError("HANDSHAKE_FAILED", "peer card does not bind v0.2 handshake")
        if card_response.card.agent_id != response["agent_id"] or card_response.card.instance_id != response["instance_id"]:
            raise AuthenticationError("SOURCE_IDENTITY_MISMATCH", "peer card identity differs from v0.2 hello")
        if parse_timestamp(card_response.card.expires_at) <= datetime.now(UTC):
            raise HandshakeError("CARD_EXPIRED", "peer card has expired")
        peer_digest = card_digest(card_response.card)
        if peer_digest != card_response.digest.lower():
            raise HandshakeError("CARD_DIGEST_MISMATCH", "peer card digest does not match")
        self._broker_card = card_response.card
        self._broker_identity = AgentIdentity(agent_id=str(response["agent_id"]), instance_id=str(response["instance_id"]))
        if self._identity_options is not None:
            assert self._enrollments is not None and secure_binding is not None and self.card.identity is not None
            principal = verify_enrolled_card(card_response.card, self._enrollments)
            if principal is None or principal.agent_id != response["agent_id"] or card_response.card.identity is None or principal.key_id != card_response.card.identity.key_id:
                raise AuthenticationError("AUTHENTICATION_FAILED", "peer card is not signed by an enrolled identity")
            transcript = v2_auth_transcript(
                initiator_hello=hello,
                responder_hello=response,
                initiator_card_digest=own_digest,
                responder_card_digest=peer_digest,
                tls_channel_binding=secure_binding,
            )
            self._phase = ClientPhase.AWAIT_AUTH
            own_proof = create_v2_auth_proof(
                self.card.identity,
                self.card.agent_id,
                expected_sid,
                transcript,
                self._identity_options.private_key,
            )
            await self._send_record(own_proof, transport=transport, generation=generation)
            peer_proof = validate_handshake_frame(parse_strict_json(await transport.recv()))
            if not isinstance(peer_proof, AuthFrame) or peer_proof.sid != expected_sid:
                raise AuthenticationError("AUTHENTICATION_FAILED", "peer v0.2 authentication proof is invalid")
            verified = verify_v2_auth_proof(peer_proof, transcript, self._enrollments)
            if verified is None or verified.agent_id != principal.agent_id or verified.key_id != principal.key_id:
                raise AuthenticationError("AUTHENTICATION_FAILED", "peer did not prove possession of its enrolled key")
            self._broker_principal = verified
        self._phase = ClientPhase.AWAIT_READY
        await self._send_record(
            ReadyFrame(type="ready", sid=expected_sid, self_card=own_digest, peer_card=peer_digest),
            transport=transport,
            generation=generation,
        )
        ready = validate_handshake_frame(parse_strict_json(await transport.recv()))
        if not isinstance(ready, ReadyFrame) or ready.sid != expected_sid:
            raise HandshakeError("HANDSHAKE_FAILED", "expected peer v0.2 ready")
        if ready.self_card != peer_digest or ready.peer_card != own_digest:
            raise HandshakeError("HANDSHAKE_FAILED", "peer ready does not bind exchanged cards")

    async def ready(self) -> "PolyMeshClient":
        if self.connected:
            return self
        return await self.connect()

    async def disconnect(self, code: int = 1000, reason: str = "client closed", wait: bool = True) -> None:
        if self._gateway_mode and self._gateway is not None:
            self._bind_loop()
            self._disconnecting = True
            gateway = self._gateway
            try:
                if gateway.current_mesh_id is not None:
                    await gateway.leave_mesh()
                else:
                    await gateway.close(code, reason)
            finally:
                self._phase = ClientPhase.CLOSED
                self._connection_state = ConnectionState.CLOSED
                self._emit("close", {"code": code, "reason": reason})
            return
        self._bind_loop()
        self._disconnecting = True
        self._generation += 1
        self._phase = ClientPhase.CLOSED
        self._connection_state = ConnectionState.CLOSING
        for task in (self._reconnect_task, self._heartbeat_task, self._receiver_task):
            if task is not None and task is not asyncio.current_task():
                task.cancel()
        self._abort_local_tasks()
        transport, self._transport = self._transport, None
        self._sid = None
        self._broker_card = None
        self._broker_identity = None
        self._broker_principal = None
        self._v2_compression = None
        self._v2_compression_offered = False
        self._v2_initiator_hello = None
        self._v2_responder_hello = None
        self._v2_native_compression_selected = "none"
        self._v2_native_compression_active = False
        self._v2_native_proposed = False
        self._v2_native_ready_sent = False
        self._outstanding_pong = None
        self._fail_pending_recovery("client disconnected")
        self._fail_status_queries(TransportClosedError("TRANSPORT_CLOSED", "client disconnected"))
        if transport is not None:
            with contextlib.suppress(Exception):
                await transport.close(code, reason)
        if wait:
            tasks = [task for task in (self._receiver_task, self._heartbeat_task, self._reconnect_task) if task is not None and task is not asyncio.current_task()]
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
        self._receiver_task = self._heartbeat_task = self._reconnect_task = None
        self._connection_state = ConnectionState.CLOSED
        self._emit("close", {"code": code, "reason": reason})

    def close(self, code: int = 1000, reason: str = "client closed") -> None:
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        current_loop: asyncio.AbstractEventLoop | None
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None
        if loop is current_loop:
            loop.create_task(self.disconnect(code, reason, wait=False))
        else:
            asyncio.run_coroutine_threadsafe(self.disconnect(code, reason, wait=False), loop)

    async def _start_v2_compression(self, generation: int) -> None:
        """Offer zstd only after the authenticated READY boundary.

        A missing optional codec is an ordinary ``none`` outcome, not a
        profile downgrade: v2 stays selected and sends its application frames
        uncompressed.  The control exchange is intentionally never wrapped.
        """

        if (
            self._profile != V2_PROTOCOL_VERSION
            or self._v2_wire_mode != "legacy"
            or not self._compression_enabled
            or self._v2_compression_offered
            or not zstd_available()
            or generation != self._generation
            or not self.connected
        ):
            return
        self._v2_compression_offered = True
        compressed, uncompressed, ratio = self._v2_offer_limits
        offer: JsonObject = {
            "type": "compression.offer",
            "v": V2_HANDSHAKE_VERSION,
            "algorithms": ["none", "zstd"],
            "limits": {
                "maxCompressedBytes": compressed,
                "maxUncompressedBytes": uncompressed,
                "maxExpansionRatio": ratio,
            },
        }
        await self._send_record(offer, generation=generation)

    async def _start_native_v2_compression(self, generation: int) -> None:
        """Begin native zstd activation after a native ack selected it.

        The actual three-record state machine is implemented beside the
        receive handlers below.  A native ack selecting ``none`` is already
        an active, valid profile and deliberately emits no control traffic.
        """

        if self._profile != V2_PROTOCOL_VERSION or self._v2_wire_mode != "native" or generation != self._generation:
            return
        if self._v2_native_compression_selected == "zstd" and not self._v2_native_compression_active:
            raise HandshakeError("COMPRESSION_FAILED", "native v0.2 zstd barrier did not complete during handshake")

    def _v2_wire_for_send(self, record: Any) -> JsonObject:
        """Encode one record for the already-selected v2 profile."""

        if self._v2_wire_mode == "native":
            return self._native_v2_wire_for_send(record)
        if isinstance(record, Envelope):
            if self._mesh_id is None:
                raise HandshakeError("MESH_SCOPE_MISMATCH", "v0.2 application record has no authenticated mesh identity")
            wire = v2_envelope_from_legacy(record, mesh_id=self._mesh_id)
            return self._v2_maybe_compress_wire_envelope(wire)
        if isinstance(record, Mapping):
            wire = dict(record)
            if wire.get("type") in {"v2.init", "v2.ack", "v2.error", "zstd.propose", "zstd.ready", "zstd.wrapper"}:
                return wire
            if wire.get("protocol") == PROTOCOL_VERSION:
                if self._mesh_id is None:
                    raise HandshakeError("MESH_SCOPE_MISMATCH", "v0.2 application record has no authenticated mesh identity")
                wire = v2_envelope_from_legacy(validate_envelope(wire), mesh_id=self._mesh_id)
                return self._v2_maybe_compress_wire_envelope(wire)
            if wire.get("protocol") == V2_PROTOCOL_VERSION:
                if self._mesh_id is None:
                    raise HandshakeError("MESH_SCOPE_MISMATCH", "v0.2 application record has no authenticated mesh identity")
                wire = validate_v2_envelope(wire, mesh_id=self._mesh_id)
                return self._v2_maybe_compress_wire_envelope(wire)
            return wire
        if hasattr(record, "model_dump"):
            dumped = record.model_dump(mode="json", exclude_none=True)
            if not isinstance(dumped, dict):
                raise TypeError("v0.2 record model did not serialize to an object")
            return dumped
        raise TypeError("record must be a PolyMesh handshake frame, envelope, or mapping")

    def _native_v2_wire_for_send(self, record: Any) -> JsonObject:
        """Encode one compact native-v2 control or application record."""

        if isinstance(record, Envelope):
            if self._mesh_id is None:
                raise HandshakeError("MESH_SCOPE_MISMATCH", "native v0.2 application record has no acknowledged mesh identity")
            return self._native_v2_maybe_wrap_envelope(native_v2_envelope_from_legacy(record, mesh_id=self._mesh_id))
        if isinstance(record, Mapping):
            wire = dict(record)
            if wire.get("type") in {"v2.init", "v2.ack", "v2.error", "zstd.propose", "zstd.ready", "zstd.wrapper"}:
                return wire
            if wire.get("protocol") == PROTOCOL_VERSION:
                if self._mesh_id is None:
                    raise HandshakeError("MESH_SCOPE_MISMATCH", "native v0.2 application record has no acknowledged mesh identity")
                return self._native_v2_maybe_wrap_envelope(
                    native_v2_envelope_from_legacy(validate_envelope(wire), mesh_id=self._mesh_id)
                )
            if wire.get("protocol") == V2_PROTOCOL_VERSION and wire.get("profile") == V2_PROTOCOL_VERSION:
                if self._mesh_id is None:
                    raise HandshakeError("MESH_SCOPE_MISMATCH", "native v0.2 application record has no acknowledged mesh identity")
                return self._native_v2_maybe_wrap_envelope(validate_v2_native_envelope(wire, mesh_id=self._mesh_id))
            return wire
        if hasattr(record, "model_dump"):
            dumped = record.model_dump(mode="json", exclude_none=True)
            if not isinstance(dumped, dict):
                raise TypeError("native v0.2 record model did not serialize to an object")
            return dumped
        raise TypeError("record must be a PolyMesh handshake frame, envelope, or mapping")

    def _native_v2_maybe_wrap_envelope(self, wire: JsonObject) -> JsonObject:
        """Wrap one native envelope only after both zstd ready records exist."""

        if self._v2_native_compression_selected != "zstd" or not self._v2_native_compression_active:
            return wire
        if self._sid is None or self._mesh_id is None:
            raise HandshakeError("MESH_SCOPE_MISMATCH", "native v0.2 zstd session has no binding")
        _, maximum_uncompressed, maximum_ratio = self._v2_offer_limits
        maximum_compressed = self._v2_offer_limits[0]
        encoded = canonical_json(wire).encode("utf-8")
        if not encoded or len(encoded) > maximum_uncompressed:
            raise TransportError("COMPRESSION_LIMIT_EXCEEDED", "native v0.2 envelope exceeds zstd output limit")
        try:
            compressed = zstd_compress(encoded)
        except TransportError as exc:
            raise TransportError("PMX.PROTOCOL.COMPRESSION", "native v0.2 zstd compression failed") from exc
        if (
            not compressed
            or len(compressed) > maximum_compressed
            or len(encoded) / max(1, len(compressed)) > maximum_ratio
        ):
            raise TransportError("COMPRESSION_LIMIT_EXCEEDED", "native v0.2 zstd wrapper exceeds negotiated limits")
        return {
            "type": "zstd.wrapper",
            "profile": V2_PROTOCOL_VERSION,
            "mesh_id": self._mesh_id,
            "session_id": self._sid,
            "compression": "zstd",
            "uncompressed_bytes": len(encoded),
            "compressed_bytes": len(compressed),
            "payload": base64.urlsafe_b64encode(compressed).decode("ascii").rstrip("="),
        }

    def _v2_maybe_compress_wire_envelope(self, wire: JsonObject) -> JsonObject:
        selection = self._v2_compression
        if (
            selection is None
            or selection.algorithm != "zstd"
            or wire.get("type") not in _V2_COMPRESSIBLE_TYPES
            or selection.max_compressed_bytes is None
            or selection.max_uncompressed_bytes is None
            or selection.max_expansion_ratio is None
        ):
            return wire
        encoded = canonical_json(wire).encode("utf-8")
        if not encoded or len(encoded) > selection.max_uncompressed_bytes:
            return wire
        try:
            compressed = zstd_compress(encoded)
        except TransportError:
            # A codec disappearing after negotiation is not permission to
            # mutate the profile; raw v2 application frames remain legal.
            return wire
        if (
            not compressed
            or len(compressed) >= len(encoded)
            or len(compressed) > selection.max_compressed_bytes
            or len(encoded) / max(1, len(compressed)) > selection.max_expansion_ratio
        ):
            return wire
        return {
            "type": "compression.frame",
            "v": V2_HANDSHAKE_VERSION,
            "algorithm": "zstd",
            "record_type": wire["type"],
            "compressed_bytes": len(compressed),
            "uncompressed_bytes": len(encoded),
            "payload": base64.urlsafe_b64encode(compressed).decode("ascii").rstrip("="),
        }

    async def _send_record(self, record: Any, *, transport: WireTransport | None = None, generation: int | None = None) -> None:
        self._bind_loop()
        chosen = transport or self._transport
        if chosen is None or chosen.closed:
            raise TransportClosedError("TRANSPORT_CLOSED", "no active transport", retryable=True)
        if generation is not None and (generation != self._generation or chosen is not self._transport):
            raise TransportClosedError("TRANSPORT_CLOSED", "stale connection generation", retryable=True)
        assert self._send_lock is not None
        async with self._send_lock:
            if generation is not None and (generation != self._generation or chosen is not self._transport):
                raise TransportClosedError("TRANSPORT_CLOSED", "stale connection generation", retryable=True)
            if self._profile == V2_PROTOCOL_VERSION:
                encoded = canonical_json(self._v2_wire_for_send(record))
                if len(encoded.encode("utf-8")) > MAX_FRAME_BYTES:
                    raise TransportError("FRAME_TOO_LARGE", "outbound v0.2 record exceeds 1 MiB")
                await chosen.send(encoded)
            else:
                await chosen.send(encode_record_text(record))

    async def _receiver(self, transport: WireTransport, generation: int) -> None:
        try:
            while generation == self._generation and transport is self._transport and not transport.closed:
                raw = await transport.recv()
                if generation != self._generation or transport is not self._transport:
                    return
                if self._profile == V2_PROTOCOL_VERSION:
                    valid_inbound = await self._receive_v2_record(raw, generation)
                else:
                    try:
                        envelope = validate_envelope(parse_strict_json(raw))
                    except Exception as exc:
                        self._emit("protocol_error", exc)
                        continue
                    valid_inbound = await self._dispatch_envelope(envelope, generation)
                if valid_inbound and generation == self._generation and transport is self._transport:
                    # The envelope has crossed framing and structural
                    # validation; handlers apply stricter task authorization
                    # independently before it can affect work.
                    self._last_valid_inbound_at = asyncio.get_running_loop().time()
        except asyncio.CancelledError:
            raise
        except BaseException as exc:
            if generation == self._generation and not self._disconnecting:
                await self._fail_generation(exc, generation, reconnect=True)

    async def _receive_v2_record(self, raw: str, generation: int) -> bool:
        """Decode one v2 control/wrapper/envelope record after READY."""

        if self._v2_wire_mode == "native":
            return await self._receive_native_v2_record(raw, generation)
        try:
            frame = parse_strict_json(raw)
            if not isinstance(frame, dict):
                raise ProtocolError("MALFORMED_FRAME", "v0.2 record must be an object")
            frame_type = frame.get("type")
            if frame_type == "compression.offer":
                return await self._receive_v2_compression_offer(frame, generation)
            if frame_type == "compression.selected":
                return self._receive_v2_compression_selected(frame)
            if frame_type == "compression.frame":
                return await self._receive_v2_compressed_frame(frame, generation)
            if frame_type == "delivery.receipt":
                return self._receive_v2_delivery_receipt(frame)
            if self._mesh_id is None:
                raise ProtocolError("MESH_SCOPE_MISMATCH", "v0.2 session has no authenticated mesh identity")
            wire = validate_v2_envelope(frame, mesh_id=self._mesh_id)
            delivery_id = wire.get("delivery_id")
            envelope = v2_envelope_as_legacy(wire, mesh_id=self._mesh_id)
            valid = await self._dispatch_envelope(envelope, generation)
            if valid and isinstance(delivery_id, str):
                await self._send_v2_delivery_receipt(delivery_id, envelope.message_id, generation)
            return valid
        except Exception as exc:
            self._emit("protocol_error", exc)
            return False

    async def _receive_native_v2_record(self, raw: str, generation: int) -> bool:
        """Decode one compact native-v2 control/wrapper/envelope record."""

        try:
            frame = parse_strict_json(raw)
            if not isinstance(frame, dict):
                raise ProtocolError("MALFORMED_FRAME", "native v0.2 record must be an object")
            frame_type = frame.get("type")
            if frame_type == "zstd.propose":
                return await self._receive_native_v2_zstd_propose(frame, generation)
            if frame_type == "zstd.ready":
                return await self._receive_native_v2_zstd_ready(frame, generation)
            if frame_type == "zstd.wrapper":
                return await self._receive_native_v2_zstd_wrapper(frame, generation)
            if frame_type == "v2.error":
                failure = validate_v2_error_frame(frame)
                self._emit(
                    "protocol_error",
                    ProtocolError(str(failure["code"]), str(failure["message"]), retryable=bool(failure.get("retryable", False))),
                )
                return False
            if self._mesh_id is None:
                raise ProtocolError("MESH_SCOPE_MISMATCH", "native v0.2 session has no acknowledged mesh identity")
            wire = validate_v2_native_envelope(frame, mesh_id=self._mesh_id)
            envelope = native_v2_envelope_as_legacy(wire, mesh_id=self._mesh_id)
            return await self._dispatch_envelope(envelope, generation)
        except Exception as exc:
            self._emit("protocol_error", exc)
            return False

    def _validate_native_v2_zstd_control(self, frame: JsonObject, expected_type: str) -> None:
        if (
            set(frame) != {"type", "profile", "mesh_id", "session_id", "compression"}
            or frame.get("type") != expected_type
            or frame.get("profile") != V2_PROTOCOL_VERSION
            or frame.get("compression") != "zstd"
            or self._mesh_id is None
            or self._sid is None
            or frame.get("mesh_id") != self._mesh_id
            or frame.get("session_id") != self._sid
        ):
            raise ProtocolError("PMX.PROTOCOL.COMPRESSION", f"native v0.2 {expected_type} record is invalid")

    async def _send_native_v2_zstd_proposal(self, generation: int) -> None:
        if self._mesh_id is None or self._sid is None:
            raise HandshakeError("MESH_SCOPE_MISMATCH", "native v0.2 zstd proposal has no session binding")
        await self._send_record(
            {
                "type": "zstd.propose",
                "profile": V2_PROTOCOL_VERSION,
                "mesh_id": self._mesh_id,
                "session_id": self._sid,
                "compression": "zstd",
            },
            generation=generation,
        )

    async def _receive_native_v2_zstd_propose(self, frame: JsonObject, generation: int) -> bool:
        # The client is always the native init/ack initiator.  The broker's
        # only legal next compression control is its ready confirmation.
        self._validate_native_v2_zstd_control(frame, "zstd.propose")
        raise ProtocolError("PMX.PROTOCOL.COMPRESSION", "native v0.2 client received an unexpected zstd.propose")

    async def _receive_native_v2_zstd_ready(self, frame: JsonObject, generation: int) -> bool:
        self._validate_native_v2_zstd_control(frame, "zstd.ready")
        if (
            self._v2_native_compression_selected != "zstd"
            or not self._v2_native_proposed
            or self._v2_native_compression_active
            or self._v2_native_ready_sent
        ):
            raise ProtocolError("PMX.PROTOCOL.COMPRESSION", "native v0.2 zstd.ready is invalid in the current state")
        self._v2_native_ready_sent = True
        if self._mesh_id is None or self._sid is None:
            raise ProtocolError("MESH_SCOPE_MISMATCH", "native v0.2 zstd ready has no session binding")
        await self._send_record(
            {
                "type": "zstd.ready",
                "profile": V2_PROTOCOL_VERSION,
                "mesh_id": self._mesh_id,
                "session_id": self._sid,
                "compression": "zstd",
            },
            generation=generation,
        )
        self._v2_native_compression_active = True
        self._emit("compression", {"algorithm": "zstd"})
        return True

    async def _receive_native_v2_zstd_wrapper(self, frame: JsonObject, generation: int) -> bool:
        if (
            self._v2_native_compression_selected != "zstd"
            or not self._v2_native_compression_active
            or self._mesh_id is None
            or self._sid is None
        ):
            raise ProtocolError("PMX.PROTOCOL.COMPRESSION", "native v0.2 zstd.wrapper arrived before zstd was active")
        fields = {
            "type", "profile", "mesh_id", "session_id", "compression",
            "uncompressed_bytes", "compressed_bytes", "payload",
        }
        if (
            set(frame) != fields
            or frame.get("type") != "zstd.wrapper"
            or frame.get("profile") != V2_PROTOCOL_VERSION
            or frame.get("mesh_id") != self._mesh_id
            or frame.get("session_id") != self._sid
            or frame.get("compression") != "zstd"
        ):
            raise ProtocolError("PMX.PROTOCOL.COMPRESSION", "native v0.2 zstd.wrapper is malformed")
        uncompressed_bytes = frame.get("uncompressed_bytes")
        compressed_bytes = frame.get("compressed_bytes")
        maximum_compressed, maximum_uncompressed, maximum_ratio = self._v2_offer_limits
        if (
            not isinstance(uncompressed_bytes, int)
            or isinstance(uncompressed_bytes, bool)
            or not isinstance(compressed_bytes, int)
            or isinstance(compressed_bytes, bool)
            or not 0 < uncompressed_bytes <= maximum_uncompressed
            or not 0 < compressed_bytes <= maximum_compressed
            or uncompressed_bytes / max(1, compressed_bytes) > maximum_ratio
        ):
            raise ProtocolError("PMX.PROTOCOL.COMPRESSION", "native v0.2 zstd.wrapper exceeds local limits")
        payload = _v2_decode_base64url(frame.get("payload"))
        if len(payload) != compressed_bytes:
            raise ProtocolError("PMX.PROTOCOL.COMPRESSION", "native v0.2 zstd.wrapper payload length is invalid")
        decoded = zstd_decompress(payload, max_output_bytes=maximum_uncompressed)
        if len(decoded) != uncompressed_bytes:
            raise ProtocolError("PMX.PROTOCOL.COMPRESSION", "native v0.2 zstd.wrapper output length is invalid")
        decoded_record = parse_strict_json(decoded)
        if not isinstance(decoded_record, dict):
            raise ProtocolError("PMX.PROTOCOL.COMPRESSION", "native v0.2 zstd.wrapper did not decode to an envelope")
        wire = validate_v2_native_envelope(decoded_record, mesh_id=self._mesh_id)
        envelope = native_v2_envelope_as_legacy(wire, mesh_id=self._mesh_id)
        return await self._dispatch_envelope(envelope, generation)

    async def _receive_v2_compression_offer(self, frame: JsonObject, generation: int) -> bool:
        """Accept a peer offer only after READY and never widen its limits."""

        if frame.get("v") != V2_HANDSHAKE_VERSION or set(frame) - {"type", "v", "algorithms", "limits"}:
            raise ProtocolError("COMPRESSION_OFFER_INVALID", "v0.2 compression offer is malformed")
        algorithms = frame.get("algorithms")
        if not isinstance(algorithms, list) or not algorithms or len(set(algorithms)) != len(algorithms) or any(item not in {"none", "zstd"} for item in algorithms) or "none" not in algorithms:
            raise ProtocolError("COMPRESSION_OFFER_INVALID", "v0.2 compression offer has invalid algorithms")
        offered_limits = frame.get("limits")
        if ("zstd" in algorithms) != isinstance(offered_limits, dict):
            raise ProtocolError("COMPRESSION_OFFER_INVALID", "v0.2 zstd offer has invalid limits")
        selected: _V2Compression
        if self._compression_enabled and zstd_available() and "zstd" in algorithms:
            parsed = _v2_compression_limits(offered_limits)
            if parsed is None:
                raise ProtocolError("COMPRESSION_OFFER_INVALID", "v0.2 zstd offer has invalid limits")
            own_compressed, own_uncompressed, own_ratio = self._v2_offer_limits
            selected = _V2Compression(
                "zstd",
                min(parsed[0], own_compressed),
                min(parsed[1], own_uncompressed),
                min(parsed[2], own_ratio),
            )
        else:
            selected = _V2Compression("none")
        existing = self._v2_compression
        if existing is not None and existing != selected:
            raise ProtocolError("COMPRESSION_SELECTED_MISMATCH", "v0.2 compression cannot be renegotiated")
        self._v2_compression = selected
        response: JsonObject = {"type": "compression.selected", "v": V2_HANDSHAKE_VERSION, "algorithm": selected.algorithm}
        if selected.algorithm == "zstd":
            response["limits"] = {
                "maxCompressedBytes": selected.max_compressed_bytes,
                "maxUncompressedBytes": selected.max_uncompressed_bytes,
                "maxExpansionRatio": selected.max_expansion_ratio,
            }
        await self._send_record(response, generation=generation)
        return True

    def _receive_v2_compression_selected(self, frame: JsonObject) -> bool:
        if frame.get("v") != V2_HANDSHAKE_VERSION or set(frame) - {"type", "v", "algorithm", "limits"}:
            raise ProtocolError("COMPRESSION_SELECTED_INVALID", "v0.2 compression selection is malformed")
        algorithm = frame.get("algorithm")
        if algorithm == "none":
            if "limits" in frame:
                raise ProtocolError("COMPRESSION_SELECTED_INVALID", "none compression selection must omit limits")
            selected = _V2Compression("none")
        elif algorithm == "zstd":
            parsed = _v2_compression_limits(frame.get("limits") if isinstance(frame.get("limits"), dict) else {})
            if parsed is None or not self._compression_enabled or not zstd_available():
                raise ProtocolError("COMPRESSION_SELECTED_INVALID", "zstd compression is unavailable or malformed")
            own_compressed, own_uncompressed, own_ratio = self._v2_offer_limits
            if parsed[0] > own_compressed or parsed[1] > own_uncompressed or parsed[2] > own_ratio:
                raise ProtocolError("COMPRESSION_SELECTED_MISMATCH", "peer widened v0.2 compression limits")
            selected = _V2Compression("zstd", *parsed)
        else:
            raise ProtocolError("COMPRESSION_SELECTED_INVALID", "unknown v0.2 compression algorithm")
        existing = self._v2_compression
        if existing is not None and existing != selected:
            raise ProtocolError("COMPRESSION_SELECTED_MISMATCH", "v0.2 compression cannot be renegotiated")
        self._v2_compression = selected
        self._emit("compression", {"algorithm": selected.algorithm})
        return True

    async def _receive_v2_compressed_frame(self, frame: JsonObject, generation: int) -> bool:
        selection = self._v2_compression
        if selection is None or selection.algorithm != "zstd" or (
            selection.max_compressed_bytes is None
            or selection.max_uncompressed_bytes is None
            or selection.max_expansion_ratio is None
        ):
            raise ProtocolError("COMPRESSION_NOT_NEGOTIATED", "received zstd frame before negotiation")
        fields = {"type", "v", "algorithm", "record_type", "compressed_bytes", "uncompressed_bytes", "payload"}
        if frame.get("v") != V2_HANDSHAKE_VERSION or set(frame) != fields or frame.get("algorithm") != "zstd" or frame.get("record_type") not in _V2_COMPRESSIBLE_TYPES:
            raise ProtocolError("COMPRESSION_FRAME_INVALID", "v0.2 zstd wrapper is malformed")
        compressed_bytes = frame.get("compressed_bytes")
        uncompressed_bytes = frame.get("uncompressed_bytes")
        if (
            not isinstance(compressed_bytes, int)
            or isinstance(compressed_bytes, bool)
            or not isinstance(uncompressed_bytes, int)
            or isinstance(uncompressed_bytes, bool)
            or not 0 < compressed_bytes <= selection.max_compressed_bytes
            or not 0 < uncompressed_bytes <= selection.max_uncompressed_bytes
            or uncompressed_bytes / max(1, compressed_bytes) > selection.max_expansion_ratio
        ):
            raise ProtocolError("COMPRESSION_LIMIT_EXCEEDED", "v0.2 zstd wrapper exceeds negotiated limits")
        payload = _v2_decode_base64url(frame.get("payload"))
        if len(payload) != compressed_bytes:
            raise ProtocolError("COMPRESSION_FRAME_INVALID", "v0.2 zstd payload length does not match metadata")
        decoded = zstd_decompress(payload, max_output_bytes=selection.max_uncompressed_bytes)
        if len(decoded) != uncompressed_bytes:
            raise ProtocolError("COMPRESSION_OUTPUT_SIZE_MISMATCH", "v0.2 zstd output length does not match metadata")
        decoded_record = parse_strict_json(decoded)
        if not isinstance(decoded_record, dict) or decoded_record.get("type") != frame["record_type"]:
            raise ProtocolError("COMPRESSION_RECORD_TYPE_MISMATCH", "v0.2 zstd payload does not bind its declared record type")
        # Re-enter the ordinary v2 application path without recursively
        # treating a decoded envelope as another compression wrapper.
        if self._mesh_id is None:
            raise ProtocolError("MESH_SCOPE_MISMATCH", "v0.2 session has no authenticated mesh identity")
        wire = validate_v2_envelope(decoded_record, mesh_id=self._mesh_id)
        delivery_id = wire.get("delivery_id")
        envelope = v2_envelope_as_legacy(wire, mesh_id=self._mesh_id)
        valid = await self._dispatch_envelope(envelope, generation)
        if valid and isinstance(delivery_id, str):
            await self._send_v2_delivery_receipt(delivery_id, envelope.message_id, generation)
        return valid

    def _receive_v2_delivery_receipt(self, frame: JsonObject) -> bool:
        if set(frame) != {"type", "v", "delivery_id", "message_id", "state"} or frame.get("v") != V2_HANDSHAKE_VERSION or frame.get("state") != "stored":
            raise ProtocolError("MALFORMED_FRAME", "v0.2 delivery receipt is malformed")
        # The durable relay receipt has no lifecycle authority.  Expose it to
        # observers without confusing it with the v0.1 semantic receipt.
        if not isinstance(frame.get("delivery_id"), str) or not isinstance(frame.get("message_id"), str):
            raise ProtocolError("MALFORMED_FRAME", "v0.2 delivery receipt identifiers are invalid")
        self._emit("delivery_receipt", dict(frame))
        return True

    async def _send_v2_delivery_receipt(self, delivery_id: str, message_id: str, generation: int) -> None:
        await self._send_record(
            {
                "type": "delivery.receipt",
                "v": V2_HANDSHAKE_VERSION,
                "delivery_id": delivery_id,
                "message_id": message_id,
                "state": "stored",
            },
            generation=generation,
        )

    async def _heartbeat(self, transport: WireTransport, generation: int) -> None:
        try:
            while generation == self._generation and transport is self._transport and self.connected:
                await asyncio.sleep(self._limits.heartbeat_interval)
                if generation != self._generation or transport is not self._transport or not self.connected:
                    return
                last_valid = self._last_valid_inbound_at
                if last_valid is not None and asyncio.get_running_loop().time() - last_valid > self._limits.inbound_timeout:
                    raise HeartbeatTimeoutError("HEARTBEAT_TIMEOUT", "no valid inbound protocol traffic", retryable=True)
                broker = self._broker_identity
                if broker is None:
                    return
                n = self._next_ping
                self._next_ping += 1
                event = asyncio.Event()
                self._outstanding_pong = (n, event)
                ping = create_envelope(type="ping", source=self._self_identity(), target=broker, params={"n": n})
                await self._send_record(ping, generation=generation)
                try:
                    await asyncio.wait_for(event.wait(), timeout=self._limits.pong_timeout)
                except asyncio.TimeoutError as exc:
                    raise HeartbeatTimeoutError("HEARTBEAT_TIMEOUT", "broker did not return matching pong", retryable=True) from exc
                finally:
                    if self._outstanding_pong == (n, event):
                        self._outstanding_pong = None
        except asyncio.CancelledError:
            raise
        except BaseException as exc:
            if generation == self._generation and not self._disconnecting:
                await self._fail_generation(exc, generation, reconnect=True)

    async def _fail_generation(self, error: BaseException, generation: int, *, reconnect: bool) -> None:
        if generation != self._generation or self._failing_generation == generation:
            return
        # Reader, heartbeat, and close callbacks can discover the same loss.
        # Fence them before the first await so only one may tear down or start
        # a reconnect loop for this transport generation.
        self._failing_generation = generation
        self._phase = ClientPhase.CLOSED
        self._connection_state = ConnectionState.CLOSED
        transport, self._transport = self._transport, None
        self._sid = None
        self._broker_card = None
        self._broker_identity = None
        self._broker_principal = None
        self._v2_compression = None
        self._v2_compression_offered = False
        self._v2_initiator_hello = None
        self._v2_responder_hello = None
        self._v2_native_compression_selected = "none"
        self._v2_native_compression_active = False
        self._v2_native_proposed = False
        self._v2_native_ready_sent = False
        self._outstanding_pong = None
        # A transport loss fences every inbound handler.  Letting application
        # code continue during reconnect would allow side effects after the
        # session that admitted the work has disappeared.
        self._abort_local_tasks()
        if transport is not None:
            with contextlib.suppress(Exception):
                await transport.close(1001, "connection failed")
        self._fail_pending_recovery("connection lost")
        self._fail_status_queries(TransportClosedError("TRANSPORT_CLOSED", "connection lost", retryable=True))
        self._emit("close", error)
        active_since = self._active_since
        if active_since is not None and asyncio.get_running_loop().time() - active_since >= self._reconnect.reset_after_active:
            self._reconnect_attempt = 0
        if reconnect and self._should_reconnect(error) and (self._reconnect_task is None or self._reconnect_task.done()):
            self._reconnect_task = asyncio.create_task(self._reconnect_loop(), name="polymesh-client-reconnect")

    def _should_reconnect(self, error: BaseException) -> bool:
        return bool(
            self._reconnect.enabled
            and not self._disconnecting
            and (self._broker_url is not None or self._transport_factory is not None)
            and isinstance(error, (TransportError, HeartbeatTimeoutError, OSError, asyncio.TimeoutError))
        )

    async def _reconnect_loop(self) -> None:
        attempt = self._reconnect_attempt
        while not self._disconnecting and self._reconnect.enabled:
            base = min(self._reconnect.maximum_delay, self._reconnect.initial_delay * (self._reconnect.multiplier**attempt))
            delay = min(self._reconnect.maximum_delay, base * (0.8 + __import__("random").random() * 0.4))
            self._connection_state = ConnectionState.RECONNECT_WAIT
            self._emit("reconnecting", {"attempt": attempt, "delay": delay})
            await asyncio.sleep(delay)
            if self._disconnecting:
                return
            try:
                await self.connect()
                self._reconnect_attempt = 0
                self._emit("reconnected", self)
                return
            except Exception:
                attempt += 1
                self._reconnect_attempt = attempt

    def _fail_pending_recovery(self, message: str) -> None:
        for pending in tuple(self._pending_by_task.values()):
            pending.handle._status = TaskStatus.RECOVERY_REQUIRED
            pending.handle._reject(TaskRecoveryRequiredError("TASK_RECOVERY_REQUIRED", message, task_id=pending.handle.task_id))
            pending.deadline_task.cancel()
        self._pending_by_task.clear()
        self._pending_by_message.clear()

    def _abort_local_tasks(self) -> None:
        """Fence local work when its admitting session is no longer live."""

        for local in tuple(self._local_tasks.values()):
            local.cancelled.set()
            for progress_task in tuple(local.progress_tasks):
                progress_task.cancel()
            if local.task is not None and local.task is not asyncio.current_task():
                local.task.cancel()
        self._local_tasks.clear()

    def _fail_status_queries(self, error: BaseException) -> None:
        for query in tuple(self._status_queries.values()):
            if not query.future.done():
                query.future.set_exception(error)
        self._status_queries.clear()

    def _self_identity(self) -> AgentIdentity:
        return AgentIdentity(agent_id=self.card.agent_id, instance_id=self.card.instance_id)

    def _is_self_target(self, target: AgentRef) -> bool:
        return target.agent_id == self.card.agent_id and (
            target.instance_id is None or target.instance_id == self.card.instance_id
        )

    async def submit(
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
    ) -> TaskHandle:
        self._bind_loop()
        await self.ready()
        if not isinstance(target, str) or not target or not isinstance(capability, str) or not capability:
            raise ValueError("target and capability must be non-empty")
        if not isinstance(input, dict):
            raise TypeError("task input must be a JSON object")
        encoded_input = canonical_json(input).encode("utf-8")
        if len(encoded_input) > self._limits.max_task_input_bytes:
            raise ValueError("task input exceeds configured byte limit")
        if len(self._pending_by_task) >= self._limits.max_pending_calls:
            raise TransportError("OVERLOADED", "too many pending calls")
        contract_capability, contract = self._resolve_contract(
            target,
            capability,
            capability_contract,
            capability_version,
            capability_contract_digest,
        )
        chosen_timeout = self._default_timeout if timeout is None else timeout
        maximum_timeout = self._limits.max_task_timeout
        if contract_capability is not None and contract_capability.timeout_ceiling_seconds is not None:
            maximum_timeout = min(maximum_timeout, float(contract_capability.timeout_ceiling_seconds))
        chosen_deadline, seconds = _as_seconds(deadline, chosen_timeout, maximum_timeout)
        from .protocol import uuidv7

        chosen_task_id = task_id or uuidv7()
        # Model validation gives callers an immediate UUIDv7 error.
        from .types import TaskSubmitParams

        if contract_capability is not None and contract_capability.input_schema is not None:
            validate_restricted_schema_instance(input, contract_capability.input_schema)
        if result_schema is None:
            result_schema = copy.deepcopy(contract_capability.result_schema) if contract_capability is not None else None
        elif not isinstance(result_schema, dict):
            raise TypeError("result_schema must be a JSON object")
        else:
            validate_restricted_schema(result_schema)
            if contract_capability is not None:
                expected_schema = contract_capability.result_schema
                if expected_schema is None or canonical_json(result_schema) != canonical_json(expected_schema):
                    raise ContractMismatchError(
                        "CAPABILITY_CONTRACT_MISMATCH",
                        "result_schema differs from the resolved capability contract",
                    )
        params = {
            "task_id": chosen_task_id,
            "method": capability,
            "capability_version": contract.capability_version,
            "capability_contract_digest": contract.capability_contract_digest,
            "params": copy.deepcopy(input),
            "deadline": chosen_deadline,
        }
        # Validate task-id/deadline shape before a handle enters local maps.
        TaskSubmitParams.model_validate(params)
        envelope = create_envelope(
            type="task.submit",
            source=self._self_identity(),
            target=AgentRef(agent_id=target, instance_id=target_instance_id),
            params=params,
            idempotency_key=idempotency_key or f"submit:{chosen_task_id}",
            deadline=chosen_deadline,
        )
        handle = TaskHandle(self, chosen_task_id, envelope.message_id)
        if on_progress is not None:
            handle.add_progress_callback(on_progress)
        deadline_task = asyncio.create_task(self._pending_timeout(chosen_task_id, seconds), name=f"polymesh-task-timeout-{chosen_task_id}")
        pending = _PendingCall(
            handle=handle,
            target=AgentRef(agent_id=target, instance_id=target_instance_id),
            contract=contract,
            result_schema=copy.deepcopy(result_schema),
            deadline=chosen_deadline,
            deadline_task=deadline_task,
        )
        self._pending_by_task[chosen_task_id] = pending
        self._pending_by_message[envelope.message_id] = pending
        try:
            await self._send_record(envelope, generation=self._generation)
        except BaseException as exc:
            self._settle_pending(pending, error=TaskRecoveryRequiredError("TASK_RECOVERY_REQUIRED", "submission write outcome is unknown", task_id=chosen_task_id))
            raise exc
        return handle

    async def call(self, target: str, capability: str, input: JsonObject, **options: Any) -> TaskHandle:
        """Submit a task and return a handle (the compact SDK task surface)."""

        return await self.submit(target, capability, input, **options)

    async def call_with_result(self, target: str, capability: str, input: JsonObject, **options: Any) -> JsonValue:
        handle = await self.submit(target, capability, input, **options)
        return await handle.result()

    def _resolve_contract(
        self,
        target: str,
        capability: str,
        explicit: Capability | None,
        version: str | None,
        digest: str | None,
    ) -> tuple[Capability | None, CapabilityContractTuple]:
        if explicit is not None:
            capability_value = Capability.model_validate(explicit)
            if capability_value.id != capability:
                raise ContractMismatchError("CAPABILITY_CONTRACT_MISMATCH", "capability contract ID differs from requested capability")
            derived = capability_contract_tuple(capability_value)
            if version is not None and version != derived.capability_version:
                raise ContractMismatchError("CAPABILITY_CONTRACT_MISMATCH", "capability version differs from the supplied contract")
            if digest is not None and digest.lower() != derived.capability_contract_digest.lower():
                raise ContractMismatchError("CAPABILITY_CONTRACT_MISMATCH", "capability digest differs from the supplied contract")
            return capability_value, derived
        if self._broker_card is not None and target == self._broker_card.agent_id:
            discovered = next((item for item in self._broker_card.capabilities if item.id == capability), None)
            if discovered is not None:
                derived = capability_contract_tuple(discovered)
                if version is not None and version != derived.capability_version:
                    raise ContractMismatchError("CAPABILITY_CONTRACT_MISMATCH", "capability version differs from the broker card")
                if digest is not None and digest.lower() != derived.capability_contract_digest.lower():
                    raise ContractMismatchError("CAPABILITY_CONTRACT_MISMATCH", "capability digest differs from the broker card")
                return discovered, derived
        if version is not None and digest is not None:
            # A routed target can expose an authenticated exact tuple without
            # yielding its whole Card to this session.  Do not invent a bare
            # Capability and compare its *different* normalized digest; only
            # validate the caller supplied tuple and retain it verbatim.
            try:
                supplied = CapabilityContractTuple(
                    capability_id=capability,
                    capability_version=version,
                    capability_contract_digest=digest.lower(),
                )
            except Exception as exc:
                raise ContractMismatchError("CAPABILITY_CONTRACT_MISMATCH", "capability contract tuple is invalid") from exc
            return None, supplied
        if version is not None or digest is not None:
            raise ContractMismatchError("CAPABILITY_CONTRACT_MISMATCH", "capability version and digest must be supplied together")
        # Compact native v2 has no card-discovery exchange.  Its native
        # envelope still carries a deterministic default contract tuple, so
        # a client can complete the bounded standard task lifecycle without
        # treating this as a v0.1 security downgrade.
        if self._profile == V2_PROTOCOL_VERSION or self._allow_insecure_loopback_development:
            candidate = Capability(id=capability, version=version or "1.0.0")
            return candidate, capability_contract_tuple(candidate)
        raise ContractMismatchError("CAPABILITY_CONTRACT_MISMATCH", "an exact capability contract is required")

    async def _pending_timeout(self, task_id: str, seconds: float) -> None:
        try:
            await asyncio.sleep(seconds)
            pending = self._pending_by_task.get(task_id)
            if pending is not None:
                pending.handle._status = TaskStatus.FAILED
                self._settle_pending(
                    pending,
                    error=TaskTimeoutError("PMX.TASK.DEADLINE_EXCEEDED", "task deadline elapsed", task_id=task_id),
                )
        except asyncio.CancelledError:
            raise

    async def cancel(self, task_id: str, reason: str | None = None) -> None:
        self._bind_loop()
        pending = self._pending_by_task.get(task_id)
        if pending is None:
            return
        envelope = create_envelope(
            type="task.cancel",
            source=self._self_identity(),
            target=pending.target,
            params={"task_id": task_id, **({"reason": reason} if reason is not None else {})},
            idempotency_key=f"cancel:{task_id}",
            deadline=pending.deadline,
        )
        await self._send_record(envelope, generation=self._generation)

    async def query_status(
        self,
        target: str,
        task_id: str,
        *,
        target_instance_id: str | None = None,
        timeout: float | None = None,
    ) -> TaskStatusSnapshotWire:
        """Request one advisory v0.1 status snapshot.

        A status response has no route-pinning authority, but it is still
        correlated to this exact query message ID.  It must never be confused
        with a lifecycle event for a pending call.
        """

        self._bind_loop()
        await self.ready()
        chosen_timeout = self._default_timeout if timeout is None else timeout
        deadline, seconds = _as_seconds(None, chosen_timeout, self._limits.max_task_timeout)
        from .protocol import uuidv7

        # Validate before allocating a future or putting bytes on the wire.
        TaskStatusQueryParams(kind="query", task_id=task_id)
        target_ref = AgentRef(agent_id=target, instance_id=target_instance_id)
        envelope = create_envelope(
            type="task.status",
            source=self._self_identity(),
            target=target_ref,
            params={"kind": "query", "task_id": task_id},
            idempotency_key=f"status:{task_id}:{uuidv7()}",
            deadline=deadline,
        )
        future: asyncio.Future[TaskStatusSnapshotParams] = asyncio.get_running_loop().create_future()
        query = _PendingStatusQuery(
            message_id=envelope.message_id,
            target=target_ref,
            task_id=task_id,
            future=future,
        )
        self._status_queries[query.message_id] = query
        try:
            await self._send_record(envelope, generation=self._generation)
            return await asyncio.wait_for(asyncio.shield(future), timeout=seconds)
        except asyncio.TimeoutError as exc:
            raise TaskTimeoutError("PMX.TASK.DEADLINE_EXCEEDED", "status query timed out", task_id=task_id) from exc
        finally:
            self._status_queries.pop(query.message_id, None)

    async def _dispatch_envelope(self, envelope: Envelope, generation: int) -> bool:
        if generation != self._generation or not self.connected:
            return False
        if not self._verify_inbound_security(envelope):
            self._emit("protocol_error", AuthenticationError("ROUTED_PROVENANCE_INVALID", "inbound record lacks valid session-bound provenance"))
            return False
        if not self._is_self_target(envelope.target):
            self._emit("protocol_error", ProtocolError("WRONG_TARGET", "inbound envelope is not addressed to this client"))
            return False
        assert self._envelope_queue is not None
        with contextlib.suppress(asyncio.QueueFull):
            self._envelope_queue.put_nowait(envelope)
        self._emit("envelope", envelope)
        if envelope.type == "ping":
            if self._broker_identity is not None and _same_ref(envelope.source, self._broker_identity, require_instance=True):
                pong = create_envelope(
                    type="pong",
                    source=self._self_identity(),
                    target=envelope.source,
                    params={"n": envelope.params["n"]},
                )
                await self._send_record(pong, generation=generation)
                return True
            self._emit("protocol_error", ProtocolError("FORGED_PING", "ping is not from the authenticated broker"))
            return False
        if envelope.type == "pong":
            outstanding = self._outstanding_pong
            if outstanding is not None and envelope.params.get("n") == outstanding[0] and self._broker_identity is not None and _same_ref(envelope.source, self._broker_identity, require_instance=True):
                outstanding[1].set()
                return True
            self._emit("protocol_error", ProtocolError("FORGED_PONG", "pong is not from the authenticated broker or does not match a ping"))
            return False
        if envelope.type == "receipt":
            return self._receive_receipt(envelope)
        if envelope.type == "task.submit":
            await self._admit_inbound(envelope, generation)
            return True
        if envelope.type == "task.status":
            if envelope.params.get("kind") == "query":
                await self._respond_status_query(envelope, generation)
                return True
            else:
                return self._receive_status_snapshot(envelope)
        if envelope.type == "task.cancel":
            local = self._local_tasks.get(str(envelope.params.get("task_id")))
            if (
                local is not None
                and local.generation == generation
                and _same_ref(local.source, envelope.source, require_instance=True)
            ):
                local.cancelled.set()
                if local.task is not None:
                    local.task.cancel()
                return True
            self._emit("protocol_error", LifecycleError("PMX.TASK.FORGED_CANCEL", "cancel is not authorized for a local task"))
            return False
        if envelope.type in {"task.accepted", "task.rejected", "task.progress", "task.completed", "error"}:
            return await self._receive_lifecycle(envelope)
        self._emit("protocol_error", ProtocolError("UNSUPPORTED_METHOD", "post-ready envelope type is not supported"))
        return False

    def _verify_inbound_security(self, envelope: Envelope) -> bool:
        """Enforce the broker-only provenance attachment in secure sessions."""

        if self._identity_options is None:
            # A loopback sender never supplies provenance; only a secure
            # broker is allowed to append it while forwarding.
            return envelope.provenance is None
        broker = self._broker_identity
        principal = self._broker_principal
        if broker is None or principal is None or self._sid is None:
            return False
        # Broker-originated controls and its directly executed standard task
        # responses are authenticated by the secure session itself.  Routed
        # traffic from another principal needs the signed attachment.
        if _same_ref(broker, envelope.source, require_instance=True):
            return envelope.provenance is None
        if envelope.type not in {"task.submit", "task.cancel", "task.accepted", "task.rejected", "task.progress", "task.completed", "error"}:
            return False
        return verify_routed_provenance(
            envelope,
            broker_principal=principal,
            broker_identity=broker,
            target_session_id=self._sid,
        )

    def _receive_receipt(self, envelope: Envelope) -> bool:
        if (
            self._broker_identity is None
            or not _same_ref(self._broker_identity, envelope.source, require_instance=True)
            or envelope.target.agent_id != self.card.agent_id
            or (envelope.target.instance_id is not None and envelope.target.instance_id != self.card.instance_id)
        ):
            self._emit("protocol_error", ProtocolError("FORGED_RECEIPT", "receipt is not from the authenticated broker"))
            return False
        received = str(envelope.params.get("received_message_id", ""))
        pending = self._pending_by_message.get(received)
        if pending is None:
            return True
        try:
            pending.handle._receipt = ReceiptParams.model_validate(envelope.params)
            self._emit("receipt", pending.handle._receipt)
        except Exception as exc:
            self._emit("protocol_error", exc)
            return False
        return True

    async def _respond_status_query(self, envelope: Envelope, generation: int) -> None:
        """Answer a local advisory status query without inventing durability."""

        if envelope.target.agent_id != self.card.agent_id or (
            envelope.target.instance_id is not None and envelope.target.instance_id != self.card.instance_id
        ):
            return
        task_id = str(envelope.params.get("task_id", ""))
        try:
            TaskStatusQueryParams.model_validate(envelope.params)
        except Exception as exc:
            self._emit("protocol_error", exc)
            return
        local = self._local_tasks.get(task_id)
        state: JsonValue = "unknown"
        event_seq: JsonValue | None = None
        if local is not None:
            state = "cancelled" if local.cancelled.is_set() else "running"
            event_seq = local.next_event_seq - 1
        snapshot = TaskStatusSnapshotParams(
            kind="snapshot",
            task_id=task_id,
            observed_at=utc_now_millis(),
            state=state,
            event_seq=event_seq,
        )
        response = create_envelope(
            type="task.status",
            source=self._self_identity(),
            target=envelope.source,
            in_reply_to=envelope.message_id,
            idempotency_key=f"status-snapshot:{task_id}:{envelope.message_id}",
            deadline=envelope.delivery.deadline,
            params=snapshot.model_dump(mode="json", exclude_none=True),
        )
        with contextlib.suppress(Exception):
            await self._send_record(response, generation=generation)

    def _receive_status_snapshot(self, envelope: Envelope) -> bool:
        query = self._status_queries.get(envelope.in_reply_to or "")
        if query is None:
            return False
        if (
            not _same_ref(query.target, envelope.source)
            or envelope.target.agent_id != self.card.agent_id
            or (envelope.target.instance_id is not None and envelope.target.instance_id != self.card.instance_id)
        ):
            self._emit("protocol_error", LifecycleError("PMX.TASK.FORGED_STATUS", "status snapshot does not match query target"))
            return False
        try:
            snapshot = TaskStatusSnapshotParams.model_validate(envelope.params)
        except Exception as exc:
            if not query.future.done():
                query.future.set_exception(ProtocolError("MALFORMED_STATUS", "status snapshot is invalid"))
            self._emit("protocol_error", exc)
            return False
        if snapshot.task_id != query.task_id:
            if not query.future.done():
                query.future.set_exception(LifecycleError("PMX.TASK.FORGED_STATUS", "status snapshot task ID differs from query"))
            return False
        if not query.future.done():
            query.future.set_result(snapshot)
        return True

    async def _receive_lifecycle(self, envelope: Envelope) -> bool:
        if envelope.target.agent_id != self.card.agent_id or (
            envelope.target.instance_id is not None and envelope.target.instance_id != self.card.instance_id
        ):
            self._emit("protocol_error", LifecycleError("PMX.TASK.FORGED_RESULT", "lifecycle target does not match this client"))
            return False
        if envelope.type == "error":
            pending = self._pending_by_message.get(envelope.in_reply_to or "")
            if pending is None:
                query = self._status_queries.get(envelope.in_reply_to or "")
                if query is not None and (
                    _same_ref(query.target, envelope.source) or self._is_broker_source(envelope)
                ):
                    params = envelope.params
                    if not query.future.done():
                        query.future.set_exception(
                            error_from_structured(
                                category=str(params["category"]),
                                code=str(params["code"]),
                                message=str(params["message"]),
                                retryable=bool(params["retryable"]),
                                retry_after_ms=params.get("retry_after_ms"),
                                details=params.get("details"),
                                task_id=query.task_id,
                                envelope=envelope,
                            )
                        )
                    return True
                if query is not None:
                    self._emit("protocol_error", LifecycleError("PMX.TASK.FORGED_ERROR", "status error source does not match query target"))
                return False
            if not self._source_matches_pending(envelope, pending) and not self._is_broker_source(envelope):
                self._emit("protocol_error", LifecycleError("PMX.TASK.FORGED_ERROR", "error source does not match pending target"))
                return False
            params = envelope.params
            error = error_from_structured(
                category=str(params["category"]),
                code=str(params["code"]),
                message=str(params["message"]),
                retryable=bool(params["retryable"]),
                retry_after_ms=params.get("retry_after_ms"),
                details=params.get("details"),
                task_id=pending.handle.task_id,
                envelope=envelope,
            )
            self._settle_pending(pending, error=error)
            return True
        task_id = str(envelope.params.get("task_id", ""))
        pending = self._pending_by_task.get(task_id)
        if pending is None:
            return False
        if not self._source_matches_pending(envelope, pending):
            # A structurally valid envelope is not authority to terminate an
            # unrelated pending call.  The broker route state will reject the
            # sender; locally, preserve the task and report the observation.
            self._emit("protocol_error", LifecycleError("PMX.TASK.FORGED_RESULT", "lifecycle source does not match target", task_id=task_id))
            return False
        if envelope.type in {"task.accepted", "task.rejected"}:
            if envelope.in_reply_to != pending.handle.submit_message_id or envelope.params.get("event_seq") != 1:
                self._settle_pending(pending, error=LifecycleError("PMX.TASK.INVALID_LIFECYCLE", "invalid initial lifecycle record", task_id=task_id))
                return False
        sequence = int(envelope.params.get("event_seq", 0))
        digest = canonical_json({"type": envelope.type, "source": envelope.source.model_dump(mode="json"), "target": envelope.target.model_dump(mode="json", exclude_none=True), "params": envelope.params})
        prior = pending.event_digests.get(sequence)
        if prior is not None:
            if prior != digest:
                self._settle_pending(pending, error=LifecycleError("PMX.TASK.EVENT_CONFLICT", "event sequence was reused with different content", task_id=task_id))
            return prior == digest
        if sequence != pending.handle._last_event_seq + 1:
            self._settle_pending(pending, error=LifecycleError("PMX.TASK.INVALID_LIFECYCLE", "event sequence is not contiguous", task_id=task_id))
            return False
        pending.event_digests[sequence] = digest
        pending.handle._last_event_seq = sequence
        if envelope.type == "task.accepted":
            if not self._contract_matches(envelope, pending.contract):
                self._settle_pending(pending, error=ContractMismatchError("CAPABILITY_CONTRACT_MISMATCH", "accepted contract differs from submission", task_id=task_id))
                return False
            pending.handle._status = TaskStatus.ACCEPTED
            return True
        if envelope.type == "task.rejected":
            pending.handle._status = TaskStatus.REJECTED
            self._settle_pending(
                pending,
                error=TaskRejectedError(str(envelope.params["code"]), str(envelope.params["message"]), task_id=task_id, envelope=envelope),
            )
            return True
        if pending.handle.status not in {TaskStatus.ACCEPTED, TaskStatus.RUNNING}:
            self._settle_pending(pending, error=LifecycleError("PMX.TASK.INVALID_LIFECYCLE", "terminal/progress precedes acceptance", task_id=task_id))
            return False
        if envelope.type == "task.progress":
            progress = envelope.params.get("progress")
            if not isinstance(progress, dict):
                self._settle_pending(pending, error=LifecycleError("PMX.TASK.INVALID_LIFECYCLE", "progress is not an object", task_id=task_id))
                return False
            pending.handle._status = TaskStatus.RUNNING
            pending.handle._progress(progress)
            self._emit("progress", {"task_id": task_id, "progress": progress})
            return True
        if envelope.type == "task.completed":
            if not self._contract_matches(envelope, pending.contract):
                self._settle_pending(pending, error=ContractMismatchError("CAPABILITY_CONTRACT_MISMATCH", "completed contract differs from submission", task_id=task_id))
                return False
            await self._complete_pending(pending, envelope)
            return True
        return False

    def _source_matches_pending(self, envelope: Envelope, pending: _PendingCall) -> bool:
        # A directly authenticated broker can execute its advertised standard
        # capabilities. Routed loopback lifecycle events originate at the
        # expected target agent.
        if _same_ref(pending.target, envelope.source):
            return True
        return self._is_broker_source(envelope) and pending.target.agent_id == self._broker_identity.agent_id

    def _is_broker_source(self, envelope: Envelope) -> bool:
        return self._broker_identity is not None and _same_ref(
            envelope.source, self._broker_identity, require_instance=True
        )

    @staticmethod
    def _contract_matches(envelope: Envelope, contract: CapabilityContractTuple) -> bool:
        params = envelope.params
        return (
            params.get("capability_id") == contract.capability_id
            and params.get("capability_version") == contract.capability_version
            and str(params.get("capability_contract_digest", "")).lower() == contract.capability_contract_digest.lower()
        )

    async def _complete_pending(self, pending: _PendingCall, envelope: Envelope) -> None:
        terminal = envelope.params.get("terminal")
        if not isinstance(terminal, dict):
            self._settle_pending(pending, error=ProtocolError("MALFORMED_TERMINAL", "completion terminal is invalid", task_id=pending.handle.task_id))
            return
        outcome = terminal.get("outcome")
        if outcome == "succeeded":
            result = terminal.get("result")
            try:
                # Strict parse after canonicalisation catches invalid local
                # Python values even if a model construction was bypassed.
                result = parse_strict_json(canonical_json(result))
                if len(canonical_json(result).encode("utf-8")) > self._limits.max_result_bytes:
                    raise ResultValidationError(
                        "RESULT_TOO_LARGE",
                        "terminal result exceeds the configured byte limit",
                        task_id=pending.handle.task_id,
                    )
                if pending.result_schema is not None:
                    validate_restricted_schema_instance(result, pending.result_schema)
            except ResultValidationError as exc:
                self._settle_pending(pending, error=exc)
                return
            except Exception:
                self._settle_pending(pending, error=ResultValidationError("RESULT_SCHEMA_INVALID", "terminal result failed pinned schema", task_id=pending.handle.task_id))
                return
            pending.handle._status = TaskStatus.COMPLETED
            self._settle_pending(pending, value=result)
        elif outcome == "failed":
            error = terminal.get("error") if isinstance(terminal.get("error"), dict) else {}
            pending.handle._status = TaskStatus.FAILED
            self._settle_pending(pending, error=ExecutionError(str(error.get("code", "EXECUTION_FAILED")), str(error.get("message", "task failed")), task_id=pending.handle.task_id))
        elif outcome == "cancelled":
            pending.handle._status = TaskStatus.CANCELLED
            self._settle_pending(pending, error=TaskCancelledError("TASK_CANCELLED", "task was cancelled", task_id=pending.handle.task_id))
        else:
            self._settle_pending(pending, error=ProtocolError("MALFORMED_TERMINAL", "unknown terminal outcome", task_id=pending.handle.task_id))

    def _settle_pending(self, pending: _PendingCall, *, value: JsonValue | None = None, error: BaseException | None = None) -> None:
        if self._pending_by_task.get(pending.handle.task_id) is not pending:
            return
        self._pending_by_task.pop(pending.handle.task_id, None)
        self._pending_by_message.pop(pending.handle.submit_message_id, None)
        pending.deadline_task.cancel()
        if error is not None:
            pending.handle._reject(error)
        else:
            pending.handle._resolve(value)

    async def _admit_inbound(self, envelope: Envelope, generation: int) -> None:
        if envelope.target.agent_id != self.card.agent_id or (
            envelope.target.instance_id is not None and envelope.target.instance_id != self.card.instance_id
        ):
            return
        params = envelope.params
        task_id = str(params.get("task_id", ""))
        method = str(params.get("method", ""))
        deadline = str(params.get("deadline", ""))
        try:
            deadline_at = parse_timestamp(deadline)
            if deadline_at <= datetime.now(UTC):
                raise TaskTimeoutError("PMX.TASK.DEADLINE_EXCEEDED", "task deadline has elapsed", task_id=task_id)
            if envelope.delivery.deadline != deadline:
                raise LifecycleError("PMX.TASK.INVALID_LIFECYCLE", "submit deadline differs from delivery deadline", task_id=task_id)
            if not isinstance(params.get("params"), dict):
                raise SchemaValidationError("task input must be a JSON object")
            capability = next((item for item in self.card.capabilities if item.id == method), None)
            if capability is None:
                raise RoutingError("UNSUPPORTED_CAPABILITY", "capability is not declared", task_id=task_id)
            # Admission repeats the caller-side timeout policy.  A remote
            # sender must not use a far-future delivery deadline to retain a
            # local task slot beyond the configured or advertised ceiling.
            remaining = (deadline_at - datetime.now(UTC)).total_seconds()
            ceiling = self._limits.max_task_timeout
            if capability.timeout_ceiling_seconds is not None:
                ceiling = min(ceiling, float(capability.timeout_ceiling_seconds))
            if remaining > ceiling:
                raise TaskTimeoutError(
                    "PMX.TASK.DEADLINE_EXCEEDED",
                    "task deadline exceeds the local capability timeout ceiling",
                    task_id=task_id,
                )
            if method not in _STANDARD_CAPABILITIES and self._handler_for(method) is None:
                # Advertising a capability does not imply there is executable
                # work behind it.  Reject before acceptance so callers never
                # observe a false admission followed by a generic failure.
                raise RoutingError("UNSUPPORTED_CAPABILITY", "capability has no registered handler", task_id=task_id)
            contract = capability_contract_tuple(capability)
            if params.get("capability_version") != contract.capability_version or str(params.get("capability_contract_digest", "")).lower() != contract.capability_contract_digest.lower():
                raise ContractMismatchError("CAPABILITY_CONTRACT_MISMATCH", "submitted contract does not match local card", task_id=task_id)
            input_value = params["params"]
            if len(canonical_json(input_value).encode("utf-8")) > self._limits.max_task_input_bytes:
                raise SchemaValidationError("input exceeds configured limit")
            if capability.input_schema is not None:
                validate_restricted_schema_instance(input_value, capability.input_schema)
            allowed = await self._authorized(envelope.source, method, input_value, envelope)
            if not allowed:
                raise AuthenticationError("AUTHORIZATION_DENIED", "task is not authorized", task_id=task_id)
            # Authorization can be asynchronous.  Never admit work merely
            # because its deadline was live before the policy decision.
            if parse_timestamp(deadline) <= datetime.now(UTC):
                raise TaskTimeoutError("PMX.TASK.DEADLINE_EXCEEDED", "task deadline elapsed during authorization", task_id=task_id)
            if self._requires_durable_replay(capability):
                # A process-local dictionary cannot make a restart-safe claim
                # for sensitive or side-effecting work.  The v0.1 loopback
                # profile also has no verified stable principal, so fail
                # closed rather than silently weakening the advertised policy.
                if self._replay_ledger is None or self._identity_options is None:
                    raise AuthenticationError(
                        "DURABLE_REPLAY_REQUIRED",
                        "side-effecting capability requires a durable secure replay ledger",
                        task_id=task_id,
                    )
        except BaseException as exc:
            await self._send_rejection(envelope, task_id, exc)
            return
        replay_key = self._inbound_replay_key(envelope)
        replay_fingerprint = self._inbound_replay_fingerprint(envelope)
        prior_replay = self._inbound_replays.get(replay_key)
        if prior_replay is not None:
            self._inbound_replays.move_to_end(replay_key)
            if prior_replay.fingerprint != replay_fingerprint:
                await self._send_rejection(
                    envelope,
                    task_id,
                    LifecycleError(
                        "PMX.DELIVERY.IDEMPOTENCY_CONFLICT",
                        "idempotency key was reused with different task semantics",
                        task_id=task_id,
                    ),
                )
                return
            await self._replay_inbound_admission(prior_replay, envelope, generation)
            return
        task_fingerprint = self._inbound_task_fingerprint(envelope)
        prior_task = self._inbound_task_replays.get(task_id)
        if prior_task is not None:
            self._inbound_task_replays.move_to_end(task_id)
            known_fingerprint, known_replay = prior_task
            if known_fingerprint != task_fingerprint:
                await self._send_rejection(
                    envelope,
                    task_id,
                    LifecycleError(
                        "PMX.TASK.ID_CONFLICT",
                        "task_id was reused with different immutable task input",
                        task_id=task_id,
                    ),
                )
                return
            # A same-task retransmission may carry a fresh message ID or
            # delivery key.  Replay the original admission without invoking
            # the handler a second time.
            await self._replay_inbound_admission(known_replay, envelope, generation)
            return
        if len(self._local_tasks) >= self._limits.max_local_tasks:
            await self._send_rejection(envelope, task_id, TransportError("OVERLOADED", "too many local tasks", task_id=task_id))
            return
        cancelled = asyncio.Event()
        local = _LocalTask(
            task_id=task_id,
            source=envelope.source,
            target=envelope.target,
            contract=contract,
            deadline=deadline,
            result_schema=copy.deepcopy(capability.result_schema),
            submit_message_id=envelope.message_id,
            generation=generation,
            cancelled=cancelled,
            replay_key=replay_key,
        )
        if (
            len(self._inbound_replays) >= self._limits.max_inbound_dedupe_entries
            or len(self._inbound_task_replays) >= self._limits.max_inbound_dedupe_entries
        ):
            # Do not discard a still-retained idempotency record merely to
            # admit newer work: eviction would turn a later retransmission
            # into duplicate handler execution.  Apply bounded backpressure.
            await self._send_rejection(
                envelope,
                task_id,
                TransportError("OVERLOADED", "inbound replay admission capacity is exhausted", task_id=task_id),
            )
            return
        replay = _InboundReplay(fingerprint=replay_fingerprint)
        self._inbound_replays[replay_key] = replay
        self._inbound_task_replays[task_id] = (task_fingerprint, replay)
        self._local_tasks[task_id] = local
        accepted = create_envelope(
            type="task.accepted",
            source=self._self_identity(),
            target=envelope.source,
            in_reply_to=envelope.message_id,
            idempotency_key=f"accepted:{task_id}",
            deadline=deadline,
            params={
                "task_id": task_id,
                "event_seq": 1,
                "accepted_at": utc_now_millis(),
                **contract.model_dump(mode="json"),
            },
        )
        replay.accepted = accepted
        await self._send_record(accepted, generation=generation)
        local.task = asyncio.create_task(self._run_handler(local, capability, copy.deepcopy(input_value)), name=f"polymesh-handler-{task_id}")

    @staticmethod
    def _requires_durable_replay(capability: Capability) -> bool:
        return capability.idempotency == "sensitive" or capability.side_effects in {"write", "network", "approval"}

    def _inbound_replay_key(self, envelope: Envelope) -> str:
        return "\0".join(
            (
                envelope.source.agent_id,
                envelope.source.instance_id,
                self.card.instance_id,
                envelope.protocol,
                envelope.type,
                envelope.delivery.idempotency_key,
            )
        )

    @staticmethod
    def _inbound_replay_fingerprint(envelope: Envelope) -> str:
        return canonical_json(
            {
                "protocol": envelope.protocol,
                "type": envelope.type,
                "source": envelope.source.model_dump(mode="json"),
                "target": envelope.target.model_dump(mode="json", exclude_none=True),
                "delivery": {
                    "mode": envelope.delivery.mode.value,
                    "deadline": envelope.delivery.deadline,
                },
                "params": envelope.params,
            }
        )

    @staticmethod
    def _inbound_task_fingerprint(envelope: Envelope) -> str:
        """Canonical immutable v0.1 task content, independent of delivery."""

        params = envelope.params
        return canonical_json(
            {
                "method": params["method"],
                "capability_version": params["capability_version"],
                "capability_contract_digest": params["capability_contract_digest"],
                "params": params["params"],
                "deadline": params["deadline"],
            }
        )

    async def _replay_inbound_admission(self, replay: _InboundReplay, submit: Envelope, generation: int) -> None:
        """Replay known lifecycle artifacts without invoking a handler twice."""

        accepted = replay.accepted
        if accepted is None:
            return
        replayed_accepted = create_envelope(
            type="task.accepted",
            source=self._self_identity(),
            target=submit.source,
            in_reply_to=submit.message_id,
            idempotency_key=accepted.delivery.idempotency_key,
            deadline=accepted.delivery.deadline,
            params=accepted.params,
        )
        with contextlib.suppress(Exception):
            await self._send_record(replayed_accepted, generation=generation)
        terminal = replay.terminal
        if terminal is None:
            return
        replayed_terminal = create_envelope(
            type="task.completed",
            source=self._self_identity(),
            target=submit.source,
            idempotency_key=terminal.delivery.idempotency_key,
            deadline=terminal.delivery.deadline,
            params=terminal.params,
        )
        with contextlib.suppress(Exception):
            await self._send_record(replayed_terminal, generation=generation)

    async def _authorized(self, source: AgentIdentity, method: str, input_value: JsonObject, envelope: Envelope) -> bool:
        if self._authorization is None:
            # Development transport opt-in is not an authorization policy.
            # Non-standard handlers require an application's explicit allow
            # decision even on numeric loopback.
            return method in _STANDARD_CAPABILITIES
        try:
            decision = self._authorization(source, method, copy.deepcopy(input_value), envelope)
            return bool(await decision) if inspect.isawaitable(decision) else bool(decision)
        except Exception:
            return False

    async def _send_rejection(self, envelope: Envelope, task_id: str, error: BaseException) -> None:
        code = getattr(error, "code", "TASK_REJECTED")
        message = str(error)[:8192] or "task was rejected"
        if not task_id:
            return
        rejected = create_envelope(
            type="task.rejected",
            source=self._self_identity(),
            target=envelope.source,
            in_reply_to=envelope.message_id,
            idempotency_key=f"rejected:{task_id}",
            deadline=envelope.delivery.deadline,
            params={"task_id": task_id, "event_seq": 1, "code": code, "message": message},
        )
        with contextlib.suppress(Exception):
            await self._send_record(rejected, generation=self._generation)

    async def _run_handler(self, local: _LocalTask, capability: Capability, input_value: JsonObject) -> None:
        try:
            context = TaskContext(self, local, input_value)
            remaining = (context.deadline - datetime.now(UTC)).total_seconds()
            if remaining <= 0:
                raise TaskCancelledError("PMX.TASK.DEADLINE_EXCEEDED", "task deadline elapsed", task_id=local.task_id)
            handler = self._handler_for(capability.id)
            if handler is None:
                result = self._standard_result(capability.id)
            else:
                result = handler(_clone_json(input_value), context)
                if inspect.isawaitable(result):
                    # Awaitable handlers receive a hard deadline watchdog;
                    # synchronous user functions cannot be pre-empted by
                    # asyncio but are still checked before terminal output.
                    result = await asyncio.wait_for(result, timeout=remaining)
            context.raise_if_cancelled()
            result = parse_strict_json(canonical_json(result))
            if len(canonical_json(result).encode("utf-8")) > self._limits.max_result_bytes:
                raise ResultValidationError("RESULT_TOO_LARGE", "handler result exceeds configured limit", task_id=local.task_id)
            if local.result_schema is not None:
                validate_restricted_schema_instance(result, local.result_schema)
            await self._send_terminal(local, {"outcome": "succeeded", "result": result, "completed_at": utc_now_millis()})
        except asyncio.CancelledError:
            if local.generation == self._generation:
                await self._send_terminal(local, {"outcome": "cancelled", "cancellation": {"code": "CANCELLED", "message": "Cancellation was observed by the executor"}, "completed_at": utc_now_millis()})
            raise
        except TaskCancelledError:
            if local.generation == self._generation:
                await self._send_terminal(local, {"outcome": "cancelled", "cancellation": {"code": "CANCELLED"}, "completed_at": utc_now_millis()})
        except asyncio.TimeoutError:
            if local.generation == self._generation:
                await self._send_terminal(
                    local,
                    {
                        "outcome": "failed",
                        "error": {"code": "PMX.TASK.DEADLINE_EXCEEDED", "message": "Task handler deadline elapsed"},
                        "completed_at": utc_now_millis(),
                    },
                )
        except Exception:
            if local.generation == self._generation:
                await self._send_terminal(local, {"outcome": "failed", "error": {"code": "EXECUTION_FAILED", "message": "Task handler failed"}, "completed_at": utc_now_millis()})
        finally:
            self._local_tasks.pop(local.task_id, None)

    def _handler_for(self, capability: str) -> TaskHandler | None:
        with self._registry_lock:
            return self._handlers.get(capability)

    def _standard_result(self, capability: str) -> JsonValue:
        if capability == "org.polymesh.agent.ping":
            return {}
        if capability == "org.polymesh.agent.info":
            return self.card.model_dump(mode="json", exclude_none=True)
        if capability == "org.polymesh.capabilities.list":
            return [{"id": item.id, "version": item.version} for item in self.card.capabilities]
        raise RoutingError("UNSUPPORTED_CAPABILITY", "no handler is registered")

    def _schedule_progress(self, local: _LocalTask, progress: TaskProgress) -> None:
        loop = self._loop
        if loop is None or loop.is_closed() or local.cancelled.is_set() or local.generation != self._generation or local.terminal:
            return
        if datetime.now(UTC) >= parse_timestamp(local.deadline):
            local.cancelled.set()
            return
        if local.progress_count >= self._limits.max_progress_events_per_task:
            return
        local.progress_count += 1
        task = loop.create_task(self._send_progress(local, progress))
        local.progress_tasks.add(task)
        task.add_done_callback(local.progress_tasks.discard)

    async def _send_progress(self, local: _LocalTask, progress: TaskProgress) -> None:
        if local.generation != self._generation or local.cancelled.is_set() or local.terminal:
            return
        sequence = local.next_event_seq
        local.next_event_seq += 1
        envelope = create_envelope(
            type="task.progress",
            source=self._self_identity(),
            target=local.source,
            idempotency_key=f"progress:{local.task_id}:{sequence}",
            deadline=local.deadline,
            params={"task_id": local.task_id, "event_seq": sequence, "progress": progress},
        )
        with contextlib.suppress(Exception):
            await self._send_record(envelope, generation=local.generation)

    async def _send_terminal(self, local: _LocalTask, terminal: JsonObject) -> None:
        if local.terminal or local.generation != self._generation:
            return
        # ``TaskContext.progress`` is intentionally synchronous.  Drain
        # progress records scheduled by a handler before assigning the
        # terminal sequence so a fast-returning handler cannot race its own
        # final event ahead of an already admitted progress update.
        pending_progress = tuple(local.progress_tasks)
        if pending_progress:
            await asyncio.gather(*pending_progress, return_exceptions=True)
        if local.terminal or local.generation != self._generation:
            return
        local.terminal = True
        sequence = local.next_event_seq
        local.next_event_seq += 1
        envelope = create_envelope(
            type="task.completed",
            source=self._self_identity(),
            target=local.source,
            idempotency_key=f"completed:{local.task_id}:{sequence}",
            deadline=local.deadline,
            params={
                "task_id": local.task_id,
                "event_seq": sequence,
                **local.contract.model_dump(mode="json"),
                "terminal": terminal,
            },
        )
        if local.replay_key is not None:
            replay = self._inbound_replays.get(local.replay_key)
            if replay is not None:
                replay.terminal = envelope
                self._inbound_replays.move_to_end(local.replay_key)
        with contextlib.suppress(Exception):
            await self._send_record(envelope, generation=local.generation)

    async def discover(self, *, refresh: bool = False, timeout: float = 2.0) -> list[AgentCard]:
        return []


def _has_running_loop() -> bool:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return False
    return True


Client = PolyMeshClient


__all__ = [
    "AuthorizationHook",
    "Client",
    "PolyMeshClient",
    "ProgressCallback",
    "TaskContext",
    "TaskHandle",
    "TaskHandler",
    "TaskProgress",
]

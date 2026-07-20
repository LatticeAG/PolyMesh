"""Async transports, endpoint policy, and generation-fenced reconnects.

This module deliberately separates carrier mechanics from the PolyMesh
handshake and task state machines.  A :class:`WireTransport` moves one text
record at a time; :class:`ConnectionSupervisor` provides the one-reader,
one-writer, bounded-queue and reconnect discipline that a client can opt into.
The public client remains free to use a test or embedding transport directly.

No transport here uses newline-delimited JSON.  One WebSocket text message is
one complete PolyMesh record.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import ipaddress
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, TypeAlias, TypeVar, runtime_checkable
from urllib.parse import SplitResult, urlsplit, urlunsplit

from .auth import TokenStore, validate_runtime_token
from .errors import (
    AuthenticationError,
    HeartbeatTimeoutError,
    ParseError,
    PolyMeshError,
    ProtocolError,
    SecureProfileUnsupportedError,
    SlowConsumerError,
    TransportClosedError,
    TransportError,
    WrongEventLoopError,
)


PROTOCOL_SUBPROTOCOL = "polymesh.0.1"
POLYMESH_PATH = "/polymesh"
MAX_FRAME_BYTES = 1_048_576


class ConnectionState(str, Enum):
    """Local carrier state; these values are never protocol frames."""

    NEW = "new"
    IDLE = "idle"
    CONNECTING = "connecting"
    HANDSHAKING = "handshaking"
    ACTIVE = "active"
    RECONNECT_WAIT = "reconnect_wait"
    CLOSING = "closing"
    CLOSED = "closed"


class TransportClosed(Exception):
    """Internal close sentinel used by in-memory transports."""


@runtime_checkable
class WireTransport(Protocol):
    """Minimal async, text-only carrier used by :class:`PolyMeshClient`.

    Implementations must return a complete WebSocket text message from
    :meth:`recv`; partial JSON and binary frames aren't valid PolyMesh records.
    ``closed`` is intentionally a simple property so a test double need not
    emulate a WebSocket state enum.
    """

    @property
    def closed(self) -> bool: ...

    async def send(self, data: str) -> None: ...

    async def recv(self) -> str: ...

    async def close(self, code: int = 1000, reason: str = "") -> None: ...


@runtime_checkable
class SecureWireTransport(WireTransport, Protocol):
    """Carrier required for the enrolled TLS/Ed25519 profile."""

    def export_tls_channel_binding(self) -> bytes:
        """Return exactly 32 TypeScript-reference-compatible exporter bytes."""


@dataclass(frozen=True, slots=True)
class ValidatedEndpoint:
    """A canonical, policy-checked v0.1 WebSocket endpoint."""

    url: str
    scheme: str
    host: str
    port: int | None
    path: str

    @property
    def is_loopback(self) -> bool:
        return is_numeric_loopback_host(self.host)

    @property
    def is_secure(self) -> bool:
        return self.scheme == "wss"


def is_numeric_loopback_host(host: str) -> bool:
    """Accept only literal ``127/8`` IPv4 or literal ``::1`` IPv6.

    ``localhost`` and an arbitrary hostname that resolves to loopback are
    deliberately rejected.  DNS resolution would make the permission check
    time-dependent and violates the selected development profile.
    """

    if not isinstance(host, str) or not host:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (isinstance(address, ipaddress.IPv4Address) and address.packed[0] == 127) or (
        isinstance(address, ipaddress.IPv6Address) and address == ipaddress.IPv6Address("::1")
    )


def _normalise_url(value: str) -> tuple[SplitResult, str]:
    if not isinstance(value, str) or not value:
        raise TransportError("INVALID_ENDPOINT", "A non-empty WebSocket endpoint is required")
    try:
        parsed = urlsplit(value)
        # Accessing .port performs validation for malformed/overflow ports.
        _ = parsed.port
    except ValueError as exc:
        raise TransportError("INVALID_ENDPOINT", "WebSocket endpoint has an invalid port") from exc
    if parsed.scheme not in {"ws", "wss"} or not parsed.hostname:
        raise TransportError("INVALID_ENDPOINT", "PolyMesh endpoints must be absolute ws:// or wss:// URLs")
    if parsed.username is not None or parsed.password is not None:
        raise TransportError("INVALID_ENDPOINT", "Endpoint credentials are not permitted")
    if parsed.query or parsed.fragment:
        raise TransportError("INVALID_ENDPOINT", "Endpoint query strings and fragments are not permitted")
    if parsed.path not in {"", POLYMESH_PATH}:
        raise TransportError("INVALID_ENDPOINT", "PolyMesh endpoint path must be /polymesh")
    # urlsplit leaves an empty path for an origin.  The reference normalises
    # precisely that form and rejects every other path spelling.
    canonical = urlunsplit((parsed.scheme, parsed.netloc, POLYMESH_PATH, "", ""))
    return parsed, canonical


def normalize_broker_url(value: str) -> str:
    """Validate URL structure and normalise an origin to ``/polymesh``."""

    return _normalise_url(value)[1]


def validate_broker_url(
    value: str,
    *,
    allow_insecure_loopback_development: bool = False,
    token: str | None = None,
    secure_identity: object | None = None,
) -> ValidatedEndpoint:
    """Validate structure and selected v0.1 transport security policy.

    ``ws://`` requires both the explicit development opt-in and a valid
    loopback runtime token.  ``wss://`` requires a secure identity and must
    not receive a runtime token.  The standard ``websockets`` carrier is not
    an enrolled-profile carrier by itself; its exporter check happens in
    :func:`open_websocket_transport`.
    """

    parsed, canonical = _normalise_url(value)
    host = parsed.hostname or ""
    if parsed.scheme == "ws":
        if not allow_insecure_loopback_development or not is_numeric_loopback_host(host):
            raise TransportError(
                "INSECURE_TRANSPORT_DISABLED",
                "Plain WebSocket requires explicit numeric-loopback development mode",
            )
        if token is None:
            raise AuthenticationError(
                "AUTHENTICATION_FAILED", "Loopback WebSocket requires a runtime token"
            )
        validate_runtime_token(token)
        if secure_identity is not None:
            raise AuthenticationError(
                "AUTHENTICATION_FAILED", "Secure identity cannot be combined with a loopback runtime token"
            )
    else:
        if token is not None:
            raise AuthenticationError(
                "AUTHENTICATION_FAILED", "Runtime tokens are loopback-only and must not be sent to WSS"
            )
        if secure_identity is None:
            raise AuthenticationError(
                "AUTHENTICATION_FAILED", "WSS requires enrolled secure identity configuration"
            )
    return ValidatedEndpoint(
        url=canonical,
        scheme=parsed.scheme,
        host=host,
        port=parsed.port,
        path=POLYMESH_PATH,
    )


def safe_close_reason(reason: str) -> str:
    """Return a native-WebSocket-safe close reason without peer text reuse."""

    if not isinstance(reason, str):
        return "connection closed"
    sanitized = "".join("?" if ord(character) < 0x20 or ord(character) == 0x7F else character for character in reason)
    encoded = sanitized.encode("utf-8", "replace")
    if len(encoded) > 123:
        return "connection closed"
    return sanitized


def valid_close_code(code: int) -> bool:
    return code in {1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014} or 3000 <= code <= 4999


class WebSocketTransport:
    """Text-only adapter around ``websockets``' asyncio client connection."""

    def __init__(self, websocket: Any, *, max_frame_bytes: int = MAX_FRAME_BYTES) -> None:
        self._websocket = websocket
        self._max_frame_bytes = max_frame_bytes
        self._closed = False

    @classmethod
    async def connect(
        cls,
        url: str,
        **kwargs: Any,
    ) -> WireTransport:
        """Convenience spelling for :func:`open_websocket_transport`."""

        return await open_websocket_transport(url, **kwargs)

    @property
    def websocket(self) -> Any:
        """Underlying carrier for advanced diagnostics; never use it to send."""

        return self._websocket

    @property
    def selected_subprotocol(self) -> str | None:
        return getattr(self._websocket, "subprotocol", None)

    @property
    def closed(self) -> bool:
        if self._closed:
            return True
        state = getattr(self._websocket, "state", None)
        # websockets 13 uses ``closed``; current versions expose State.CLOSED.
        if getattr(self._websocket, "closed", False):
            return True
        return getattr(state, "name", "").upper() == "CLOSED"

    @property
    def is_open(self) -> bool:
        return not self.closed

    async def send(self, data: str) -> None:
        if self.closed:
            raise TransportClosedError("TRANSPORT_CLOSED", "Cannot send on a closed WebSocket", retryable=True)
        if not isinstance(data, str):
            raise TypeError("PolyMesh WebSocket records must be text")
        try:
            encoded = data.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise TransportError("MALFORMED_FRAME", "Outbound record contains invalid Unicode") from exc
        if len(encoded) > self._max_frame_bytes:
            raise TransportError("FRAME_TOO_LARGE", "Outbound WebSocket record exceeds 1 MiB")
        try:
            await self._websocket.send(data)
        except Exception as exc:
            self._closed = True
            raise TransportClosedError("TRANSPORT_CLOSED", "WebSocket write failed", retryable=True) from exc

    async def recv(self) -> str:
        if self.closed:
            raise TransportClosedError("TRANSPORT_CLOSED", "WebSocket is closed", retryable=True)
        try:
            data = await self._websocket.recv()
        except Exception as exc:
            self._closed = True
            raise TransportClosedError("TRANSPORT_CLOSED", "WebSocket closed while receiving", retryable=True) from exc
        if isinstance(data, bytes):
            # Binary frames never reach the JSON parser. Best effort close is
            # enough; the caller will surface a protocol failure.
            await self.close(1003, "binary frame not supported")
            raise TransportError("MALFORMED_FRAME", "Binary WebSocket frames are not supported")
        if not isinstance(data, str):
            raise TransportError("MALFORMED_FRAME", "WebSocket delivered a non-text record")
        try:
            size = len(data.encode("utf-8", "strict"))
        except UnicodeEncodeError as exc:
            raise TransportError("MALFORMED_FRAME", "WebSocket text has invalid Unicode") from exc
        if size > self._max_frame_bytes:
            await self.close(1009, "frame too large")
            raise TransportError("FRAME_TOO_LARGE", "Inbound WebSocket record exceeds 1 MiB")
        return data

    async def close(self, code: int = 1000, reason: str = "") -> None:
        if self._closed:
            return
        self._closed = True
        safe_code = code if valid_close_code(code) else 1000
        safe_reason = safe_close_reason(reason)
        try:
            await self._websocket.close(code=safe_code, reason=safe_reason)
        except TypeError:  # Some lightweight test doubles accept positional args.
            with contextlib.suppress(Exception):
                await self._websocket.close(safe_code, safe_reason)
        except Exception:
            # Close is idempotent/best effort. The caller is already leaving
            # the session and must not retain it because close reporting failed.
            pass


SecureTransportFactory: TypeAlias = Callable[[ValidatedEndpoint], Awaitable[WireTransport]]


async def _open_standard_websocket(
    endpoint: ValidatedEndpoint,
    *,
    token: str,
    open_timeout: float,
    max_frame_bytes: int,
) -> WebSocketTransport:
    """Open the required loopback WebSocket with extensions/proxies disabled."""

    try:
        from websockets.asyncio.client import connect as websocket_connect
    except ImportError:  # pragma: no cover - covered by package dependency
        try:
            from websockets.client import connect as websocket_connect  # type: ignore[no-redef]
        except ImportError as exc:  # pragma: no cover
            raise TransportError("TRANSPORT_UNAVAILABLE", "websockets is not installed") from exc

    options: dict[str, Any] = {
        "subprotocols": [PROTOCOL_SUBPROTOCOL],
        "compression": None,
        "max_size": max_frame_bytes,
        "max_queue": 16,
        "open_timeout": open_timeout,
        # PolyMesh protocol heartbeats are separate from native WS pings.
        "ping_interval": None,
        "ping_timeout": None,
    }
    signature = inspect.signature(websocket_connect)
    headers = {"x-polymesh-token": token}
    if "additional_headers" in signature.parameters:
        options["additional_headers"] = headers
    else:  # websockets 13 legacy spelling
        options["extra_headers"] = headers
    if "proxy" in signature.parameters:
        # Never send a loopback token through a configured ambient proxy.
        options["proxy"] = None

    connector = websocket_connect(endpoint.url, **options)
    # websockets 14+ follows HTTP redirects by default. The selected profile
    # forbids them because a token-bearing upgrade must never move origins.
    if hasattr(connector, "process_redirect"):
        setattr(connector, "process_redirect", lambda exc: exc)
    try:
        websocket = await connector
    except Exception as exc:
        raise TransportError("TRANSPORT_CONNECT_FAILED", "Unable to open PolyMesh WebSocket", retryable=True) from exc
    transport = WebSocketTransport(websocket, max_frame_bytes=max_frame_bytes)
    if transport.selected_subprotocol != PROTOCOL_SUBPROTOCOL:
        await transport.close(1002, "subprotocol mismatch")
        raise TransportError("SUBPROTOCOL_MISMATCH", "Peer did not select polymesh.0.1")
    return transport


async def open_websocket_transport(
    url: str,
    *,
    token: str | None = None,
    allow_insecure_loopback_development: bool = False,
    secure_identity: object | None = None,
    secure_transport_factory: SecureTransportFactory | None = None,
    open_timeout: float = 5.0,
    max_frame_bytes: int = MAX_FRAME_BYTES,
) -> WireTransport:
    """Open one policy-checked selected-profile WebSocket transport.

    The ordinary :mod:`websockets` carrier can safely implement only the
    numeric-loopback token profile.  Enrolled WSS callers must provide an
    explicit exporter-capable factory; an SSL socket's ``tls-unique`` value or
    certificate fingerprint is not an interchangeable channel binding.
    """

    endpoint = validate_broker_url(
        url,
        allow_insecure_loopback_development=allow_insecure_loopback_development,
        token=token,
        secure_identity=secure_identity,
    )
    if endpoint.scheme == "ws":
        assert token is not None
        return await _open_standard_websocket(
            endpoint, token=token, open_timeout=open_timeout, max_frame_bytes=max_frame_bytes
        )
    if secure_transport_factory is None:
        raise SecureProfileUnsupportedError(
            "SECURE_PROFILE_UNSUPPORTED",
            "The standard WebSocket carrier cannot export the required TLS channel binding",
        )
    transport = await secure_transport_factory(endpoint)
    if not isinstance(transport, WireTransport):
        # Runtime Protocol checking ensures the basic async surface is present
        # without tying embedding adapters to a concrete class.
        raise SecureProfileUnsupportedError("SECURE_PROFILE_UNSUPPORTED", "Secure transport has no WireTransport interface")
    exporter = getattr(transport, "export_tls_channel_binding", None)
    if not callable(exporter):
        with contextlib.suppress(Exception):
            await transport.close(1002, "missing TLS exporter")
        raise SecureProfileUnsupportedError("SECURE_PROFILE_UNSUPPORTED", "Secure transport cannot export TLS channel binding")
    try:
        binding = exporter()
    except Exception as exc:
        with contextlib.suppress(Exception):
            await transport.close(1002, "TLS exporter failed")
        raise SecureProfileUnsupportedError("SECURE_PROFILE_UNSUPPORTED", "Secure TLS exporter is unavailable") from exc
    if not isinstance(binding, bytes) or len(binding) != 32:
        with contextlib.suppress(Exception):
            await transport.close(1002, "invalid TLS exporter")
        raise SecureProfileUnsupportedError("SECURE_PROFILE_UNSUPPORTED", "Secure TLS exporter must return exactly 32 bytes")
    return transport


class WebSocketConnector:
    """Reconnect-safe connector that rereads a token store before each dial."""

    def __init__(
        self,
        url: str,
        *,
        token: str | None = None,
        token_store: TokenStore | None = None,
        allow_insecure_loopback_development: bool = False,
        secure_identity: object | None = None,
        secure_transport_factory: SecureTransportFactory | None = None,
        open_timeout: float = 5.0,
        max_frame_bytes: int = MAX_FRAME_BYTES,
    ) -> None:
        if token is not None and token_store is not None:
            raise ValueError("Specify either token or token_store, not both")
        self.url = url
        self.token = validate_runtime_token(token) if token is not None else None
        self.token_store = token_store
        self.allow_insecure_loopback_development = allow_insecure_loopback_development
        self.secure_identity = secure_identity
        self.secure_transport_factory = secure_transport_factory
        self.open_timeout = open_timeout
        self.max_frame_bytes = max_frame_bytes

    async def __call__(self) -> WireTransport:
        # Token rotation takes effect on reconnect because the read happens
        # immediately before every HTTP upgrade, not just at construction.
        token = self.token_store.read() if self.token_store is not None else self.token
        return await open_websocket_transport(
            self.url,
            token=token,
            allow_insecure_loopback_development=self.allow_insecure_loopback_development,
            secure_identity=self.secure_identity,
            secure_transport_factory=self.secure_transport_factory,
            open_timeout=self.open_timeout,
            max_frame_bytes=self.max_frame_bytes,
        )


def websocket_connector(url: str, **kwargs: Any) -> WebSocketConnector:
    """Convenience factory returning a reconnect-safe :class:`WebSocketConnector`."""

    return WebSocketConnector(url, **kwargs)


_CLOSE_SENTINEL = object()


class InMemoryTransport:
    """A small paired text transport for deterministic asyncio tests.

    It intentionally preserves message boundaries and lets tests inject binary
    records, delayed closes, and stale callbacks without opening a network
    port.  It is not a broker and performs no protocol parsing.
    """

    def __init__(self) -> None:
        self._incoming: asyncio.Queue[str | bytes | object] = asyncio.Queue()
        self._peer: InMemoryTransport | None = None
        self._closed = False
        self.close_code: int | None = None
        self.close_reason: str = ""

    @classmethod
    def pair(cls) -> tuple["InMemoryTransport", "InMemoryTransport"]:
        left, right = cls(), cls()
        left._peer = right
        right._peer = left
        return left, right

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def is_open(self) -> bool:
        return not self._closed

    async def send(self, data: str) -> None:
        if self._closed or self._peer is None or self._peer._closed:
            raise TransportClosedError("TRANSPORT_CLOSED", "In-memory wire is closed", retryable=True)
        if not isinstance(data, str):
            raise TypeError("In-memory PolyMesh records must be text")
        if len(data.encode("utf-8", "strict")) > MAX_FRAME_BYTES:
            raise TransportError("FRAME_TOO_LARGE", "In-memory record exceeds 1 MiB")
        await self._peer._incoming.put(data)

    async def recv(self) -> str:
        record = await self._incoming.get()
        if record is _CLOSE_SENTINEL:
            raise TransportClosedError("TRANSPORT_CLOSED", "In-memory wire is closed", retryable=True)
        if isinstance(record, bytes):
            raise TransportError("MALFORMED_FRAME", "Binary WebSocket frames are not supported")
        if not isinstance(record, str):
            raise TransportError("MALFORMED_FRAME", "In-memory wire received an invalid record")
        return record

    async def close(self, code: int = 1000, reason: str = "") -> None:
        if self._closed:
            return
        self._closed = True
        self.close_code = code if valid_close_code(code) else 1000
        self.close_reason = safe_close_reason(reason)
        await self._incoming.put(_CLOSE_SENTINEL)
        if self._peer is not None and not self._peer._closed:
            self._peer._closed = True
            self._peer.close_code = self.close_code
            self._peer.close_reason = self.close_reason
            await self._peer._incoming.put(_CLOSE_SENTINEL)

    async def feed_text(self, data: str) -> None:
        """Inject a text record into this endpoint (test helper)."""

        await self._incoming.put(data)

    async def feed_binary(self, data: bytes = b"x") -> None:
        """Inject a binary record into this endpoint (test helper)."""

        await self._incoming.put(data)

    async def force_close(self, code: int = 1006, reason: str = "transport lost") -> None:
        """Close only this endpoint, modelling a one-sided carrier loss."""

        if self._closed:
            return
        self._closed = True
        self.close_code = code
        self.close_reason = safe_close_reason(reason)
        await self._incoming.put(_CLOSE_SENTINEL)


MemoryWireTransport = InMemoryTransport


@dataclass(frozen=True, slots=True)
class ReconnectSettings:
    """Transport-local reconnect policy matching the v0.1 SDK defaults."""

    enabled: bool = True
    initial_delay: float = 1.0
    maximum_delay: float = 60.0
    multiplier: float = 2.0
    jitter: float = 0.20
    reset_after_active: float = 90.0
    resend_pending: bool = False

    def __post_init__(self) -> None:
        if self.resend_pending is not False:
            raise ValueError("v0.1 reconnect cannot resend pending tasks")
        if not self.enabled:
            return
        if not (0.0 < self.initial_delay <= 60.0):
            raise ValueError("initial_delay must be in (0, 60]")
        if not (0.0 < self.maximum_delay <= 300.0):
            raise ValueError("maximum_delay must be in (0, 300]")
        if self.maximum_delay < self.initial_delay:
            raise ValueError("maximum_delay must not be smaller than initial_delay")
        if not (1.0 <= self.multiplier <= 10.0):
            raise ValueError("multiplier must be in [1, 10]")
        if not (0.0 <= self.jitter <= 1.0):
            raise ValueError("jitter must be in [0, 1]")
        if self.reset_after_active <= 0:
            raise ValueError("reset_after_active must be positive")

    @classmethod
    def from_policy(cls, value: Any | None) -> "ReconnectSettings":
        """Adapt the Pydantic ``types.ReconnectPolicy`` without importing it."""

        if value is None:
            return cls()
        if isinstance(value, cls):
            return value
        fields = (
            "enabled",
            "initial_delay",
            "maximum_delay",
            "multiplier",
            "jitter",
            "reset_after_active",
            "resend_pending",
        )
        return cls(**{name: getattr(value, name) for name in fields})


@dataclass(slots=True)
class _Outbound:
    data: str
    written: asyncio.Future[None]


@dataclass(slots=True)
class TransportSession:
    """Mutable per-generation carrier state; never reuse it after a failure."""

    generation: int
    transport: WireTransport
    control_queue: asyncio.Queue[_Outbound]
    application_queue: asyncio.Queue[_Outbound]
    inbound_queue: asyncio.Queue[str | BaseException]
    outbound_ready: asyncio.Event
    reader_task: asyncio.Task[None] | None = None
    writer_task: asyncio.Task[None] | None = None
    heartbeat_task: asyncio.Task[None] | None = None
    active_since: float | None = None
    last_valid_inbound_at: float | None = None
    next_ping: int = 0
    outstanding_ping: tuple[int, float] | None = None
    current_outbound: _Outbound | None = None


RecordCallback: TypeAlias = Callable[[str, int], Awaitable[bool | None] | bool | None]
StateCallback: TypeAlias = Callable[[ConnectionState, int], Awaitable[None] | None]
LossCallback: TypeAlias = Callable[[BaseException, int], Awaitable[None] | None]
HeartbeatFactory: TypeAlias = Callable[[int], Awaitable[str] | str]
TransportFactory: TypeAlias = Callable[[], Awaitable[WireTransport]]

_CallbackValue = TypeVar("_CallbackValue")


async def _maybe_await(value: Awaitable[_CallbackValue] | _CallbackValue) -> _CallbackValue:
    if inspect.isawaitable(value):
        return await value
    return value


class ConnectionSupervisor:
    """A generation-fenced transport session manager.

    It doesn't parse or authorize records.  Instead, a client passes an
    ``on_record`` callback and calls :meth:`record_valid_inbound` only after
    strict framing, parser, session, provenance and lifecycle checks succeed.
    This is what keeps arbitrary carrier activity from satisfying heartbeat
    liveness.
    """

    def __init__(
        self,
        connector: TransportFactory,
        *,
        on_record: RecordCallback | None = None,
        on_state: StateCallback | None = None,
        on_lost: LossCallback | None = None,
        on_reconnected: StateCallback | None = None,
        reconnect: ReconnectSettings | Any | None = None,
        max_control_queue: int = 32,
        max_application_queue: int = 128,
        max_inbound_queue: int = 128,
        write_timeout: float = 10.0,
        heartbeat_interval: float = 30.0,
        pong_timeout: float = 5.0,
        inbound_timeout: float = 90.0,
        heartbeat_factory: HeartbeatFactory | None = None,
        random_fn: Callable[[], float] | None = None,
    ) -> None:
        if not callable(connector):
            raise TypeError("connector must be an async callable")
        if min(max_control_queue, max_application_queue, max_inbound_queue) < 1:
            raise ValueError("transport queues must have positive bounds")
        if write_timeout <= 0 or heartbeat_interval <= 0 or pong_timeout <= 0 or inbound_timeout <= 0:
            raise ValueError("transport timeouts must be positive")
        self._connector = connector
        self._on_record = on_record
        self._on_state = on_state
        self._on_lost = on_lost
        self._on_reconnected = on_reconnected
        self._reconnect = ReconnectSettings.from_policy(reconnect)
        self._max_control_queue = max_control_queue
        self._max_application_queue = max_application_queue
        self._max_inbound_queue = max_inbound_queue
        self._write_timeout = write_timeout
        self._heartbeat_interval = heartbeat_interval
        self._pong_timeout = pong_timeout
        self._inbound_timeout = inbound_timeout
        self._heartbeat_factory = heartbeat_factory
        self._random = random_fn or random.random

        self._state = ConnectionState.IDLE
        self._generation = 0
        self._session: TransportSession | None = None
        self._state_lock = asyncio.Lock()
        self._connect_task: asyncio.Task[TransportSession] | None = None
        self._reconnect_task: asyncio.Task[None] | None = None
        self._reset_task: asyncio.Task[None] | None = None
        self._owner_loop: asyncio.AbstractEventLoop | None = None
        self._manual_close = False
        self._reconnect_attempt = 0

    @property
    def state(self) -> ConnectionState:
        return self._state

    @property
    def connection_state(self) -> ConnectionState:
        return self._state

    @property
    def generation(self) -> int:
        return self._generation

    @property
    def session(self) -> TransportSession | None:
        return self._session

    @property
    def transport(self) -> WireTransport | None:
        return self._session.transport if self._session is not None else None

    @property
    def connected(self) -> bool:
        return self._state is ConnectionState.ACTIVE and self._session is not None and not self._session.transport.closed

    @property
    def loop(self) -> asyncio.AbstractEventLoop | None:
        return self._owner_loop

    def _assert_owner_loop(self) -> asyncio.AbstractEventLoop:
        loop = asyncio.get_running_loop()
        if self._owner_loop is None:
            self._owner_loop = loop
        elif self._owner_loop is not loop:
            raise WrongEventLoopError("WRONG_EVENT_LOOP", "Transport supervisor is bound to a different event loop")
        return loop

    async def is_current(self, generation: int, transport: WireTransport) -> bool:
        self._assert_owner_loop()
        async with self._state_lock:
            return (
                self._session is not None
                and self._session.generation == generation
                and self._session.transport is transport
            )

    async def connect(self) -> TransportSession:
        """Open one generation, sharing concurrent callers' connection task."""

        self._assert_owner_loop()
        async with self._state_lock:
            self._manual_close = False
            if self._session is not None and not self._session.transport.closed:
                return self._session
            task = self._connect_task
            if task is None or task.done():
                task = asyncio.create_task(self._open_generation(), name="polymesh-transport-connect")
                self._connect_task = task
        return await asyncio.shield(task)

    async def _open_generation(self) -> TransportSession:
        self._assert_owner_loop()
        async with self._state_lock:
            if self._manual_close:
                raise TransportClosedError("TRANSPORT_CLOSED", "Transport was explicitly disconnected")
            self._generation += 1
            generation = self._generation
            self._state = ConnectionState.CONNECTING
        await self._emit_state(ConnectionState.CONNECTING, generation)
        try:
            transport = await self._connector()
        except BaseException as exc:
            async with self._state_lock:
                if generation == self._generation and self._session is None:
                    self._state = ConnectionState.CLOSED
            await self._emit_state(ConnectionState.CLOSED, generation)
            raise self._as_transport_error(exc, "TRANSPORT_CONNECT_FAILED") from exc
        if not isinstance(transport, WireTransport):
            with contextlib.suppress(Exception):
                await transport.close()  # type: ignore[union-attr]
            raise TypeError("connector must return an async WireTransport")

        stale = False
        async with self._state_lock:
            if self._manual_close or generation != self._generation or self._session is not None:
                stale = True
            else:
                session = TransportSession(
                    generation=generation,
                    transport=transport,
                    control_queue=asyncio.Queue(self._max_control_queue),
                    application_queue=asyncio.Queue(self._max_application_queue),
                    inbound_queue=asyncio.Queue(self._max_inbound_queue),
                    outbound_ready=asyncio.Event(),
                )
                self._session = session
                self._state = ConnectionState.HANDSHAKING
        if stale:
            with contextlib.suppress(Exception):
                await transport.close(1000, "stale connection")
            raise TransportClosedError("TRANSPORT_CLOSED", "Connection attempt was fenced by a newer generation")

        session.reader_task = asyncio.create_task(
            self._reader(session), name=f"polymesh-reader-{generation}"
        )
        session.writer_task = asyncio.create_task(
            self._writer(session), name=f"polymesh-writer-{generation}"
        )
        await self._emit_state(ConnectionState.HANDSHAKING, generation)
        return session

    async def activate(self, generation: int | None = None) -> None:
        """Mark a fully validated handshake active and begin protocol heartbeat."""

        self._assert_owner_loop()
        async with self._state_lock:
            session = self._session
            if session is None or (generation is not None and session.generation != generation):
                raise TransportClosedError("TRANSPORT_CLOSED", "Cannot activate a stale connection")
            if session.transport.closed:
                raise TransportClosedError("TRANSPORT_CLOSED", "Cannot activate a closed connection", retryable=True)
            self._state = ConnectionState.ACTIVE
            now = asyncio.get_running_loop().time()
            session.active_since = now
            session.last_valid_inbound_at = now
            session.next_ping = 0
            session.outstanding_ping = None
            if session.heartbeat_task is None or session.heartbeat_task.done():
                session.heartbeat_task = asyncio.create_task(
                    self._heartbeat(session), name=f"polymesh-heartbeat-{session.generation}"
                )
            if self._reset_task is not None:
                self._reset_task.cancel()
            self._reset_task = asyncio.create_task(
                self._reset_reconnect_counter(session), name=f"polymesh-reconnect-reset-{session.generation}"
            )
            generation_value = session.generation
        await self._emit_state(ConnectionState.ACTIVE, generation_value)
        if generation_value > 1 and self._on_reconnected is not None:
            await _maybe_await(self._on_reconnected(ConnectionState.ACTIVE, generation_value))

    async def record_valid_inbound(self, generation: int | None = None) -> bool:
        """Refresh heartbeat liveness only after the caller fully validates a record."""

        self._assert_owner_loop()
        async with self._state_lock:
            session = self._session
            if session is None or self._state is not ConnectionState.ACTIVE:
                return False
            if generation is not None and session.generation != generation:
                return False
            session.last_valid_inbound_at = asyncio.get_running_loop().time()
            return True

    async def notify_pong(self, n: int, generation: int | None = None) -> bool:
        """Accept exactly the current generation's outstanding protocol pong."""

        self._assert_owner_loop()
        async with self._state_lock:
            session = self._session
            if session is None or self._state is not ConnectionState.ACTIVE:
                return False
            if generation is not None and session.generation != generation:
                return False
            outstanding = session.outstanding_ping
            if outstanding is None or outstanding[0] != n:
                return False
            session.outstanding_ping = None
            return True

    async def send(
        self,
        data: str,
        *,
        control: bool = False,
        generation: int | None = None,
        wait_written: bool = True,
    ) -> None:
        """Queue a complete text record; only the writer calls carrier ``send``."""

        self._assert_owner_loop()
        if not isinstance(data, str):
            raise TypeError("PolyMesh carrier records must be text")
        try:
            encoded = data.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise TransportError("MALFORMED_FRAME", "Outbound record contains invalid Unicode") from exc
        if len(encoded) > MAX_FRAME_BYTES:
            raise TransportError("FRAME_TOO_LARGE", "Outbound record exceeds 1 MiB")
        async with self._state_lock:
            session = self._session
            if session is None or session.transport.closed or self._state in {ConnectionState.CLOSING, ConnectionState.CLOSED, ConnectionState.RECONNECT_WAIT}:
                raise TransportClosedError("TRANSPORT_CLOSED", "No live transport generation", retryable=True)
            if generation is not None and session.generation != generation:
                raise TransportClosedError("TRANSPORT_CLOSED", "Outbound record belongs to a stale generation", retryable=True)
            queue = session.control_queue if control else session.application_queue
            if queue.full():
                raise SlowConsumerError("SLOW_CONSUMER", "Outbound transport queue is full", retryable=True)
            completion = asyncio.get_running_loop().create_future()
            queue.put_nowait(_Outbound(data, completion))
            session.outbound_ready.set()
        if wait_written:
            await completion

    async def next_record(self, generation: int | None = None) -> str:
        """Await one raw inbound text record when no ``on_record`` callback is used."""

        self._assert_owner_loop()
        async with self._state_lock:
            session = self._session
            if session is None or (generation is not None and session.generation != generation):
                raise TransportClosedError("TRANSPORT_CLOSED", "No current transport generation", retryable=True)
        record = await session.inbound_queue.get()
        if isinstance(record, BaseException):
            raise record
        return record

    async def fail_current(
        self,
        error: BaseException | None = None,
        *,
        transient: bool = True,
        generation: int | None = None,
        transport: WireTransport | None = None,
    ) -> bool:
        """Fence and close exactly one generation, optionally scheduling reconnect."""

        self._assert_owner_loop()
        raw_failure = error or TransportClosedError("TRANSPORT_CLOSED", "Transport connection closed", retryable=True)
        # Never surface carrier/library exception text through the public loss
        # callback or queued send futures: it can contain URLs, proxy details,
        # or a custom transport's credential diagnostic. Existing SDK errors
        # already carry bounded, code-oriented messages and are retained.
        failure: BaseException = raw_failure if isinstance(raw_failure, PolyMeshError) else self._as_transport_error(raw_failure, "TRANSPORT_CLOSED")
        async with self._state_lock:
            session = self._session
            if session is None:
                return False
            if generation is not None and session.generation != generation:
                return False
            if transport is not None and session.transport is not transport:
                return False
            # Clear before awaiting user code/close so old callbacks cannot
            # mutate a replacement connection.
            self._session = None
            self._generation += 1
            fenced_generation = session.generation
            should_reconnect = transient and self._reconnect.enabled and not self._manual_close
            self._state = ConnectionState.RECONNECT_WAIT if should_reconnect else ConnectionState.CLOSED
            reset_task = self._reset_task
            self._reset_task = None
        if reset_task is not None and reset_task is not asyncio.current_task():
            reset_task.cancel()
        self._finish_queued(session, failure)
        self._finish_inbound(session, failure)
        await self._cancel_session_tasks(session)
        with contextlib.suppress(Exception):
            await session.transport.close(1001, "transport lost")
        if self._on_lost is not None:
            with contextlib.suppress(Exception):
                await _maybe_await(self._on_lost(failure, fenced_generation))
        await self._emit_state(self._state, fenced_generation)
        if should_reconnect:
            self._schedule_reconnect()
        return True

    async def disconnect(self, code: int = 1000, reason: str = "client closed") -> None:
        """Idempotently stop reconnecting and fence the current generation."""

        self._assert_owner_loop()
        async with self._state_lock:
            self._manual_close = True
            session = self._session
            self._session = None
            self._generation += 1
            self._state = ConnectionState.CLOSING if session is not None else ConnectionState.CLOSED
            reconnect_task = self._reconnect_task
            self._reconnect_task = None
            reset_task = self._reset_task
            self._reset_task = None
        for task in (reconnect_task, reset_task):
            if task is not None and task is not asyncio.current_task():
                task.cancel()
        if session is not None:
            self._finish_queued(
                session,
                TransportClosedError("TRANSPORT_CLOSED", "Transport was explicitly disconnected", retryable=False),
            )
            self._finish_inbound(
                session,
                TransportClosedError("TRANSPORT_CLOSED", "Transport was explicitly disconnected", retryable=False),
            )
            await self._cancel_session_tasks(session)
            with contextlib.suppress(Exception):
                await session.transport.close(code if valid_close_code(code) else 1000, safe_close_reason(reason))
        async with self._state_lock:
            self._state = ConnectionState.CLOSED
            generation = self._generation
        await self._emit_state(ConnectionState.CLOSED, generation)

    def close_from_thread(self, code: int = 1000, reason: str = "client closed") -> None:
        """Begin the same close transition safely from a non-owner thread."""

        loop = self._owner_loop
        if loop is None or loop.is_closed():
            return

        def schedule() -> None:
            task = asyncio.create_task(self.disconnect(code, reason))
            # Mark exception observed; threaded cleanup has no caller waiting.
            task.add_done_callback(lambda completed: completed.exception() if not completed.cancelled() else None)

        loop.call_soon_threadsafe(schedule)

    def reconnect_delay(self, attempt: int) -> float:
        """Return v0.1 exponential-backoff delay for zero-based ``attempt``."""

        if attempt < 0:
            raise ValueError("reconnect attempt must not be negative")
        policy = self._reconnect
        base = min(policy.maximum_delay, policy.initial_delay * (policy.multiplier**attempt))
        factor = (1.0 - policy.jitter) + (2.0 * policy.jitter * self._random())
        return min(policy.maximum_delay, base * factor)

    def _schedule_reconnect(self) -> None:
        if self._manual_close or not self._reconnect.enabled:
            return
        task = self._reconnect_task
        if task is not None and not task.done():
            return
        self._reconnect_task = asyncio.create_task(self._reconnect_loop(), name="polymesh-reconnect")

    async def _reconnect_loop(self) -> None:
        while True:
            self._assert_owner_loop()
            async with self._state_lock:
                if self._manual_close or not self._reconnect.enabled or self._session is not None:
                    return
                self._state = ConnectionState.RECONNECT_WAIT
                attempt = self._reconnect_attempt
                generation = self._generation
            await self._emit_state(ConnectionState.RECONNECT_WAIT, generation)
            await asyncio.sleep(self.reconnect_delay(attempt))
            async with self._state_lock:
                if self._manual_close or self._session is not None:
                    return
            try:
                await self._open_generation()
                return
            except asyncio.CancelledError:
                raise
            except BaseException:
                # A bounded local setup failure is retryable. Identity/parser
                # failures must be supplied to fail_current with transient=False
                # by the handshake owner and therefore never reach this loop.
                self._reconnect_attempt += 1
                continue

    async def _reader(self, session: TransportSession) -> None:
        try:
            while await self.is_current(session.generation, session.transport):
                data = await session.transport.recv()
                if not await self.is_current(session.generation, session.transport):
                    return
                if self._on_record is None:
                    if session.inbound_queue.full():
                        raise SlowConsumerError("SLOW_CONSUMER", "Inbound transport queue is full", retryable=True)
                    session.inbound_queue.put_nowait(data)
                else:
                    valid = await _maybe_await(self._on_record(data, session.generation))
                    # A callback may return True only after it performs the
                    # full protocol/session validation pipeline.
                    if valid is True:
                        await self.record_valid_inbound(session.generation)
        except asyncio.CancelledError:
            raise
        except BaseException as exc:
            await self.fail_current(exc, transient=self._is_transient_carrier_failure(exc), generation=session.generation, transport=session.transport)

    async def _writer(self, session: TransportSession) -> None:
        try:
            while await self.is_current(session.generation, session.transport):
                item = await self._next_outbound(session)
                if not await self.is_current(session.generation, session.transport):
                    if not item.written.done():
                        item.written.set_exception(TransportClosedError("TRANSPORT_CLOSED", "Stale writer generation", retryable=True))
                    return
                session.current_outbound = item
                try:
                    try:
                        await asyncio.wait_for(session.transport.send(item.data), timeout=self._write_timeout)
                    except asyncio.TimeoutError as exc:
                        error = SlowConsumerError("SLOW_CONSUMER", "Outbound write did not drain before timeout", retryable=True)
                        if not item.written.done():
                            item.written.set_exception(error)
                        raise error from exc
                    except BaseException as exc:
                        error = self._as_transport_error(exc, "TRANSPORT_CLOSED")
                        if not item.written.done():
                            item.written.set_exception(error)
                        raise error from exc
                    if not item.written.done():
                        item.written.set_result(None)
                finally:
                    if session.current_outbound is item:
                        session.current_outbound = None
        except asyncio.CancelledError:
            raise
        except BaseException as exc:
            await self.fail_current(exc, transient=True, generation=session.generation, transport=session.transport)

    async def _next_outbound(self, session: TransportSession) -> _Outbound:
        # An Event avoids creating two competing Queue.get() tasks. Such
        # tasks can each remove an item before a close fences the writer,
        # orphaning a caller's write-completion future. Check both queues
        # synchronously, then clear/recheck before waiting to avoid a missed
        # producer wake-up.
        while True:
            try:
                return session.control_queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
            try:
                return session.application_queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
            session.outbound_ready.clear()
            if not session.control_queue.empty() or not session.application_queue.empty():
                session.outbound_ready.set()
                continue
            await session.outbound_ready.wait()

    async def _heartbeat(self, session: TransportSession) -> None:
        if self._heartbeat_factory is None:
            return
        try:
            loop = asyncio.get_running_loop()
            next_ping_at = loop.time() + self._heartbeat_interval
            while await self.is_current(session.generation, session.transport):
                if self._state is not ConnectionState.ACTIVE:
                    return
                now = loop.time()
                last_valid = session.last_valid_inbound_at or now
                outstanding = session.outstanding_ping
                due = min(next_ping_at, last_valid + self._inbound_timeout)
                if outstanding is not None:
                    due = min(due, outstanding[1])
                await asyncio.sleep(max(0.0, due - now))
                if not await self.is_current(session.generation, session.transport) or self._state is not ConnectionState.ACTIVE:
                    return
                now = loop.time()
                if session.outstanding_ping is not None and now >= session.outstanding_ping[1]:
                    raise HeartbeatTimeoutError("HEARTBEAT_TIMEOUT", "Broker did not answer the protocol heartbeat", retryable=True)
                if now >= (session.last_valid_inbound_at or now) + self._inbound_timeout:
                    raise HeartbeatTimeoutError("HEARTBEAT_TIMEOUT", "No valid inbound PolyMesh record arrived before timeout", retryable=True)
                if session.outstanding_ping is None and now >= next_ping_at:
                    n = session.next_ping
                    session.next_ping += 1
                    payload = await _maybe_await(self._heartbeat_factory(n))
                    if not isinstance(payload, str):
                        raise TypeError("heartbeat_factory must produce a text record")
                    # The pong deadline starts only once the one writer has
                    # accepted this ping for carrier delivery.
                    await self.send(payload, control=True, generation=session.generation, wait_written=True)
                    if not await self.is_current(session.generation, session.transport):
                        return
                    session.outstanding_ping = (n, loop.time() + self._pong_timeout)
                    next_ping_at = loop.time() + self._heartbeat_interval
        except asyncio.CancelledError:
            raise
        except BaseException as exc:
            await self.fail_current(exc, transient=True, generation=session.generation, transport=session.transport)

    async def _reset_reconnect_counter(self, session: TransportSession) -> None:
        try:
            await asyncio.sleep(self._reconnect.reset_after_active)
            if await self.is_current(session.generation, session.transport) and self._state is ConnectionState.ACTIVE:
                self._reconnect_attempt = 0
        except asyncio.CancelledError:
            return

    async def _cancel_session_tasks(self, session: TransportSession) -> None:
        current = asyncio.current_task()
        tasks = [session.reader_task, session.writer_task, session.heartbeat_task]
        for task in tasks:
            if task is not None and task is not current and not task.done():
                task.cancel()
        for task in tasks:
            if task is not None and task is not current:
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task

    @staticmethod
    def _finish_queued(session: TransportSession, error: BaseException) -> None:
        current = session.current_outbound
        if current is not None and not current.written.done():
            current.written.set_exception(error)
        for queue in (session.control_queue, session.application_queue):
            while True:
                try:
                    item = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                if not item.written.done():
                    item.written.set_exception(error)

    @staticmethod
    def _finish_inbound(session: TransportSession, error: BaseException) -> None:
        # Once a generation is fenced, buffered raw records must not be
        # mistaken for records on its replacement. Wake a caller waiting in
        # next_record() with the same safe terminal error.
        while True:
            try:
                session.inbound_queue.get_nowait()
            except asyncio.QueueEmpty:
                break
        with contextlib.suppress(asyncio.QueueFull):
            session.inbound_queue.put_nowait(error)

    @staticmethod
    def _is_transient_carrier_failure(error: BaseException) -> bool:
        # Parser, identity, and protocol callers must explicitly use
        # fail_current(..., transient=False). Binary frames and malformed text
        # may be detected at the carrier boundary, however, so classify those
        # closed protocol failures here too rather than reconnecting a hostile
        # session indefinitely. A raw carrier close/write failure is safely
        # reconnectable for future work.
        if isinstance(error, (AuthenticationError, SecureProfileUnsupportedError, ParseError, ProtocolError)):
            return False
        if isinstance(error, TransportError) and error.code in {
            "MALFORMED_FRAME",
            "FRAME_TOO_LARGE",
            "SUBPROTOCOL_MISMATCH",
            "SECURITY_PROFILE_MISMATCH",
        }:
            return False
        return True

    @staticmethod
    def _as_transport_error(error: BaseException, code: str) -> TransportError:
        if isinstance(error, TransportError):
            return error
        return TransportError(code, "Transport operation failed", retryable=True)

    async def _emit_state(self, state: ConnectionState, generation: int) -> None:
        if self._on_state is None:
            return
        with contextlib.suppress(Exception):
            await _maybe_await(self._on_state(state, generation))


# Names used by applications that prefer a manager/session vocabulary.
TransportManager = ConnectionSupervisor
TransportState = ConnectionState


__all__ = [
    "ConnectionState",
    "ConnectionSupervisor",
    "InMemoryTransport",
    "MAX_FRAME_BYTES",
    "MemoryWireTransport",
    "POLYMESH_PATH",
    "PROTOCOL_SUBPROTOCOL",
    "ReconnectSettings",
    "SecureTransportFactory",
    "SecureWireTransport",
    "TransportManager",
    "TransportSession",
    "TransportState",
    "ValidatedEndpoint",
    "WebSocketConnector",
    "WebSocketTransport",
    "WireTransport",
    "is_numeric_loopback_host",
    "normalize_broker_url",
    "open_websocket_transport",
    "safe_close_reason",
    "valid_close_code",
    "validate_broker_url",
    "websocket_connector",
]

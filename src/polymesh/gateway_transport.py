"""PolyMesh v5 Gateway Transport — async API-key → JWT → WSS relay client.

Additive to broker loopback / WSS modes. Wire messages follow the gateway
relay contract; local envelope bridging is best-effort via ``create_envelope``.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import logging
import math
import random
import re
from collections.abc import Awaitable, Callable, Mapping, MutableMapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, TypedDict
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

from .errors import MalformedJsonError, ResourceExhaustedError
from .protocol import create_envelope, parse_strict_json, uuidv7
from .types import base64url_encode, format_timestamp

logger = logging.getLogger(__name__)

JsonValue = Any
JsonObject = dict[str, JsonValue]

# PolyMesh AgentIdentity.instance_id must be 16-byte base64url; SPEC's literal
# ``"gateway"`` is not valid on the Python wire model, so bridge envelopes use
# a fixed sentinel derived from ``b"polymesh.gateway"``.
_GATEWAY_INSTANCE_ID = base64url_encode(b"polymesh.gateway")

INVITE_CODE_RE = re.compile(r"^[A-Z0-9][A-Z0-9-]{2,63}$")
AGENT_ID_SAFE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9._-]*$")
KNOWN_ERROR_CODES = frozenset(
    {
        "API_KEY_REQUIRED",
        "GATEWAY_URL_REQUIRED",
        "INVALID_GATEWAY_URL",
        "AUTH_FAILED",
        "AUTH_INVALID_KEY",
        "AUTH_REVOKED",
        "AUTH_EXPIRED",
        "TOKEN_REFRESH_FAILED",
        "WS_CONNECT_FAILED",
        "WS_CONNECT_TIMEOUT",
        "WS_ERROR",
        "NOT_CONNECTED",
        "NOT_IN_MESH",
        "MESH_ID_REQUIRED",
        "MESH_NOT_FOUND",
        "INVITE_INVALID",
        "JOIN_FAILED",
        "JOIN_TIMEOUT",
        "JOIN_SUPERSEDED",
        "DISCOVERY_FAILED",
        "DISCOVERY_SUPERSEDED",
        "DISCOVERY_TIMEOUT",
        "INVALID_TASK",
        "DUPLICATE_TASK_ID",
        "INVALID_CAPABILITY",
        "MALFORMED_FRAME",
        "PROTOCOL_UNKNOWN_TYPE",
        "SEND_FAILED",
        "TRANSPORT_CLOSED",
        "RECONNECT_EXHAUSTED",
        "TIMEOUT",
        "DNS_FAILURE",
        "CONNECTION_REFUSED",
        "NETWORK_TIMEOUT",
        "HTTPX_REQUIRED",
        "GATEWAY_MODE_REQUIRED",
        "GATEWAY_MODE_ACTIVE",
    }
)


class GatewayCapability(TypedDict, total=False):
    name: str
    schema: JsonObject
    scope: str
    security: str


class GatewayAgentInfo(TypedDict, total=False):
    id: str
    display_name: str
    capabilities: list[GatewayCapability] | list[JsonValue]
    last_seen: str | None
    metadata: JsonObject


class GatewayTokenResponse(TypedDict):
    token: str
    expires_at: str


class GatewayJoinMeshOptions(TypedDict, total=False):
    invite_code: str
    capabilities: list[GatewayCapability]
    display_name: str


class GatewayDiscoverQuery(TypedDict, total=False):
    capability: str
    name: str
    agent_id: str
    metadata: Mapping[str, str | int | float | bool]
    page: int
    limit: int


class GatewayDiscoverResult(TypedDict):
    agents: list[GatewayAgentInfo]
    page: int
    limit: int
    total: int
    has_more: bool


class GatewayMeshJoined(TypedDict, total=False):
    mesh_id: str
    members: list[GatewayAgentInfo]
    agent_id: str


class GatewayReconnectOptions(TypedDict, total=False):
    enabled: bool
    initial_delay_ms: int
    max_delay_ms: int
    multiplier: float
    jitter: float
    max_attempts: int


_DEFAULT_RECONNECT: GatewayReconnectOptions = {
    "enabled": True,
    "initial_delay_ms": 500,
    "max_delay_ms": 30_000,
    "multiplier": 2.0,
    "jitter": 0.2,
    "max_attempts": 10,
}


class GatewayTransportError(Exception):
    """Structured failure for gateway REST / WebSocket operations."""

    def __init__(
        self,
        code: str,
        message: str | None = None,
        *,
        retryable: bool = False,
        status: int | None = None,
        cause: BaseException | None = None,
    ) -> None:
        self.code = code
        self.retryable = bool(retryable)
        self.status = status
        self.__cause__ = cause
        super().__init__(message or code)

    @property
    def cause(self) -> BaseException | None:
        return self.__cause__


def gateway_http_base(gateway_url: str) -> str:
    """Convert a gateway WSS/HTTPS URL into the REST HTTP(S) origin + path."""

    try:
        parsed = urlsplit(gateway_url)
    except Exception as exc:
        raise GatewayTransportError("INVALID_GATEWAY_URL", "gateway_url must be a valid URL") from exc
    scheme = parsed.scheme.lower()
    if scheme == "wss":
        scheme = "https"
    elif scheme == "ws":
        scheme = "http"
    elif scheme not in {"https", "http"}:
        raise GatewayTransportError("INVALID_GATEWAY_URL", "gateway_url must use ws(s) or http(s)")
    path = parsed.path or "/"
    if path == "/api/v1/ws" or path.endswith("/api/v1/ws"):
        path = re.sub(r"/?api/v1/ws$", "", path) or "/"
    path = path.rstrip("/") if path != "/" else "/"
    base = urlunsplit((scheme, parsed.netloc, path if path != "/" else "", "", ""))
    if path == "/":
        # origin only — no trailing slash
        return f"{scheme}://{parsed.netloc}"
    return base.rstrip("/")


def gateway_ws_url(gateway_url: str, token: str, mesh_id: str | None = None) -> str:
    """Build the authenticated gateway WebSocket endpoint URL."""

    try:
        parsed = urlsplit(gateway_url)
    except Exception as exc:
        raise GatewayTransportError("INVALID_GATEWAY_URL", "gateway_url must be a valid URL") from exc
    scheme = parsed.scheme.lower()
    if scheme == "https":
        scheme = "wss"
    elif scheme == "http":
        scheme = "ws"
    elif scheme not in {"wss", "ws"}:
        raise GatewayTransportError("INVALID_GATEWAY_URL", "gateway_url must use ws(s) or http(s)")
    path = parsed.path or "/"
    if not path or path == "/":
        path = "/api/v1/ws"
    elif not path.endswith("/api/v1/ws"):
        path = f"{path.rstrip('/')}/api/v1/ws"
    query_items: list[tuple[str, str]] = [("token", token)]
    if mesh_id:
        query_items.append(("mesh", mesh_id))
    return urlunsplit((scheme, parsed.netloc, path, urlencode(query_items), ""))


def _is_record(value: object) -> bool:
    return isinstance(value, dict)


def _sanitize_agent_id(value: str) -> str:
    if AGENT_ID_SAFE_RE.fullmatch(value):
        return value
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", ".", value).strip(".")
    return f"agent.{cleaned or 'unknown'}"


def _decode_jwt_sub(token: str) -> str | None:
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        payload = json.loads(raw.decode("utf-8"))
        sub = payload.get("sub") if isinstance(payload, dict) else None
        return sub if isinstance(sub, str) else None
    except Exception:
        return None


def _parse_expires_at(value: str) -> datetime | None:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _backoff_delay_ms(
    attempt: int,
    *,
    initial_delay_ms: float,
    max_delay_ms: float,
    multiplier: float,
    jitter: float,
) -> float:
    """Exponential backoff with full jitter (§2.14). ``attempt`` is 1-based."""

    base = min(initial_delay_ms * (multiplier ** max(attempt - 1, 0)), max_delay_ms)
    return base * (1.0 - jitter + 2.0 * jitter * random.random())


def _normalize_discover_result(payload: Mapping[str, Any] | Sequence[Any]) -> GatewayDiscoverResult:
    if isinstance(payload, Sequence) and not isinstance(payload, (str, bytes, bytearray)):
        agents = list(payload)  # type: ignore[arg-type]
        count = len(agents)
        return {
            "agents": agents,  # type: ignore[typeddict-item]
            "page": 1,
            "limit": count,
            "total": count,
            "has_more": False,
        }
    agents_raw = payload.get("agents") if isinstance(payload, Mapping) else None
    agents: list[GatewayAgentInfo] = list(agents_raw) if isinstance(agents_raw, list) else []
    page = int(payload["page"]) if isinstance(payload.get("page"), int) else 1
    limit = int(payload["limit"]) if isinstance(payload.get("limit"), int) else len(agents)
    total = int(payload["total"]) if isinstance(payload.get("total"), int) else len(agents)
    has_more = bool(payload["has_more"]) if isinstance(payload.get("has_more"), bool) else False
    if "page" not in payload and "limit" not in payload and "total" not in payload:
        page, limit, total, has_more = 1, len(agents), len(agents), False
    return {
        "agents": agents,
        "page": page,
        "limit": limit,
        "total": total,
        "has_more": has_more,
    }


def _text_from_frame(raw: object) -> str:
    if isinstance(raw, str):
        return raw
    if isinstance(raw, (bytes, bytearray, memoryview)):
        return bytes(raw).decode("utf-8")
    raise GatewayTransportError("MALFORMED_FRAME", "Gateway WebSocket frame is not text")


def _map_network_error(exc: BaseException) -> GatewayTransportError:
    name = type(exc).__name__
    message = str(exc) or name
    lowered = message.lower()
    if "name or service not known" in lowered or "getaddrinfo" in lowered or "nodename" in lowered:
        return GatewayTransportError("DNS_FAILURE", message, retryable=True, cause=exc)
    if "connection refused" in lowered or "connect call failed" in lowered:
        return GatewayTransportError("CONNECTION_REFUSED", message, retryable=True, cause=exc)
    if "timeout" in lowered or name.endswith("Timeout"):
        return GatewayTransportError("NETWORK_TIMEOUT", message, retryable=True, cause=exc)
    return GatewayTransportError("WS_CONNECT_FAILED", message, retryable=True, cause=exc)


class GatewayTransport:
    """Standalone gateway relay transport (async)."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        gateway_url: str | None = None,
        agent_id: str | None = None,
        mesh_id: str | None = None,
        request_timeout_ms: float = 15_000,
        token_refresh_skew_ms: float = 300_000,
        reconnect: GatewayReconnectOptions | None = None,
        http_client: Any | None = None,
        ws_connect: Callable[[str], Awaitable[Any]] | None = None,
        event_handlers: MutableMapping[str, list[Callable[..., Any]]] | None = None,
    ) -> None:
        if not math.isfinite(request_timeout_ms) or request_timeout_ms <= 0:
            raise ValueError("request_timeout_ms must be a positive finite number")
        if not math.isfinite(token_refresh_skew_ms) or token_refresh_skew_ms < 0:
            raise ValueError("token_refresh_skew_ms must be a non-negative finite number")

        self._api_key = api_key
        self._gateway_url = gateway_url
        self._agent_id = agent_id
        self._mesh_id = mesh_id
        self._token: str | None = None
        self._token_expires_at: str | None = None
        self._request_timeout_ms = float(request_timeout_ms)
        self._token_refresh_skew_ms = float(token_refresh_skew_ms)
        merged = dict(_DEFAULT_RECONNECT)
        if reconnect:
            merged.update(reconnect)
        self._reconnect = merged
        self._http_client = http_client
        self._owns_http_client = http_client is None
        self._ws_connect = ws_connect
        self._handlers: dict[str, list[Callable[..., Any]]] = {}
        if event_handlers:
            for name, handlers in event_handlers.items():
                self._handlers[name] = list(handlers)

        self._ws: Any | None = None
        self._bound = False
        self._closed = False
        self._receiver_task: asyncio.Task[None] | None = None
        self._refresh_task: asyncio.Task[None] | None = None
        self._reconnect_task: asyncio.Task[None] | None = None
        self._event_bridge: Callable[[str, Any], None] | None = None

        self._pending_join: dict[str, Any] | None = None
        self._pending_discovery: dict[str, Any] | None = None
        self._join_capabilities: Sequence[GatewayCapability] | None = None
        self._join_display_name: str | None = None
        self._malformed_window: list[float] = []

    # -- properties ---------------------------------------------------------

    @property
    def connected(self) -> bool:
        if self._ws is None or self._closed:
            return False
        if self._bound:
            closed = getattr(self._ws, "closed", False)
            if closed:
                return False
            state = getattr(self._ws, "state", None)
            if getattr(state, "name", "").upper() == "CLOSED":
                return False
            return True
        return False

    @property
    def current_mesh_id(self) -> str | None:
        return self._mesh_id

    @property
    def current_token(self) -> str | None:
        return self._token

    @property
    def current_agent_id(self) -> str | None:
        return self._agent_id

    @property
    def current_gateway_url(self) -> str | None:
        return self._gateway_url

    @property
    def token_expires_at(self) -> str | None:
        return self._token_expires_at

    # -- events -------------------------------------------------------------

    def on(self, event: str, handler: Callable[..., Any]) -> Callable[[], None]:
        if not callable(handler):
            raise TypeError("handler must be callable")
        bucket = self._handlers.setdefault(event, [])
        bucket.append(handler)

        def unsubscribe() -> None:
            self.off(event, handler)

        return unsubscribe

    def off(self, event: str, handler: Callable[..., Any] | None = None) -> None:
        if handler is None:
            self._handlers.pop(event, None)
            return
        bucket = self._handlers.get(event)
        if not bucket:
            return
        with contextlib.suppress(ValueError):
            bucket.remove(handler)
        if not bucket:
            self._handlers.pop(event, None)

    def _emit(self, event: str, payload: Any = None) -> None:
        handlers = list(self._handlers.get(event, ()))
        for handler in handlers:
            try:
                outcome = handler(payload)
                if asyncio.iscoroutine(outcome) or asyncio.isfuture(outcome):
                    try:
                        loop = asyncio.get_running_loop()
                    except RuntimeError:
                        pass
                    else:
                        loop.create_task(outcome)  # type: ignore[arg-type]
            except Exception as exc:
                logger.exception("gateway event handler failed for %s", event)
                if event != "error":
                    with contextlib.suppress(Exception):
                        self._emit(
                            "error",
                            GatewayTransportError("WS_ERROR", f"event handler failed: {exc}", retryable=False, cause=exc),
                        )
        if self._event_bridge is not None:
            with contextlib.suppress(Exception):
                self._event_bridge(event, payload)

    # -- httpx --------------------------------------------------------------

    def _require_httpx(self) -> Any:
        try:
            import httpx
        except ImportError as exc:
            raise GatewayTransportError(
                "HTTPX_REQUIRED",
                "httpx is required for gateway REST; pip install 'latticeag-polymesh[gateway]'",
                retryable=False,
                cause=exc,
            ) from exc
        return httpx

    async def _get_http_client(self) -> Any:
        if self._http_client is not None:
            return self._http_client
        httpx = self._require_httpx()
        timeout_s = self._request_timeout_ms / 1000.0
        self._http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_s),
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )
        self._owns_http_client = True
        return self._http_client

    async def _aclose_owned_http(self) -> None:
        if self._owns_http_client and self._http_client is not None:
            client, self._http_client = self._http_client, None
            with contextlib.suppress(Exception):
                await client.aclose()

    # -- websocket connect helper -------------------------------------------

    async def _default_ws_connect(self, url: str) -> Any:
        try:
            from websockets.asyncio.client import connect as websocket_connect
        except ImportError:
            try:
                from websockets.client import connect as websocket_connect  # type: ignore[no-redef]
            except ImportError as exc:
                raise GatewayTransportError(
                    "WS_CONNECT_FAILED",
                    "websockets is not installed",
                    retryable=False,
                    cause=exc,
                ) from exc
        open_timeout = self._request_timeout_ms / 1000.0
        try:
            return await asyncio.wait_for(websocket_connect(url), timeout=open_timeout)
        except asyncio.TimeoutError as exc:
            raise GatewayTransportError(
                "WS_CONNECT_TIMEOUT",
                "Timed out opening gateway WebSocket",
                retryable=True,
                cause=exc,
            ) from exc
        except GatewayTransportError:
            raise
        except Exception as exc:
            raise _map_network_error(exc) from exc

    async def _open_socket(self, url: str) -> None:
        await self._close_socket(1000, "reconnect", disable_reconnect=False, emit_close=False)
        self._closed = False
        connector = self._ws_connect or self._default_ws_connect
        try:
            socket = await connector(url)
        except GatewayTransportError:
            raise
        except Exception as exc:
            mapped = _map_network_error(exc)
            if "timeout" in str(exc).lower():
                raise GatewayTransportError(
                    "WS_CONNECT_TIMEOUT",
                    "Timed out opening gateway WebSocket",
                    retryable=True,
                    cause=exc,
                ) from exc
            raise mapped from exc
        self._ws = socket
        self._bound = True
        self._receiver_task = asyncio.create_task(self._receiver_loop(), name="polymesh-gateway-receiver")

    async def _receiver_loop(self) -> None:
        socket = self._ws
        if socket is None:
            return
        try:
            while not self._closed and self._ws is socket:
                try:
                    raw = await socket.recv()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    if self._closed:
                        return
                    self._bound = False
                    self._ws = None
                    self._reject_pending(
                        GatewayTransportError("TRANSPORT_CLOSED", f"Gateway WebSocket closed: {exc}", retryable=True, cause=exc)
                    )
                    self._emit("close", {"code": 0, "reason": str(exc)})
                    if not self._closed and self._reconnect.get("enabled", True):
                        await self._start_reconnect()
                    return
                try:
                    self.handle_message(raw)
                except Exception as exc:
                    self._emit("error", exc if isinstance(exc, GatewayTransportError) else GatewayTransportError("WS_ERROR", str(exc), retryable=True, cause=exc))
        except asyncio.CancelledError:
            return

    async def _close_socket(
        self,
        code: int = 1000,
        reason: str = "close",
        *,
        disable_reconnect: bool = True,
        emit_close: bool = True,
    ) -> None:
        if disable_reconnect:
            self._closed = True
        socket, self._ws = self._ws, None
        self._bound = False
        task, self._receiver_task = self._receiver_task, None
        if task is not None and task is not asyncio.current_task():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        self._reject_pending(GatewayTransportError("TRANSPORT_CLOSED", reason, retryable=True))
        if socket is not None:
            with contextlib.suppress(Exception):
                close = getattr(socket, "close", None)
                if close is not None:
                    result = close(code, reason)
                    if asyncio.iscoroutine(result) or asyncio.isfuture(result):
                        await asyncio.wait_for(result, timeout=1.0)
        if emit_close:
            self._emit("close", {"code": code, "reason": reason})

    def _reject_pending(self, error: Exception) -> None:
        if self._pending_join is not None:
            pending = self._pending_join
            self._pending_join = None
            future: asyncio.Future[GatewayMeshJoined] = pending["future"]
            if not future.done():
                future.set_exception(error)
        if self._pending_discovery is not None:
            pending = self._pending_discovery
            self._pending_discovery = None
            future_d: asyncio.Future[GatewayDiscoverResult] = pending["future"]
            if not future_d.done():
                future_d.set_exception(error)

    async def _send_wire(self, message: Mapping[str, Any]) -> None:
        socket = self._ws
        if socket is None or not self.connected:
            raise GatewayTransportError("NOT_CONNECTED", "No active gateway WebSocket")
        payload = json.dumps(message, separators=(",", ":"), ensure_ascii=False)
        try:
            result = socket.send(payload)
            if asyncio.iscoroutine(result) or asyncio.isfuture(result):
                await result
        except GatewayTransportError:
            raise
        except Exception as exc:
            raise GatewayTransportError("SEND_FAILED", str(exc) or "socket.send failed", retryable=True, cause=exc) from exc

    # -- token refresh timer ------------------------------------------------

    def _cancel_refresh_task(self) -> None:
        task, self._refresh_task = self._refresh_task, None
        if task is not None and not task.done():
            task.cancel()

    def _schedule_token_refresh(self) -> None:
        self._cancel_refresh_task()
        if not self._token_expires_at:
            return
        expires = _parse_expires_at(self._token_expires_at)
        if expires is None:
            return

        async def _run() -> None:
            try:
                now = datetime.now(UTC)
                target = expires - timedelta(milliseconds=self._token_refresh_skew_ms)
                delay = max((target - now).total_seconds(), 1.0)
                await asyncio.sleep(delay)
                if self._closed:
                    return
                self._emit("token.expiring", {"expires_at": self._token_expires_at})
                await self.refresh_token()
            except asyncio.CancelledError:
                return
            except Exception as exc:
                self._emit("error", exc if isinstance(exc, GatewayTransportError) else GatewayTransportError("TOKEN_REFRESH_FAILED", str(exc), retryable=True, cause=exc))

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._refresh_task = loop.create_task(_run(), name="polymesh-gateway-token-refresh")

    # -- auth / REST --------------------------------------------------------

    async def _exchange_token(self, api_key: str, gateway_url: str) -> GatewayTokenResponse:
        client = await self._get_http_client()
        base = gateway_http_base(gateway_url)
        url = f"{base}/api/v1/auth/token"
        try:
            response = await client.post(
                url,
                json={"api_key": api_key},
                headers={"content-type": "application/json", "accept": "application/json"},
            )
        except Exception as exc:
            raise _map_network_error(exc) from exc

        status = int(response.status_code)
        if status == 401:
            raise GatewayTransportError("AUTH_INVALID_KEY", "Gateway rejected API key", retryable=False, status=401)
        if status == 403:
            raise GatewayTransportError("AUTH_REVOKED", "Gateway access revoked", retryable=False, status=403)
        if status < 200 or status >= 300:
            body = ""
            with contextlib.suppress(Exception):
                body = (await response.aread()).decode("utf-8", "replace")[:200]
            raise GatewayTransportError(
                "AUTH_FAILED",
                f"Gateway token exchange failed ({status})" + (f": {body}" if body else ""),
                retryable=status >= 500,
                status=status,
            )
        try:
            json_body = response.json()
        except Exception as exc:
            raise GatewayTransportError("AUTH_FAILED", "Gateway token response is not JSON", retryable=False, status=status, cause=exc) from exc
        if not _is_record(json_body) or not isinstance(json_body.get("token"), str) or not isinstance(json_body.get("expires_at"), str):
            raise GatewayTransportError("AUTH_FAILED", "Gateway token response is missing token/expires_at", retryable=False, status=status)
        return {"token": json_body["token"], "expires_at": json_body["expires_at"]}

    async def _rest_join_mesh(self, mesh_id: str, invite_code: str) -> None:
        if not self._gateway_url or not self._agent_id:
            return
        client = await self._get_http_client()
        base = gateway_http_base(self._gateway_url)
        url = f"{base}/api/v1/meshes/{quote(mesh_id, safe='')}/join"
        headers = {"content-type": "application/json", "accept": "application/json"}
        if self._token:
            headers["authorization"] = f"Bearer {self._token}"
        try:
            response = await client.post(
                url,
                json={"agent_id": self._agent_id, "invite_code": invite_code},
                headers=headers,
            )
        except Exception as exc:
            raise _map_network_error(exc) from exc
        status = int(response.status_code)
        if status == 409 or 200 <= status < 300:
            return
        body_text = ""
        body_json: Any = None
        with contextlib.suppress(Exception):
            body_text = (await response.aread()).decode("utf-8", "replace")[:200]
            body_json = json.loads(body_text) if body_text else None
        code_from_body = body_json.get("code") if isinstance(body_json, dict) else None
        if status == 404:
            raise GatewayTransportError("MESH_NOT_FOUND", "Mesh not found", retryable=False, status=404)
        if status == 401:
            raise GatewayTransportError("AUTH_EXPIRED", "Authentication expired during mesh join", retryable=True, status=401)
        if status == 403:
            if isinstance(code_from_body, str) and code_from_body.upper() in {"INVITE_INVALID", "INVITE_EXPIRED", "INVITE_EXHAUSTED"}:
                raise GatewayTransportError("INVITE_INVALID", body_text or "Invite invalid", retryable=False, status=403)
            if isinstance(code_from_body, str) and "INVITE" in code_from_body.upper():
                raise GatewayTransportError("INVITE_INVALID", body_text or "Invite invalid", retryable=False, status=403)
            raise GatewayTransportError("AUTH_REVOKED", body_text or "Join forbidden", retryable=False, status=403)
        raise GatewayTransportError(
            "JOIN_FAILED",
            f"REST mesh join failed ({status})" + (f": {body_text}" if body_text else ""),
            retryable=status >= 500,
            status=status,
        )

    async def _rest_discover_agents(self, mesh_id: str, query: GatewayDiscoverQuery) -> GatewayDiscoverResult:
        if not self._gateway_url:
            raise GatewayTransportError("GATEWAY_URL_REQUIRED", "gateway_url is required for discovery")
        client = await self._get_http_client()
        base = gateway_http_base(self._gateway_url)
        params: list[tuple[str, str]] = []
        if "capability" in query and query["capability"] is not None:
            params.append(("capability", str(query["capability"])))
        if "name" in query and query["name"] is not None:
            params.append(("name", str(query["name"])))
        if "agent_id" in query and query["agent_id"] is not None:
            params.append(("agent_id", str(query["agent_id"])))
        if "page" in query and query["page"] is not None:
            params.append(("page", str(query["page"])))
        if "limit" in query and query["limit"] is not None:
            params.append(("limit", str(query["limit"])))
        metadata = query.get("metadata")
        if isinstance(metadata, Mapping):
            for key, value in metadata.items():
                params.append((f"meta.{key}", str(value)))
        qs = f"?{urlencode(params)}" if params else ""
        url = f"{base}/api/v1/meshes/{quote(mesh_id, safe='')}/agents{qs}"
        headers = {"accept": "application/json"}
        if self._token:
            headers["authorization"] = f"Bearer {self._token}"
        try:
            response = await client.get(url, headers=headers)
        except Exception as exc:
            raise _map_network_error(exc) from exc
        status = int(response.status_code)
        if status < 200 or status >= 300:
            body = ""
            with contextlib.suppress(Exception):
                body = (await response.aread()).decode("utf-8", "replace")[:200]
            raise GatewayTransportError(
                "DISCOVERY_FAILED",
                f"REST discovery failed ({status})" + (f": {body}" if body else ""),
                retryable=status >= 500,
                status=status,
            )
        try:
            json_body = response.json()
        except Exception as exc:
            raise GatewayTransportError("DISCOVERY_FAILED", "Discovery response is not JSON", retryable=False, status=status, cause=exc) from exc
        if isinstance(json_body, list):
            return _normalize_discover_result(json_body)
        if not _is_record(json_body) or not isinstance(json_body.get("agents"), list):
            raise GatewayTransportError("DISCOVERY_FAILED", "Discovery response is missing agents[]", retryable=False, status=status)
        return _normalize_discover_result(json_body)

    # -- reconnect ----------------------------------------------------------

    async def _start_reconnect(self) -> None:
        if self._reconnect_task is not None and not self._reconnect_task.done():
            return
        if not self._reconnect.get("enabled", True) or self._closed:
            return
        self._reconnect_task = asyncio.create_task(self._reconnect_loop(), name="polymesh-gateway-reconnect")

    async def _reconnect_loop(self) -> None:
        max_attempts = int(self._reconnect.get("max_attempts", 10))
        initial = float(self._reconnect.get("initial_delay_ms", 500))
        max_delay = float(self._reconnect.get("max_delay_ms", 30_000))
        multiplier = float(self._reconnect.get("multiplier", 2))
        jitter = float(self._reconnect.get("jitter", 0.2))
        last_mesh = self._mesh_id
        for attempt in range(1, max_attempts + 1):
            if self._closed:
                return
            delay_ms = _backoff_delay_ms(
                attempt,
                initial_delay_ms=initial,
                max_delay_ms=max_delay,
                multiplier=multiplier,
                jitter=jitter,
            )
            self._emit("reconnecting", {"attempt": attempt, "delayMs": delay_ms, "delay_ms": delay_ms})
            await asyncio.sleep(delay_ms / 1000.0)
            if self._closed:
                return
            try:
                if self._api_key and self._gateway_url:
                    needs_refresh = True
                    if self._token_expires_at:
                        expires = _parse_expires_at(self._token_expires_at)
                        if expires is not None:
                            skew = timedelta(milliseconds=self._token_refresh_skew_ms)
                            needs_refresh = datetime.now(UTC) >= (expires - skew)
                    if needs_refresh or not self._token:
                        auth = await self._exchange_token(self._api_key, self._gateway_url)
                        self._token = auth["token"]
                        self._token_expires_at = auth["expires_at"]
                        sub = _decode_jwt_sub(auth["token"])
                        if sub:
                            self._agent_id = sub
                        self._schedule_token_refresh()
                if not self._token or not self._gateway_url:
                    raise GatewayTransportError("NOT_CONNECTED", "Cannot reconnect without credentials")
                await self._open_socket(gateway_ws_url(self._gateway_url, self._token, last_mesh))
                if last_mesh:
                    self._mesh_id = last_mesh
                    with contextlib.suppress(Exception):
                        await self._send_wire(
                            {
                                "type": "mesh.join",
                                "mesh_id": last_mesh,
                                **({"capabilities": list(self._join_capabilities)} if self._join_capabilities is not None else {}),
                                **({"display_name": self._join_display_name} if self._join_display_name is not None else {}),
                                **({"agent_id": self._agent_id} if self._agent_id is not None else {}),
                            }
                        )
                self._emit("reconnected", {"mesh_id": self._mesh_id, "agent_id": self._agent_id})
                return
            except GatewayTransportError as exc:
                if not exc.retryable:
                    self._emit("error", exc)
                    self._closed = True
                    self._emit("close", {"code": 0, "reason": exc.code})
                    return
                continue
            except Exception as exc:
                self._emit("error", _map_network_error(exc))
                continue
        error = GatewayTransportError("RECONNECT_EXHAUSTED", "Max reconnect attempts exceeded", retryable=False)
        self._emit("error", error)
        self._closed = True
        self._emit("close", {"code": 0, "reason": "RECONNECT_EXHAUSTED"})

    async def _connect_with_retries(self, api_key: str, gateway_url: str) -> None:
        max_attempts = int(self._reconnect.get("max_attempts", 10))
        initial = float(self._reconnect.get("initial_delay_ms", 500))
        max_delay = float(self._reconnect.get("max_delay_ms", 30_000))
        multiplier = float(self._reconnect.get("multiplier", 2))
        jitter = float(self._reconnect.get("jitter", 0.2))
        last_error: Exception | None = None
        for attempt in range(1, max_attempts + 1):
            try:
                auth = await self._exchange_token(api_key, gateway_url)
                self._token = auth["token"]
                self._token_expires_at = auth["expires_at"]
                sub = _decode_jwt_sub(auth["token"])
                if sub:
                    self._agent_id = sub
                self._schedule_token_refresh()
                await self._open_socket(gateway_ws_url(gateway_url, auth["token"], self._mesh_id))
                return
            except GatewayTransportError as exc:
                last_error = exc
                if not exc.retryable or attempt >= max_attempts:
                    if attempt >= max_attempts and exc.retryable:
                        raise GatewayTransportError("RECONNECT_EXHAUSTED", "Max connect attempts exceeded", retryable=False, cause=exc) from exc
                    raise
                delay_ms = _backoff_delay_ms(
                    attempt,
                    initial_delay_ms=initial,
                    max_delay_ms=max_delay,
                    multiplier=multiplier,
                    jitter=jitter,
                )
                self._emit("reconnecting", {"attempt": attempt, "delayMs": delay_ms, "delay_ms": delay_ms})
                await asyncio.sleep(delay_ms / 1000.0)
            except Exception as exc:
                last_error = _map_network_error(exc)
                if attempt >= max_attempts:
                    raise GatewayTransportError("RECONNECT_EXHAUSTED", "Max connect attempts exceeded", retryable=False, cause=last_error) from exc
                delay_ms = _backoff_delay_ms(
                    attempt,
                    initial_delay_ms=initial,
                    max_delay_ms=max_delay,
                    multiplier=multiplier,
                    jitter=jitter,
                )
                self._emit("reconnecting", {"attempt": attempt, "delayMs": delay_ms, "delay_ms": delay_ms})
                await asyncio.sleep(delay_ms / 1000.0)
        if last_error is not None:
            raise last_error
        raise GatewayTransportError("RECONNECT_EXHAUSTED", "Max connect attempts exceeded", retryable=False)

    # -- public API ---------------------------------------------------------

    async def connect_gateway(
        self,
        api_key: str | None = None,
        gateway_url: str | None = None,
    ) -> GatewayTransport:
        key = api_key if api_key is not None else self._api_key
        url = gateway_url if gateway_url is not None else self._gateway_url
        if not key:
            raise GatewayTransportError("API_KEY_REQUIRED", "An API key is required to connect to the gateway")
        if not url:
            raise GatewayTransportError("GATEWAY_URL_REQUIRED", "A gateway_url is required")
        self._api_key = key
        self._gateway_url = url
        self._closed = False
        if self._reconnect_task is not None and not self._reconnect_task.done():
            self._reconnect_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._reconnect_task
            self._reconnect_task = None
        await self._connect_with_retries(key, url)
        self._emit(
            "connected",
            {"token": self._token, "expires_at": self._token_expires_at, "agent_id": self._agent_id},
        )
        return self

    async def join_mesh(
        self,
        mesh_id: str,
        *,
        invite_code: str | None = None,
        capabilities: Sequence[GatewayCapability] | None = None,
        display_name: str | None = None,
    ) -> GatewayMeshJoined:
        if not mesh_id or not isinstance(mesh_id, str):
            raise GatewayTransportError("MESH_ID_REQUIRED", "mesh_id is required")
        if not self.connected or self._ws is None:
            raise GatewayTransportError("NOT_CONNECTED", "connect_gateway() must be called before join_mesh()")

        invite: str | None = None
        if invite_code is not None:
            invite = invite_code.strip().upper()
            if not INVITE_CODE_RE.fullmatch(invite):
                raise GatewayTransportError("INVITE_INVALID", "Invite code format is invalid", retryable=False)

        if invite and self._gateway_url and self._agent_id:
            await self._rest_join_mesh(mesh_id, invite)

        self._join_capabilities = capabilities
        self._join_display_name = display_name

        max_send_attempts = 3
        last_error: Exception | None = None
        for send_attempt in range(max_send_attempts):
            if self._pending_join is not None:
                previous = self._pending_join
                self._pending_join = None
                prev_future: asyncio.Future[GatewayMeshJoined] = previous["future"]
                if not prev_future.done():
                    prev_future.set_exception(
                        GatewayTransportError("JOIN_SUPERSEDED", "A newer join_mesh() replaced the pending join")
                    )

            loop = asyncio.get_running_loop()
            future: asyncio.Future[GatewayMeshJoined] = loop.create_future()
            self._pending_join = {"mesh_id": mesh_id, "future": future}
            self._mesh_id = mesh_id
            wire: dict[str, Any] = {"type": "mesh.join", "mesh_id": mesh_id}
            if invite is not None:
                wire["invite_code"] = invite
            if capabilities is not None:
                wire["capabilities"] = list(capabilities)
            if display_name is not None:
                wire["display_name"] = display_name
            if self._agent_id is not None:
                wire["agent_id"] = self._agent_id
            try:
                await self._send_wire(wire)
            except GatewayTransportError as exc:
                self._pending_join = None
                if not future.done():
                    future.cancel()
                raise

            try:
                return await asyncio.wait_for(future, timeout=self._request_timeout_ms / 1000.0)
            except asyncio.TimeoutError as exc:
                if self._pending_join is not None and self._pending_join.get("future") is future:
                    self._pending_join = None
                last_error = GatewayTransportError("JOIN_TIMEOUT", "Timed out waiting for mesh.joined", retryable=True, cause=exc)
                if send_attempt + 1 >= max_send_attempts:
                    raise last_error from exc
                delay_ms = min(1000 * (2**send_attempt), float(self._reconnect.get("max_delay_ms", 30_000)))
                await asyncio.sleep(delay_ms / 1000.0)
                continue
            except GatewayTransportError as exc:
                if not exc.retryable or exc.code in {"JOIN_SUPERSEDED", "INVITE_INVALID", "MESH_NOT_FOUND", "AUTH_REVOKED", "AUTH_INVALID_KEY"}:
                    raise
                last_error = exc
                if send_attempt + 1 >= max_send_attempts:
                    raise
                delay_ms = min(1000 * (2**send_attempt), float(self._reconnect.get("max_delay_ms", 30_000)))
                await asyncio.sleep(delay_ms / 1000.0)
                continue
        if last_error is not None:
            raise last_error
        raise GatewayTransportError("JOIN_FAILED", "join_mesh failed", retryable=True)

    async def discover_agents(
        self,
        query: GatewayDiscoverQuery | None = None,
        /,
        **filters: Any,
    ) -> GatewayDiscoverResult:
        if not self.connected or self._ws is None:
            raise GatewayTransportError("NOT_CONNECTED", "connect_gateway() must be called before discover_agents()")
        if not self._mesh_id:
            raise GatewayTransportError("NOT_IN_MESH", "join_mesh() must be called before discover_agents()")

        merged: dict[str, Any] = {}
        if query:
            merged.update(dict(query))
        merged.update(filters)
        discover_query: GatewayDiscoverQuery = merged  # type: ignore[assignment]
        mesh_id = self._mesh_id

        if self._pending_discovery is not None:
            previous = self._pending_discovery
            self._pending_discovery = None
            prev_future: asyncio.Future[GatewayDiscoverResult] = previous["future"]
            if not prev_future.done():
                prev_future.set_exception(
                    GatewayTransportError("DISCOVERY_SUPERSEDED", "A newer discover_agents() replaced the pending request")
                )

        loop = asyncio.get_running_loop()
        future: asyncio.Future[GatewayDiscoverResult] = loop.create_future()
        soft_ms = min(1_500.0, self._request_timeout_ms)
        self._pending_discovery = {"future": future}

        wire: dict[str, Any] = {"type": "discovery.request", "mesh_id": mesh_id}
        for key in ("capability", "name", "agent_id", "page", "limit"):
            if key in discover_query and discover_query[key] is not None:  # type: ignore[literal-required]
                wire[key] = discover_query[key]  # type: ignore[literal-required]
        metadata = discover_query.get("metadata")
        if metadata is not None:
            wire["metadata"] = dict(metadata)

        with contextlib.suppress(GatewayTransportError):
            await self._send_wire(wire)

        try:
            return await asyncio.wait_for(future, timeout=soft_ms / 1000.0)
        except asyncio.TimeoutError:
            if self._pending_discovery is not None and self._pending_discovery.get("future") is future:
                self._pending_discovery = None
            try:
                return await self._rest_discover_agents(mesh_id, discover_query)
            except GatewayTransportError as rest_error:
                if rest_error.code == "DISCOVERY_FAILED" and rest_error.retryable:
                    raise GatewayTransportError(
                        "DISCOVERY_TIMEOUT",
                        "Neither WS nor REST discovery answered",
                        retryable=True,
                        cause=rest_error,
                    ) from rest_error
                if rest_error.retryable or rest_error.code in {"DNS_FAILURE", "CONNECTION_REFUSED", "NETWORK_TIMEOUT"}:
                    raise GatewayTransportError(
                        "DISCOVERY_TIMEOUT",
                        "Neither WS nor REST discovery answered",
                        retryable=True,
                        cause=rest_error,
                    ) from rest_error
                raise

    async def leave_mesh(self) -> None:
        was_connected = self._ws is not None and self.connected
        mesh_id = self._mesh_id
        self._closed = True
        self._cancel_refresh_task()
        if self._reconnect_task is not None and not self._reconnect_task.done():
            self._reconnect_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._reconnect_task
            self._reconnect_task = None
        if was_connected and self._ws is not None:
            with contextlib.suppress(Exception):
                # Bypass connected check — we already flipped closed to stop reconnect.
                payload = json.dumps(
                    {"type": "mesh.leave", **({"mesh_id": mesh_id} if mesh_id is not None else {})},
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
                result = self._ws.send(payload)
                if asyncio.iscoroutine(result) or asyncio.isfuture(result):
                    await result
        self._mesh_id = None
        await self._close_socket(1000, "mesh.leave", disable_reconnect=True, emit_close=True)

    async def submit_task(
        self,
        target: str,
        capability: str,
        payload: JsonValue,
        *,
        task_id: str | None = None,
    ) -> str:
        if not self.connected:
            raise GatewayTransportError("NOT_CONNECTED", "connect_gateway() must be called before submit_task()")
        if not self._mesh_id:
            raise GatewayTransportError("NOT_IN_MESH", "join_mesh() must be called before submit_task()")
        if not target or not capability:
            raise GatewayTransportError("INVALID_TASK", "target and capability are required")
        chosen_task_id = task_id or uuidv7()
        wire: dict[str, Any] = {
            "type": "task.submit",
            "target": target,
            "capability": capability,
            "payload": payload,
            "task_id": chosen_task_id,
        }
        if self._agent_id:
            envelope = _gateway_outbound_submit_envelope(self._agent_id, target, capability, payload, chosen_task_id)
            if envelope is not None:
                self._emit("envelope", envelope)
        await self._send_wire(wire)
        return chosen_task_id

    async def refresh_token(self) -> GatewayTokenResponse:
        if not self._api_key or not self._gateway_url:
            raise GatewayTransportError("NOT_CONNECTED", "Cannot refresh token before connect_gateway()")
        try:
            auth = await self._exchange_token(self._api_key, self._gateway_url)
        except GatewayTransportError as exc:
            if exc.code == "AUTH_FAILED":
                raise GatewayTransportError(
                    "TOKEN_REFRESH_FAILED",
                    str(exc),
                    retryable=exc.retryable,
                    status=exc.status,
                    cause=exc,
                ) from exc
            raise
        self._token = auth["token"]
        self._token_expires_at = auth["expires_at"]
        sub = _decode_jwt_sub(auth["token"])
        if sub:
            self._agent_id = sub
        self._schedule_token_refresh()
        self._emit("token.refreshed", auth)
        return auth

    def handle_message(self, raw: str | bytes | bytearray | memoryview | object) -> None:
        try:
            text = _text_from_frame(raw)
        except GatewayTransportError as exc:
            self._note_malformed()
            self._emit("error", exc)
            return

        try:
            value = parse_strict_json(text)
        except (MalformedJsonError, ResourceExhaustedError) as exc:
            self._note_malformed()
            self._emit("error", GatewayTransportError("MALFORMED_FRAME", str(exc) or "Invalid JSON frame", cause=exc))
            return
        except Exception as exc:
            self._note_malformed()
            self._emit("error", GatewayTransportError("MALFORMED_FRAME", "Invalid JSON frame", cause=exc))
            return

        if not _is_record(value) or not isinstance(value.get("type"), str):
            self._note_malformed()
            self._emit("error", GatewayTransportError("MALFORMED_FRAME", "Gateway message requires a type field"))
            return

        message: dict[str, Any] = value  # type: ignore[assignment]
        msg_type = message["type"]
        self._emit("message", message)
        self._emit(msg_type, message)

        if msg_type == "mesh.joined":
            mesh_id = message["mesh_id"] if isinstance(message.get("mesh_id"), str) else self._mesh_id
            members = message["members"] if isinstance(message.get("members"), list) else []
            if isinstance(message.get("agent_id"), str):
                self._agent_id = message["agent_id"]
            if mesh_id:
                self._mesh_id = mesh_id
            if self._pending_join is not None:
                pending = self._pending_join
                self._pending_join = None
                result: GatewayMeshJoined = {
                    "mesh_id": mesh_id or pending["mesh_id"],
                    "members": members,  # type: ignore[typeddict-item]
                }
                if self._agent_id is not None:
                    result["agent_id"] = self._agent_id
                future: asyncio.Future[GatewayMeshJoined] = pending["future"]
                if not future.done():
                    future.set_result(result)
            return

        if msg_type == "discovery.response":
            if self._pending_discovery is not None:
                pending = self._pending_discovery
                self._pending_discovery = None
                result_d = _normalize_discover_result(message)
                future_d: asyncio.Future[GatewayDiscoverResult] = pending["future"]
                if not future_d.done():
                    future_d.set_result(result_d)
            return

        if msg_type == "card.registered":
            if isinstance(message.get("agent_id"), str):
                self._agent_id = message["agent_id"]
            return

        if msg_type == "token.expiring":
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                return
            loop.create_task(self._refresh_from_warning())
            return

        if msg_type in {
            "task.submit",
            "task.accepted",
            "task.progress",
            "task.completed",
            "task.failed",
            "task.fail",
            "error",
        }:
            envelope = _gateway_message_to_envelope(message, self._agent_id)
            if envelope is not None:
                self._emit("envelope", envelope)
            if msg_type == "error":
                code = message.get("code") if isinstance(message.get("code"), str) else "GATEWAY_ERROR"
                err = GatewayTransportError(
                    code if isinstance(code, str) else "GATEWAY_ERROR",
                    message["message"] if isinstance(message.get("message"), str) else "gateway error",
                    retryable=False,
                )
                self._emit("error", err)
            return

        # Unknown type — emit only; may surface PROTOCOL_UNKNOWN_TYPE without closing.
        self._emit(
            "error",
            GatewayTransportError("PROTOCOL_UNKNOWN_TYPE", f"Unknown gateway message type: {msg_type}", retryable=False),
        )

    async def _refresh_from_warning(self) -> None:
        try:
            await self.refresh_token()
        except Exception as exc:
            self._emit(
                "error",
                exc
                if isinstance(exc, GatewayTransportError)
                else GatewayTransportError("TOKEN_REFRESH_FAILED", str(exc), retryable=True, cause=exc),
            )

    def _note_malformed(self) -> None:
        try:
            now = asyncio.get_running_loop().time()
        except RuntimeError:
            now = 0.0
        self._malformed_window = [t for t in self._malformed_window if now - t < 1.0]
        self._malformed_window.append(now)

    async def close(self, code: int = 1000, reason: str = "close") -> None:
        self._closed = True
        self._cancel_refresh_task()
        if self._reconnect_task is not None and not self._reconnect_task.done():
            self._reconnect_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._reconnect_task
            self._reconnect_task = None
        await self._close_socket(code, reason, disable_reconnect=True, emit_close=True)
        await self._aclose_owned_http()
        self._api_key = None

    async def __aenter__(self) -> GatewayTransport:
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        try:
            if self._mesh_id is not None:
                await self.leave_mesh()
            else:
                await self.close()
        except Exception:
            if exc_type is None:
                raise
        finally:
            await self._aclose_owned_http()


def _gateway_outbound_submit_envelope(
    agent_id: str,
    target: str,
    capability: str,
    payload: JsonValue,
    task_id: str,
) -> Any | None:
    try:
        method = (
            capability
            if "." in capability
            else f"org.gateway.{re.sub(r'[^a-z0-9]+', '.', capability, flags=re.I).strip('.').lower()}"
        )
        deadline = format_timestamp(datetime.now(UTC) + timedelta(seconds=60))
        params: JsonObject = {
            "task_id": task_id,
            "method": method,
            "capability_version": "1.0.0",
            "capability_contract_digest": "0" * 64,
            "params": payload if isinstance(payload, dict) else {"value": payload},
            "deadline": deadline,
        }
        return create_envelope(
            type="task.submit",
            source={"agent_id": _sanitize_agent_id(agent_id), "instance_id": _GATEWAY_INSTANCE_ID},
            target={"agent_id": _sanitize_agent_id(target)},
            params=params,
            deadline=deadline,
        )
    except Exception:
        return None


def _gateway_message_to_envelope(message: Mapping[str, Any], local_agent_id: str | None) -> Any | None:
    msg_type = message.get("type")
    if not isinstance(msg_type, str):
        return None
    task_id = message.get("task_id") if isinstance(message.get("task_id"), str) else None
    if task_id is None and msg_type != "error":
        return None

    mapped: str | None = {
        "task.submit": "task.submit",
        "task.accepted": "task.accepted",
        "task.progress": "task.progress",
        "task.completed": "task.completed",
        "task.failed": "task.rejected",
        "task.fail": "task.rejected",
        "error": "error",
    }.get(msg_type)
    if mapped is None:
        return None

    source_id = message["from"] if isinstance(message.get("from"), str) else (local_agent_id or "gateway")
    target_id = message["target"] if isinstance(message.get("target"), str) else (local_agent_id or "local")
    now = format_timestamp(datetime.now(UTC))

    try:
        if mapped == "task.submit":
            capability = message["capability"] if isinstance(message.get("capability"), str) else "org.gateway.task"
            method = capability if "." in capability else f"org.gateway.{capability}"
            deadline = format_timestamp(datetime.now(UTC) + timedelta(seconds=60))
            payload = message.get("payload")
            return create_envelope(
                type="task.submit",
                source={"agent_id": _sanitize_agent_id(source_id), "instance_id": _GATEWAY_INSTANCE_ID},
                target={"agent_id": _sanitize_agent_id(target_id)},
                params={
                    "task_id": task_id,
                    "method": method,
                    "capability_version": "1.0.0",
                    "capability_contract_digest": "0" * 64,
                    "params": payload if isinstance(payload, dict) else {"value": payload},
                    "deadline": deadline,
                },
                deadline=deadline,
            )
        if mapped == "task.accepted":
            return create_envelope(
                type="task.accepted",
                source={"agent_id": _sanitize_agent_id(source_id), "instance_id": _GATEWAY_INSTANCE_ID},
                target={"agent_id": _sanitize_agent_id(target_id)},
                params={
                    "task_id": task_id,
                    "event_seq": 1,
                    "accepted_at": now,
                    "capability_id": "org.gateway.task",
                    "capability_version": "1.0.0",
                    "capability_contract_digest": "0" * 64,
                },
            )
        if mapped == "task.progress":
            progress_raw = message.get("progress")
            if isinstance(progress_raw, (int, float)):
                progress: JsonObject = {"fraction": float(progress_raw)}
                if isinstance(message.get("message"), str):
                    progress["status"] = message["message"]
            elif isinstance(progress_raw, dict):
                progress = dict(progress_raw)
            else:
                progress = {"status": "progress"}
            return create_envelope(
                type="task.progress",
                source={"agent_id": _sanitize_agent_id(source_id), "instance_id": _GATEWAY_INSTANCE_ID},
                target={"agent_id": _sanitize_agent_id(target_id)},
                params={"task_id": task_id, "event_seq": 2, "progress": progress},
            )
        if mapped == "task.completed":
            result_raw = message.get("result")
            result = dict(result_raw) if isinstance(result_raw, dict) else {"value": result_raw}
            return create_envelope(
                type="task.completed",
                source={"agent_id": _sanitize_agent_id(source_id), "instance_id": _GATEWAY_INSTANCE_ID},
                target={"agent_id": _sanitize_agent_id(target_id)},
                params={
                    "task_id": task_id,
                    "event_seq": 2,
                    "terminal": {
                        "outcome": "succeeded",
                        "completed_at": now,
                        "result": result,
                    },
                    "capability_id": "org.gateway.task",
                    "capability_version": "1.0.0",
                    "capability_contract_digest": "0" * 64,
                },
            )
        if mapped == "task.rejected":
            return create_envelope(
                type="task.rejected",
                source={"agent_id": _sanitize_agent_id(source_id), "instance_id": _GATEWAY_INSTANCE_ID},
                target={"agent_id": _sanitize_agent_id(target_id)},
                params={
                    "task_id": task_id,
                    "event_seq": 1,
                    "code": "GATEWAY_TASK_FAILED",
                    "message": message["error"] if isinstance(message.get("error"), str) else "task failed",
                },
            )
        if mapped == "error":
            return create_envelope(
                type="error",
                source={"agent_id": _sanitize_agent_id(source_id), "instance_id": _GATEWAY_INSTANCE_ID},
                target={"agent_id": _sanitize_agent_id(target_id)},
                params={
                    "category": "protocol",
                    "code": message["code"] if isinstance(message.get("code"), str) else "GATEWAY_ERROR",
                    "message": message["message"] if isinstance(message.get("message"), str) else "gateway error",
                    "retryable": False,
                    "retry_after_ms": None,
                },
                in_reply_to=uuidv7(),
            )
    except Exception:
        return None
    return None


__all__ = [
    "GatewayAgentInfo",
    "GatewayCapability",
    "GatewayDiscoverQuery",
    "GatewayDiscoverResult",
    "GatewayJoinMeshOptions",
    "GatewayMeshJoined",
    "GatewayReconnectOptions",
    "GatewayTokenResponse",
    "GatewayTransport",
    "GatewayTransportError",
    "gateway_http_base",
    "gateway_ws_url",
]

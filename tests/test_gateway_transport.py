"""PM-V5-SPEC §9.1 — GatewayTransport pytest-asyncio suite (mock WS + HTTP)."""

from __future__ import annotations

import asyncio
import base64
import json
import contextlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from polymesh.gateway_transport import GatewayTransport, GatewayTransportError

GATEWAY_URL = "wss://gateway.test.example/api/v1/ws"
API_KEY = "pmgk_test_key"
AGENT_ID = "agent.test.one"
MESH_ID = "friends"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_jwt(sub: str = AGENT_ID) -> str:
    header = _b64url(b'{"alg":"none","typ":"JWT"}')
    payload = _b64url(json.dumps({"sub": sub}, separators=(",", ":")).encode("utf-8"))
    return f"{header}.{payload}.sig"


def far_expires_at() -> str:
    return (datetime.now(UTC) + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


class FakeWebSocket:
    """Queue-driven fake matching websockets-style send/recv/close."""

    def __init__(self) -> None:
        self.sent: list[str] = []
        self.closed = False
        self.close_calls: list[tuple[int, str]] = []
        self._inbound: asyncio.Queue[Any] = asyncio.Queue()

    async def send(self, data: str) -> None:
        if self.closed:
            raise RuntimeError("Cannot send on closed WebSocket")
        self.sent.append(data)

    async def recv(self) -> Any:
        item = await self._inbound.get()
        if isinstance(item, BaseException):
            raise item
        return item

    def __aiter__(self) -> FakeWebSocket:
        return self

    async def __anext__(self) -> Any:
        try:
            return await self.recv()
        except Exception as exc:
            raise StopAsyncIteration from exc

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.closed = True
        self.close_calls.append((code, reason))
        with contextlib.suppress(asyncio.QueueFull):
            self._inbound.put_nowait(RuntimeError(f"WebSocket closed: {code} {reason}"))

    def push(self, message: Any) -> None:
        if isinstance(message, (dict, list)):
            message = json.dumps(message, separators=(",", ":"))
        self._inbound.put_nowait(message)

    def push_close(self, exc: BaseException | None = None) -> None:
        self.closed = True
        self._inbound.put_nowait(exc or ConnectionError("unexpected close"))

    def sent_types(self) -> list[str]:
        out: list[str] = []
        for raw in self.sent:
            try:
                parsed = json.loads(raw)
            except Exception:
                continue
            if isinstance(parsed, dict) and isinstance(parsed.get("type"), str):
                out.append(parsed["type"])
        return out

    def last_sent(self, msg_type: str) -> dict[str, Any] | None:
        for raw in reversed(self.sent):
            try:
                parsed = json.loads(raw)
            except Exception:
                continue
            if isinstance(parsed, dict) and parsed.get("type") == msg_type:
                return parsed
        return None


class GatewayHarness:
    """Injected httpx + ws_connect test double for GatewayTransport."""

    def __init__(self) -> None:
        self.token = make_jwt(AGENT_ID)
        self.expires_at = far_expires_at()
        self.auth_status = 200
        self.join_status = 200
        self.discover_status = 200
        self.discover_body: dict[str, Any] = {
            "agents": [{"id": "agent.peer", "capabilities": [{"name": "echo"}]}],
            "page": 1,
            "limit": 10,
            "total": 1,
            "has_more": False,
        }
        self.sockets: list[FakeWebSocket] = []
        self.http_requests: list[httpx.Request] = []
        self._client = httpx.AsyncClient(transport=httpx.MockTransport(self._handle_http))

    def _handle_http(self, request: httpx.Request) -> httpx.Response:
        self.http_requests.append(request)
        path = request.url.path
        if path.endswith("/api/v1/auth/token") and request.method == "POST":
            if self.auth_status == 401:
                return httpx.Response(401, json={"error": "invalid key"})
            if self.auth_status == 403:
                return httpx.Response(403, json={"error": "revoked"})
            if self.auth_status != 200:
                return httpx.Response(self.auth_status, json={"error": "auth failed"})
            return httpx.Response(
                200,
                json={"token": self.token, "expires_at": self.expires_at},
            )
        if "/join" in path and request.method == "POST":
            if self.join_status == 404:
                return httpx.Response(404, json={"code": "MESH_NOT_FOUND"})
            if self.join_status != 200 and self.join_status != 409:
                return httpx.Response(self.join_status, json={"error": "join failed"})
            return httpx.Response(self.join_status, json={"ok": True})
        if path.rstrip("/").endswith("/agents") and request.method == "GET":
            if self.discover_status != 200:
                return httpx.Response(self.discover_status, json={"error": "discover failed"})
            return httpx.Response(200, json=self.discover_body)
        return httpx.Response(404, json={"error": f"unhandled {request.method} {path}"})

    async def ws_connect(self, url: str) -> FakeWebSocket:
        assert "token=" in url
        socket = FakeWebSocket()
        self.sockets.append(socket)
        return socket

    @property
    def ws(self) -> FakeWebSocket:
        assert self.sockets, "no WebSocket opened yet"
        return self.sockets[-1]

    @property
    def http_client(self) -> httpx.AsyncClient:
        return self._client

    def transport(self, **kwargs: Any) -> GatewayTransport:
        defaults: dict[str, Any] = {
            "api_key": API_KEY,
            "gateway_url": GATEWAY_URL,
            "request_timeout_ms": 2_000,
            "token_refresh_skew_ms": 60_000,
            "reconnect": {
                "enabled": True,
                "initial_delay_ms": 20,
                "max_delay_ms": 50,
                "multiplier": 1.0,
                "jitter": 0.0,
                "max_attempts": 5,
            },
            "http_client": self._client,
            "ws_connect": self.ws_connect,
        }
        defaults.update(kwargs)
        return GatewayTransport(**defaults)

    async def aclose(self) -> None:
        await self._client.aclose()


async def wait_until(
    predicate: Callable[[], bool],
    *,
    timeout: float = 2.0,
    interval: float = 0.005,
) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if predicate():
            return
        await asyncio.sleep(interval)
    raise TimeoutError("condition not met before timeout")


async def wait_for_sent(ws: FakeWebSocket, msg_type: str, *, timeout: float = 2.0) -> dict[str, Any]:
    await wait_until(lambda: ws.last_sent(msg_type) is not None, timeout=timeout)
    found = ws.last_sent(msg_type)
    assert found is not None
    return found


async def join_and_complete(transport: GatewayTransport, harness: GatewayHarness, mesh_id: str = MESH_ID) -> dict[str, Any]:
    join_task = asyncio.create_task(transport.join_mesh(mesh_id, display_name="Tester"))
    await wait_for_sent(harness.ws, "mesh.join")
    harness.ws.push(
        {
            "type": "mesh.joined",
            "mesh_id": mesh_id,
            "agent_id": AGENT_ID,
            "members": [{"id": "agent.peer", "capabilities": [{"name": "echo"}]}],
        }
    )
    return await asyncio.wait_for(join_task, timeout=2.0)


async def cleanup_transport(transport: GatewayTransport | None) -> None:
    if transport is None:
        return
    for task_attr in ("_receiver_task", "_refresh_task", "_reconnect_task"):
        task = getattr(transport, task_attr, None)
        if isinstance(task, asyncio.Task) and not task.done():
            task.cancel()
    with contextlib.suppress(Exception):
        await asyncio.wait_for(transport.close(), timeout=2.0)
    for task_attr in ("_receiver_task", "_refresh_task", "_reconnect_task"):
        task = getattr(transport, task_attr, None)
        if isinstance(task, asyncio.Task) and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task


@pytest.fixture
async def harness() -> Any:
    h = GatewayHarness()
    try:
        yield h
    finally:
        await h.aclose()


# ---------------------------------------------------------------------------
# §9.1 scenarios
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_happy_path_connect_join_submit_completed(harness: GatewayHarness) -> None:
    transport = harness.transport()
    completed: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()

    def on_completed(msg: dict[str, Any]) -> None:
        if not completed.done():
            completed.set_result(msg)

    transport.on("task.completed", on_completed)
    try:
        await transport.connect_gateway()
        assert transport.connected
        assert transport.current_agent_id == AGENT_ID
        assert transport.current_token == harness.token

        joined = await join_and_complete(transport, harness)
        assert joined["mesh_id"] == MESH_ID
        assert transport.current_mesh_id == MESH_ID

        task_id = await transport.submit_task("agent.peer", "echo", {"text": "hi"}, task_id="task_happy_1")
        assert task_id == "task_happy_1"
        submitted = await wait_for_sent(harness.ws, "task.submit")
        assert submitted["target"] == "agent.peer"
        assert submitted["capability"] == "echo"

        harness.ws.push(
            {
                "type": "task.completed",
                "task_id": task_id,
                "from": "agent.peer",
                "result": {"text": "hi"},
            }
        )
        done = await asyncio.wait_for(completed, timeout=2.0)
        assert done["task_id"] == task_id
        assert transport.connected
    finally:
        await cleanup_transport(transport)


@pytest.mark.asyncio
async def test_auth_401_maps_to_auth_invalid_key(harness: GatewayHarness) -> None:
    harness.auth_status = 401
    transport = harness.transport(reconnect={"enabled": False, "max_attempts": 1})
    try:
        with pytest.raises(GatewayTransportError) as exc_info:
            await transport.connect_gateway()
        assert exc_info.value.code == "AUTH_INVALID_KEY"
        assert exc_info.value.status == 401
        assert harness.sockets == []
        assert not transport.connected
    finally:
        await cleanup_transport(transport)


@pytest.mark.asyncio
async def test_auth_403_maps_to_auth_revoked(harness: GatewayHarness) -> None:
    harness.auth_status = 403
    transport = harness.transport(reconnect={"enabled": False, "max_attempts": 1})
    try:
        with pytest.raises(GatewayTransportError) as exc_info:
            await transport.connect_gateway()
        assert exc_info.value.code == "AUTH_REVOKED"
        assert exc_info.value.status == 403
        assert harness.sockets == []
    finally:
        await cleanup_transport(transport)


@pytest.mark.asyncio
async def test_reconnect_after_unexpected_close(harness: GatewayHarness) -> None:
    transport = harness.transport()
    events: list[str] = []
    reconnected = asyncio.get_running_loop().create_future()

    transport.on("reconnecting", lambda _p: events.append("reconnecting"))
    transport.on(
        "reconnected",
        lambda p: (
            events.append("reconnected"),
            reconnected.set_result(p) if not reconnected.done() else None,
        ),
    )
    try:
        await transport.connect_gateway()
        await join_and_complete(transport, harness)
        assert len(harness.sockets) == 1

        harness.ws.push_close()
        payload = await asyncio.wait_for(reconnected, timeout=2.0)
        assert "reconnecting" in events
        assert "reconnected" in events
        assert len(harness.sockets) >= 2
        assert transport.connected
        assert transport.current_mesh_id == MESH_ID
        assert payload.get("mesh_id") == MESH_ID
        # Reconnect restores membership by re-sending mesh.join
        await wait_until(lambda: harness.ws.sent_types().count("mesh.join") >= 1, timeout=1.0)
    finally:
        await cleanup_transport(transport)


@pytest.mark.asyncio
async def test_duplicate_task_id_error_keeps_connection(harness: GatewayHarness) -> None:
    transport = harness.transport()
    err_fut: asyncio.Future[GatewayTransportError] = asyncio.get_running_loop().create_future()

    def on_error(err: Any) -> None:
        if isinstance(err, GatewayTransportError) and err.code == "DUPLICATE_TASK_ID" and not err_fut.done():
            err_fut.set_result(err)

    transport.on("error", on_error)
    try:
        await transport.connect_gateway()
        await join_and_complete(transport, harness)
        task_id = await transport.submit_task("agent.peer", "echo", {}, task_id="dup-1")
        harness.ws.push(
            {
                "type": "error",
                "code": "DUPLICATE_TASK_ID",
                "message": "task_id already used",
                "task_id": task_id,
            }
        )
        err = await asyncio.wait_for(err_fut, timeout=2.0)
        assert err.code == "DUPLICATE_TASK_ID"
        assert transport.connected
        assert transport.current_mesh_id == MESH_ID
    finally:
        await cleanup_transport(transport)


@pytest.mark.asyncio
async def test_invalid_capability_error(harness: GatewayHarness) -> None:
    transport = harness.transport()
    err_fut: asyncio.Future[GatewayTransportError] = asyncio.get_running_loop().create_future()

    def on_error(err: Any) -> None:
        if isinstance(err, GatewayTransportError) and err.code == "INVALID_CAPABILITY" and not err_fut.done():
            err_fut.set_result(err)

    transport.on("error", on_error)
    try:
        await transport.connect_gateway()
        await join_and_complete(transport, harness)
        await transport.submit_task("agent.peer", "no.such.cap", {"x": 1}, task_id="cap-1")
        harness.ws.push(
            {
                "type": "error",
                "code": "INVALID_CAPABILITY",
                "message": "capability not offered",
                "task_id": "cap-1",
            }
        )
        err = await asyncio.wait_for(err_fut, timeout=2.0)
        assert err.code == "INVALID_CAPABILITY"
        assert transport.connected
    finally:
        await cleanup_transport(transport)


@pytest.mark.asyncio
async def test_mesh_not_found(harness: GatewayHarness) -> None:
    harness.join_status = 404
    transport = harness.transport()
    try:
        await transport.connect_gateway()
        with pytest.raises(GatewayTransportError) as exc_info:
            await transport.join_mesh("missing-mesh", invite_code="INVITE-1")
        assert exc_info.value.code == "MESH_NOT_FOUND"
        assert exc_info.value.status == 404
        assert transport.connected  # auth/WS still up; mesh not joined via REST
    finally:
        await cleanup_transport(transport)


@pytest.mark.asyncio
async def test_leave_mesh_cleanup_submit_fails(harness: GatewayHarness) -> None:
    transport = harness.transport()
    try:
        await transport.connect_gateway()
        await join_and_complete(transport, harness)
        await transport.leave_mesh()
        assert transport.current_mesh_id is None
        assert not transport.connected
        leave = harness.sockets[0].last_sent("mesh.leave")
        assert leave is not None
        assert leave.get("mesh_id") == MESH_ID
        with pytest.raises(GatewayTransportError) as exc_info:
            await transport.submit_task("agent.peer", "echo", {})
        assert exc_info.value.code in {"NOT_CONNECTED", "NOT_IN_MESH"}
    finally:
        await cleanup_transport(transport)


@pytest.mark.asyncio
async def test_token_expiring_triggers_refresh(harness: GatewayHarness) -> None:
    transport = harness.transport()
    refreshed: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
    expiring: asyncio.Future[Any] = asyncio.get_running_loop().create_future()

    transport.on("token.expiring", lambda p: expiring.set_result(p) if not expiring.done() else None)
    transport.on("token.refreshed", lambda p: refreshed.set_result(p) if not refreshed.done() else None)
    try:
        await transport.connect_gateway()
        new_token = make_jwt("agent.test.refreshed")
        harness.token = new_token
        harness.expires_at = far_expires_at()

        harness.ws.push({"type": "token.expiring", "expires_at": transport.token_expires_at})
        await asyncio.wait_for(expiring, timeout=2.0)
        auth = await asyncio.wait_for(refreshed, timeout=2.0)
        assert auth["token"] == new_token
        assert transport.current_token == new_token
        assert transport.current_agent_id == "agent.test.refreshed"
    finally:
        await cleanup_transport(transport)


@pytest.mark.asyncio
async def test_discover_agents_returns_paginated_result(harness: GatewayHarness) -> None:
    transport = harness.transport()
    try:
        await transport.connect_gateway()
        await join_and_complete(transport, harness)

        discover_task = asyncio.create_task(
            transport.discover_agents(capability="echo", page=2, limit=5)
        )
        await wait_for_sent(harness.ws, "discovery.request")
        harness.ws.push(
            {
                "type": "discovery.response",
                "agents": [
                    {"id": "agent.a", "capabilities": [{"name": "echo"}]},
                    {"id": "agent.b", "capabilities": [{"name": "echo"}]},
                ],
                "page": 2,
                "limit": 5,
                "total": 12,
                "has_more": True,
            }
        )
        result = await asyncio.wait_for(discover_task, timeout=2.0)
        assert result["page"] == 2
        assert result["limit"] == 5
        assert result["total"] == 12
        assert result["has_more"] is True
        assert len(result["agents"]) == 2
        assert result["agents"][0]["id"] == "agent.a"
    finally:
        await cleanup_transport(transport)


@pytest.mark.asyncio
async def test_malformed_frame_emits_malformed_frame(harness: GatewayHarness) -> None:
    transport = harness.transport()
    err_fut: asyncio.Future[GatewayTransportError] = asyncio.get_running_loop().create_future()

    def on_error(err: Any) -> None:
        if isinstance(err, GatewayTransportError) and err.code == "MALFORMED_FRAME" and not err_fut.done():
            err_fut.set_result(err)

    transport.on("error", on_error)
    try:
        await transport.connect_gateway()
        harness.ws.push("{not-valid-json")
        err = await asyncio.wait_for(err_fut, timeout=2.0)
        assert err.code == "MALFORMED_FRAME"
        assert transport.connected
    finally:
        await cleanup_transport(transport)


@pytest.mark.asyncio
async def test_async_with_context_manager_cleanup(harness: GatewayHarness) -> None:
    transport = harness.transport()
    async with transport:
        await transport.connect_gateway()
        await join_and_complete(transport, harness)
        assert transport.connected
        assert transport.current_mesh_id == MESH_ID
    assert not transport.connected
    assert transport.current_mesh_id is None
    # leave_mesh path should have sent mesh.leave on the original socket
    assert "mesh.leave" in harness.sockets[0].sent_types()
    await cleanup_transport(transport)


@pytest.mark.asyncio
async def test_submit_before_join_raises_not_in_mesh(harness: GatewayHarness) -> None:
    """Extra coverage: connected but not in a mesh."""
    transport = harness.transport()
    try:
        await transport.connect_gateway()
        with pytest.raises(GatewayTransportError) as exc_info:
            await transport.submit_task("agent.peer", "echo", {})
        assert exc_info.value.code == "NOT_IN_MESH"
    finally:
        await cleanup_transport(transport)

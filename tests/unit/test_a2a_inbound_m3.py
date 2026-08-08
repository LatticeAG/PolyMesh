"""PolyMesh v6 M3 - A2A inbound adapter tests (§E.4.2 / §E.5.3)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from polymesh.a2a import (
    CAPABILITY_CAPACITY,
    IP_CAPACITY,
    MESH_CREDENTIAL_HEADERS,
    PRINCIPAL_CAPACITY,
    InboundHandler,
    RateLimit,
    create_inbound_handler,
)
from polymesh.a2a.inbound_handler import CAPABILITIES_LIST
from polymesh.protocol import uuidv7


PING = {
    "name": "org.polymesh.agent.ping",
    "description": "ping",
    "version": "1.0.0",
    "input_schema": {"type": "object"},
    "result_schema": {"type": "object"},
}
CALENDAR = {
    "name": "org.polymesh.calendar.check",
    "description": "check calendar",
    "version": "1.0.0",
    "input_schema": {"type": "object"},
    "result_schema": {"type": "object"},
}
SHELL = {
    "name": "org.polymesh.shell.exec",
    "description": "shell",
    "version": "1.0.0",
    "approval": "always",
}
CAPS_LIST = {
    "name": CAPABILITIES_LIST,
    "description": "list published skills",
    "version": "1.0.0",
    "input_schema": {"type": "object"},
    "result_schema": {"type": "object"},
}


def _send_params(skill: str, payload: dict[str, Any] | None = None, task_id: str | None = None) -> dict[str, Any]:
    params: dict[str, Any] = {
        "message": {"role": "user", "parts": [{"type": "data", "data": dict(payload or {})}]},
        "metadata": {"skill": skill},
    }
    if task_id is not None:
        params["id"] = task_id
    return params


def _handler(**overrides: Any) -> InboundHandler:
    on_submit = overrides.pop(
        "on_submit",
        lambda _env: {"state": "SUCCEEDED", "result": {"ok": True}},
    )
    auth = overrides.pop("auth", {"mode": "none"})
    capabilities = overrides.pop("capabilities", [PING, CALENDAR, SHELL, CAPS_LIST])
    opts: dict[str, Any] = {
        "inbound_enabled": True,
        "capabilities": capabilities,
        "auth": auth,
    }
    opts.update(overrides)
    return create_inbound_handler(
        opts,
        capabilities=capabilities,
        auth=auth,
        on_submit=on_submit,
        allow_public_unauthenticated=bool(opts.get("allow_public_unauthenticated", False)),
        sse_client_timeout_ms=int(opts.get("sse_client_timeout_ms", 45_000)),
    )


@pytest.mark.asyncio
async def test_inbound_tasks_send_accepts_valid_task() -> None:
    h = _handler()
    res = await h.handle(
        {"jsonrpc": "2.0", "id": 1, "method": "tasks/send", "params": _send_params("agent.ping", {"hello": 1})}
    )
    assert "result" in res
    task = res["result"]
    assert task["id"]
    assert task["status"]["state"] in {"submitted", "working", "completed"}
    assert task["metadata"]["polymesh_capability_id"] == "org.polymesh.agent.ping"


@pytest.mark.asyncio
async def test_inbound_unknown_skill_returns_minus_32601() -> None:
    h = _handler()
    res = await h.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/send",
            "params": _send_params("totally.unknown.skill"),
        }
    )
    assert res["error"]["code"] == -32601
    assert res["error"]["data"]["polymesh_code"] == "UNSUPPORTED_CAPABILITY"


@pytest.mark.asyncio
async def test_inbound_schema_invalid_rejected_fail_closed() -> None:
    h = _handler()
    res = await h.handle(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tasks/send",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"type": "data", "data": {}}],
                    "extraField": True,
                },
                "metadata": {"skill": "agent.ping"},
            },
        }
    )
    assert res["error"]["code"] == -32600
    assert res["error"]["data"]["polymesh_code"] == "MALFORMED"


@pytest.mark.asyncio
async def test_inbound_auth_reject_invalid_credentials() -> None:
    h = _handler(auth={"mode": "bearer", "token": "correct-secret"}, allow_public_unauthenticated=False)
    res = await h.handle(
        {"jsonrpc": "2.0", "id": 3, "method": "tasks/send", "params": _send_params("agent.ping")},
        headers={"Authorization": "Bearer wrong"},
    )
    assert res["error"]["code"] == -32001
    assert res["error"]["data"]["polymesh_code"] == "AUTHENTICATION_FAILED"


@pytest.mark.asyncio
async def test_inbound_mesh_credential_never_forwarded_inbound() -> None:
    h = _handler(auth={"mode": "bearer", "token": "a2a-token"})
    await h.handle(
        {"jsonrpc": "2.0", "id": 4, "method": "tasks/send", "params": _send_params("agent.ping")},
        headers={
            "Authorization": "Bearer a2a-token",
            "x-polymesh-token": "mesh-jwt-must-not-cross",
            "x-gateway-jwt": "gateway-secret",
        },
    )
    submit = h.last_mesh_submit
    assert submit is not None
    lowered = {k.lower() for k in submit["headers"]}
    for name in MESH_CREDENTIAL_HEADERS:
        assert name not in lowered
    assert submit["principal_id"].startswith("a2a:")
    assert submit["rooms"] == []


@pytest.mark.asyncio
async def test_inbound_cross_principal_task_get_uniform_not_found() -> None:
    h = _handler(auth={"mode": "api_key_header", "token": "k", "header_name": "X-API-Key"})
    created = await h.handle(
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tasks/send",
            "params": _send_params("agent.ping", {}, uuidv7()),
        },
        headers={"X-API-Key": "k"},
    )
    task_id = created["result"]["id"]
    # Rewrite owner to simulate cross-principal get.
    h._tasks[task_id]["principal_id"] = "a2a:other-principal"
    cross = await h.handle(
        {"jsonrpc": "2.0", "id": 7, "method": "tasks/get", "params": {"id": task_id}},
        headers={"X-API-Key": "k"},
    )
    assert cross["error"]["code"] == -32004
    assert cross["error"]["data"]["polymesh_code"] == "TASK_NOT_FOUND"


def test_inbound_rate_limit_bucket_capacity_and_refill() -> None:
    now = {"t": 1_000_000.0}

    def clock() -> float:
        return now["t"]

    limiter = RateLimit(
        {
            "enabled": True,
            "ip_capacity": IP_CAPACITY,
            "ip_refill_per_sec": 1.0,
            "principal_capacity": PRINCIPAL_CAPACITY,
            "principal_refill_per_sec": 0.5,
            "capability_capacity": CAPABILITY_CAPACITY,
            "capability_refill_per_sec": 0.167,
        },
        now=clock,
    )
    for _ in range(int(CAPABILITY_CAPACITY)):
        assert limiter.allow(ip="10.0.0.1", principal="a2a:p1", capability="org.polymesh.agent.ping")
    assert limiter.allow(ip="10.0.0.1", principal="a2a:p1", capability="org.polymesh.agent.ping") is False
    now["t"] += 6.0
    assert limiter.allow(ip="10.0.0.1", principal="a2a:p1", capability="org.polymesh.agent.ping") is True


@pytest.mark.asyncio
async def test_inbound_capabilities_list_only_published_skills() -> None:
    h = _handler()
    res = await h.handle(
        {"jsonrpc": "2.0", "id": 1, "method": "tasks/send", "params": _send_params("capabilities.list")}
    )
    task = res["result"]
    assert task["status"]["state"] == "completed"
    skills = task["artifacts"][0]["parts"][0]["data"]["skills"]
    names = [s["name"] for s in skills]
    assert "agent.ping" in names
    assert "calendar.check" in names
    assert "shell.exec" not in names
    card = h.handle_card_request()
    card_names = [s["name"] for s in card["skills"]]
    assert "shell.exec" not in card_names


@pytest.mark.asyncio
async def test_inbound_second_class_no_room_access() -> None:
    h = _handler(
        capabilities=[
            PING,
            {"name": "org.polymesh.room.join", "description": "join room", "version": "1.0.0"},
        ]
    )
    with pytest.raises(Exception):
        h.join_room("room-1")
    with pytest.raises(Exception):
        h.list_mesh_members()
    res = await h.handle(
        {"jsonrpc": "2.0", "id": 8, "method": "tasks/send", "params": _send_params("room.join")}
    )
    assert res["error"]["data"]["polymesh_code"] in {"AUTHORIZATION_DENIED", "UNSUPPORTED_CAPABILITY"}
    scope = h.trust_scope_for({})
    assert scope["rooms"] == []
    assert scope["topology_read"] is False


@pytest.mark.asyncio
async def test_inbound_sse_stream_replays_from_event_seq() -> None:
    h = _handler(on_submit=lambda _env: {"state": "RUNNING"})
    created = await h.handle(
        {"jsonrpc": "2.0", "id": 1, "method": "tasks/send", "params": _send_params("agent.ping")}
    )
    task_id = created["result"]["id"]
    h.apply_mesh_event(task_id, state="RUNNING", progress=0.5)
    h.apply_mesh_event(task_id, state="SUCCEEDED", result={"done": True})
    events = h.stream_events(task_id, from_event_seq=2)
    assert len(events) >= 1
    assert events[0]["adapter_seq"] >= 2
    assert any(e["task"]["status"]["state"] == "completed" for e in events)


@pytest.mark.asyncio
async def test_inbound_sse_client_timeout_closes_stream() -> None:
    h = _handler(on_submit=lambda _env: {"state": "RUNNING"}, sse_client_timeout_ms=45_000)
    created = await h.handle(
        {"jsonrpc": "2.0", "id": 1, "method": "tasks/send", "params": _send_params("agent.ping")}
    )
    task_id = created["result"]["id"]
    closed = h.stream_events(task_id, client_timeout_ms=0)
    assert closed == []


@pytest.mark.asyncio
async def test_inbound_bidirectional_interop_mock_a2a_client_tasks_mesh_agent() -> None:
    import urllib.request

    mesh_work: list[dict[str, Any]] = []

    def on_submit(env: dict[str, Any]) -> dict[str, Any]:
        mesh_work.append({"capability": env["capability"], "payload": env["payload"]})
        day = env["payload"].get("day") if isinstance(env["payload"], dict) else None
        return {"state": "SUCCEEDED", "result": {"free": True, "day": day}}

    h = create_inbound_handler(
        {
            "inbound_enabled": True,
            "capabilities": [CALENDAR],
            "auth": {"mode": "none"},
            "listen_host": "127.0.0.1",
            "listen_port": 0,
        },
        on_submit=on_submit,
    )
    h.start()
    try:
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "interop-1",
                "method": "tasks/send",
                "params": _send_params("calendar.check", {"day": "2026-08-08"}),
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            h.url,
            data=body,
            headers={"content-type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        assert "error" not in payload
        assert payload["result"]["status"]["state"] == "completed"
        assert len(mesh_work) == 1
        assert mesh_work[0]["capability"] == "org.polymesh.calendar.check"

        get_body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "interop-2",
                "method": "tasks/get",
                "params": {"id": payload["result"]["id"]},
            }
        ).encode("utf-8")
        get_req = urllib.request.Request(
            h.url,
            data=get_body,
            headers={"content-type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(get_req, timeout=5) as resp:
            get_payload = json.loads(resp.read().decode("utf-8"))
        assert get_payload["result"]["status"]["state"] == "completed"
    finally:
        h.stop()


@pytest.mark.asyncio
async def test_inbound_cancel_returns_canceled_state() -> None:
    h = _handler(on_submit=lambda _env: {"state": "RUNNING"})
    created = await h.handle(
        {"jsonrpc": "2.0", "id": 1, "method": "tasks/send", "params": _send_params("agent.ping")}
    )
    task_id = created["result"]["id"]
    canceled = await h.handle(
        {"jsonrpc": "2.0", "id": 2, "method": "tasks/cancel", "params": {"id": task_id, "reason": "user"}}
    )
    assert canceled["result"]["status"]["state"] == "canceled"
    assert canceled["result"]["metadata"]["polymesh_state"] == "CANCELLED"

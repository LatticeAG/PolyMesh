"""PolyMesh v6 M2 — A2A outbound adapter tests."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from polymesh.a2a import (
    A2AAdapter,
    A2AError,
    AdapterEventLog,
    ERROR_TABLE,
    IdempotencyStore,
    MockA2AServer,
    MonotonicStateGate,
    TaskIdBijection,
    compute_fingerprint,
    compute_poll_delay,
    is_uuidv7,
    map_outbound_task_id,
    skill_name_from_capability_name,
)
from polymesh.a2a.poller import POLL_BASE_MS, POLL_MAX_MS
from polymesh.protocol import uuidv7


class _FixedRng:
    def __init__(self, value: float = 0.0) -> None:
        self.value = value

    def uniform(self, a: float, b: float) -> float:
        return a + (b - a) * self.value


@pytest.fixture
def mock_server() -> MockA2AServer:
    return MockA2AServer(states=["completed"], result={"ok": True})


def _adapter(mock: MockA2AServer, **overrides: Any) -> A2AAdapter:
    url = MockA2AServer.__dict__.get  # placate linters
    del url
    config = {
        "outbound_enabled": True,
        "trusted_endpoints": [mock.__class__.__module__ and "https://mock-a2a.test/a2a"],
        **overrides,
    }
    # Prefer DEFAULT_URL from mock module
    from polymesh.a2a.mock_server import DEFAULT_URL

    config["trusted_endpoints"] = [DEFAULT_URL]
    return A2AAdapter(config, transport=mock.transport(), rng=_FixedRng(0.5))


@pytest.mark.asyncio
async def test_outbound_send_mock_completion(mock_server: MockA2AServer) -> None:
    from polymesh.a2a.mock_server import DEFAULT_URL

    adapter = _adapter(mock_server)
    result = await adapter.execute_outbound(
        a2a_url=DEFAULT_URL,
        capability="org.polymesh.calendar.check",
        payload={"day": "2026-08-08"},
        task_id=uuidv7(),
        deadline=__import__("time").time() * 1000 + 5000,
    )
    assert result["status"] == "SUCCEEDED"
    assert result["result"] == {"ok": True}
    body = next(
        entry["raw_body"]
        for entry in mock_server.requests
        if '"method":"tasks/send"' in entry["raw_body"] or '"method": "tasks/send"' in entry["raw_body"]
    )
    assert "calendar.check" in body
    assert "org.polymesh.calendar.check" in body


def test_outbound_skill_name_strip() -> None:
    assert skill_name_from_capability_name("org.polymesh.calendar.check") == "calendar.check"
    assert skill_name_from_capability_name("com.vendor.x") == "com.vendor.x"


def test_outbound_task_id_uuidv7_passthrough() -> None:
    task_id = uuidv7()
    assert is_uuidv7(task_id)
    assert map_outbound_task_id(task_id) == task_id


def test_outbound_task_id_bijection() -> None:
    store = TaskIdBijection()
    first = map_outbound_task_id("local-1", store=store, mint=lambda: "01900000-0000-7000-8000-0000000000aa")
    second = map_outbound_task_id("local-1", store=store, mint=lambda: "01900000-0000-7000-8000-0000000000bb")
    assert first == second == "01900000-0000-7000-8000-0000000000aa"


def test_outbound_poll_backoff() -> None:
    assert compute_poll_delay(0, _FixedRng(0.5)) == POLL_BASE_MS
    assert min(POLL_BASE_MS * (2**5), POLL_MAX_MS) == POLL_MAX_MS
    assert compute_poll_delay(5, _FixedRng(0.5)) == POLL_MAX_MS


def test_outbound_jitter_bounds() -> None:
    for n in range(6):
        base = min(POLL_BASE_MS * (2**n), POLL_MAX_MS)
        for i in range(21):
            delay = compute_poll_delay(n, _FixedRng(i / 20))
            assert base * 0.8 - 1e-9 <= delay <= base * 1.2 + 1e-9


@pytest.mark.asyncio
async def test_outbound_deadline(mock_server: MockA2AServer) -> None:
    from polymesh.a2a.mock_server import DEFAULT_URL

    mock_server.states = ["working"] * 50
    now = {"t": 0}

    async def fake_sleep(seconds: float) -> None:
        now["t"] += int(seconds * 1000)

    adapter = A2AAdapter(
        {"outbound_enabled": True, "trusted_endpoints": [DEFAULT_URL]},
        transport=mock_server.transport(),
        sleep=fake_sleep,
        now_ms=lambda: now["t"],
        rng=_FixedRng(0.5),
    )
    with pytest.raises(A2AError) as exc:
        await adapter.execute_outbound(
            a2a_url=DEFAULT_URL,
            capability="org.polymesh.agent.ping",
            payload={},
            task_id=uuidv7(),
            deadline=800,
        )
    assert exc.value.code == "DEADLINE"


def test_outbound_monotonic() -> None:
    gate = MonotonicStateGate()
    assert gate.accept("submitted")
    assert gate.accept("working")
    assert gate.accept("completed")
    assert gate.accept("working") is False


@pytest.mark.asyncio
async def test_outbound_credential_allowlist() -> None:
    adapter = A2AAdapter({"outbound_enabled": True, "trusted_endpoints": ["https://trusted.example/a2a"]})
    with pytest.raises(A2AError) as exc:
        await adapter.execute_outbound(
            a2a_url="https://evil.example/a2a",
            capability="org.polymesh.agent.ping",
            payload={},
            task_id=uuidv7(),
        )
    assert exc.value.code == "AUTHORIZATION_DENIED"


@pytest.mark.asyncio
async def test_outbound_mesh_token_never_on_wire(mock_server: MockA2AServer) -> None:
    from polymesh.a2a.mock_server import DEFAULT_URL

    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtZXNoLXVzZXIifQ.signaturepartgoesherexx"
    adapter = _adapter(mock_server)
    await adapter.execute_outbound(
        a2a_url=DEFAULT_URL,
        capability="org.polymesh.agent.ping",
        payload={"token": jwt, "note": f"Bearer {jwt}"},
        task_id=uuidv7(),
        deadline=__import__("time").time() * 1000 + 5000,
    )
    joined = "\n".join(mock_server.raw_bodies())
    assert jwt not in joined
    assert "[REDACTED]" in joined
    assert adapter.get_redaction_log()


def test_outbound_error_http_503() -> None:
    from polymesh.a2a.errors import error_from_http_status

    err = error_from_http_status(503)
    assert err.code == "TARGET_UNAVAILABLE"
    assert err.retryable is True
    assert err.json_rpc_code == -32008


def test_outbound_error_jsonrpc_auth() -> None:
    from polymesh.a2a.errors import error_from_json_rpc

    err = error_from_json_rpc(
        {"code": -32001, "message": "Authentication failed", "data": {"polymesh_code": "AUTHENTICATION_FAILED"}}
    )
    assert err.code == "AUTHENTICATION_FAILED"
    assert err.json_rpc_code == -32001
    assert ERROR_TABLE["AUTHENTICATION_FAILED"].json_rpc_code == -32001


@pytest.mark.asyncio
async def test_outbound_idempotency_cached(mock_server: MockA2AServer) -> None:
    from polymesh.a2a.mock_server import DEFAULT_URL

    adapter = _adapter(mock_server)
    kwargs = {
        "a2a_url": DEFAULT_URL,
        "capability": "org.polymesh.calendar.check",
        "payload": {"day": "x"},
        "idempotency_key": "idem-1",
        "deadline": __import__("time").time() * 1000 + 5000,
    }
    first = await adapter.execute_outbound(task_id=uuidv7(), **kwargs)
    sends_before = mock_server.send_count
    second = await adapter.execute_outbound(task_id=uuidv7(), **kwargs)
    assert second["status"] == first["status"]
    assert second.get("from_cache") is True
    assert mock_server.send_count == sends_before


def test_outbound_idempotency_fingerprint_excludes_task_id() -> None:
    a = compute_fingerprint(
        principal_id="p",
        capability="org.polymesh.calendar.check",
        payload={"day": 1},
        task_id="t1",
        idempotency_key="k",
    )
    b = compute_fingerprint(
        principal_id="p",
        capability="org.polymesh.calendar.check",
        payload={"day": 1},
        task_id="t2",
        idempotency_key="k",
    )
    assert a == b
    c = compute_fingerprint(
        principal_id="p",
        capability="org.polymesh.calendar.check",
        payload={"day": 1},
        task_id="t1",
    )
    d = compute_fingerprint(
        principal_id="p",
        capability="org.polymesh.calendar.check",
        payload={"day": 1},
        task_id="t2",
    )
    assert c != d


def test_outbound_event_log_cap() -> None:
    log = AdapterEventLog(cap=1000)
    task_id = "cap-task"
    for _ in range(1005):
        log.append(task_id, "progress", state="RUNNING", terminal=False)
    log.append(task_id, "done", state="SUCCEEDED", terminal=True)
    events = log.get(task_id)
    non_terminal = [e for e in events if not e.get("terminal")]
    terminal = [e for e in events if e.get("terminal")]
    assert len(non_terminal) <= 1000
    assert len(terminal) == 1

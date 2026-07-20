from __future__ import annotations

import asyncio
import os

import pytest

from polymesh.auth import TokenStore
from polymesh.errors import AuthenticationError, TokenError, TransportError
from polymesh.transport import (
    ConnectionSupervisor,
    InMemoryTransport,
    ReconnectSettings,
    normalize_broker_url,
    validate_broker_url,
)


def test_token_store_round_trip_and_rejects_unsafe_file(tmp_path) -> None:
    os.chmod(tmp_path, 0o700)
    store = TokenStore(tmp_path / "token")
    token = store.write_new()

    assert len(token) == 43
    assert store.read() == token

    os.chmod(store.path, 0o644)
    with pytest.raises(TokenError):
        store.read()


def test_loopback_endpoint_policy() -> None:
    token = "A" * 43
    assert normalize_broker_url("ws://127.0.0.1:7337") == "ws://127.0.0.1:7337/polymesh"
    assert validate_broker_url(
        "ws://[::1]:7337", allow_insecure_loopback_development=True, token=token
    ).path == "/polymesh"

    with pytest.raises(TransportError):
        validate_broker_url("ws://localhost:7337", allow_insecure_loopback_development=True, token=token)
    with pytest.raises(TransportError):
        validate_broker_url("ws://127.0.0.1:7337/other", allow_insecure_loopback_development=True, token=token)
    with pytest.raises(AuthenticationError):
        validate_broker_url("wss://broker.example/polymesh", token=token, secure_identity=object())


@pytest.mark.asyncio
async def test_reconnect_fences_old_generation() -> None:
    first, first_peer = InMemoryTransport.pair()
    second, second_peer = InMemoryTransport.pair()
    attempts = [first, second]
    records: list[tuple[str, int]] = []

    async def connector() -> InMemoryTransport:
        return attempts.pop(0)

    async def on_record(value: str, generation: int) -> bool:
        records.append((value, generation))
        return True

    supervisor = ConnectionSupervisor(
        connector,
        on_record=on_record,
        reconnect=ReconnectSettings(initial_delay=0.001, maximum_delay=0.001, jitter=0.0),
        heartbeat_interval=30,
        pong_timeout=5,
        inbound_timeout=90,
    )
    old = await supervisor.connect()
    await supervisor.activate(old.generation)
    await first.force_close()

    for _ in range(100):
        if supervisor.session is not None and supervisor.session.transport is second:
            break
        await asyncio.sleep(0.001)
    assert supervisor.session is not None
    assert supervisor.session.transport is second
    assert supervisor.generation > old.generation

    # A delayed event from the fenced endpoint cannot be dispatched through
    # the new session; the active endpoint still can.
    await first.feed_text("stale")
    await second_peer.send("fresh")
    await asyncio.sleep(0)
    assert records == [("fresh", supervisor.session.generation)]

    await supervisor.disconnect()
    await first_peer.close()


@pytest.mark.asyncio
async def test_reconnect_backoff_is_bounded_and_never_enables_pending_resend() -> None:
    left, right = InMemoryTransport.pair()

    async def connector() -> InMemoryTransport:
        return left

    policy = ReconnectSettings(
        initial_delay=1.0,
        maximum_delay=60.0,
        multiplier=2.0,
        jitter=0.20,
        resend_pending=False,
    )
    supervisor = ConnectionSupervisor(connector, reconnect=policy, random_fn=lambda: 0.5)

    assert supervisor.reconnect_delay(0) == 1.0
    assert supervisor.reconnect_delay(1) == 2.0
    assert supervisor.reconnect_delay(6) == 60.0
    with pytest.raises(ValueError):
        supervisor.reconnect_delay(-1)
    with pytest.raises(ValueError):
        ReconnectSettings(resend_pending=True)

    await supervisor.connect()
    await supervisor.disconnect()
    await right.close()

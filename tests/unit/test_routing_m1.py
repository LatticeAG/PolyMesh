"""PolyMesh v6 M1 capability routing unit tests."""

from __future__ import annotations

import asyncio
import copy
from datetime import UTC, datetime
from typing import Any

import pytest

from polymesh.router import (
    HEARTBEAT_MS,
    ROUTING_ERROR_CODES,
    CapabilityRouter,
    RoutingError,
    capability_exact_match,
    capability_glob_match,
    freeze_registry_view,
    freshness_bucket,
    is_retryable_failure,
)

FIXED_NOW = "2026-08-08T12:00:00.000Z"
FIXED_NOW_MS = int(datetime.fromisoformat(FIXED_NOW.replace("Z", "+00:00")).timestamp() * 1000)


def _iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000.0, tz=UTC).isoformat().replace("+00:00", "Z")


def _agent(
    agent_id: str,
    *,
    capabilities: list[dict[str, Any]],
    health: str = "healthy",
    locality: str = "lan",
    last_seen: str | int | None = FIXED_NOW,
    instance_id: str | None = None,
    mesh_member: bool = True,
    perm_hint: str | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "agent_id": agent_id,
        "display_name": agent_id,
        "capabilities": capabilities,
        "health": health,
        "locality": locality,
        "mesh_member": mesh_member,
        "last_seen": last_seen,
    }
    if instance_id is not None:
        entry["instance_id"] = instance_id
    if perm_hint is not None:
        entry["perm_hint"] = perm_hint
    return entry


def _registry(*agents: dict[str, Any]) -> dict[str, Any]:
    return {"agents": list(agents), "last_refreshed_at": FIXED_NOW}


def _router(registry: dict[str, Any] | None = None, **kwargs: Any) -> CapabilityRouter:
    return CapabilityRouter(
        registry=registry,
        observed_at=lambda: FIXED_NOW_MS,
        mark_stale_offline=False,
        **kwargs,
    )


def test_routing_capability_route_basic() -> None:
    registry = _registry(
        _agent(
            "org.polymesh.dual",
            locality="lan",
            capabilities=[
                {"name": "calendar.check", "dialect": "a2a", "a2a_url": "https://example.test/a2a"},
                {"name": "calendar.check", "dialect": "native"},
            ],
        )
    )
    router = _router(registry)
    winner, routed, count = router.capability_route(
        capability="calendar.check",
        now_ms=FIXED_NOW_MS,
    )
    assert winner["agent_id"] == "org.polymesh.dual"
    assert winner["dialect"] == "native"
    assert count == 2
    assert routed["type"] == "task.routed"
    assert routed["chosen_agent"] == "org.polymesh.dual"
    assert routed["dialect"] == "native"
    assert routed["capability"] == "calendar.check"
    assert routed["reroute_count"] == 0
    assert routed["candidate_count"] == 2


def test_routing_concurrent_exclusion_sets() -> None:
    """Concurrent tasks must not share exclusion sets (§B.16)."""
    registry = _registry(
        _agent("org.polymesh.alpha", capabilities=[{"name": "job", "dialect": "native"}]),
        _agent("org.polymesh.beta", capabilities=[{"name": "job", "dialect": "native"}]),
    )
    hits: dict[str, list[str]] = {"t1": [], "t2": []}

    async def dispatch(req: dict[str, Any]) -> None:
        task_id = str(req["task_id"])
        agent_id = str(req["agent_id"])
        hits.setdefault(task_id, []).append(agent_id)
        # First attempt for each task fails so each builds its own exclusion set.
        if len(hits[task_id]) == 1:
            raise TimeoutError("ETIMEDOUT")

    router = _router(registry, native_dispatch=dispatch)

    async def run() -> None:
        r1, r2 = await asyncio.gather(
            router.route_task({"capability": "job", "payload": {}, "task_id": "t1", "max_reroutes": 3}),
            router.route_task({"capability": "job", "payload": {}, "task_id": "t2", "max_reroutes": 3}),
        )
        assert r1["routed"]["reroute_count"] == 1
        assert r2["routed"]["reroute_count"] == 1
        assert "org.polymesh.alpha" in r1["routed"]["excluded_agents"] or "org.polymesh.beta" in r1["routed"][
            "excluded_agents"
        ]
        assert set(hits["t1"]) == {"org.polymesh.alpha", "org.polymesh.beta"}
        assert set(hits["t2"]) == {"org.polymesh.alpha", "org.polymesh.beta"}
        # Same first pick (shared RR), but each task keeps its own exclusion set.
        assert hits["t1"][0] == hits["t2"][0]
        assert r1["chosen"]["agent_id"] == hits["t1"][1]
        assert r2["chosen"]["agent_id"] == hits["t2"][1]

    asyncio.run(run())


def test_routing_snapshot_freeze() -> None:
    live = _registry(
        _agent("org.polymesh.a", capabilities=[{"name": "echo", "dialect": "native"}]),
    )
    frozen = freeze_registry_view(live)
    live["agents"].append(
        _agent("org.polymesh.b", capabilities=[{"name": "echo", "dialect": "native"}])
    )
    assert len(frozen["agents"]) == 1
    assert len(live["agents"]) == 2

    # Nested mutation of the source must not affect the frozen view.
    src = _registry(_agent("org.polymesh.z", capabilities=[{"name": "echo", "dialect": "native"}]))
    view = freeze_registry_view(src)
    src["agents"][0]["agent_id"] = "changed"
    src["agents"][0]["capabilities"][0]["name"] = "other"
    assert view["agents"][0]["agent_id"] == "org.polymesh.z"
    assert view["agents"][0]["capabilities"][0]["name"] == "echo"

    router = _router(copy.deepcopy(frozen))
    winner, _, count = router.capability_route(
        capability="echo",
        registry=frozen,
        now_ms=FIXED_NOW_MS,
        advance_rr=False,
    )
    assert winner["agent_id"] == "org.polymesh.a"
    assert count == 1
    assert router.freeze_snapshot()["agents"][0]["agent_id"] == "org.polymesh.a"


def test_routing_dialect_preference() -> None:
    registry = _registry(
        _agent(
            "org.polymesh.dual",
            capabilities=[
                {"name": "calendar.check", "dialect": "a2a", "a2a_url": "https://example.test/a2a"},
                {"name": "calendar.check", "dialect": "native"},
            ],
        )
    )
    router = _router(registry, adapter_available=True)
    winner, _, _ = router.capability_route(capability="calendar.check", now_ms=FIXED_NOW_MS)
    assert winner["dialect"] == "native"

    a2a_winner, _, _ = router.capability_route(
        capability="calendar.check",
        prefer_dialects=("a2a", "native"),
        now_ms=FIXED_NOW_MS,
        advance_rr=False,
    )
    assert a2a_winner["dialect"] == "a2a"


def test_routing_reroute_excludes_failed_agent() -> None:
    registry = _registry(
        _agent("org.polymesh.flaky", capabilities=[{"name": "job", "dialect": "native"}]),
        _agent("org.polymesh.stable", capabilities=[{"name": "job", "dialect": "native"}]),
    )
    attempts: list[str] = []

    async def dispatch(req: dict[str, Any]) -> None:
        attempts.append(str(req["agent_id"]))
        if req["agent_id"] == "org.polymesh.flaky":
            raise TimeoutError("NETWORK_TIMEOUT")

    router = _router(registry, native_dispatch=dispatch)
    result = asyncio.run(
        router.route_task({"capability": "job", "payload": {}, "task_id": "reroute-1", "max_reroutes": 3})
    )
    assert result["chosen"]["agent_id"] == "org.polymesh.stable"
    assert result["routed"]["reroute_count"] == 1
    assert "org.polymesh.flaky" in result["routed"]["excluded_agents"]
    assert attempts == ["org.polymesh.flaky", "org.polymesh.stable"]


def test_routing_locality_preference() -> None:
    registry = _registry(
        _agent(
            "org.polymesh.lan-peer",
            locality="lan",
            capabilities=[{"name": "ping", "dialect": "native"}],
        ),
        _agent(
            "org.polymesh.local",
            locality="same_host",
            capabilities=[{"name": "ping", "dialect": "native"}],
        ),
    )
    router = _router(registry)
    winner, routed, _ = router.capability_route(capability="ping", now_ms=FIXED_NOW_MS)
    assert winner["agent_id"] == "org.polymesh.local"
    assert winner["locality"] == "same_host"
    assert routed["locality_tier"] == "same_host"


def test_routing_freshness_bucket() -> None:
    assert freshness_bucket(None, "same_host") == "missing"
    gran = HEARTBEAT_MS["same_host"]
    assert gran == 30_000
    t0 = FIXED_NOW_MS
    assert freshness_bucket(t0 - 5_000, "same_host") == freshness_bucket(t0 - 10_000, "same_host")
    assert freshness_bucket(t0, "same_host") == str(t0 // gran)
    assert freshness_bucket(t0 - gran - 1, "same_host") != freshness_bucket(t0, "same_host")

    # Same Pref 1–2 and same bucket → RR / stable agent_id order (§H.freshness_bucket).
    registry = _registry(
        _agent(
            "org.polymesh.a",
            locality="same_host",
            last_seen=_iso(t0 - 5_000),
            capabilities=[{"name": "echo", "dialect": "native"}],
        ),
        _agent(
            "org.polymesh.b",
            locality="same_host",
            last_seen=_iso(t0 - 10_000),
            capabilities=[{"name": "echo", "dialect": "native"}],
        ),
    )
    router = _router(registry)
    winner, _, _ = router.capability_route(capability="echo", now_ms=t0, advance_rr=True)
    assert winner["agent_id"] == "org.polymesh.a"


def test_routing_explicit_target_capability_not_advertised() -> None:
    registry = _registry(
        _agent(
            "org.polymesh.target",
            capabilities=[{"name": "other.thing", "dialect": "native"}],
        )
    )
    router = _router(registry)
    with pytest.raises(RoutingError) as excinfo:
        router.explicit_target_verify(
            target="org.polymesh.target",
            capability="missing.cap",
            now_ms=FIXED_NOW_MS,
        )
    assert excinfo.value.code == "CAPABILITY_NOT_ADVERTISED"
    assert excinfo.value.code in ROUTING_ERROR_CODES


def test_routing_explicit_target_ambiguous() -> None:
    registry = _registry(
        _agent("org.personal.alice", capabilities=[{"name": "greet", "dialect": "native"}]),
        _agent("org.work.alice", capabilities=[{"name": "greet", "dialect": "native"}]),
    )
    router = _router(
        registry,
        canonical_expansion={"alice": ["org.personal.alice", "org.work.alice"]},
    )
    with pytest.raises(RoutingError) as excinfo:
        router.explicit_target_verify(
            target="alice",
            capability="greet",
            now_ms=FIXED_NOW_MS,
        )
    assert excinfo.value.code == "AMBIGUOUS_TARGET"


def test_routing_error_bare_codes() -> None:
    expected = {
        "NO_CANDIDATES",
        "ALL_CANDIDATES_EXHAUSTED",
        "TARGET_UNAVAILABLE",
        "AMBIGUOUS_TARGET",
        "CAPABILITY_NOT_ADVERTISED",
        "DIALECT_UNSUPPORTED",
    }
    assert ROUTING_ERROR_CODES == frozenset(expected)
    for code in ROUTING_ERROR_CODES:
        assert not code.startswith("PMX.")
        err = RoutingError(code)
        assert err.code == code
        assert err.to_dict()["code"] == code


def test_retryability_permission_denied_not_retryable() -> None:
    assert is_retryable_failure(RoutingError("PERMISSION_DENIED")) is False
    assert is_retryable_failure({"code": "AUTHORIZATION_DENIED", "message": "authz"}) is False
    assert is_retryable_failure({"code": "FORBIDDEN", "message": "policy_reject"}) is False
    assert is_retryable_failure(PermissionError("ACCESS_DENIED")) is False


def test_retryability_transport_timeout_retryable() -> None:
    assert is_retryable_failure(TimeoutError("ETIMEDOUT")) is True
    assert is_retryable_failure({"code": "NETWORK_TIMEOUT"}) is True
    assert is_retryable_failure({"code": "TARGET_UNAVAILABLE"}) is True
    assert is_retryable_failure({"code": "WS_ERROR", "status": 503}) is True
    assert is_retryable_failure(RoutingError("TIMEOUT", "deadline")) is True


def test_retryability_post_accept_by_idempotency() -> None:
    err = {"code": "REMOTE_FAILURE", "message": "worker crashed"}
    assert (
        is_retryable_failure(err, post_accept=True, idempotency="pure", side_effects="none") is True
    )
    assert (
        is_retryable_failure(err, post_accept=True, idempotency="idempotent", side_effects="read")
        is True
    )
    assert (
        is_retryable_failure(err, post_accept=True, idempotency="sensitive", side_effects="write")
        is False
    )
    assert (
        is_retryable_failure(err, post_accept=True, idempotency="sensitive", side_effects="approval")
        is False
    )
    assert (
        is_retryable_failure(
            {"code": "RESULT_TOO_LARGE"},
            idempotency="pure",
        )
        is True
    )
    assert (
        is_retryable_failure(
            {"code": "RESULT_TOO_LARGE"},
            idempotency="idempotent",
        )
        is False
    )


def test_routing_glob_match() -> None:
    assert capability_exact_match("org.example.echo", "org.example.echo") is True
    assert capability_exact_match("org.example.echo", "org.example.*") is False
    assert capability_glob_match("org.example.echo", "org.example.echo") is True
    assert capability_glob_match("org.example.echo", "org.example.*") is True
    assert capability_glob_match("org.example.echo", "org.*.echo") is True
    assert capability_glob_match("org.example.echo", "*.example.echo") is True
    assert capability_glob_match("org.example.echo", "org.example.other") is False
    assert capability_glob_match("org.example.echo", "org.ex*") is False  # partial segment
    assert capability_glob_match("a.b", "a.b.c") is False
    with pytest.raises(RoutingError) as excinfo:
        _router(_registry()).capability_route(capability="org.example.*")
    assert excinfo.value.code == "INVALID_TASK"


def test_routing_round_robin_advances() -> None:
    registry = _registry(
        _agent("org.polymesh.worker-a", capabilities=[{"name": "work", "dialect": "native"}]),
        _agent("org.polymesh.worker-b", capabilities=[{"name": "work", "dialect": "native"}]),
        _agent("org.polymesh.worker-c", capabilities=[{"name": "work", "dialect": "native"}]),
    )
    router = _router(registry)
    first, _, _ = router.capability_route(capability="work", now_ms=FIXED_NOW_MS)
    second, _, _ = router.capability_route(capability="work", now_ms=FIXED_NOW_MS)
    third, _, _ = router.capability_route(capability="work", now_ms=FIXED_NOW_MS)
    fourth, _, _ = router.capability_route(capability="work", now_ms=FIXED_NOW_MS)
    assert first["agent_id"] == "org.polymesh.worker-a"
    assert second["agent_id"] == "org.polymesh.worker-b"
    assert third["agent_id"] == "org.polymesh.worker-c"
    assert fourth["agent_id"] == "org.polymesh.worker-a"
    assert router.get_round_robin_state()  # cursor advanced


def test_routing_determinism_identical_snapshots() -> None:
    registry = _registry(
        _agent("org.polymesh.worker-c", capabilities=[{"name": "work", "dialect": "native"}]),
        _agent("org.polymesh.worker-a", capabilities=[{"name": "work", "dialect": "native"}]),
        _agent("org.polymesh.worker-b", capabilities=[{"name": "work", "dialect": "native"}]),
    )
    r1 = _router(copy.deepcopy(registry))
    r2 = _router(copy.deepcopy(registry))
    w1, ev1, c1 = r1.capability_route(capability="work", now_ms=FIXED_NOW_MS, advance_rr=True)
    w2, ev2, c2 = r2.capability_route(capability="work", now_ms=FIXED_NOW_MS, advance_rr=True)
    assert w1["agent_id"] == w2["agent_id"] == "org.polymesh.worker-a"
    assert w1["dialect"] == w2["dialect"]
    assert c1 == c2
    assert ev1["chosen_agent"] == ev2["chosen_agent"]
    assert r1.get_round_robin_state() == r2.get_round_robin_state()


def test_routing_cold_start_no_reroute_increment() -> None:
    discovered: list[int] = []
    router_box: dict[str, CapabilityRouter] = {}

    def on_discover() -> None:
        discovered.append(1)
        router_box["r"].set_registry(
            _registry(
                _agent("org.polymesh.late", capabilities=[{"name": "boot", "dialect": "native"}]),
            )
        )

    router = CapabilityRouter(
        registry={"agents": [], "last_refreshed_at": FIXED_NOW},
        observed_at=lambda: FIXED_NOW_MS,
        mark_stale_offline=False,
        cold_start_policy="lazy",
        on_discover=on_discover,
        native_dispatch=lambda _req: None,
    )
    router_box["r"] = router

    async def run() -> dict[str, Any]:
        return await router.route_task(
            {"capability": "boot", "payload": {}, "task_id": "cold-1", "max_reroutes": 3}
        )

    result = asyncio.run(run())
    assert discovered == [1]
    assert result["chosen"]["agent_id"] == "org.polymesh.late"
    assert result["routed"]["reroute_count"] == 0


def test_routing_a2a_without_bridge_fails_closed() -> None:
    registry = _registry(
        _agent(
            "org.polymesh.a2a-only",
            capabilities=[
                {"name": "remote.skill", "dialect": "a2a", "a2a_url": "https://example.test/a2a"},
            ],
        )
    )
    router = _router(registry, a2a_bridge=None, adapter_available=False)

    with pytest.raises(RoutingError) as explicit:
        router.explicit_target_verify(
            target="org.polymesh.a2a-only",
            capability="remote.skill",
            now_ms=FIXED_NOW_MS,
        )
    assert explicit.value.code == "DIALECT_UNSUPPORTED"

    async def run() -> None:
        with pytest.raises(RoutingError) as excinfo:
            await router.route_task(
                {
                    "capability": "remote.skill",
                    "payload": {},
                    "task_id": "a2a-fail",
                    "prefer_dialects": ("a2a",),
                }
            )
        assert excinfo.value.code == "DIALECT_UNSUPPORTED"
        assert (excinfo.value.details or {}).get("bridge") == "BRIDGE_UNBOUND"

    asyncio.run(run())

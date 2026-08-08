"""PolyMesh v6 M1 capability routing engine (PRODUCT layer).

Implements Part B ranking, exclusion, bounded re-route, and explicit-target
verification. Dialects are opaque routing attributes — this module MUST NOT
parse A2A payloads.
"""

from __future__ import annotations

import contextlib
import copy
import inspect
import math
import threading
import time
from collections.abc import Awaitable, Callable, Mapping, MutableMapping, Sequence
from enum import Enum
from typing import Any, Literal, Protocol, TypedDict, cast

from .protocol import uuidv7

Dialect = Literal["native", "a2a"]
LocalityClass = Literal["same_host", "lan", "relay", "unknown"]
HealthState = Literal["healthy", "degraded", "unhealthy", "offline", "unknown"]
PermHint = Literal["allow", "deny", "absent"]
RerouteReason = Literal[
    "retryable_transport",
    "retryable_remote",
    "timeout",
    "unhealthy",
    "policy_reject",
]
ColdStartPolicy = Literal["eager", "lazy", "manual"]
IdempotencyClass = Literal["pure", "idempotent", "sensitive"]
SideEffectsClass = Literal["none", "read", "write", "network", "approval"]

ROUTING_ERROR_CODES: frozenset[str] = frozenset(
    {
        "NO_CANDIDATES",
        "ALL_CANDIDATES_EXHAUSTED",
        "TARGET_UNAVAILABLE",
        "AMBIGUOUS_TARGET",
        "CAPABILITY_NOT_ADVERTISED",
        "DIALECT_UNSUPPORTED",
    }
)

# Lease TTL / heartbeat granularity by locality (§B.5.3 / §B.6.5).
HEARTBEAT_MS: dict[LocalityClass, int] = {
    "same_host": 30_000,
    "lan": 60_000,
    "relay": 120_000,
    "unknown": 60_000,
}
LEASE_TTL_MS: dict[LocalityClass, int] = dict(HEARTBEAT_MS)
DEFAULT_MAX_ROUTE_STALENESS_MS = HEARTBEAT_MS["same_host"]

DIALECT_RANK: dict[str, int] = {"native": 0, "a2a": 1}
LOCALITY_RANK: dict[str, int] = {
    "same_host": 0,
    "lan": 1,
    "relay": 2,
    "unknown": 3,
}
_HEALTHY_STATES = frozenset({"healthy", "degraded"})
_DEFAULT_PREFER_DIALECTS: tuple[Dialect, ...] = ("native", "a2a")


class RoutingAttemptState(str, Enum):
    """Routing attempt lifecycle (§B.16) plus SDK bookkeeping states."""

    SUBMITTED = "SUBMITTED"
    ROUTING = "ROUTING"
    COLLECTING = "COLLECTING"
    FILTERING = "FILTERING"
    RANKING = "RANKING"
    DISPATCHING = "DISPATCHING"
    WAITING = "WAITING"
    HANDOFF = "HANDOFF"
    FAILED = "FAILED"
    REROUTING = "REROUTING"
    EXHAUSTED = "EXHAUSTED"
    SUCCEEDED = "SUCCEEDED"


class CapabilityEntry(TypedDict, total=False):
    name: str
    schema: dict[str, Any]
    scope: str
    dialect: Dialect
    a2a_url: str
    version: str
    contract_digest: str
    idempotency: IdempotencyClass
    side_effects: SideEffectsClass
    max_result_bytes: int


class RegistryAgentEntry(TypedDict, total=False):
    agent_id: str
    display_name: str
    capabilities: list[CapabilityEntry]
    health: HealthState
    last_seen: str | None
    locality: LocalityClass
    metadata: dict[str, str | int | float | bool]
    mesh_member: bool
    instance_id: str
    perm_hint: PermHint


class RegistryView(TypedDict, total=False):
    agents: list[RegistryAgentEntry]
    last_refreshed_at: str


class RoutingCandidate(TypedDict, total=False):
    agent_id: str
    instance_id: str
    capability: str
    dialect: Dialect
    a2a_url: str
    locality: LocalityClass
    last_seen_ms: int
    healthy: bool
    health: HealthState
    perm_hint: PermHint
    score_hint: float


class RankCandidatesOptions(TypedDict, total=False):
    capability: str
    exclude: Sequence[str]
    prefer_dialects: Sequence[Dialect]
    now_ms: int


class SelectCandidateOptions(TypedDict, total=False):
    capability: str
    exclude: Sequence[str]
    prefer_dialects: Sequence[Dialect]
    round_robin_key: str
    now_ms: int


class RouteTaskOptions(TypedDict, total=False):
    capability: str
    payload: Any
    task_id: str
    target: str
    max_reroutes: int
    prefer_dialects: Sequence[Dialect]


class TaskRoutedEvent(TypedDict, total=False):
    type: Literal["task.routed"]
    task_id: str
    candidate_count: int
    chosen_agent: str
    dialect: Dialect
    reroute_count: int
    excluded_agents: list[str]
    capability: str
    locality_tier: LocalityClass
    observed_at: str
    ranked_scores: list[dict[str, Any]]


class RerouteEvent(TypedDict):
    task_id: str
    failed_agent: str
    reason: RerouteReason
    attempt: int
    excluded_agents: list[str]


class DialectPreferenceHooks(Protocol):
    def prefer_dialects(
        self, capability: str
    ) -> Sequence[Dialect] | Awaitable[Sequence[Dialect]]: ...

    def accept_candidate(
        self, candidate: RoutingCandidate, capability: str
    ) -> bool | Awaitable[bool]: ...


class RoutingError(Exception):
    """PRODUCT routing failure with a bare §B.14 / §F.2.1 code."""

    def __init__(
        self,
        code: str,
        message: str | None = None,
        *,
        task_id: str | None = None,
        capability: str | None = None,
        target: str | None = None,
        excluded_agents: Sequence[str] | None = None,
        reroute_count: int | None = None,
        observed_at: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        self.code = code
        self.message = message or code
        self.task_id = task_id
        self.capability = capability
        self.target = target
        self.excluded_agents = list(excluded_agents) if excluded_agents is not None else None
        self.reroute_count = reroute_count
        self.observed_at = observed_at
        self.details = dict(details) if details is not None else None
        super().__init__(self.message)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.task_id is not None:
            out["task_id"] = self.task_id
        if self.capability is not None:
            out["capability"] = self.capability
        if self.target is not None:
            out["target"] = self.target
        if self.excluded_agents is not None:
            out["excluded_agents"] = list(self.excluded_agents)
        if self.reroute_count is not None:
            out["reroute_count"] = self.reroute_count
        if self.observed_at is not None:
            out["observed_at"] = self.observed_at
        if self.details is not None:
            out["details"] = dict(self.details)
        return out


def dialect_rank(dialect: str | None) -> int:
    if dialect is None or dialect == "":
        return DIALECT_RANK["native"]
    return DIALECT_RANK.get(dialect, 1)


def locality_rank(locality: str | None) -> int:
    if locality is None:
        return LOCALITY_RANK["unknown"]
    return LOCALITY_RANK.get(locality, LOCALITY_RANK["unknown"])


def capability_exact_match(name: str, pattern: str) -> bool:
    return name == pattern


def capability_glob_match(name: str, pattern: str) -> bool:
    """Segment glob match for discovery filters (§B.10). Not for dispatch."""
    if "*" not in pattern:
        return name == pattern
    if any("*" in segment and segment != "*" for segment in pattern.split(".")):
        return False
    ns = name.split(".")
    ps = pattern.split(".")
    if len(ns) != len(ps):
        return False
    if any(segment == "" for segment in ns) or any(segment == "" for segment in ps):
        return False
    for n_seg, p_seg in zip(ns, ps, strict=True):
        if p_seg == "*":
            continue
        if p_seg != n_seg:
            return False
    return True


def freshness_bucket(
    last_seen_ms: int | float | None,
    locality: LocalityClass | str | None,
    *,
    heartbeat_ms: Mapping[str, int] | None = None,
) -> str:
    """Quantize last_seen to locality heartbeat granularity (§B.6.5)."""
    if last_seen_ms is None or (isinstance(last_seen_ms, float) and math.isnan(last_seen_ms)):
        return "missing"
    table = heartbeat_ms or HEARTBEAT_MS
    tier = locality if isinstance(locality, str) and locality in table else "unknown"
    gran = int(table.get(tier, table["unknown"]))
    if gran <= 0:
        gran = HEARTBEAT_MS["unknown"]
    return str(math.floor(float(last_seen_ms) / gran))


def freshness_key(candidate: Mapping[str, Any]) -> float:
    """Ascending sort key: fresher (larger bucket) first; missing → +inf."""
    ms = candidate.get("last_seen_ms")
    if ms is None:
        return math.inf
    bucket = freshness_bucket(int(ms), cast(LocalityClass | None, candidate.get("locality")))
    if bucket == "missing":
        return math.inf
    return -float(bucket)


def freeze_registry_view(registry: RegistryView | Mapping[str, Any] | None) -> RegistryView:
    """Deep-copy RegistryView at route.begin (§B.17.3)."""
    if registry is None:
        return {"agents": []}
    return cast(RegistryView, copy.deepcopy(dict(registry)))


def exclusion_key(agent_id: str, instance_id: str | None = None) -> str:
    if instance_id:
        return f"{agent_id}\0{instance_id}"
    return agent_id


def exclusion_agent_ids(keys: Sequence[str] | set[str]) -> list[str]:
    """Map exclusion keys to sorted agent_id strings for events."""
    agents: set[str] = set()
    for key in keys:
        agents.add(key.split("\0", 1)[0])
    return sorted(agents)


def _candidate_exclusion_key(candidate: Mapping[str, Any]) -> str:
    instance = candidate.get("instance_id")
    return exclusion_key(str(candidate["agent_id"]), str(instance) if instance else None)


def _is_excluded(candidate: Mapping[str, Any], excluded: set[str]) -> bool:
    agent_id = str(candidate["agent_id"])
    if agent_id in excluded:
        return True
    key = _candidate_exclusion_key(candidate)
    if key in excluded:
        return True
    # Instance-aware key also matches agent-only exclusion of same agent.
    instance = candidate.get("instance_id")
    if instance and exclusion_key(agent_id, str(instance)) in excluded:
        return True
    return False


def _parse_last_seen_ms(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str) and value:
        try:
            from datetime import datetime

            text = value.replace("Z", "+00:00") if value.endswith("Z") else value
            return int(datetime.fromisoformat(text).timestamp() * 1000)
        except ValueError:
            return None
    return None


def _observed_at_iso(now_ms: int) -> str:
    from datetime import UTC, datetime

    return datetime.fromtimestamp(now_ms / 1000.0, tz=UTC).isoformat().replace("+00:00", "Z")


def _now_ms() -> int:
    return int(time.time() * 1000)


def collect_candidates(
    registry: RegistryView | Mapping[str, Any],
    capability: str,
) -> list[RoutingCandidate]:
    """Collect dialect-tagged candidates for an exact capability (§B.4)."""
    agents = list(registry.get("agents") or [])
    agents.sort(key=lambda a: str(a.get("agent_id") or ""))
    out: list[RoutingCandidate] = []
    seen: set[tuple[str, str]] = set()

    for agent in agents:
        agent_id = str(agent.get("agent_id") or "")
        if not agent_id:
            continue
        ads = list(agent.get("capabilities") or [])
        ads.sort(
            key=lambda adv: (
                str(adv.get("name") or ""),
                str(adv.get("dialect") or "native"),
            )
        )
        health = cast(HealthState, agent.get("health") or "unknown")
        locality = cast(LocalityClass, agent.get("locality") or "unknown")
        last_seen_ms = _parse_last_seen_ms(agent.get("last_seen"))
        instance_id = agent.get("instance_id")
        perm_hint = agent.get("perm_hint")

        for adv in ads:
            name = adv.get("name")
            if not isinstance(name, str) or not capability_exact_match(name, capability):
                continue
            dialect_raw = adv.get("dialect") or "native"
            if dialect_raw not in {"native", "a2a"}:
                continue
            dialect = cast(Dialect, dialect_raw)
            a2a_url = adv.get("a2a_url")
            if dialect == "a2a" and (not isinstance(a2a_url, str) or not a2a_url):
                continue
            pair = (agent_id, dialect)
            if pair in seen:
                continue
            seen.add(pair)
            candidate: RoutingCandidate = {
                "agent_id": agent_id,
                "capability": capability,
                "dialect": dialect,
                "locality": locality,
                "health": health,
                "healthy": health in _HEALTHY_STATES,
            }
            if instance_id:
                candidate["instance_id"] = str(instance_id)
            if last_seen_ms is not None:
                candidate["last_seen_ms"] = last_seen_ms
            if dialect == "a2a" and isinstance(a2a_url, str):
                candidate["a2a_url"] = a2a_url
            if perm_hint in {"allow", "deny", "absent"}:
                candidate["perm_hint"] = cast(PermHint, perm_hint)
            out.append(candidate)
    return out


def filter_health(
    candidates: Sequence[RoutingCandidate],
    *,
    now_ms: int | None = None,
    mark_stale_offline: bool = True,
    max_route_staleness_ms: int | None = None,
) -> list[RoutingCandidate]:
    """Keep healthy|degraded; optionally drop lease-stale entries (§B.5)."""
    observed = _now_ms() if now_ms is None else now_ms
    staleness = (
        DEFAULT_MAX_ROUTE_STALENESS_MS if max_route_staleness_ms is None else max_route_staleness_ms
    )
    kept: list[RoutingCandidate] = []
    for candidate in candidates:
        health = candidate.get("health")
        healthy_flag = candidate.get("healthy")
        if health is not None:
            eligible = health in _HEALTHY_STATES
        elif healthy_flag is not None:
            eligible = bool(healthy_flag)
        else:
            eligible = False
        if not eligible:
            continue
        if mark_stale_offline:
            ms = candidate.get("last_seen_ms")
            locality = cast(LocalityClass, candidate.get("locality") or "unknown")
            ttl = LEASE_TTL_MS.get(locality, LEASE_TTL_MS["unknown"])
            if ms is None:
                # Missing last_seen: fail closed as unknown/offline for lease check.
                continue
            age = observed - int(ms)
            if age > ttl or age > staleness:
                continue
        kept.append(candidate)
    return kept


def filter_permission(
    candidates: Sequence[RoutingCandidate],
    caller_id: str | None = None,
    capability: str | None = None,
) -> list[RoutingCandidate]:
    """Exclude DENY hints; ALLOW and ABSENT remain (§B.6.1)."""
    del caller_id, capability  # hints are already projected onto candidates
    out: list[RoutingCandidate] = []
    for candidate in candidates:
        hint = candidate.get("perm_hint")
        if hint == "deny":
            continue
        out.append(candidate)
    return out


def _prefer_dialect_order(
    prefer_dialects: Sequence[Dialect] | None,
) -> list[Dialect]:
    if not prefer_dialects:
        return list(_DEFAULT_PREFER_DIALECTS)
    seen: list[Dialect] = []
    for dialect in prefer_dialects:
        if dialect in {"native", "a2a"} and dialect not in seen:
            seen.append(cast(Dialect, dialect))
    return seen or list(_DEFAULT_PREFER_DIALECTS)


def _effective_dialect_rank(dialect: str, prefer: Sequence[Dialect]) -> int:
    try:
        return list(prefer).index(cast(Dialect, dialect))
    except ValueError:
        return len(prefer) + dialect_rank(dialect)


def stable_rank(
    candidates: Sequence[RoutingCandidate],
    *,
    capability: str,
    rr_state: MutableMapping[str, int],
    rr_lock: threading.Lock,
    prefer_dialects: Sequence[Dialect] | None = None,
    advance: bool = True,
) -> list[RoutingCandidate]:
    """Lexicographic Pref 1–5 ranking with process-local round-robin (§B.6)."""
    prefer = _prefer_dialect_order(prefer_dialects)
    filtered = [c for c in candidates if c.get("dialect") in prefer]
    if not filtered:
        filtered = list(candidates)

    # Group by Pref 1–3 keys for RR index assignment.
    groups: dict[tuple[Any, ...], list[RoutingCandidate]] = {}
    for candidate in filtered:
        d_rank = _effective_dialect_rank(str(candidate.get("dialect") or "native"), prefer)
        l_rank = locality_rank(candidate.get("locality"))
        f_key = freshness_key(candidate)
        groups.setdefault((d_rank, l_rank, f_key), []).append(candidate)

    rr_index_map: dict[int, int] = {}

    with rr_lock:
        for group_key, members in groups.items():
            ordered = sorted(
                members,
                key=lambda c: (
                    str(c.get("agent_id") or ""),
                    str(c.get("dialect") or ""),
                ),
            )
            d_rank, l_rank, _f_key = group_key
            sample = ordered[0]
            bucket = freshness_bucket(
                sample.get("last_seen_ms"),
                cast(LocalityClass | None, sample.get("locality")),
            )
            rr_key = f"{capability}\0{d_rank}\0{l_rank}\0{bucket}"
            n = len(ordered)
            cursor = int(rr_state.get(rr_key, 0)) % n if n else 0
            # T[(cursor + i) mod n] := i  (§B.6.5)
            for i in range(n):
                rr_index_map[id(ordered[(cursor + i) % n])] = i

        ranked = sorted(
            filtered,
            key=lambda c: (
                _effective_dialect_rank(str(c.get("dialect") or "native"), prefer),
                locality_rank(c.get("locality")),
                freshness_key(c),
                rr_index_map.get(id(c), 0),
                str(c.get("agent_id") or ""),
                str(c.get("dialect") or ""),
            ),
        )

        if advance and ranked:
            winner = ranked[0]
            d_rank = _effective_dialect_rank(str(winner.get("dialect") or "native"), prefer)
            l_rank = locality_rank(winner.get("locality"))
            bucket = freshness_bucket(
                winner.get("last_seen_ms"),
                cast(LocalityClass | None, winner.get("locality")),
            )
            rr_key = f"{capability}\0{d_rank}\0{l_rank}\0{bucket}"
            tie = [
                c
                for c in filtered
                if _effective_dialect_rank(str(c.get("dialect") or "native"), prefer) == d_rank
                and locality_rank(c.get("locality")) == l_rank
                and freshness_key(c) == freshness_key(winner)
            ]
            n = max(1, len(tie))
            cursor = int(rr_state.get(rr_key, 0)) % n
            rr_state[rr_key] = (cursor + 1) % n

    return ranked


def is_retryable_failure(
    error: Any,
    *,
    idempotency: IdempotencyClass | str | None = None,
    side_effects: SideEffectsClass | str | None = None,
    post_accept: bool = False,
) -> bool:
    """Classify whether a dispatch failure may trigger re-route (§B.7.3)."""
    code = ""
    message = ""
    status: int | None = None
    retryable_flag: bool | None = None

    if isinstance(error, RoutingError):
        code = error.code
        message = error.message
    elif isinstance(error, Mapping):
        code = str(error.get("code") or error.get("error") or "")
        message = str(error.get("message") or "")
        raw_status = error.get("status") or error.get("http_status")
        if isinstance(raw_status, int):
            status = raw_status
        if "retryable" in error:
            retryable_flag = bool(error["retryable"])
    elif isinstance(error, BaseException):
        code = str(getattr(error, "code", "") or "")
        message = str(error)
        raw_status = getattr(error, "status", None) or getattr(error, "http_status", None)
        if isinstance(raw_status, int):
            status = raw_status
        if hasattr(error, "retryable"):
            retryable_flag = bool(getattr(error, "retryable"))
    else:
        message = str(error)

    blob = f"{code} {message}".upper()

    if any(
        token in blob
        for token in (
            "PERMISSION_DENIED",
            "AUTHZ",
            "AUTHORIZATION",
            "FORBIDDEN",
            "POLICY_REJECT",
            "ACCESS_DENIED",
        )
    ):
        return False
    if any(
        token in blob
        for token in (
            "INVALID_PARAMS",
            "SCHEMA",
            "VALIDATION",
            "MALFORMED",
        )
    ):
        return False
    if "CANCEL" in blob:
        return False
    if "RESULT_TOO_LARGE" in blob:
        return idempotency == "pure"
    if post_accept:
        if side_effects in {"write", "approval"}:
            return False
        if idempotency in {"pure", "idempotent"}:
            return True
        if side_effects in {"none", "read"}:
            return True
        return False
    if status in {502, 503, 504}:
        return True
    if code in {
        "TARGET_UNAVAILABLE",
        "CAPABILITY_NOT_ADVERTISED",
        "TIMEOUT",
        "ETIMEDOUT",
        "ECONNRESET",
        "ECONNREFUSED",
        "NETWORK_TIMEOUT",
        "CONNECTION_REFUSED",
        "WS_ERROR",
        "TRANSPORT_CLOSED",
    }:
        return True
    if any(
        token in blob
        for token in (
            "TIMEOUT",
            "ETIMEDOUT",
            "ECONNRESET",
            "ECONNREFUSED",
            "502",
            "503",
            "504",
            "UNAVAILABLE",
            "RETRYABLE",
        )
    ):
        return True
    if retryable_flag is not None:
        return retryable_flag
    return False


classify_retryability = is_retryable_failure


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


class CapabilityRouter:
    """Concrete PRODUCT capability router (Part B / §E.2.4)."""

    def __init__(
        self,
        *,
        registry: RegistryView | Mapping[str, Any] | None = None,
        observed_at: Callable[[], int | float | str] | None = None,
        rr_state: MutableMapping[str, int] | None = None,
        a2a_bridge: Callable[..., Awaitable[None]] | Mapping[str, Any] | None = None,
        native_dispatch: Callable[..., Awaitable[None] | None] | None = None,
        adapter_available: bool | None = None,
        canonical_expansion: Mapping[str, Sequence[str]] | None = None,
        cold_start_policy: ColdStartPolicy = "eager",
        on_discover: Callable[[], Awaitable[None] | None] | None = None,
        caller_id: str | None = None,
        mark_stale_offline: bool = True,
        max_route_staleness_ms: int | None = None,
    ) -> None:
        self._registry: RegistryView = freeze_registry_view(registry)
        self._observed_at = observed_at
        self._rr_state: MutableMapping[str, int] = rr_state if rr_state is not None else {}
        self._rr_lock = threading.Lock()
        self._a2a_bridge = a2a_bridge
        self._native_dispatch = native_dispatch
        self._adapter_available = (
            bool(a2a_bridge) if adapter_available is None else bool(adapter_available)
        )
        self._canonical_expansion = {
            key: list(values) for key, values in (canonical_expansion or {}).items()
        }
        self._cold_start_policy: ColdStartPolicy = cold_start_policy
        self._on_discover = on_discover
        self._caller_id = caller_id
        self._mark_stale_offline = mark_stale_offline
        self._max_route_staleness_ms = max_route_staleness_ms
        self._hooks: DialectPreferenceHooks | None = None
        self._reroute_handlers: list[Callable[[RerouteEvent], None]] = []
        self._task_routed_handlers: list[Callable[[TaskRoutedEvent], None]] = []
        self._attempt_state: dict[str, RoutingAttemptState] = {}
        self._handlers_lock = threading.Lock()

    @property
    def cold_start_policy(self) -> ColdStartPolicy:
        return self._cold_start_policy

    def set_registry(self, registry: RegistryView | Mapping[str, Any] | None) -> None:
        self._registry = freeze_registry_view(registry)

    def freeze_snapshot(self) -> RegistryView:
        self._registry = freeze_registry_view(self._registry)
        return self._registry

    def set_a2a_outbound_bridge(
        self,
        bridge: Callable[..., Awaitable[None]] | Mapping[str, Any] | None,
    ) -> None:
        self._a2a_bridge = bridge
        self._adapter_available = bridge is not None

    def set_dialect_preference_hooks(self, hooks: DialectPreferenceHooks | None) -> None:
        self._hooks = hooks

    def on_reroute(self, handler: Callable[[RerouteEvent], None]) -> Callable[[], None]:
        with self._handlers_lock:
            self._reroute_handlers.append(handler)

        def unsubscribe() -> None:
            with self._handlers_lock:
                with contextlib.suppress(ValueError):
                    self._reroute_handlers.remove(handler)

        return unsubscribe

    def on_task_routed(self, handler: Callable[[TaskRoutedEvent], None]) -> Callable[[], None]:
        with self._handlers_lock:
            self._task_routed_handlers.append(handler)

        def unsubscribe() -> None:
            with self._handlers_lock:
                with contextlib.suppress(ValueError):
                    self._task_routed_handlers.remove(handler)

        return unsubscribe

    def get_round_robin_state(self) -> dict[str, int]:
        with self._rr_lock:
            return dict(self._rr_state)

    def reset_round_robin(self) -> None:
        with self._rr_lock:
            self._rr_state.clear()

    def get_attempt_state(self, task_id: str) -> RoutingAttemptState | None:
        return self._attempt_state.get(task_id)

    def _emit_reroute(self, event: RerouteEvent) -> None:
        with self._handlers_lock:
            handlers = list(self._reroute_handlers)
        for handler in handlers:
            try:
                handler(event)
            except Exception:
                pass

    def _emit_task_routed(self, event: TaskRoutedEvent) -> None:
        with self._handlers_lock:
            handlers = list(self._task_routed_handlers)
        for handler in handlers:
            try:
                handler(event)
            except Exception:
                pass

    def _resolve_now_ms(self, options: Mapping[str, Any] | None = None) -> int:
        if options and isinstance(options.get("now_ms"), int):
            return int(options["now_ms"])
        if self._observed_at is not None:
            value = self._observed_at()
            if isinstance(value, (int, float)):
                return int(value)
            parsed = _parse_last_seen_ms(value)
            if parsed is not None:
                return parsed
        return _now_ms()

    async def _resolve_prefer_dialects(
        self,
        capability: str,
        override: Sequence[Dialect] | None,
    ) -> list[Dialect]:
        if override is not None:
            return _prefer_dialect_order(override)
        hooks = self._hooks
        if hooks is not None and hasattr(hooks, "prefer_dialects"):
            preferred = await _maybe_await(hooks.prefer_dialects(capability))
            return _prefer_dialect_order(preferred)
        return list(_DEFAULT_PREFER_DIALECTS)

    async def _apply_accept_hooks(
        self,
        candidates: Sequence[RoutingCandidate],
        capability: str,
    ) -> list[RoutingCandidate]:
        hooks = self._hooks
        if hooks is None or not hasattr(hooks, "accept_candidate"):
            return list(candidates)
        kept: list[RoutingCandidate] = []
        for candidate in candidates:
            try:
                accepted = await _maybe_await(hooks.accept_candidate(candidate, capability))
            except Exception:
                accepted = True
            if accepted is False:
                continue
            kept.append(candidate)
        return kept

    def rank_candidates(
        self,
        candidates: Sequence[RoutingCandidate],
        options: RankCandidatesOptions | Mapping[str, Any],
    ) -> list[RoutingCandidate]:
        capability = str(options.get("capability") or "")
        prefer = options.get("prefer_dialects")
        prefer_list = _prefer_dialect_order(cast(Sequence[Dialect] | None, prefer))
        exclude_raw = options.get("exclude") or ()
        excluded = set(exclude_raw) if not isinstance(exclude_raw, set) else set(exclude_raw)
        now_ms = self._resolve_now_ms(options)

        working = [
            c
            for c in candidates
            if not _is_excluded(c, excluded)
            and (not prefer_list or c.get("dialect") in prefer_list)
        ]
        working = filter_health(
            working,
            now_ms=now_ms,
            mark_stale_offline=False,
        )
        return stable_rank(
            working,
            capability=capability,
            rr_state=self._rr_state,
            rr_lock=self._rr_lock,
            prefer_dialects=prefer_list,
            advance=False,
        )

    def select_candidate(
        self,
        candidates: Sequence[RoutingCandidate],
        options: SelectCandidateOptions | Mapping[str, Any],
    ) -> RoutingCandidate | None:
        ranked = self.rank_candidates(candidates, options)
        if not ranked:
            return None
        # Advance RR only when selecting a winner.
        capability = str(options.get("capability") or "")
        prefer = _prefer_dialect_order(cast(Sequence[Dialect] | None, options.get("prefer_dialects")))
        advanced = stable_rank(
            ranked,
            capability=capability,
            rr_state=self._rr_state,
            rr_lock=self._rr_lock,
            prefer_dialects=prefer,
            advance=True,
        )
        return advanced[0] if advanced else None

    def explicit_target_verify(
        self,
        *,
        target: str,
        capability: str,
        registry: RegistryView | None = None,
        prefer_dialects: Sequence[Dialect] | None = None,
        task_id: str | None = None,
        now_ms: int | None = None,
    ) -> RoutingCandidate:
        """Verify explicit target without multi-candidate ranking (§B.13)."""
        view = registry if registry is not None else self._registry
        observed = _now_ms() if now_ms is None else now_ms
        ids = self._lookup_target_ids(target, view)
        if not ids:
            raise RoutingError(
                "TARGET_UNAVAILABLE",
                "explicit target not found in registry",
                task_id=task_id,
                capability=capability,
                target=target,
                observed_at=_observed_at_iso(observed),
            )
        if len(ids) > 1:
            raise RoutingError(
                "AMBIGUOUS_TARGET",
                "target resolves to multiple agents",
                task_id=task_id,
                capability=capability,
                target=target,
                observed_at=_observed_at_iso(observed),
            )
        agent_id = ids[0]
        agents = [a for a in (view.get("agents") or []) if a.get("agent_id") == agent_id]
        if not agents:
            raise RoutingError(
                "TARGET_UNAVAILABLE",
                "explicit target not found in registry",
                task_id=task_id,
                capability=capability,
                target=target,
            )
        if len({(a.get("agent_id"), a.get("instance_id")) for a in agents}) > 1 and len(agents) > 1:
            # Conflicting unresolved identities for same agent_id.
            raise RoutingError(
                "AMBIGUOUS_TARGET",
                "conflicting registry identities for target",
                task_id=task_id,
                capability=capability,
                target=target,
            )
        agent = agents[0]
        mesh_member = agent.get("mesh_member")
        caps = list(agent.get("capabilities") or [])
        matching = [c for c in caps if capability_exact_match(str(c.get("name") or ""), capability)]
        if not matching:
            raise RoutingError(
                "CAPABILITY_NOT_ADVERTISED",
                "target does not advertise capability",
                task_id=task_id,
                capability=capability,
                target=target,
            )

        prefer = _prefer_dialect_order(prefer_dialects)
        usable: list[RoutingCandidate] = []
        a2a_only_unusable = False
        for adv in matching:
            dialect_raw = adv.get("dialect") or "native"
            if dialect_raw not in {"native", "a2a"}:
                continue
            dialect = cast(Dialect, dialect_raw)
            if dialect == "native":
                if mesh_member is False and not any(
                    (a.get("dialect") or "native") == "native" for a in matching
                ):
                    continue
                usable.append(
                    self._agent_to_candidate(agent, capability, dialect=dialect, a2a_url=None)
                )
            elif dialect == "a2a":
                a2a_url = adv.get("a2a_url")
                if not isinstance(a2a_url, str) or not a2a_url:
                    continue
                if not self._adapter_available:
                    a2a_only_unusable = True
                    continue
                usable.append(
                    self._agent_to_candidate(agent, capability, dialect=dialect, a2a_url=a2a_url)
                )

        if not usable:
            if a2a_only_unusable:
                raise RoutingError(
                    "DIALECT_UNSUPPORTED",
                    "a2a dialect requires an outbound bridge",
                    task_id=task_id,
                    capability=capability,
                    target=target,
                )
            raise RoutingError(
                "CAPABILITY_NOT_ADVERTISED",
                "no usable dialect advertisement for capability",
                task_id=task_id,
                capability=capability,
                target=target,
            )

        hint = agent.get("perm_hint")
        if hint == "deny":
            raise RoutingError(
                "TARGET_UNAVAILABLE",
                "caller denied by permission hint",
                task_id=task_id,
                capability=capability,
                target=target,
            )

        usable = [c for c in usable if c.get("dialect") in prefer] or usable
        ranked = stable_rank(
            usable,
            capability=capability,
            rr_state=self._rr_state,
            rr_lock=self._rr_lock,
            prefer_dialects=prefer,
            advance=True,
        )
        return ranked[0]

    def _lookup_target_ids(self, target: str, registry: RegistryView) -> list[str]:
        if not target:
            return []
        agents = list(registry.get("agents") or [])
        exact = sorted({str(a["agent_id"]) for a in agents if a.get("agent_id") == target})
        if exact:
            return exact
        expanded = self._canonical_expansion.get(target)
        if expanded:
            found = sorted({aid for aid in expanded if any(a.get("agent_id") == aid for a in agents)})
            return found
        return []

    def _agent_to_candidate(
        self,
        agent: RegistryAgentEntry | Mapping[str, Any],
        capability: str,
        *,
        dialect: Dialect,
        a2a_url: str | None,
    ) -> RoutingCandidate:
        health = cast(HealthState, agent.get("health") or "unknown")
        locality = cast(LocalityClass, agent.get("locality") or "unknown")
        last_seen_ms = _parse_last_seen_ms(agent.get("last_seen"))
        candidate: RoutingCandidate = {
            "agent_id": str(agent["agent_id"]),
            "capability": capability,
            "dialect": dialect,
            "locality": locality,
            "health": health,
            "healthy": health in _HEALTHY_STATES,
        }
        if agent.get("instance_id"):
            candidate["instance_id"] = str(agent["instance_id"])
        if last_seen_ms is not None:
            candidate["last_seen_ms"] = last_seen_ms
        if a2a_url:
            candidate["a2a_url"] = a2a_url
        if agent.get("perm_hint") in {"allow", "deny", "absent"}:
            candidate["perm_hint"] = cast(PermHint, agent["perm_hint"])
        return candidate

    def capability_route(
        self,
        *,
        capability: str,
        registry: RegistryView | None = None,
        excluded: set[str] | None = None,
        reroute_count: int = 0,
        prefer_dialects: Sequence[Dialect] | None = None,
        task_id: str | None = None,
        now_ms: int | None = None,
        advance_rr: bool = True,
    ) -> tuple[RoutingCandidate, TaskRoutedEvent, int]:
        """Sync selection path (§B.3). Returns (winner, task.routed, candidate_count)."""
        if "*" in capability:
            raise RoutingError(
                "INVALID_TASK",
                "capability for dispatch must be exact",
                task_id=task_id,
                capability=capability,
            )
        view = freeze_registry_view(registry if registry is not None else self._registry)
        observed = self._resolve_now_ms({"now_ms": now_ms} if now_ms is not None else None)
        observed_iso = _observed_at_iso(observed)
        exclude_set = set(excluded or ())
        if task_id:
            self._attempt_state[task_id] = RoutingAttemptState.COLLECTING

        raw = collect_candidates(view, capability)
        if task_id:
            self._attempt_state[task_id] = RoutingAttemptState.FILTERING
        if not raw:
            raise RoutingError(
                "NO_CANDIDATES",
                "no advertisers for capability",
                task_id=task_id,
                capability=capability,
                excluded_agents=exclusion_agent_ids(exclude_set),
                reroute_count=reroute_count,
                observed_at=observed_iso,
            )

        healthy = filter_health(
            raw,
            now_ms=observed,
            mark_stale_offline=self._mark_stale_offline,
            max_route_staleness_ms=self._max_route_staleness_ms,
        )
        if not healthy:
            raise RoutingError(
                "NO_CANDIDATES",
                "no healthy advertisers",
                task_id=task_id,
                capability=capability,
                excluded_agents=exclusion_agent_ids(exclude_set),
                reroute_count=reroute_count,
                observed_at=observed_iso,
            )

        allowed = filter_permission(healthy, self._caller_id, capability)
        if not allowed:
            raise RoutingError(
                "NO_CANDIDATES",
                "no authorized advertisers",
                task_id=task_id,
                capability=capability,
                excluded_agents=exclusion_agent_ids(exclude_set),
                reroute_count=reroute_count,
                observed_at=observed_iso,
            )

        candidate_count = len(allowed)
        remaining = [c for c in allowed if not _is_excluded(c, exclude_set)]
        if not remaining:
            code = "ALL_CANDIDATES_EXHAUSTED" if exclude_set else "NO_CANDIDATES"
            raise RoutingError(
                code,
                "all candidates excluded or failed" if exclude_set else "empty after filters",
                task_id=task_id,
                capability=capability,
                excluded_agents=exclusion_agent_ids(exclude_set),
                reroute_count=reroute_count,
                observed_at=observed_iso,
            )

        prefer = _prefer_dialect_order(prefer_dialects)
        remaining = [c for c in remaining if c.get("dialect") in prefer] or remaining
        if task_id:
            self._attempt_state[task_id] = RoutingAttemptState.RANKING
        ranked = stable_rank(
            remaining,
            capability=capability,
            rr_state=self._rr_state,
            rr_lock=self._rr_lock,
            prefer_dialects=prefer,
            advance=advance_rr,
        )
        winner = ranked[0]
        routed: TaskRoutedEvent = {
            "type": "task.routed",
            "task_id": task_id or "",
            "candidate_count": candidate_count,
            "chosen_agent": str(winner["agent_id"]),
            "dialect": cast(Dialect, winner["dialect"]),
            "reroute_count": reroute_count,
            "excluded_agents": exclusion_agent_ids(exclude_set),
            "capability": capability,
            "locality_tier": cast(LocalityClass, winner.get("locality") or "unknown"),
            "observed_at": observed_iso,
        }
        return winner, routed, candidate_count

    async def _capability_route_async(
        self,
        *,
        capability: str,
        registry: RegistryView,
        excluded: set[str],
        reroute_count: int,
        prefer_dialects: Sequence[Dialect],
        task_id: str,
        now_ms: int,
    ) -> tuple[RoutingCandidate, TaskRoutedEvent, int]:
        if "*" in capability:
            raise RoutingError(
                "INVALID_TASK",
                "capability for dispatch must be exact",
                task_id=task_id,
                capability=capability,
            )
        observed_iso = _observed_at_iso(now_ms)
        self._attempt_state[task_id] = RoutingAttemptState.COLLECTING
        raw = collect_candidates(registry, capability)
        raw = await self._apply_accept_hooks(raw, capability)
        self._attempt_state[task_id] = RoutingAttemptState.FILTERING
        if not raw:
            raise RoutingError(
                "NO_CANDIDATES",
                "no advertisers for capability",
                task_id=task_id,
                capability=capability,
                excluded_agents=exclusion_agent_ids(excluded),
                reroute_count=reroute_count,
                observed_at=observed_iso,
            )
        healthy = filter_health(
            raw,
            now_ms=now_ms,
            mark_stale_offline=self._mark_stale_offline,
            max_route_staleness_ms=self._max_route_staleness_ms,
        )
        if not healthy:
            raise RoutingError(
                "NO_CANDIDATES",
                "no healthy advertisers",
                task_id=task_id,
                capability=capability,
                excluded_agents=exclusion_agent_ids(excluded),
                reroute_count=reroute_count,
                observed_at=observed_iso,
            )
        allowed = filter_permission(healthy, self._caller_id, capability)
        if not allowed:
            raise RoutingError(
                "NO_CANDIDATES",
                "no authorized advertisers",
                task_id=task_id,
                capability=capability,
                excluded_agents=exclusion_agent_ids(excluded),
                reroute_count=reroute_count,
                observed_at=observed_iso,
            )
        candidate_count = len(allowed)
        remaining = [c for c in allowed if not _is_excluded(c, excluded)]
        if not remaining:
            code = "ALL_CANDIDATES_EXHAUSTED" if excluded else "NO_CANDIDATES"
            raise RoutingError(
                code,
                "all candidates excluded or failed" if excluded else "empty after filters",
                task_id=task_id,
                capability=capability,
                excluded_agents=exclusion_agent_ids(excluded),
                reroute_count=reroute_count,
                observed_at=observed_iso,
            )
        prefer = _prefer_dialect_order(prefer_dialects)
        remaining = [c for c in remaining if c.get("dialect") in prefer] or remaining
        self._attempt_state[task_id] = RoutingAttemptState.RANKING
        ranked = stable_rank(
            remaining,
            capability=capability,
            rr_state=self._rr_state,
            rr_lock=self._rr_lock,
            prefer_dialects=prefer,
            advance=True,
        )
        winner = ranked[0]
        routed: TaskRoutedEvent = {
            "type": "task.routed",
            "task_id": task_id,
            "candidate_count": candidate_count,
            "chosen_agent": str(winner["agent_id"]),
            "dialect": cast(Dialect, winner["dialect"]),
            "reroute_count": reroute_count,
            "excluded_agents": exclusion_agent_ids(excluded),
            "capability": capability,
            "locality_tier": cast(LocalityClass, winner.get("locality") or "unknown"),
            "observed_at": observed_iso,
        }
        return winner, routed, candidate_count

    async def route_task(
        self,
        options: RouteTaskOptions | Mapping[str, Any],
    ) -> dict[str, Any]:
        capability = str(options.get("capability") or "")
        payload = options.get("payload")
        task_id = str(options.get("task_id") or uuidv7())
        target = options.get("target")
        target_str = str(target).strip() if isinstance(target, str) and target.strip() else None
        max_reroutes = min(int(options.get("max_reroutes") or 3), 3)
        prefer_override = cast(Sequence[Dialect] | None, options.get("prefer_dialects"))

        self._attempt_state[task_id] = RoutingAttemptState.SUBMITTED
        prefer = await self._resolve_prefer_dialects(capability, prefer_override)
        snapshot = self.freeze_snapshot()
        observed = self._resolve_now_ms()

        if target_str:
            return await self._route_explicit(
                task_id=task_id,
                capability=capability,
                payload=payload,
                target=target_str,
                prefer_dialects=prefer,
                max_reroutes=max_reroutes,
                registry=snapshot,
                now_ms=observed,
            )

        return await self._route_capability(
            task_id=task_id,
            capability=capability,
            payload=payload,
            prefer_dialects=prefer,
            max_reroutes=max_reroutes,
            registry=snapshot,
            now_ms=observed,
            discovery_budget=1 if self._cold_start_policy == "lazy" else 0,
        )

    async def _route_explicit(
        self,
        *,
        task_id: str,
        capability: str,
        payload: Any,
        target: str,
        prefer_dialects: Sequence[Dialect],
        max_reroutes: int,
        registry: RegistryView,
        now_ms: int,
    ) -> dict[str, Any]:
        self._attempt_state[task_id] = RoutingAttemptState.ROUTING
        last_error: BaseException | None = None
        attempts = max(1, min(max_reroutes, 3))
        for attempt in range(attempts):
            try:
                chosen = self.explicit_target_verify(
                    target=target,
                    capability=capability,
                    registry=registry,
                    prefer_dialects=prefer_dialects,
                    task_id=task_id,
                    now_ms=now_ms,
                )
            except RoutingError:
                self._attempt_state[task_id] = RoutingAttemptState.EXHAUSTED
                raise

            routed: TaskRoutedEvent = {
                "type": "task.routed",
                "task_id": task_id,
                "candidate_count": 1,
                "chosen_agent": str(chosen["agent_id"]),
                "dialect": cast(Dialect, chosen["dialect"]),
                "reroute_count": 0,
                "excluded_agents": [],
                "capability": capability,
                "locality_tier": cast(LocalityClass, chosen.get("locality") or "unknown"),
                "observed_at": _observed_at_iso(now_ms),
            }
            self._emit_task_routed(routed)
            try:
                await self._dispatch(chosen, capability=capability, payload=payload, task_id=task_id)
                self._attempt_state[task_id] = RoutingAttemptState.SUCCEEDED
                return {"task_id": task_id, "chosen": chosen, "routed": routed}
            except Exception as exc:
                last_error = exc
                self._attempt_state[task_id] = RoutingAttemptState.FAILED
                if not is_retryable_failure(exc) or attempt + 1 >= attempts:
                    self._attempt_state[task_id] = RoutingAttemptState.EXHAUSTED
                    if isinstance(exc, RoutingError):
                        raise
                    raise RoutingError(
                        "TARGET_UNAVAILABLE",
                        str(exc),
                        task_id=task_id,
                        capability=capability,
                        target=target,
                        reroute_count=0,
                    ) from exc
                # Same-target retry only — no agent substitution (§B.7.5).
                continue

        self._attempt_state[task_id] = RoutingAttemptState.EXHAUSTED
        raise RoutingError(
            "TARGET_UNAVAILABLE",
            str(last_error) if last_error else "explicit target unavailable",
            task_id=task_id,
            capability=capability,
            target=target,
        )

    async def _route_capability(
        self,
        *,
        task_id: str,
        capability: str,
        payload: Any,
        prefer_dialects: Sequence[Dialect],
        max_reroutes: int,
        registry: RegistryView,
        now_ms: int,
        discovery_budget: int,
    ) -> dict[str, Any]:
        excluded: set[str] = set()
        reroute_count = 0
        last_error: BaseException | None = None
        self._attempt_state[task_id] = RoutingAttemptState.ROUTING

        while reroute_count < max_reroutes:
            try:
                prefer = prefer_dialects
                winner, routed, _count = await self._capability_route_async(
                    capability=capability,
                    registry=registry,
                    excluded=excluded,
                    reroute_count=reroute_count,
                    prefer_dialects=prefer,
                    task_id=task_id,
                    now_ms=now_ms,
                )
            except RoutingError as err:
                if (
                    err.code == "NO_CANDIDATES"
                    and discovery_budget > 0
                    and self._on_discover is not None
                ):
                    discovery_budget -= 1
                    await _maybe_await(self._on_discover())
                    registry = self.freeze_snapshot()
                    # Lazy discovery MUST NOT increment reroute_count.
                    continue
                self._attempt_state[task_id] = RoutingAttemptState.EXHAUSTED
                err.task_id = err.task_id or task_id
                err.capability = err.capability or capability
                err.reroute_count = reroute_count if err.reroute_count is None else err.reroute_count
                raise

            routed["task_id"] = task_id
            self._emit_task_routed(routed)
            self._attempt_state[task_id] = RoutingAttemptState.DISPATCHING
            try:
                await self._dispatch(winner, capability=capability, payload=payload, task_id=task_id)
                self._attempt_state[task_id] = RoutingAttemptState.SUCCEEDED
                return {"task_id": task_id, "chosen": winner, "routed": routed}
            except Exception as exc:
                last_error = exc
                self._attempt_state[task_id] = RoutingAttemptState.FAILED
                if not is_retryable_failure(exc):
                    self._attempt_state[task_id] = RoutingAttemptState.EXHAUSTED
                    if isinstance(exc, RoutingError):
                        raise
                    raise RoutingError(
                        getattr(exc, "code", None) or "ALL_CANDIDATES_EXHAUSTED",
                        str(exc),
                        task_id=task_id,
                        capability=capability,
                        excluded_agents=exclusion_agent_ids(excluded),
                        reroute_count=reroute_count,
                    ) from exc

                if reroute_count + 1 >= max_reroutes:
                    self._attempt_state[task_id] = RoutingAttemptState.EXHAUSTED
                    raise RoutingError(
                        "ALL_CANDIDATES_EXHAUSTED",
                        str(exc),
                        task_id=task_id,
                        capability=capability,
                        excluded_agents=exclusion_agent_ids(
                            excluded | {_candidate_exclusion_key(winner)}
                        ),
                        reroute_count=reroute_count,
                    ) from exc

                self._attempt_state[task_id] = RoutingAttemptState.REROUTING
                excluded.add(_candidate_exclusion_key(winner))
                # Also exclude all dialects for this agent_id.
                excluded.add(str(winner["agent_id"]))
                reason = _reroute_reason(exc)
                reroute_count += 1
                event: RerouteEvent = {
                    "task_id": task_id,
                    "failed_agent": str(winner["agent_id"]),
                    "reason": reason,
                    "attempt": reroute_count,
                    "excluded_agents": exclusion_agent_ids(excluded),
                }
                self._emit_reroute(event)
                continue

        self._attempt_state[task_id] = RoutingAttemptState.EXHAUSTED
        raise RoutingError(
            "ALL_CANDIDATES_EXHAUSTED",
            str(last_error) if last_error else "routing exhausted",
            task_id=task_id,
            capability=capability,
            excluded_agents=exclusion_agent_ids(excluded),
            reroute_count=reroute_count,
        )

    async def _dispatch(
        self,
        chosen: RoutingCandidate,
        *,
        capability: str,
        payload: Any,
        task_id: str,
    ) -> None:
        dialect = chosen.get("dialect") or "native"
        if dialect == "native":
            self._attempt_state[task_id] = RoutingAttemptState.WAITING
            if self._native_dispatch is not None:
                await _maybe_await(
                    self._native_dispatch(
                        {
                            "agent_id": chosen["agent_id"],
                            "capability": capability,
                            "payload": payload,
                            "task_id": task_id,
                            "instance_id": chosen.get("instance_id"),
                        }
                    )
                )
            self._attempt_state[task_id] = RoutingAttemptState.HANDOFF
            return

        if dialect == "a2a":
            bridge = self._a2a_bridge
            if bridge is None:
                raise RoutingError(
                    "DIALECT_UNSUPPORTED",
                    "a2a outbound bridge unbound",
                    task_id=task_id,
                    capability=capability,
                    details={"bridge": "BRIDGE_UNBOUND"},
                )
            a2a_url = chosen.get("a2a_url")
            if not a2a_url:
                raise RoutingError(
                    "DIALECT_UNSUPPORTED",
                    "a2a candidate missing a2a_url",
                    task_id=task_id,
                    capability=capability,
                )
            self._attempt_state[task_id] = RoutingAttemptState.WAITING
            send_input = {
                "a2a_url": a2a_url,
                "capability": capability,
                "payload": payload,
                "task_id": task_id,
            }
            if callable(bridge):
                try:
                    result = bridge(**send_input)
                except TypeError:
                    result = bridge(send_input)
                await _maybe_await(result)
            elif isinstance(bridge, Mapping) and callable(bridge.get("send")):
                await _maybe_await(bridge["send"](send_input))
            else:
                raise RoutingError(
                    "DIALECT_UNSUPPORTED",
                    "a2a outbound bridge unbound",
                    task_id=task_id,
                    capability=capability,
                    details={"bridge": "BRIDGE_UNBOUND"},
                )
            self._attempt_state[task_id] = RoutingAttemptState.HANDOFF
            return

        raise RoutingError(
            "DIALECT_UNSUPPORTED",
            f"unsupported dialect {dialect!r}",
            task_id=task_id,
            capability=capability,
        )


def _reroute_reason(error: Any) -> RerouteReason:
    blob = f"{getattr(error, 'code', '')} {error}".upper()
    if "TIMEOUT" in blob:
        return "timeout"
    if "UNHEALTHY" in blob:
        return "unhealthy"
    if "POLICY" in blob or "PERMISSION" in blob:
        return "policy_reject"
    if "REMOTE" in blob or "503" in blob or "502" in blob or "504" in blob:
        return "retryable_remote"
    return "retryable_transport"


def create_capability_router(**kwargs: Any) -> CapabilityRouter:
    return CapabilityRouter(**kwargs)


__all__ = [
    "CapabilityEntry",
    "CapabilityRouter",
    "ColdStartPolicy",
    "Dialect",
    "DialectPreferenceHooks",
    "HEARTBEAT_MS",
    "HealthState",
    "LEASE_TTL_MS",
    "LocalityClass",
    "PermHint",
    "ROUTING_ERROR_CODES",
    "RankCandidatesOptions",
    "RegistryAgentEntry",
    "RegistryView",
    "RerouteEvent",
    "RerouteReason",
    "RouteTaskOptions",
    "RoutingAttemptState",
    "RoutingCandidate",
    "RoutingError",
    "SelectCandidateOptions",
    "TaskRoutedEvent",
    "capability_exact_match",
    "capability_glob_match",
    "classify_retryability",
    "collect_candidates",
    "create_capability_router",
    "dialect_rank",
    "exclusion_agent_ids",
    "exclusion_key",
    "filter_health",
    "filter_permission",
    "freeze_registry_view",
    "freshness_bucket",
    "freshness_key",
    "is_retryable_failure",
    "locality_rank",
    "stable_rank",
]

"""A2A adapter: outbound orchestration (§A.9, §A.10, §A.12, §A.13, §A.17).

M2 covers the outbound half only -- mesh task in, ``tasks/send`` out, poll to a
terminal state, project the result back onto PolyMesh lifecycle vocabulary.
Inbound serving lands in M3.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
from typing import Any

from .auth_boundary import A2AAuthBoundary
from .config import load_a2a_config
from .errors import A2AError
from .event_log import AdapterEventLog
from .idempotency import IdempotencyStore
from .outbound_client import OutboundClient
from .poller import poll_until_terminal
from .task_translator import (
    A2A_STATE_TO_POLYMESH,
    MonotonicStateGate,
    TaskIdBijection,
    build_send_params,
    is_terminal_a2a_state,
    map_outbound_task_id,
    translate_task_event,
)
from .types import A2AAdapterConfig, AdapterEvent, OutboundResult

DEFAULT_TIMEOUT_MS = 60000


def _now_ms() -> int:
    return int(time.time() * 1000)


def _iso_from_ms(epoch_ms: int) -> str:
    return datetime.fromtimestamp(epoch_ms / 1000.0, tz=UTC).isoformat().replace("+00:00", "Z")


class A2AAdapter:
    """Owns the outbound A2A path for one PolyMesh agent."""

    def __init__(
        self,
        config: A2AAdapterConfig | Mapping[str, Any] | None = None,
        *,
        env: Mapping[str, str] | None = None,
        client: Any = None,
        outbound_client: OutboundClient | None = None,
        rng: Any = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
        now_ms: Callable[[], int] | None = None,
        on_request: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.config: A2AAdapterConfig = load_a2a_config(env, config)
        self._now_ms = now_ms or _now_ms
        self._sleep = sleep
        self._rng = rng
        self.redactions: list[dict[str, Any]] = []
        self.auth = A2AAuthBoundary(self.config, on_redaction=self.redactions.append)
        self.event_log = AdapterEventLog(
            path=self.config.get("event_log_path"),
            cap=int(self.config.get("event_log_cap", 1000)),
        )
        self.idempotency = IdempotencyStore(
            path=self.config.get("idempotency_store_path"),
            retention_ms=int(self.config.get("idempotency_retention_ms", 24 * 60 * 60 * 1000)),
            now_ms=self._now_ms,
        )
        self.task_ids = TaskIdBijection(self.config.get("task_id_store_path"))
        self.client = outbound_client or OutboundClient(
            config=self.config,
            auth=self.auth,
            client=client,
            on_request=on_request,
        )

    async def aclose(self) -> None:
        await self.client.aclose()

    async def __aenter__(self) -> A2AAdapter:
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.aclose()

    def get_events(self, task_id: str) -> list[AdapterEvent]:
        return self.event_log.get(task_id)

    def resolve_deadline_ms(self, *, deadline_ms: int | None = None, timeout_ms: int | None = None) -> int:
        if deadline_ms is not None:
            return int(deadline_ms)
        return self._now_ms() + int(timeout_ms if timeout_ms is not None else DEFAULT_TIMEOUT_MS)

    async def execute_outbound(
        self,
        *,
        a2a_url: str,
        capability: str,
        payload: Any,
        task_id: str,
        idempotency_key: str | None = None,
        principal_id: str | None = None,
        deadline_ms: int | None = None,
        timeout_ms: int | None = None,
        cancel_event: asyncio.Event | None = None,
    ) -> OutboundResult:
        """Run one outbound task end to end and project its terminal state."""

        self.auth.assert_trusted_endpoint(a2a_url)

        cached, keys = self.idempotency.check(
            capability_id=capability,
            payload=payload,
            task_id=task_id,
            principal_id=principal_id,
            idempotency_key=idempotency_key,
        )
        if cached is not None and cached.result is not None:
            return {**dict(cached.result), "cached": True}  # type: ignore[return-value]

        self.event_log.ensure(task_id)
        self.event_log.append(task_id, "outbound.begin", state="SUBMITTED")

        remote_task_id = map_outbound_task_id(task_id, store=self.task_ids)
        hygiene = self.auth.sanitize_outbound_payload(payload, task_id=task_id)
        if hygiene.redacted:
            self.event_log.append(
                task_id,
                "outbound.payload_redacted",
                payload={"redactions": [event.path for event in hygiene.redactions]},
            )

        resolved_deadline_ms = self.resolve_deadline_ms(deadline_ms=deadline_ms, timeout_ms=timeout_ms)
        params = build_send_params(
            remote_task_id=remote_task_id,
            capability=capability,
            payload=hygiene.value,
            idempotency_key=idempotency_key,
            deadline=_iso_from_ms(resolved_deadline_ms),
        )

        if cached is None:
            self.idempotency.store(keys, task_id, remote_task_id)

        try:
            accepted = await self.client.tasks_send(a2a_url, params, task_id=task_id)
        except A2AError as exc:
            self.event_log.append(
                task_id,
                "outbound.send_failed",
                state="FAILED",
                terminal=True,
                payload={"code": exc.code, "retryable": exc.retryable},
            )
            self.idempotency.forget(keys.dedup_key)
            raise

        bound_remote_id = accepted.get("id") if isinstance(accepted.get("id"), str) else remote_task_id
        self.task_ids.bind(task_id, str(bound_remote_id))
        self.event_log.append(task_id, "outbound.accepted", state="ACCEPTED")

        gate = MonotonicStateGate()
        send_state = accepted.get("status", {}).get("state") if isinstance(accepted.get("status"), Mapping) else None
        if isinstance(send_state, str) and send_state in A2A_STATE_TO_POLYMESH:
            gate.accept(send_state)

        snapshot: Mapping[str, Any] = accepted
        poll_count = 0
        if not is_terminal_a2a_state(send_state):
            try:
                snapshot, poll_count = await poll_until_terminal(
                    fetch=lambda: self.client.tasks_get(a2a_url, str(bound_remote_id), task_id=task_id),
                    task_id=task_id,
                    deadline_ms=resolved_deadline_ms,
                    cancel_event=cancel_event,
                    gate=gate,
                    rng=self._rng,
                    sleep=self._sleep,
                    now_ms=self._now_ms,
                    on_event=lambda event: self.event_log.append(
                        task_id,
                        "outbound.status",
                        state=event.get("state"),
                        payload={"progress": event.get("progress")} if event.get("progress") is not None else None,
                    ),
                )
            except A2AError as exc:
                self.event_log.append(
                    task_id,
                    "outbound.deadline" if exc.code == "DEADLINE" else "outbound.failed",
                    state="FAILED",
                    terminal=True,
                    payload={"code": exc.code, "retryable": exc.retryable},
                )
                raise

        event = translate_task_event(snapshot, task_id=task_id)
        result: OutboundResult = {
            "task_id": task_id,
            "remote_task_id": str(bound_remote_id),
            "state": event["state"],
            "a2a_state": event["a2a_state"],
            "poll_count": poll_count,
            "cached": False,
        }
        if "result" in event:
            result["result"] = event["result"]
        if event.get("error") is not None:
            result["error"] = event["error"]

        terminal_event = self.event_log.append(
            task_id,
            "outbound.terminal",
            state=event["state"],
            terminal=True,
            payload=result.get("error") or result.get("result"),
        )
        result["event_seq"] = terminal_event["event_seq"]
        self.idempotency.complete(keys.dedup_key, result)
        return result

    async def cancel_outbound(self, *, a2a_url: str, task_id: str) -> Mapping[str, Any]:
        """Best-effort remote cancel for a task already sent (§A.10.5)."""

        self.auth.assert_trusted_endpoint(a2a_url)
        remote_task_id = self.task_ids.remote_for(task_id) or task_id
        snapshot = await self.client.tasks_cancel(a2a_url, remote_task_id, task_id=task_id)
        self.event_log.append(task_id, "outbound.cancelled", state="CANCELLED", terminal=True)
        return snapshot

    def create_outbound_bridge(self) -> OutboundBridge:
        """Bridge object accepted by ``CapabilityRouter.set_a2a_outbound_bridge``."""

        return OutboundBridge(self)


class OutboundBridge(Mapping):
    """Adapter facade the routing engine drives (§E.2.3).

    ``CapabilityRouter`` calls a bridge either as ``bridge(**send_input)`` or as
    ``bridge["send"](send_input)``; both shapes land on :meth:`send`.
    """

    __slots__ = ("_adapter",)

    def __init__(self, adapter: A2AAdapter) -> None:
        self._adapter = adapter

    @property
    def adapter(self) -> A2AAdapter:
        return self._adapter

    async def send(self, input_map: Mapping[str, Any] | None = None, /, **kwargs: Any) -> OutboundResult:
        merged: dict[str, Any] = {**dict(input_map or {}), **kwargs}
        accepted = (
            "a2a_url",
            "capability",
            "payload",
            "task_id",
            "idempotency_key",
            "principal_id",
            "deadline_ms",
            "timeout_ms",
            "cancel_event",
        )
        call = {key: merged[key] for key in accepted if key in merged}
        result = await self._adapter.execute_outbound(**call)
        state = result.get("state")
        if state in {"FAILED", "REJECTED", "CANCELLED"}:
            error = result.get("error") or {}
            raise A2AError(
                str(error.get("code") or "EXECUTION_FAILED"),
                str(error.get("message") or "remote A2A task did not succeed"),
                retryable=bool(error.get("retryable", False)),
                task_id=str(result.get("task_id") or ""),
                details={"remote_task_id": result.get("remote_task_id")},
            )
        return result

    async def cancel(self, input_map: Mapping[str, Any] | None = None, /, **kwargs: Any) -> Mapping[str, Any]:
        merged: dict[str, Any] = {**dict(input_map or {}), **kwargs}
        return await self._adapter.cancel_outbound(
            a2a_url=merged["a2a_url"],
            task_id=merged["task_id"],
        )

    async def __call__(self, input_map: Mapping[str, Any] | None = None, /, **kwargs: Any) -> OutboundResult:
        return await self.send(input_map, **kwargs)

    def __getitem__(self, key: str) -> Any:
        if key == "send":
            return self.send
        if key == "cancel":
            return self.cancel
        raise KeyError(key)

    def __iter__(self) -> Any:
        return iter(("send", "cancel"))

    def __len__(self) -> int:
        return 2


def create_a2a_adapter(
    config: A2AAdapterConfig | Mapping[str, Any] | None = None,
    **kwargs: Any,
) -> A2AAdapter:
    return A2AAdapter(config, **kwargs)


def create_outbound_bridge(
    config: A2AAdapterConfig | Mapping[str, Any] | None = None,
    **kwargs: Any,
) -> OutboundBridge:
    """Build an adapter and return its router bridge in one step."""

    if isinstance(config, A2AAdapter):
        return config.create_outbound_bridge()
    return A2AAdapter(config, **kwargs).create_outbound_bridge()


__all__ = [
    "A2AAdapter",
    "DEFAULT_TIMEOUT_MS",
    "OutboundBridge",
    "create_a2a_adapter",
    "create_outbound_bridge",
]

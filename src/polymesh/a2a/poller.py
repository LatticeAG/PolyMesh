"""Status polling with the normative A2A backoff schedule (§A.10).

``delay = max(0, base + base * Uniform(-0.20, +0.20))`` where
``base = min(500 * 2**n, 15000)``.  Polling stops on a terminal state, the mesh
deadline, or cancellation; the wait itself is interruptible.
"""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Protocol

from .errors import A2AError
from .task_translator import MonotonicStateGate, is_terminal_a2a_state, translate_task_event
from .types import TranslatedTaskEvent

POLL_BASE_MS = 500
POLL_MAX_MS = 15000
POLL_JITTER_RATIO = 0.20


class _Rng(Protocol):
    def uniform(self, a: float, b: float) -> float: ...


def compute_poll_delay(n: int, rng: _Rng | None = None) -> float:
    """Poll delay in milliseconds for zero-based attempt index ``n`` (§A.10.2)."""

    if not isinstance(n, int) or isinstance(n, bool) or n < 0:
        raise ValueError("poll attempt index must be a non-negative integer")
    # 2 ** n on a large n is cheap in Python but pointless past the cap.
    base = POLL_MAX_MS if n >= 32 else min(POLL_BASE_MS * (2**n), POLL_MAX_MS)
    source = rng if rng is not None else random
    jitter = base * source.uniform(-POLL_JITTER_RATIO, POLL_JITTER_RATIO)
    return max(0.0, base + jitter)


def _now_ms() -> int:
    return int(time.time() * 1000)


async def _interruptible_sleep(
    delay_ms: float,
    *,
    sleep: Callable[[float], Awaitable[None]],
    cancel_event: asyncio.Event | None,
) -> bool:
    """Sleep ``delay_ms``; return True when cancellation interrupted the wait."""

    if cancel_event is not None and cancel_event.is_set():
        return True
    if delay_ms <= 0:
        return cancel_event is not None and cancel_event.is_set()
    if cancel_event is None:
        await sleep(delay_ms / 1000.0)
        return False
    waiter = asyncio.ensure_future(cancel_event.wait())
    sleeper = asyncio.ensure_future(sleep(delay_ms / 1000.0))
    try:
        done, pending = await asyncio.wait({waiter, sleeper}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in (waiter, sleeper):
            if not task.done():
                task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    return waiter in done


async def poll_until_terminal(
    *,
    fetch: Callable[[], Awaitable[Mapping[str, Any]]],
    task_id: str,
    deadline_ms: int | None = None,
    cancel_event: asyncio.Event | None = None,
    on_event: Callable[[TranslatedTaskEvent], None] | None = None,
    gate: MonotonicStateGate | None = None,
    rng: _Rng | None = None,
    sleep: Callable[[float], Awaitable[None]] | None = None,
    now_ms: Callable[[], int] | None = None,
    max_attempts: int | None = None,
) -> tuple[Mapping[str, Any], int]:
    """Poll ``fetch`` until the remote task is terminal (§A.10.3).

    Returns the terminal task snapshot and the number of polls performed.
    """

    clock = now_ms or _now_ms
    sleeper = sleep or asyncio.sleep
    state_gate = gate if gate is not None else MonotonicStateGate()
    attempt = 0
    poll_count = 0

    while True:
        if cancel_event is not None and cancel_event.is_set():
            raise A2AError("TASK_CANCELLED", "outbound A2A task cancelled by caller", task_id=task_id)
        if deadline_ms is not None and clock() >= deadline_ms:
            raise A2AError("DEADLINE", "outbound A2A task exceeded its mesh deadline", task_id=task_id)

        snapshot = await fetch()
        poll_count += 1
        state = snapshot.get("status", {}).get("state") if isinstance(snapshot, Mapping) else None
        if state_gate.accept(str(state)):
            event = translate_task_event(snapshot, task_id=task_id)
            if on_event is not None:
                on_event(event)
        if is_terminal_a2a_state(state):
            return snapshot, poll_count

        if max_attempts is not None and attempt + 1 >= max_attempts:
            raise A2AError("DEADLINE", "outbound A2A task exceeded its poll budget", task_id=task_id)

        delay_ms = compute_poll_delay(attempt, rng)
        if deadline_ms is not None:
            remaining = deadline_ms - clock()
            if remaining <= 0:
                raise A2AError("DEADLINE", "outbound A2A task exceeded its mesh deadline", task_id=task_id)
            delay_ms = min(delay_ms, float(remaining))
        if await _interruptible_sleep(delay_ms, sleep=sleeper, cancel_event=cancel_event):
            raise A2AError("TASK_CANCELLED", "outbound A2A task cancelled by caller", task_id=task_id)
        attempt += 1


__all__ = [
    "POLL_BASE_MS",
    "POLL_JITTER_RATIO",
    "POLL_MAX_MS",
    "compute_poll_delay",
    "poll_until_terminal",
]

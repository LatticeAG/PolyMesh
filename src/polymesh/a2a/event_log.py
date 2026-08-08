"""Adapter-owned per-task event log (§A.17).

Retention is bounded: the last ``cap`` non-terminal events plus the terminal
event, which is never evicted (§A.17.5).  Sequence numbers keep increasing
across eviction so a consumer can detect the gap.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .types import EVENT_LOG_CAP, AdapterEvent, PolyMeshTaskState


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + f".{int(time.time() * 1000) % 1000:03d}Z"


class AdapterEventLog:
    """Bounded per-task event ring with terminal-event preservation."""

    def __init__(
        self,
        *,
        path: str | os.PathLike[str] | None = None,
        cap: int = EVENT_LOG_CAP,
        clock: Callable[[], str] | None = None,
    ) -> None:
        if int(cap) <= 0:
            raise ValueError("event log cap must be positive")
        self._path = Path(path) if path is not None else None
        self._cap = int(cap)
        self._clock = clock or _iso_now
        self._events: dict[str, list[AdapterEvent]] = {}
        self._seq: dict[str, int] = {}
        self._lock = threading.Lock()
        self._load()

    @property
    def cap(self) -> int:
        return self._cap

    def ensure(self, task_id: str) -> None:
        with self._lock:
            self._events.setdefault(task_id, [])
            self._seq.setdefault(task_id, 0)

    def contains(self, task_id: str) -> bool:
        return task_id in self._events

    def last_seq(self, task_id: str) -> int:
        return self._seq.get(task_id, 0)

    def append(
        self,
        task_id: str,
        event_type: str,
        *,
        state: PolyMeshTaskState | None = None,
        payload: Any = None,
        terminal: bool = False,
    ) -> AdapterEvent:
        with self._lock:
            events = self._events.setdefault(task_id, [])
            seq = self._seq.get(task_id, 0) + 1
            self._seq[task_id] = seq
            event: AdapterEvent = {
                "task_id": task_id,
                "event_seq": seq,
                "type": event_type,
                "state": state,
                "terminal": bool(terminal),
                "observed_at": self._clock(),
            }
            if payload is not None:
                event["payload"] = payload
            events.append(event)
            self._events[task_id] = self._trim(events)
        self._persist()
        return event

    def _trim(self, events: list[AdapterEvent]) -> list[AdapterEvent]:
        non_terminal = [event for event in events if not event.get("terminal")]
        terminal = [event for event in events if event.get("terminal")]
        kept = non_terminal[-self._cap :] if len(non_terminal) > self._cap else non_terminal
        # Only the newest terminal event is retained; earlier ones are dead history.
        if terminal:
            kept = [*kept, terminal[-1]]
        return sorted(kept, key=lambda event: int(event.get("event_seq", 0)))

    def get(self, task_id: str) -> list[AdapterEvent]:
        return [dict(event) for event in self._events.get(task_id, [])]  # type: ignore[misc]

    def task_ids(self) -> list[str]:
        return list(self._events)

    def clear(self, task_id: str | None = None) -> None:
        with self._lock:
            if task_id is None:
                self._events.clear()
                self._seq.clear()
            else:
                self._events.pop(task_id, None)
                self._seq.pop(task_id, None)
        self._persist()

    def _load(self) -> None:
        if self._path is None or not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text("utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(raw, Mapping):
            return
        for task_id, body in raw.items():
            if not isinstance(body, Mapping):
                continue
            events = body.get("events")
            if isinstance(events, list):
                self._events[str(task_id)] = [event for event in events if isinstance(event, dict)]
            self._seq[str(task_id)] = int(body.get("seq", len(self._events.get(str(task_id), []))))

    def _persist(self) -> None:
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        snapshot = {
            task_id: {"events": events, "seq": self._seq.get(task_id, 0)}
            for task_id, events in self._events.items()
        }
        handle = tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=str(self._path.parent), delete=False, prefix=".a2a-events-"
        )
        try:
            handle.write(json.dumps(snapshot, separators=(",", ":"), default=str))
            handle.flush()
            os.fsync(handle.fileno())
        finally:
            handle.close()
        os.replace(handle.name, self._path)


__all__ = ["AdapterEventLog", "EVENT_LOG_CAP"]

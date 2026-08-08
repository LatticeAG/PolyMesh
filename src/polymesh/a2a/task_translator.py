"""Lifecycle translation between PolyMesh task states and A2A task states.

Covers §A.6 (state and progress mapping), §A.6.5 / §A.17.4 (shared task id
space with a durable bijection), and §A.10.6 (monotonic acceptance).
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from ..protocol import uuidv7
from .card_mapper import skill_name_from_capability_name
from .errors import A2ADialectError, error_from_a2a_task_error
from .types import A2ASendParams, A2ATaskState, PolyMeshTaskState, TranslatedTaskEvent

A2A_TERMINAL_STATES: frozenset[str] = frozenset({"completed", "failed", "canceled"})

#: §A.6.3 inverse: A2A state -> PolyMesh state.
A2A_STATE_TO_POLYMESH: dict[str, PolyMeshTaskState] = {
    "submitted": "SUBMITTED",
    "working": "RUNNING",
    "completed": "SUCCEEDED",
    "failed": "FAILED",
    "canceled": "CANCELLED",
}

#: §A.6.3 forward: PolyMesh state -> A2A state.
POLYMESH_STATE_TO_A2A: dict[str, A2ATaskState] = {
    "SUBMITTED": "submitted",
    "ACCEPTED": "working",
    "QUEUED": "working",
    "RUNNING": "working",
    "WAITING": "working",
    "REJECTED": "failed",
    "SUCCEEDED": "completed",
    "FAILED": "failed",
    "CANCELLED": "canceled",
}

#: Monotonic rank used by §A.10.6; terminal states share the top rank.
A2A_STATE_RANK: dict[str, int] = {
    "submitted": 0,
    "working": 1,
    "completed": 2,
    "failed": 2,
    "canceled": 2,
}

_UUID_HYPHEN_POSITIONS = (8, 13, 18, 23)


def is_terminal_a2a_state(state: str | None) -> bool:
    return str(state) in A2A_TERMINAL_STATES


def is_uuidv7(value: Any) -> bool:
    """True when ``value`` is a canonical UUIDv7 string (version nibble 7)."""

    if not isinstance(value, str) or len(value) != 36:
        return False
    if any(value[index] != "-" for index in _UUID_HYPHEN_POSITIONS):
        return False
    hex_only = value.replace("-", "")
    if len(hex_only) != 32:
        return False
    try:
        int(hex_only, 16)
    except ValueError:
        return False
    return value[14] == "7" and value[19].lower() in {"8", "9", "a", "b"}


class TaskIdBijection:
    """Durable ``local_task_id <-> remote_task_id`` mapping (§A.17.4)."""

    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        self._path = Path(path) if path is not None else None
        self._local_to_remote: dict[str, str] = {}
        self._remote_to_local: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if self._path is None or not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text("utf-8"))
        except (OSError, ValueError):
            return
        pairs = raw.get("pairs") if isinstance(raw, Mapping) else None
        if not isinstance(pairs, Mapping):
            return
        for local, remote in pairs.items():
            if isinstance(local, str) and isinstance(remote, str):
                self._local_to_remote[local] = remote
                self._remote_to_local[remote] = local

    def _persist(self) -> None:
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"pairs": self._local_to_remote}, separators=(",", ":"), sort_keys=True)
        handle = tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=str(self._path.parent), delete=False, prefix=".a2a-taskids-"
        )
        try:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        finally:
            handle.close()
        os.replace(handle.name, self._path)

    def remote_for(self, local_task_id: str) -> str | None:
        return self._local_to_remote.get(local_task_id)

    def local_for(self, remote_task_id: str) -> str | None:
        return self._remote_to_local.get(remote_task_id)

    def bind(self, local_task_id: str, remote_task_id: str) -> str:
        existing = self._local_to_remote.get(local_task_id)
        if existing == remote_task_id:
            return existing
        self._local_to_remote[local_task_id] = remote_task_id
        self._remote_to_local[remote_task_id] = local_task_id
        self._persist()
        return remote_task_id

    def __len__(self) -> int:
        return len(self._local_to_remote)


def map_outbound_task_id(
    task_id: str,
    *,
    store: TaskIdBijection | None = None,
    mint: Callable[[], str] | None = None,
) -> str:
    """UUIDv7 passthrough, else mint a UUIDv7 and reuse it on every retry."""

    if not isinstance(task_id, str) or not 1 <= len(task_id) <= 128:
        raise A2ADialectError("MALFORMED", "task_id must be a 1-128 character string")
    if is_uuidv7(task_id):
        return task_id
    if store is not None:
        existing = store.remote_for(task_id)
        if existing is not None:
            return existing
    minted = (mint or uuidv7)()
    if store is not None:
        store.bind(task_id, minted)
    return minted


def build_send_params(
    *,
    remote_task_id: str,
    capability: str,
    payload: Any,
    idempotency_key: str | None = None,
    deadline: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> A2ASendParams:
    """Build the ``tasks/send`` params for one outbound call (§A.9.2).

    The mesh capability id travels in metadata; the skill carries the stripped
    name so an A2A-native peer can route it (§A.5.1).
    """

    merged: dict[str, Any] = {"polymesh_capability_id": capability}
    if idempotency_key:
        merged["idempotency_key"] = idempotency_key
    if deadline:
        merged["deadline"] = deadline
    if metadata:
        merged.update(dict(metadata))
    return {
        "id": remote_task_id,
        "skill": skill_name_from_capability_name(capability),
        "message": {"role": "user", "parts": [{"type": "data", "data": payload}]},
        "metadata": merged,
    }


class MonotonicStateGate:
    """Reject regressive or post-terminal status updates (§A.10.6)."""

    def __init__(self) -> None:
        self._last_state: str | None = None
        self._last_rank: int = -1
        self._terminal = False

    @property
    def last_state(self) -> str | None:
        return self._last_state

    @property
    def terminal(self) -> bool:
        return self._terminal

    def accept(self, state: str) -> bool:
        rank = A2A_STATE_RANK.get(str(state))
        if rank is None:
            raise A2ADialectError("MALFORMED", f"unknown A2A task state {state!r}")
        if self._terminal:
            return False
        if rank < self._last_rank:
            return False
        self._last_state = str(state)
        self._last_rank = rank
        self._terminal = is_terminal_a2a_state(state)
        return True


def extract_artifact_result(task: Mapping[str, Any]) -> Any:
    """Pull the JSON result out of an A2A task's artifacts (§A.9.3)."""

    artifacts = task.get("artifacts")
    if not isinstance(artifacts, Sequence) or isinstance(artifacts, (str, bytes)):
        return None
    for artifact in artifacts:
        if not isinstance(artifact, Mapping):
            continue
        parts = artifact.get("parts")
        if not isinstance(parts, Sequence) or isinstance(parts, (str, bytes)):
            continue
        for part in parts:
            if not isinstance(part, Mapping):
                continue
            if "data" in part:
                return part["data"]
            text = part.get("text")
            if isinstance(text, str):
                try:
                    return json.loads(text)
                except ValueError:
                    return text
    return None


def _status_message(status: Mapping[str, Any]) -> str | None:
    message = status.get("message")
    if isinstance(message, str):
        return message
    if isinstance(message, Mapping):
        parts = message.get("parts")
        if isinstance(parts, Sequence) and not isinstance(parts, (str, bytes)):
            for part in parts:
                if isinstance(part, Mapping) and isinstance(part.get("text"), str):
                    return part["text"]
    return None


def translate_task_event(
    task: Mapping[str, Any],
    *,
    task_id: str,
    event_seq: int | None = None,
) -> TranslatedTaskEvent:
    """Project one remote A2A task snapshot onto a mesh lifecycle event."""

    if not isinstance(task, Mapping):
        raise A2ADialectError("MALFORMED", "A2A task snapshot must be an object")
    status = task.get("status")
    if not isinstance(status, Mapping):
        raise A2ADialectError("MALFORMED", "A2A task snapshot missing status object")
    state = status.get("state")
    if not isinstance(state, str) or state not in A2A_STATE_TO_POLYMESH:
        raise A2ADialectError("MALFORMED", f"unknown A2A task state {state!r}")

    mesh_state = A2A_STATE_TO_POLYMESH[state]
    hinted = task.get("metadata", {}).get("polymesh_state") if isinstance(task.get("metadata"), Mapping) else None
    if isinstance(hinted, str) and POLYMESH_STATE_TO_A2A.get(hinted) == state:
        mesh_state = hinted  # type: ignore[assignment]

    event: TranslatedTaskEvent = {
        "task_id": task_id,
        "state": mesh_state,
        "a2a_state": state,  # type: ignore[typeddict-item]
        "terminal": is_terminal_a2a_state(state),
    }
    remote_id = task.get("id")
    if isinstance(remote_id, str):
        event["remote_task_id"] = remote_id
    if event_seq is not None:
        event["event_seq"] = int(event_seq)

    progress = status.get("progress")
    if isinstance(progress, (int, float)) and not isinstance(progress, bool):
        event["progress"] = float(progress)
    message = _status_message(status)
    if message is not None:
        event["message"] = message

    if state == "completed":
        event["result"] = extract_artifact_result(task)
    elif state == "failed":
        error = status.get("error")
        mapped = error_from_a2a_task_error(error if isinstance(error, Mapping) else None, task_id=task_id)
        event["error"] = {
            "code": mapped.code,
            "message": str(mapped),
            "retryable": mapped.retryable,
            "json_rpc_code": mapped.json_rpc_code,
        }
    return event


__all__ = [
    "A2A_STATE_RANK",
    "A2A_STATE_TO_POLYMESH",
    "A2A_TERMINAL_STATES",
    "MonotonicStateGate",
    "POLYMESH_STATE_TO_A2A",
    "TaskIdBijection",
    "build_send_params",
    "extract_artifact_result",
    "is_terminal_a2a_state",
    "is_uuidv7",
    "map_outbound_task_id",
    "translate_task_event",
]

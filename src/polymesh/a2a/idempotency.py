"""Adapter-local outbound dedup store (§A.12).

The fingerprint is the dedup identity of one outbound call.  When the caller
supplies an ``idempotency_key`` the fingerprint MUST NOT include ``task_id``:
two retries of the same logical work carry different mesh task ids and still
have to collapse onto one remote execution (§A.12.2).
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .errors import A2AError
from .types import IDEMPOTENCY_RETENTION_MS, OutboundResult


def canonical_json(value: Any) -> str:
    """Stable JSON encoding used for every digest in this module."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def fingerprint_payload(
    *,
    capability_id: str,
    payload: Any,
    principal_id: str | None = None,
    task_id: str | None = None,
    include_task_id: bool = True,
) -> str:
    """Fingerprint one outbound call (§A.12.2)."""

    material: dict[str, Any] = {
        "principal_id": principal_id,
        "capability_id": capability_id,
        "input": payload,
    }
    if include_task_id:
        material["task_id"] = task_id
    return _sha256(canonical_json(material))


@dataclass
class DedupKeys:
    dedup_key: str
    fingerprint: str
    payload_digest: str
    includes_task_id: bool


@dataclass
class IdempotencyRecord:
    dedup_key: str
    fingerprint: str
    payload_digest: str
    task_id: str
    created_at_ms: int
    expires_at_ms: int
    remote_task_id: str | None = None
    result: OutboundResult | None = field(default=None)

    @classmethod
    def from_json(cls, raw: Mapping[str, Any]) -> IdempotencyRecord:
        return cls(
            dedup_key=str(raw["dedup_key"]),
            fingerprint=str(raw.get("fingerprint", "")),
            payload_digest=str(raw.get("payload_digest", "")),
            task_id=str(raw.get("task_id", "")),
            created_at_ms=int(raw.get("created_at_ms", 0)),
            expires_at_ms=int(raw.get("expires_at_ms", 0)),
            remote_task_id=raw.get("remote_task_id"),
            result=raw.get("result"),
        )


class IdempotencyStore:
    """In-memory dedup store with an optional JSON file for durability."""

    def __init__(
        self,
        *,
        path: str | os.PathLike[str] | None = None,
        retention_ms: int = IDEMPOTENCY_RETENTION_MS,
        now_ms: Callable[[], int] | None = None,
    ) -> None:
        self._path = Path(path) if path is not None else None
        self._retention_ms = int(retention_ms)
        self._now_ms = now_ms or (lambda: int(time.time() * 1000))
        self._records: dict[str, IdempotencyRecord] = {}
        self._load()

    @staticmethod
    def compute_keys(
        *,
        capability_id: str,
        payload: Any,
        task_id: str | None = None,
        principal_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> DedupKeys:
        include_task_id = not idempotency_key
        fingerprint = fingerprint_payload(
            capability_id=capability_id,
            payload=payload,
            principal_id=principal_id,
            task_id=task_id,
            include_task_id=include_task_id,
        )
        return DedupKeys(
            dedup_key=idempotency_key or fingerprint,
            fingerprint=fingerprint,
            payload_digest=_sha256(canonical_json(payload)),
            includes_task_id=include_task_id,
        )

    def lookup(self, dedup_key: str) -> IdempotencyRecord | None:
        self._purge_expired()
        return self._records.get(dedup_key)

    def check(
        self,
        *,
        capability_id: str,
        payload: Any,
        task_id: str,
        principal_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> tuple[IdempotencyRecord | None, DedupKeys]:
        """Return any live record for this call, rejecting key reuse (§A.12.3)."""

        keys = self.compute_keys(
            capability_id=capability_id,
            payload=payload,
            task_id=task_id,
            principal_id=principal_id,
            idempotency_key=idempotency_key,
        )
        existing = self.lookup(keys.dedup_key)
        if existing is None:
            return None, keys
        if existing.payload_digest != keys.payload_digest:
            raise A2AError(
                "IDEMPOTENCY_CONFLICT",
                "idempotency key reused with a different payload",
                task_id=task_id,
                details={"dedup_key": keys.dedup_key},
            )
        return existing, keys

    def store(self, keys: DedupKeys, task_id: str, remote_task_id: str | None = None) -> IdempotencyRecord:
        now = self._now_ms()
        record = IdempotencyRecord(
            dedup_key=keys.dedup_key,
            fingerprint=keys.fingerprint,
            payload_digest=keys.payload_digest,
            task_id=task_id,
            created_at_ms=now,
            expires_at_ms=now + self._retention_ms,
            remote_task_id=remote_task_id,
        )
        self._records[keys.dedup_key] = record
        self._persist()
        return record

    def complete(self, dedup_key: str, result: OutboundResult) -> None:
        record = self._records.get(dedup_key)
        if record is None:
            return
        record.result = dict(result)  # type: ignore[assignment]
        remote = result.get("remote_task_id")
        if isinstance(remote, str):
            record.remote_task_id = remote
        self._persist()

    def forget(self, dedup_key: str) -> None:
        if self._records.pop(dedup_key, None) is not None:
            self._persist()

    def __len__(self) -> int:
        return len(self._records)

    def _purge_expired(self) -> None:
        now = self._now_ms()
        expired = [key for key, record in self._records.items() if record.expires_at_ms <= now]
        for key in expired:
            del self._records[key]
        if expired:
            self._persist()

    def _load(self) -> None:
        if self._path is None or not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text("utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(raw, list):
            return
        for entry in raw:
            if isinstance(entry, Mapping) and entry.get("dedup_key"):
                record = IdempotencyRecord.from_json(entry)
                self._records[record.dedup_key] = record

    def _persist(self) -> None:
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps([asdict(record) for record in self._records.values()], separators=(",", ":"), default=str)
        handle = tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=str(self._path.parent), delete=False, prefix=".a2a-idem-"
        )
        try:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        finally:
            handle.close()
        os.replace(handle.name, self._path)


def payload_digest(value: Any) -> str:
    return _sha256(canonical_json(value))


def compute_fingerprint(
    *,
    principal_id: str | None,
    capability: str,
    payload: Any,
    task_id: str | None = None,
    idempotency_key: str | None = None,
) -> str:
    """Compatibility wrapper used by tests / adapter call sites."""

    return IdempotencyStore.compute_keys(
        capability_id=capability,
        payload=payload,
        task_id=task_id,
        principal_id=principal_id,
        idempotency_key=idempotency_key,
    ).fingerprint


__all__ = [
    "DedupKeys",
    "IdempotencyRecord",
    "IdempotencyStore",
    "canonical_json",
    "compute_fingerprint",
    "fingerprint_payload",
    "payload_digest",
]

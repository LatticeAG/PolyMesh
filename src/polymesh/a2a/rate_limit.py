"""Token bucket for inbound A2A binding (§A.16.1).

M2 ships the bucket itself; binding it to an inbound HTTP surface lands with
the inbound handler in M3.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from typing import Any

DEFAULT_CAPACITY = 20.0
DEFAULT_REFILL_PER_SEC = 5.0


class TokenBucket:
    """Simple monotonic-clock token bucket."""

    def __init__(
        self,
        *,
        capacity: float = DEFAULT_CAPACITY,
        refill_per_sec: float = DEFAULT_REFILL_PER_SEC,
        now: Callable[[], float] | None = None,
    ) -> None:
        if capacity <= 0 or refill_per_sec <= 0:
            raise ValueError("token bucket capacity and refill rate must be positive")
        self._capacity = float(capacity)
        self._refill_per_sec = float(refill_per_sec)
        self._now = now or time.monotonic
        self._tokens = float(capacity)
        self._updated_at = self._now()

    @property
    def tokens(self) -> float:
        self._refill()
        return self._tokens

    def _refill(self) -> None:
        now = self._now()
        elapsed = max(0.0, now - self._updated_at)
        self._updated_at = now
        self._tokens = min(self._capacity, self._tokens + elapsed * self._refill_per_sec)

    def try_consume(self, amount: float = 1.0) -> bool:
        self._refill()
        if self._tokens < amount:
            return False
        self._tokens -= amount
        return True

    def retry_after_ms(self, amount: float = 1.0) -> int:
        self._refill()
        deficit = max(0.0, amount - self._tokens)
        return int((deficit / self._refill_per_sec) * 1000)


def bucket_from_config(config: Mapping[str, Any] | None) -> TokenBucket | None:
    """Build a bucket from the ``rate_limit`` config block, or None if disabled."""

    settings = dict(config or {})
    if not settings.get("enabled", True):
        return None
    return TokenBucket(
        capacity=float(settings.get("capacity") or DEFAULT_CAPACITY),
        refill_per_sec=float(settings.get("refill_per_sec") or DEFAULT_REFILL_PER_SEC),
    )


__all__ = ["DEFAULT_CAPACITY", "DEFAULT_REFILL_PER_SEC", "TokenBucket", "bucket_from_config"]

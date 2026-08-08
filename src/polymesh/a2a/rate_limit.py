"""Inbound rate limiting -- M3 stub (§A.14).

Outbound calls are paced by the poll backoff, so M2 needs no admission control.
The token bucket is here so M3 can bind it to the inbound handler without
changing the package surface; it currently admits everything.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from typing import Any


class RateLimit:
    """Token bucket placeholder; ``allow`` is a no-op gate in M2."""

    def __init__(
        self,
        config: Mapping[str, Any] | None = None,
        *,
        now: Callable[[], float] | None = None,
    ) -> None:
        settings = dict(config or {})
        self.enabled = bool(settings.get("enabled", False))
        self.capacity = float(settings.get("capacity", 20.0))
        self.refill_per_sec = float(settings.get("refill_per_sec", 10.0))
        self._now = now or time.monotonic
        self._tokens = self.capacity
        self._updated = self._now()

    def allow(self, _key: str | None = None, cost: float = 1.0) -> bool:
        if not self.enabled:
            return True
        now = self._now()
        self._tokens = min(self.capacity, self._tokens + (now - self._updated) * self.refill_per_sec)
        self._updated = now
        if self._tokens < cost:
            return False
        self._tokens -= cost
        return True

    @property
    def tokens(self) -> float:
        return self._tokens


def create_rate_limit(config: Mapping[str, Any] | None = None, **kwargs: Any) -> RateLimit:
    return RateLimit(config, **kwargs)


__all__ = ["RateLimit", "create_rate_limit"]

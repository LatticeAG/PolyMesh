"""Hierarchical inbound token-bucket rate limiting (§A.16.1).

Buckets (capacity / refill-per-sec):
  - connection/IP: 60 / 1.0
  - principal: 30 / 0.5
  - capability × principal: 10 / 0.167
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from typing import Any

# Spec §A.16.1 defaults.
IP_CAPACITY = 60.0
IP_REFILL_PER_SEC = 1.0
PRINCIPAL_CAPACITY = 30.0
PRINCIPAL_REFILL_PER_SEC = 0.5
CAPABILITY_CAPACITY = 10.0
CAPABILITY_REFILL_PER_SEC = 0.167


class TokenBucket:
    """Single token bucket with continuous refill."""

    def __init__(
        self,
        capacity: float,
        refill_per_sec: float,
        *,
        now: Callable[[], float] | None = None,
    ) -> None:
        self.capacity = float(capacity)
        self.refill_per_sec = float(refill_per_sec)
        self._now = now or time.monotonic
        self._tokens = self.capacity
        self._updated = self._now()

    def _refill(self) -> None:
        now = self._now()
        elapsed = max(0.0, now - self._updated)
        if elapsed > 0:
            self._tokens = min(self.capacity, self._tokens + elapsed * self.refill_per_sec)
            self._updated = now

    @property
    def tokens(self) -> float:
        self._refill()
        return self._tokens

    def available(self, cost: float = 1.0) -> bool:
        self._refill()
        return self._tokens >= cost

    def try_consume(self, cost: float = 1.0) -> bool:
        self._refill()
        if self._tokens < cost:
            return False
        self._tokens -= cost
        return True


class KeyedTokenBuckets:
    """Per-key token buckets sharing capacity/refill parameters."""

    def __init__(
        self,
        capacity: float,
        refill_per_sec: float,
        *,
        now: Callable[[], float] | None = None,
    ) -> None:
        self.capacity = float(capacity)
        self.refill_per_sec = float(refill_per_sec)
        self._now = now or time.monotonic
        self._buckets: dict[str, TokenBucket] = {}

    def _bucket(self, key: str) -> TokenBucket:
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = TokenBucket(self.capacity, self.refill_per_sec, now=self._now)
            self._buckets[key] = bucket
        return bucket

    def available(self, key: str, cost: float = 1.0) -> bool:
        return self._bucket(key).available(cost)

    def try_consume(self, key: str, cost: float = 1.0) -> bool:
        return self._bucket(key).try_consume(cost)

    def tokens(self, key: str) -> float:
        return self._bucket(key).tokens


class RateLimit:
    """§A.16.1 hierarchical limiter. ``allow`` requires every applicable bucket."""

    def __init__(
        self,
        config: Mapping[str, Any] | None = None,
        *,
        now: Callable[[], float] | None = None,
    ) -> None:
        settings = dict(config or {})
        self.enabled = bool(settings.get("enabled", True))
        self._now = now or time.monotonic
        self.ip = KeyedTokenBuckets(
            float(settings.get("ip_capacity", IP_CAPACITY)),
            float(settings.get("ip_refill_per_sec", IP_REFILL_PER_SEC)),
            now=self._now,
        )
        self.principal = KeyedTokenBuckets(
            float(settings.get("principal_capacity", PRINCIPAL_CAPACITY)),
            float(settings.get("principal_refill_per_sec", PRINCIPAL_REFILL_PER_SEC)),
            now=self._now,
        )
        self.capability = KeyedTokenBuckets(
            float(settings.get("capability_capacity", CAPABILITY_CAPACITY)),
            float(settings.get("capability_refill_per_sec", CAPABILITY_REFILL_PER_SEC)),
            now=self._now,
        )
        # Legacy single-bucket fields kept for M2 config compatibility.
        self.capacity = float(settings.get("capacity", PRINCIPAL_CAPACITY))
        self.refill_per_sec = float(settings.get("refill_per_sec", PRINCIPAL_REFILL_PER_SEC))
        self._legacy = TokenBucket(self.capacity, self.refill_per_sec, now=self._now)

    def allow(
        self,
        key: str | None = None,
        cost: float = 1.0,
        *,
        ip: str | None = None,
        principal: str | None = None,
        capability: str | None = None,
    ) -> bool:
        """Admit one request. Prefer hierarchical keys; fall back to legacy ``key``."""

        if not self.enabled:
            return True

        # Hierarchical path (§A.16.1).
        if ip is not None or principal is not None:
            ip_key = ip or "unknown"
            principal_key = principal or "anonymous"
            buckets: list[tuple[KeyedTokenBuckets, str]] = [
                (self.ip, ip_key),
                (self.principal, principal_key),
            ]
            if capability:
                buckets.append((self.capability, f"{principal_key}|{capability}"))
            if not all(bucket.available(k, cost) for bucket, k in buckets):
                return False
            for bucket, k in buckets:
                bucket.try_consume(k, cost)
            return True

        # Legacy single-key path (M2 stub compatibility).
        if key is None:
            return self._legacy.try_consume(cost)
        return self.principal.try_consume(key, cost)

    @property
    def tokens(self) -> float:
        return self._legacy.tokens


def create_rate_limit(config: Mapping[str, Any] | None = None, **kwargs: Any) -> RateLimit:
    return RateLimit(config, **kwargs)


__all__ = [
    "CAPABILITY_CAPACITY",
    "CAPABILITY_REFILL_PER_SEC",
    "IP_CAPACITY",
    "IP_REFILL_PER_SEC",
    "PRINCIPAL_CAPACITY",
    "PRINCIPAL_REFILL_PER_SEC",
    "KeyedTokenBuckets",
    "RateLimit",
    "TokenBucket",
    "create_rate_limit",
]

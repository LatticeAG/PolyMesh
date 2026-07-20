"""Opt-in local card discovery helpers.

PolyMesh v0.1 has no discovery envelope. These objects deliberately only
return cards explicitly placed in a local cache/provider; they never treat a
hint as an enrollment or initiate a connection on its own.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable, Protocol

from .types import AgentCard


class DiscoveryProvider(Protocol):
    async def discover(self, *, refresh: bool = False, timeout: float = 2.0) -> list[AgentCard]:
        """Return locally configured card hints, without connecting to them."""


class CardCache:
    """A small, process-local, explicit discovery cache.

    Inserting a card validates its structural shape through ``AgentCard`` but
    does not claim that its identity is enrolled or that its endpoint is
    trusted. Callers still need normal handshake/authentication before use.
    """

    def __init__(self, cards: Iterable[AgentCard] = ()) -> None:
        self._cards: dict[tuple[str, str], AgentCard] = {}
        self.update(cards)

    def update(self, cards: Iterable[AgentCard]) -> None:
        for card in cards:
            validated = AgentCard.model_validate(card)
            self._cards[(validated.agent_id, validated.instance_id)] = validated

    def remove(self, agent_id: str, instance_id: str) -> bool:
        return self._cards.pop((agent_id, instance_id), None) is not None

    def snapshot(self) -> list[AgentCard]:
        return [self._cards[key] for key in sorted(self._cards)]

    async def discover(self, *, refresh: bool = False, timeout: float = 2.0) -> list[AgentCard]:
        if timeout <= 0:
            raise ValueError("discovery timeout must be positive")
        # Keep the async surface compatible with future providers while doing
        # no implicit I/O in the v0.1 cache implementation.
        await asyncio.sleep(0)
        return self.snapshot()


class StaticDiscoveryProvider(CardCache):
    """Named alias for a cache supplied directly by an application."""


__all__ = ["CardCache", "DiscoveryProvider", "StaticDiscoveryProvider"]

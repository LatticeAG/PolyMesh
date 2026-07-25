"""Stable public surface for the PolyMesh Python SDK.

Implementation modules intentionally remain importable independently during
embedding and tests.  Client names are resolved lazily so importing a wire
model never opens a transport or creates an asyncio dependency cycle.
"""

from __future__ import annotations

from typing import Any

from .errors import PolyMeshError
from .types import (
    AgentCard,
    AgentCardBuilder,
    AgentIdentity,
    AgentRef,
    Capability,
    CapabilityBuilder,
    Delivery,
    DeliveryMode,
    Envelope,
    TaskStatus,
)

__all__ = [
    "AgentCard",
    "AgentCardBuilder",
    "AgentIdentity",
    "AgentRef",
    "Capability",
    "CapabilityBuilder",
    "Client",
    "Delivery",
    "DeliveryMode",
    "Envelope",
    "GatewayDiscoverResult",
    "GatewayTransport",
    "GatewayTransportError",
    "PolyMeshClient",
    "PolyMeshError",
    "TaskContext",
    "TaskHandle",
    "TaskStatus",
]


def __getattr__(name: str) -> Any:
    if name in {"PolyMeshClient", "Client", "TaskContext", "TaskHandle"}:
        from .client import Client, PolyMeshClient, TaskContext, TaskHandle

        values = {
            "PolyMeshClient": PolyMeshClient,
            "Client": Client,
            "TaskContext": TaskContext,
            "TaskHandle": TaskHandle,
        }
        globals().update(values)
        return values[name]
    if name in {"GatewayTransport", "GatewayTransportError", "GatewayDiscoverResult"}:
        from .gateway_transport import GatewayDiscoverResult, GatewayTransport, GatewayTransportError

        values = {
            "GatewayTransport": GatewayTransport,
            "GatewayTransportError": GatewayTransportError,
            "GatewayDiscoverResult": GatewayDiscoverResult,
        }
        globals().update(values)
        return values[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

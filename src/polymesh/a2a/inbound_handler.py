"""Inbound A2A ingress (``tasks/send``, ``tasks/get``, ``tasks/cancel``).

Deliberately unimplemented in M2: the outbound milestone ships no listening
socket.  The inbound JSON-RPC surface, AgentCard publication, and rate-limit
binding land in M3.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

_M3 = "M3"


class A2AInboundHandler:
    """Placeholder for the M3 inbound JSON-RPC handler."""

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise NotImplementedError(_M3)


async def handle_json_rpc(_request: Mapping[str, Any], **_kwargs: Any) -> dict[str, Any]:
    raise NotImplementedError(_M3)


async def start_inbound_server(*_args: Any, **_kwargs: Any) -> None:
    raise NotImplementedError(_M3)


__all__ = ["A2AInboundHandler", "handle_json_rpc", "start_inbound_server"]

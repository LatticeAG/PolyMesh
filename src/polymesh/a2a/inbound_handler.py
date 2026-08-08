"""Inbound A2A JSON-RPC handler -- M3.

The module exists in M2 so the package tree matches §E.1 and so callers get a
coded failure instead of an ``ImportError`` if they wire inbound too early.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .errors import A2ADialectError

M3_MESSAGE = "inbound A2A serving arrives in M3; only the outbound path is implemented"


class InboundHandler:
    """Placeholder for the inbound JSON-RPC surface (§A.8)."""

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        self.enabled = False

    async def handle(self, _request: Mapping[str, Any] | None = None) -> Any:
        raise A2ADialectError("UNSUPPORTED_METHOD", M3_MESSAGE)

    async def handle_card_request(self) -> Any:
        raise A2ADialectError("UNSUPPORTED_METHOD", M3_MESSAGE)


def create_inbound_handler(*args: Any, **kwargs: Any) -> InboundHandler:
    return InboundHandler(*args, **kwargs)


__all__ = ["InboundHandler", "M3_MESSAGE", "create_inbound_handler"]

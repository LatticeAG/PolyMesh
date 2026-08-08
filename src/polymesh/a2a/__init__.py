"""PolyMesh A2A leaf-dialect adapter (WIRE). Outbound M2; inbound M3."""

from __future__ import annotations

from .adapter import A2AAdapter
from .auth_boundary import (
    A2AAuthBoundary,
    REDACTED,
    redact_credentials,
)
from .card_mapper import (
    map_card_from_a2a,
    map_card_to_a2a,
    skill_name_from_capability_name,
)
from .config import load_a2a_config, redact_config
from .errors import A2ADialectError, A2AError, ERROR_TABLE
from .event_log import AdapterEventLog
from .idempotency import IdempotencyStore, compute_fingerprint
from .mock_server import MockA2AServer
from .outbound_client import OutboundA2AClient, OutboundClient
from .poller import compute_poll_delay, poll_until_terminal
from .task_translator import (
    MonotonicStateGate,
    TaskIdBijection,
    is_uuidv7,
    map_outbound_task_id,
    translate_task_event,
)
from .types import A2AAdapterConfig

# Spec / Part E aliases
load_a2a_adapter_config = load_a2a_config
assert_safe_to_log_config = redact_config
redact_text = lambda s: redact_credentials(s).value  # noqa: E731
redact_value = lambda v: redact_credentials(v).value  # noqa: E731

__all__ = [
    "A2AAdapter",
    "A2AAdapterConfig",
    "A2AAuthBoundary",
    "A2ADialectError",
    "A2AError",
    "AdapterEventLog",
    "ERROR_TABLE",
    "IdempotencyStore",
    "MockA2AServer",
    "MonotonicStateGate",
    "OutboundA2AClient",
    "REDACTED",
    "TaskIdBijection",
    "assert_safe_to_log_config",
    "compute_fingerprint",
    "compute_poll_delay",
    "is_uuidv7",
    "load_a2a_adapter_config",
    "load_a2a_config",
    "map_card_from_a2a",
    "map_card_to_a2a",
    "map_outbound_task_id",
    "poll_until_terminal",
    "redact_config",
    "redact_credentials",
    "redact_text",
    "redact_value",
    "skill_name_from_capability_name",
    "translate_task_event",
]

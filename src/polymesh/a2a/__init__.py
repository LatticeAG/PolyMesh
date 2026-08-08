"""PolyMesh A2A leaf adapter (PM-V6-SPEC Part A).

M2 ships the outbound path: a PolyMesh task is projected onto an A2A
``tasks/send`` call, polled to a terminal state, and translated back into mesh
lifecycle vocabulary.  Inbound serving is stubbed for M3.

The adapter is a leaf: it depends on the PolyMesh product layer, never the
reverse, and A2A credentials terminate here (§A.13).
"""

from __future__ import annotations

from .adapter import (
    A2AAdapter,
    OutboundBridge,
    create_a2a_adapter,
    create_outbound_bridge,
)
from .auth_boundary import (
    MESH_CREDENTIAL_HEADERS,
    A2AAuthBoundary,
    credential_thumbprint,
    map_to_mesh_trust_scope,
    redact_credentials,
)
from .card_mapper import (
    FIDELITY_CLAUSE,
    INBOUND_PUBLISH_DENYLIST,
    POLYMESH_CAPABILITY_PREFIX,
    capability_name_from_skill_name,
    is_publishable_skill,
    map_capabilities_to_skills,
    map_capability_to_skill,
    map_card_from_a2a,
    map_card_to_a2a,
    skill_name_from_capability_name,
)
from .config import (
    DEFAULT_CONFIG,
    load_a2a_config,
    normalize_trusted_endpoint,
    redact_config,
)
from .errors import (
    ERROR_TABLE,
    A2AConfigError,
    A2ADialectError,
    A2AError,
    error_from_a2a_task_error,
    error_from_http_status,
    error_from_json_rpc,
    error_from_transport,
    is_retryable_code,
    json_rpc_code_for,
    normalize_code,
)
from .event_log import AdapterEventLog
from .idempotency import IdempotencyStore, canonical_json, compute_fingerprint, fingerprint_payload
from .inbound_handler import InboundHandler, create_inbound_handler, project_mesh_to_a2a_task
from .jsonrpc import build_request, extract_result, parse_response_body
from .mock_server import MockA2AServer, create_mock_a2a_server
from .outbound_client import OutboundClient
from .poller import POLL_BASE_MS, POLL_JITTER_RATIO, POLL_MAX_MS, compute_poll_delay, poll_until_terminal
from .rate_limit import (
    CAPABILITY_CAPACITY,
    CAPABILITY_REFILL_PER_SEC,
    IP_CAPACITY,
    IP_REFILL_PER_SEC,
    PRINCIPAL_CAPACITY,
    PRINCIPAL_REFILL_PER_SEC,
    RateLimit,
    create_rate_limit,
)
from .task_translator import (
    A2A_STATE_TO_POLYMESH,
    POLYMESH_STATE_TO_A2A,
    MonotonicStateGate,
    TaskIdBijection,
    build_send_params,
    extract_artifact_result,
    is_terminal_a2a_state,
    is_uuidv7,
    map_outbound_task_id,
    translate_task_event,
)
from .types import EVENT_LOG_CAP, IDEMPOTENCY_RETENTION_MS

__all__ = [
    "A2A_STATE_TO_POLYMESH",
    "A2AAdapter",
    "A2AAuthBoundary",
    "A2AConfigError",
    "A2ADialectError",
    "A2AError",
    "AdapterEventLog",
    "CAPABILITY_CAPACITY",
    "CAPABILITY_REFILL_PER_SEC",
    "DEFAULT_CONFIG",
    "ERROR_TABLE",
    "EVENT_LOG_CAP",
    "FIDELITY_CLAUSE",
    "IDEMPOTENCY_RETENTION_MS",
    "INBOUND_PUBLISH_DENYLIST",
    "IP_CAPACITY",
    "IP_REFILL_PER_SEC",
    "IdempotencyStore",
    "InboundHandler",
    "MESH_CREDENTIAL_HEADERS",
    "MockA2AServer",
    "MonotonicStateGate",
    "POLL_BASE_MS",
    "POLL_JITTER_RATIO",
    "POLL_MAX_MS",
    "POLYMESH_CAPABILITY_PREFIX",
    "POLYMESH_STATE_TO_A2A",
    "PRINCIPAL_CAPACITY",
    "PRINCIPAL_REFILL_PER_SEC",
    "OutboundBridge",
    "OutboundClient",
    "RateLimit",
    "TaskIdBijection",
    "build_request",
    "build_send_params",
    "canonical_json",
    "capability_name_from_skill_name",
    "compute_fingerprint",
    "compute_poll_delay",
    "create_a2a_adapter",
    "create_inbound_handler",
    "create_mock_a2a_server",
    "create_outbound_bridge",
    "create_rate_limit",
    "credential_thumbprint",
    "error_from_a2a_task_error",
    "error_from_http_status",
    "error_from_json_rpc",
    "error_from_transport",
    "extract_artifact_result",
    "extract_result",
    "fingerprint_payload",
    "is_publishable_skill",
    "is_retryable_code",
    "is_terminal_a2a_state",
    "is_uuidv7",
    "json_rpc_code_for",
    "load_a2a_config",
    "map_capabilities_to_skills",
    "map_capability_to_skill",
    "map_card_from_a2a",
    "map_card_to_a2a",
    "map_outbound_task_id",
    "map_to_mesh_trust_scope",
    "normalize_code",
    "normalize_trusted_endpoint",
    "parse_response_body",
    "poll_until_terminal",
    "project_mesh_to_a2a_task",
    "redact_config",
    "redact_credentials",
    "skill_name_from_capability_name",
    "translate_task_event",
]

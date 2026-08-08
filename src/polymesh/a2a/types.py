"""Dialect-local types for the A2A leaf adapter.

These records describe the A2A wire shapes and the adapter's own projection of
them.  They never re-export PolyMesh client internals: the adapter depends on
the product layer, not the other way around.
"""

from __future__ import annotations

from typing import Any, Literal, TypedDict


#: Per-task adapter event retention before the terminal event (§A.17.5).
EVENT_LOG_CAP = 1000

#: Idempotency record retention (§A.12.3).
IDEMPOTENCY_RETENTION_MS = 24 * 60 * 60 * 1000

A2ATaskState = Literal["submitted", "working", "completed", "failed", "canceled"]

PolyMeshTaskState = Literal[
    "SUBMITTED",
    "ACCEPTED",
    "QUEUED",
    "RUNNING",
    "WAITING",
    "REJECTED",
    "SUCCEEDED",
    "FAILED",
    "CANCELLED",
]

AuthMode = Literal["none", "bearer", "api_key_header"]


class A2AAuthConfig(TypedDict, total=False):
    """Outbound credential material for one adapter (§E.13.1)."""

    mode: AuthMode
    token: str
    token_file: str
    header_name: str


class A2ARateLimitConfig(TypedDict, total=False):
    enabled: bool
    capacity: float
    refill_per_sec: float


class TrustedEndpoint(TypedDict, total=False):
    """One operator-declared outbound endpoint identity (§A.13.3.1).

    ``match`` selects how a discovered ``a2a_url`` is compared against ``url``:
    ``exact`` (path equality), ``prefix`` (path prefix), or ``origin``.
    """

    url: str
    match: Literal["exact", "prefix", "origin"]
    auth: A2AAuthConfig


class A2AAdapterConfig(TypedDict, total=False):
    """Adapter configuration per §E.13.1 plus outbound trust additions."""

    enabled: bool
    inbound_enabled: bool
    outbound_enabled: bool
    a2a_url: str
    listen_host: str
    listen_port: int
    public_card_path: str
    jsonrpc_path: str
    sse_enabled: bool
    poll_max_ms: int
    auth: A2AAuthConfig
    rate_limit: A2ARateLimitConfig
    idempotency_store_path: str
    idempotency_retention_ms: int
    trusted_endpoints: list[str | TrustedEndpoint]
    allow_wildcard_endpoints: bool
    allow_public_unauthenticated: bool
    event_log_cap: int
    event_log_path: str
    request_timeout_ms: int
    task_id_store_path: str


class A2AMessagePart(TypedDict, total=False):
    type: str
    data: Any
    text: str
    mimeType: str


class A2AMessage(TypedDict, total=False):
    role: str
    parts: list[A2AMessagePart]


class A2AArtifact(TypedDict, total=False):
    name: str
    parts: list[A2AMessagePart]


class A2AErrorObject(TypedDict, total=False):
    code: str
    message: str
    data: dict[str, Any]


class A2ATaskStatus(TypedDict, total=False):
    state: A2ATaskState
    progress: float
    message: A2AMessage | str
    error: A2AErrorObject
    timestamp: str


class A2ATask(TypedDict, total=False):
    id: str
    sessionId: str
    status: A2ATaskStatus
    artifacts: list[A2AArtifact]
    metadata: dict[str, Any]


class A2ASendParams(TypedDict, total=False):
    id: str
    skill: str
    message: A2AMessage
    metadata: dict[str, Any]


class TranslatedTaskEvent(TypedDict, total=False):
    """Adapter projection of one remote status observation."""

    task_id: str
    remote_task_id: str
    state: PolyMeshTaskState
    a2a_state: A2ATaskState
    terminal: bool
    event_seq: int
    progress: float | None
    message: str | None
    result: Any
    error: dict[str, Any] | None


class AdapterEvent(TypedDict, total=False):
    """One entry of the adapter-owned per-task event log (§A.17)."""

    task_id: str
    event_seq: int
    type: str
    state: PolyMeshTaskState | None
    terminal: bool
    payload: Any
    observed_at: str


class OutboundSendInput(TypedDict, total=False):
    """Payload handed to the bridge by ``CapabilityRouter`` (§E.2.3)."""

    a2a_url: str
    capability: str
    payload: Any
    task_id: str
    idempotency_key: str
    principal_id: str
    deadline_ms: int


class OutboundResult(TypedDict, total=False):
    """Value returned by :meth:`polymesh.a2a.A2AAdapter.execute_outbound`."""

    task_id: str
    remote_task_id: str
    state: PolyMeshTaskState
    a2a_state: A2ATaskState
    result: Any
    error: dict[str, Any] | None
    event_seq: int
    poll_count: int
    cached: bool


class A2ASkill(TypedDict, total=False):
    name: str
    description: str
    inputModes: list[str]
    outputModes: list[str]
    inputSchema: dict[str, Any]
    outputSchema: dict[str, Any]
    tags: list[str]
    metadata: dict[str, Any]


class A2AAgentCard(TypedDict, total=False):
    name: str
    description: str
    url: str
    version: str
    capabilities: dict[str, Any]
    skills: list[A2ASkill]
    metadata: dict[str, Any]


__all__ = [
    "A2AAdapterConfig",
    "A2AAgentCard",
    "A2AArtifact",
    "A2AAuthConfig",
    "A2AErrorObject",
    "A2AMessage",
    "A2AMessagePart",
    "A2ARateLimitConfig",
    "A2ASendParams",
    "A2ASkill",
    "A2ATask",
    "A2ATaskState",
    "A2ATaskStatus",
    "AdapterEvent",
    "AuthMode",
    "EVENT_LOG_CAP",
    "IDEMPOTENCY_RETENTION_MS",
    "OutboundResult",
    "OutboundSendInput",
    "PolyMeshTaskState",
    "TranslatedTaskEvent",
    "TrustedEndpoint",
]

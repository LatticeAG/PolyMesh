"""A2A / JSON-RPC / PolyMesh error mapping (§A.11).

Every failure the adapter surfaces to the routing engine carries a PolyMesh
code, the JSON-RPC code an A2A peer would see, and the retryable default from
the master table.  Raw HTTP status codes never escape this module.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, NamedTuple

from ..errors import PolyMeshError


class ErrorTableEntry(NamedTuple):
    json_rpc_code: int
    retryable: bool
    message: str
    category: str


#: §A.11.1 master table, keyed by PolyMesh code.
ERROR_TABLE: dict[str, ErrorTableEntry] = {
    "UNSUPPORTED_CAPABILITY": ErrorTableEntry(-32601, False, "Skill unsupported", "protocol"),
    "UNSUPPORTED_METHOD": ErrorTableEntry(-32601, False, "Method not found", "protocol"),
    "AUTHORIZATION_DENIED": ErrorTableEntry(-32001, False, "Authorization denied", "identity"),
    "AUTHENTICATION_FAILED": ErrorTableEntry(-32001, False, "Authentication failed", "identity"),
    "RATE_LIMITED": ErrorTableEntry(-32002, True, "Rate limited", "resource"),
    "OVERLOADED": ErrorTableEntry(-32002, True, "Overloaded", "resource"),
    "QUOTA_EXCEEDED": ErrorTableEntry(-32002, True, "Quota exceeded", "resource"),
    "MALFORMED": ErrorTableEntry(-32600, False, "Invalid request", "parse"),
    "MALFORMED_JSON": ErrorTableEntry(-32700, False, "Parse error", "parse"),
    "MALFORMED_FRAME": ErrorTableEntry(-32600, False, "Invalid request", "parse"),
    "INTERNAL": ErrorTableEntry(-32603, False, "Internal error", "internal"),
    "TASK_NOT_FOUND": ErrorTableEntry(-32004, False, "Task not found", "task"),
    "DEADLINE": ErrorTableEntry(-32005, False, "Deadline exceeded", "timeout"),
    "IDEMPOTENCY_CONFLICT": ErrorTableEntry(-32006, False, "Idempotency conflict", "delivery"),
    "UNKNOWN_TARGET": ErrorTableEntry(-32007, False, "Unknown target", "routing"),
    "TARGET_UNAVAILABLE": ErrorTableEntry(-32008, True, "Target unavailable", "routing"),
    "EXECUTION_FAILED": ErrorTableEntry(-32009, False, "Execution failed", "execution"),
    "DEPENDENCY_FAILED": ErrorTableEntry(-32009, False, "Dependency failed", "execution"),
    "RESULT_TOO_LARGE": ErrorTableEntry(-32010, False, "Result too large", "execution"),
    "CANCEL_NOT_SUPPORTED": ErrorTableEntry(-32011, False, "Cancel not supported", "task"),
    "TASK_CONFLICT": ErrorTableEntry(-32012, False, "Task conflict", "task"),
    "TASK_CANCELLED": ErrorTableEntry(-32603, False, "Task cancelled", "task"),
    "UNSUPPORTED_PROTOCOL_VERSION": ErrorTableEntry(-32600, False, "Invalid request", "protocol"),
    "SCHEMA_VALIDATION_FAILED": ErrorTableEntry(-32600, False, "Invalid request", "protocol"),
    "BRIDGE_UNBOUND": ErrorTableEntry(-32603, False, "A2A outbound bridge unbound", "internal"),
}

#: Aliases accepted from mesh-side or peer-supplied payloads.
CODE_ALIASES: dict[str, str] = {
    "INTERNAL_ERROR": "INTERNAL",
    "PMX.TASK.NOT_FOUND": "TASK_NOT_FOUND",
    "PMX.TASK.DEADLINE_EXCEEDED": "DEADLINE",
    "PMX.TASK.CONFLICT": "TASK_CONFLICT",
    "PMX.DELIVERY.IDEMPOTENCY_CONFLICT": "IDEMPOTENCY_CONFLICT",
    "PMX.DELIVERY.MESSAGE_ID_CONFLICT": "IDEMPOTENCY_CONFLICT",
    "MESSAGE_ID_CONFLICT": "IDEMPOTENCY_CONFLICT",
    "SOURCE_IDENTITY_MISMATCH": "AUTHORIZATION_DENIED",
    "A2A_BRIDGE_UNBOUND": "BRIDGE_UNBOUND",
}

#: Fallback when only a JSON-RPC code is known (§A.11.2).
JSON_RPC_TO_POLYMESH: dict[int, str] = {
    -32700: "MALFORMED_JSON",
    -32600: "MALFORMED",
    -32601: "UNSUPPORTED_METHOD",
    -32602: "MALFORMED",
    -32603: "INTERNAL",
    -32001: "AUTHENTICATION_FAILED",
    -32002: "RATE_LIMITED",
    -32004: "TASK_NOT_FOUND",
    -32005: "DEADLINE",
    -32006: "IDEMPOTENCY_CONFLICT",
    -32007: "UNKNOWN_TARGET",
    -32008: "TARGET_UNAVAILABLE",
    -32009: "EXECUTION_FAILED",
    -32010: "RESULT_TOO_LARGE",
    -32011: "CANCEL_NOT_SUPPORTED",
    -32012: "TASK_CONFLICT",
}


def normalize_code(code: str | None) -> str:
    if not code:
        return "INTERNAL"
    upper = str(code).upper()
    upper = CODE_ALIASES.get(upper, upper)
    return upper if upper in ERROR_TABLE else "INTERNAL"


def json_rpc_code_for(code: str | None) -> int:
    return ERROR_TABLE[normalize_code(code)].json_rpc_code


def is_retryable_code(code: str | None) -> bool:
    return ERROR_TABLE[normalize_code(code)].retryable


class A2AError(PolyMeshError):
    """A failure crossing the A2A dialect boundary."""

    default_code = "INTERNAL"
    default_category = "protocol"

    def __init__(
        self,
        code: str | None = None,
        message: str | None = None,
        *,
        json_rpc_code: int | None = None,
        retryable: bool | None = None,
        retry_after_ms: int | None = None,
        details: dict[str, Any] | None = None,
        task_id: str | None = None,
        category: str | None = None,
    ) -> None:
        resolved = normalize_code(code or self.default_code)
        entry = ERROR_TABLE[resolved]
        self.json_rpc_code = entry.json_rpc_code if json_rpc_code is None else int(json_rpc_code)
        super().__init__(
            resolved,
            message or entry.message,
            category=category or entry.category,
            retryable=entry.retryable if retryable is None else bool(retryable),
            retry_after_ms=retry_after_ms,
            details=details,
            task_id=task_id,
        )

    def to_json_rpc_error(self) -> dict[str, Any]:
        """Render the §A.11.4 JSON-RPC error object for this failure."""

        data: dict[str, Any] = {"polymesh_code": self.code, "retryable": self.retryable}
        if self.retry_after_ms is not None:
            data["retry_after_ms"] = self.retry_after_ms
        if self.details:
            data["details"] = self.details
        return {"code": self.json_rpc_code, "message": str(self), "data": data}


class A2ADialectError(A2AError):
    """A translation failure: the peer spoke A2A the adapter cannot project."""

    default_code = "MALFORMED"
    default_category = "protocol"


class A2AConfigError(A2ADialectError):
    """Adapter configuration is unsafe or incomplete; the adapter fails closed."""

    default_code = "MALFORMED"


def error_from_http_status(
    status: int,
    *,
    message: str | None = None,
    retry_after_ms: int | None = None,
    details: dict[str, Any] | None = None,
) -> A2AError:
    """Classify an HTTP response with no usable JSON-RPC body (§A.9.2.1)."""

    if status in {408, 429}:
        code = "RATE_LIMITED"
    elif status >= 500:
        code = "TARGET_UNAVAILABLE"
    elif status == 401:
        code = "AUTHENTICATION_FAILED"
    elif status == 403:
        code = "AUTHORIZATION_DENIED"
    elif status == 404:
        code = "UNSUPPORTED_METHOD"
    elif status == 400:
        code = "MALFORMED"
    else:
        code = "EXECUTION_FAILED"
    merged = dict(details or {})
    merged["http_status"] = status
    return A2AError(
        code,
        message or f"remote A2A endpoint returned HTTP {status}",
        retry_after_ms=retry_after_ms,
        details=merged,
    )


def error_from_transport(exc: BaseException, *, details: dict[str, Any] | None = None) -> A2AError:
    """Connection refused / reset / timeout before a response (§A.9.2.1)."""

    merged = dict(details or {})
    merged.setdefault("cause", type(exc).__name__)
    return A2AError("TARGET_UNAVAILABLE", "remote A2A endpoint unreachable", details=merged)


def error_from_json_rpc(error: Mapping[str, Any], *, task_id: str | None = None) -> A2AError:
    """Map a JSON-RPC error body to a PolyMesh code (§A.11.1)."""

    data = error.get("data") if isinstance(error.get("data"), Mapping) else {}
    raw_code = error.get("code")
    json_rpc_code = int(raw_code) if isinstance(raw_code, int) else -32603
    polymesh_code = data.get("polymesh_code") if isinstance(data, Mapping) else None
    if not isinstance(polymesh_code, str):
        polymesh_code = JSON_RPC_TO_POLYMESH.get(json_rpc_code, "INTERNAL")
    resolved = normalize_code(polymesh_code)
    retryable = data.get("retryable") if isinstance(data, Mapping) else None
    retry_after = data.get("retry_after_ms") if isinstance(data, Mapping) else None
    message = error.get("message")
    return A2AError(
        resolved,
        str(message) if isinstance(message, str) and message else None,
        json_rpc_code=json_rpc_code,
        retryable=bool(retryable) if isinstance(retryable, bool) else None,
        retry_after_ms=int(retry_after) if isinstance(retry_after, int) else None,
        details={"source": "a2a_json_rpc"},
        task_id=task_id,
    )


def error_from_a2a_task_error(
    error: Mapping[str, Any] | None,
    *,
    task_id: str | None = None,
) -> A2AError:
    """Map an A2A ``status.error`` object on a terminal failed task."""

    code = error.get("code") if isinstance(error, Mapping) else None
    message = error.get("message") if isinstance(error, Mapping) else None
    resolved = normalize_code(code if isinstance(code, str) else "EXECUTION_FAILED")
    if resolved == "INTERNAL" and isinstance(code, str) and code:
        resolved = "EXECUTION_FAILED"
    return A2AError(
        resolved,
        str(message) if isinstance(message, str) and message else None,
        details={"source": "a2a_task_error"},
        task_id=task_id,
    )


__all__ = [
    "A2AConfigError",
    "A2ADialectError",
    "A2AError",
    "CODE_ALIASES",
    "ERROR_TABLE",
    "ErrorTableEntry",
    "JSON_RPC_TO_POLYMESH",
    "error_from_a2a_task_error",
    "error_from_http_status",
    "error_from_json_rpc",
    "error_from_transport",
    "is_retryable_code",
    "json_rpc_code_for",
    "normalize_code",
]

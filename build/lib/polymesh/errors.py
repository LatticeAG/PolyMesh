"""Exceptions exposed by the PolyMesh Python SDK.

The wire protocol deliberately keeps errors small and structured.  These
classes retain those machine-readable fields without ever embedding a secret
or an unbounded peer supplied value in ``str(error)``.
"""

from __future__ import annotations

from typing import Any, Literal


ErrorCategoryName = Literal[
    "parse",
    "protocol",
    "identity",
    "routing",
    "delivery",
    "resource",
    "task",
    "execution",
    "internal",
    "transport",
    "timeout",
]


class PolyMeshError(Exception):
    """Base class for all SDK failures which have protocol meaning."""

    default_code = "POLYMESH_ERROR"
    default_category: ErrorCategoryName = "protocol"

    def __init__(
        self,
        code: str | None = None,
        message: str | None = None,
        *,
        category: ErrorCategoryName | str | None = None,
        retryable: bool = False,
        retry_after_ms: int | None = None,
        details: dict[str, Any] | None = None,
        task_id: str | None = None,
        envelope: Any | None = None,
    ) -> None:
        # A single positional value is most often intended as a message for a
        # specialised exception (``MalformedJsonError("bad input")``).  Keep
        # explicit protocol codes intact when they look like a code.
        if message is None and code is not None and not _looks_like_code(code):
            message, code = code, None
        self.code = code or self.default_code
        self.category = category or self.default_category
        self.retryable = bool(retryable)
        self.retry_after_ms = retry_after_ms
        self.details = details
        self.task_id = task_id
        self.envelope = envelope
        super().__init__(message or self.code)


def _looks_like_code(value: str) -> bool:
    return bool(value) and all(character.isupper() or character.isdigit() or character in "._-" for character in value)


class ProtocolError(PolyMeshError):
    default_code = "PROTOCOL_ERROR"
    default_category = "protocol"


class ParseError(ProtocolError):
    default_code = "MALFORMED_JSON"
    default_category = "parse"


class MalformedJsonError(ParseError):
    default_code = "MALFORMED_JSON"


class DuplicateMemberError(ParseError):
    default_code = "DUPLICATE_MEMBER"


class FrameTooLargeError(ParseError):
    default_code = "FRAME_TOO_LARGE"
    default_category = "resource"


class ResourceError(PolyMeshError):
    default_code = "RESOURCE_EXHAUSTED"
    default_category = "resource"


class ResourceExhaustedError(ResourceError):
    default_code = "RESOURCE_EXHAUSTED"


class HandshakeError(ProtocolError):
    default_code = "HANDSHAKE_FAILED"


class SchemaValidationError(ProtocolError):
    default_code = "SCHEMA_VALIDATION_FAILED"


class LifecycleError(ProtocolError):
    default_code = "PMX.TASK.INVALID_LIFECYCLE"


class AuthenticationError(PolyMeshError):
    default_code = "AUTHENTICATION_FAILED"
    default_category = "identity"


class AuthError(AuthenticationError):
    """Backwards-friendly name for :class:`AuthenticationError`."""


class TokenError(AuthenticationError):
    default_code = "AUTHENTICATION_FAILED"


class TLSVerificationError(AuthenticationError):
    default_code = "TLS_VERIFICATION_FAILED"


class EnrollmentError(AuthenticationError):
    default_code = "ENROLLMENT_FAILED"


class CardSignatureError(AuthenticationError):
    default_code = "CARD_SIGNATURE_INVALID"


class ProvenanceError(AuthenticationError):
    default_code = "ROUTED_PROVENANCE_INVALID"


class SecureProfileUnsupportedError(AuthenticationError):
    default_code = "SECURE_PROFILE_UNSUPPORTED"


class RoutingError(PolyMeshError):
    default_code = "TARGET_UNAVAILABLE"
    default_category = "routing"


class DeliveryError(PolyMeshError):
    default_code = "DELIVERY_FAILED"
    default_category = "delivery"


class TaskError(PolyMeshError):
    default_code = "TASK_FAILED"
    default_category = "task"


class TaskRejectedError(TaskError):
    default_code = "TASK_REJECTED"


class TaskNotFoundError(TaskError):
    default_code = "PMX.TASK.NOT_FOUND"


class TaskCancelledError(TaskError):
    default_code = "TASK_CANCELLED"


class TaskRecoveryRequiredError(TaskError):
    default_code = "TASK_RECOVERY_REQUIRED"


class ContractMismatchError(TaskError):
    default_code = "CAPABILITY_CONTRACT_MISMATCH"


class ExecutionError(PolyMeshError):
    default_code = "EXECUTION_FAILED"
    default_category = "execution"


class ResultValidationError(ExecutionError):
    default_code = "RESULT_SCHEMA_INVALID"


class TransportError(PolyMeshError):
    default_code = "TRANSPORT_ERROR"
    default_category = "transport"


class TransportClosedError(TransportError):
    default_code = "TRANSPORT_CLOSED"


class SlowConsumerError(TransportError):
    default_code = "SLOW_CONSUMER"


class ReconnectExhaustedError(TransportError):
    default_code = "RECONNECT_EXHAUSTED"


class WrongEventLoopError(TransportError):
    default_code = "WRONG_EVENT_LOOP"


class TimeoutError(PolyMeshError):
    default_code = "TIMEOUT"
    default_category = "timeout"


class HandshakeTimeoutError(TimeoutError):
    default_code = "HANDSHAKE_TIMEOUT"


class HeartbeatTimeoutError(TimeoutError):
    default_code = "HEARTBEAT_TIMEOUT"


class TaskTimeoutError(TimeoutError, TaskError):
    default_code = "PMX.TASK.DEADLINE_EXCEEDED"


def error_from_structured(
    *,
    category: str,
    code: str,
    message: str,
    retryable: bool = False,
    retry_after_ms: int | None = None,
    details: dict[str, Any] | None = None,
    task_id: str | None = None,
    envelope: Any | None = None,
) -> PolyMeshError:
    """Map a validated remote structured error to its public local class."""

    by_category: dict[str, type[PolyMeshError]] = {
        "parse": ParseError,
        "protocol": ProtocolError,
        "identity": AuthenticationError,
        "routing": RoutingError,
        "delivery": DeliveryError,
        "resource": ResourceError,
        "task": TaskError,
        "execution": ExecutionError,
        "internal": PolyMeshError,
    }
    # Important code-specific mappings take precedence over the broad wire
    # category, matching the SDK conformance table.
    by_code: dict[str, type[PolyMeshError]] = {
        "MALFORMED_JSON": MalformedJsonError,
        "DUPLICATE_MEMBER": DuplicateMemberError,
        "RESOURCE_EXHAUSTED": ResourceError,
        "OVERLOADED": ResourceError,
        "FRAME_TOO_LARGE": FrameTooLargeError,
        "HANDSHAKE_TIMEOUT": HandshakeTimeoutError,
        "HEARTBEAT_TIMEOUT": HeartbeatTimeoutError,
        "AUTHENTICATION_FAILED": AuthenticationError,
        "SECURITY_PROFILE_MISMATCH": AuthenticationError,
        "AUTHORIZATION_DENIED": AuthenticationError,
        "TASK_CANCELLED": TaskCancelledError,
        "PMX.TASK.NOT_FOUND": TaskNotFoundError,
        "PMX.TASK.DEADLINE_EXCEEDED": TaskTimeoutError,
        "PMX.TASK.EVENT_CONFLICT": LifecycleError,
        "PMX.TASK.INVALID_LIFECYCLE": LifecycleError,
        "CAPABILITY_CONTRACT_MISMATCH": ContractMismatchError,
        "PMX.TASK.CONTRACT_MISMATCH": ContractMismatchError,
        "RESULT_SCHEMA_INVALID": ResultValidationError,
        "RESULT_TOO_LARGE": ResultValidationError,
        "INSECURE_TRANSPORT_DISABLED": TransportError,
        "TRANSPORT_CLOSED": TransportClosedError,
        "ROUTED_PROVENANCE_INVALID": ProvenanceError,
        "TARGET_UNAVAILABLE": RoutingError,
        "PMX.ROUTING.PINNED_INSTANCE_UNAVAILABLE": RoutingError,
        "PMX.DELIVERY.MESSAGE_ID_CONFLICT": DeliveryError,
        "PMX.DELIVERY.IDEMPOTENCY_CONFLICT": DeliveryError,
    }
    error_type = by_code.get(code, by_category.get(category, PolyMeshError))
    return error_type(
        code,
        message,
        category=category,
        retryable=retryable,
        retry_after_ms=retry_after_ms,
        details=details,
        task_id=task_id,
        envelope=envelope,
    )


__all__ = [
    name for name, value in tuple(globals().items()) if isinstance(value, type) and issubclass(value, PolyMeshError)
] + ["error_from_structured"]

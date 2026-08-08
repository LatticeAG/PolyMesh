"""JSON-RPC 2.0 request/response framing for the A2A dialect (§A.7).

Framing is deliberately schema-strict: an unparseable or shape-invalid response
fails closed rather than being coerced into a task state.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from ..protocol import uuidv7
from .errors import A2ADialectError, A2AError, error_from_json_rpc

JSONRPC_VERSION = "2.0"

A2A_METHODS = ("tasks/send", "tasks/get", "tasks/cancel", "message/stream")


def new_request_id() -> str:
    return uuidv7()


def build_request(method: str, params: Mapping[str, Any] | None = None, *, request_id: str | None = None) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 request envelope."""

    if method not in A2A_METHODS:
        raise A2ADialectError("UNSUPPORTED_METHOD", f"unsupported A2A method {method!r}")
    request: dict[str, Any] = {
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id or new_request_id(),
        "method": method,
    }
    if params is not None:
        request["params"] = dict(params)
    return request


def encode_request(request: Mapping[str, Any]) -> bytes:
    return json.dumps(request, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def parse_response_body(body: bytes | str) -> dict[str, Any]:
    """Decode a JSON-RPC response body, failing closed on malformed JSON."""

    text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
    try:
        parsed = json.loads(text)
    except (ValueError, UnicodeDecodeError) as exc:
        raise A2ADialectError("MALFORMED_JSON", "remote A2A response was not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise A2ADialectError("MALFORMED", "remote A2A response was not a JSON-RPC object")
    return parsed


def extract_result(
    response: Mapping[str, Any],
    *,
    request_id: str | None = None,
    task_id: str | None = None,
) -> Any:
    """Return ``result`` or raise the mapped error for an ``error`` body."""

    if response.get("jsonrpc") != JSONRPC_VERSION:
        raise A2ADialectError("MALFORMED", "remote A2A response missing jsonrpc 2.0 marker")
    error = response.get("error")
    if isinstance(error, Mapping):
        raise error_from_json_rpc(error, task_id=task_id)
    if "result" not in response:
        raise A2ADialectError("MALFORMED", "remote A2A response carried neither result nor error")
    if request_id is not None and response.get("id") not in (None, request_id):
        raise A2ADialectError("MALFORMED", "remote A2A response id did not match the request")
    return response["result"]


def build_error_response(request_id: Any, error: A2AError) -> dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "error": error.to_json_rpc_error()}


def build_result_response(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": result}


__all__ = [
    "A2A_METHODS",
    "JSONRPC_VERSION",
    "build_error_response",
    "build_request",
    "build_result_response",
    "encode_request",
    "extract_result",
    "new_request_id",
    "parse_response_body",
]

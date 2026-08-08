"""In-process mock A2A peer for tests and local demos.

Exposes an ASGI application so tests can drive the real outbound client over
``httpx.ASGITransport`` without binding a socket.  Every request is captured
verbatim so tests can assert what actually crossed the wire.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from .jsonrpc import JSONRPC_VERSION

DEFAULT_URL = "https://mock-a2a.test/a2a"


class MockA2AServer:
    """Scriptable A2A peer.

    ``states`` is the sequence of ``status.state`` values returned by
    ``tasks/get``; the last value repeats once exhausted.
    """

    def __init__(
        self,
        *,
        send_state: str = "submitted",
        states: Sequence[str] | None = None,
        result: Any = None,
        http_status: int | None = None,
        json_rpc_error: Mapping[str, Any] | None = None,
        error_after_sends: int = 0,
        task_error: Mapping[str, Any] | None = None,
        require_auth: str | None = None,
        progress: float | None = None,
    ) -> None:
        self.send_state = send_state
        self.states = list(states or ["completed"])
        self.result = result if result is not None else {"ok": True}
        self.http_status = http_status
        self.json_rpc_error = dict(json_rpc_error) if json_rpc_error is not None else None
        self.error_after_sends = int(error_after_sends)
        self.task_error = dict(task_error) if task_error is not None else None
        self.require_auth = require_auth
        self.progress = progress

        self.requests: list[dict[str, Any]] = []
        self.send_count = 0
        self.get_count = 0
        self.cancel_count = 0
        self._tasks: dict[str, dict[str, Any]] = {}
        self._get_index: dict[str, int] = {}

    # -- introspection -------------------------------------------------

    @property
    def last_request(self) -> dict[str, Any]:
        if not self.requests:
            raise AssertionError("mock A2A server received no requests")
        return self.requests[-1]

    def raw_bodies(self) -> list[str]:
        return [entry["raw_body"] for entry in self.requests]

    def header_values(self) -> list[str]:
        values: list[str] = []
        for entry in self.requests:
            values.extend(str(value) for value in entry["headers"].values())
        return values

    # -- protocol ------------------------------------------------------

    def _task_snapshot(self, task_id: str, state: str) -> dict[str, Any]:
        status: dict[str, Any] = {"state": state}
        if self.progress is not None and state == "working":
            status["progress"] = self.progress
        if state == "completed":
            status["progress"] = 1
        if state == "failed":
            status["error"] = self.task_error or {"code": "EXECUTION_FAILED", "message": "remote failure"}
        task: dict[str, Any] = {"id": task_id, "status": status, "metadata": {}}
        if state == "completed":
            task["artifacts"] = [{"name": "result", "parts": [{"type": "data", "data": self.result}]}]
        return task

    def handle(self, request: Mapping[str, Any]) -> tuple[int, dict[str, Any]]:
        method = request.get("method")
        params = request.get("params") if isinstance(request.get("params"), Mapping) else {}
        request_id = request.get("id")

        if method == "tasks/send":
            self.send_count += 1
            if self.json_rpc_error is not None and self.send_count > self.error_after_sends:
                return 200, {"jsonrpc": JSONRPC_VERSION, "id": request_id, "error": dict(self.json_rpc_error)}
            task_id = str(params.get("id") or f"remote-{self.send_count}")
            self._tasks[task_id] = dict(params)
            self._get_index[task_id] = 0
            return 200, {
                "jsonrpc": JSONRPC_VERSION,
                "id": request_id,
                "result": self._task_snapshot(task_id, self.send_state),
            }

        if method == "tasks/get":
            self.get_count += 1
            task_id = str(params.get("id") or "")
            if task_id not in self._tasks:
                return 200, {
                    "jsonrpc": JSONRPC_VERSION,
                    "id": request_id,
                    "error": {"code": -32004, "message": "Task not found", "data": {"polymesh_code": "TASK_NOT_FOUND"}},
                }
            index = self._get_index.get(task_id, 0)
            state = self.states[min(index, len(self.states) - 1)]
            self._get_index[task_id] = index + 1
            return 200, {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": self._task_snapshot(task_id, state)}

        if method == "tasks/cancel":
            self.cancel_count += 1
            task_id = str(params.get("id") or "")
            return 200, {
                "jsonrpc": JSONRPC_VERSION,
                "id": request_id,
                "result": self._task_snapshot(task_id, "canceled"),
            }

        return 200, {
            "jsonrpc": JSONRPC_VERSION,
            "id": request_id,
            "error": {"code": -32601, "message": "Method not found", "data": {"polymesh_code": "UNSUPPORTED_METHOD"}},
        }

    # -- ASGI ----------------------------------------------------------

    async def __call__(self, scope: Mapping[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":  # pragma: no cover - transport only speaks http
            raise AssertionError("mock A2A server only speaks HTTP")

        chunks: list[bytes] = []
        while True:
            message = await receive()
            if message.get("type") != "http.request":
                break
            chunks.append(message.get("body") or b"")
            if not message.get("more_body"):
                break
        raw_body = b"".join(chunks).decode("utf-8", errors="replace")
        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1") for key, value in scope.get("headers") or []
        }
        try:
            parsed = json.loads(raw_body) if raw_body else {}
        except ValueError:
            parsed = {}
        self.requests.append(
            {
                "path": scope.get("path", "/"),
                "headers": headers,
                "raw_body": raw_body,
                "body": parsed if isinstance(parsed, dict) else {},
            }
        )

        if self.require_auth is not None and headers.get("authorization") != self.require_auth:
            await _respond(send, 401, {"error": "unauthorized"})
            return
        if self.http_status is not None and self.http_status >= 400:
            await _respond(send, self.http_status, {"error": "mock failure"})
            return

        status, body = self.handle(parsed if isinstance(parsed, dict) else {})
        await _respond(send, status, body)

    def transport(self) -> Any:
        """Return an ``httpx.ASGITransport`` bound to this mock."""

        import httpx

        return httpx.ASGITransport(app=self)


async def _respond(send: Any, status: int, body: Mapping[str, Any]) -> None:
    payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode("latin-1")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload})


__all__ = ["DEFAULT_URL", "MockA2AServer"]

"""Threaded mock A2A JSON-RPC server for outbound conformance tests (§E.4.4).

It speaks just enough of the dialect to drive the adapter: ``tasks/send``,
``tasks/get`` with a configurable number of non-terminal polls, ``tasks/cancel``,
plus knobs for HTTP-level and JSON-RPC-level failures.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from ..protocol import uuidv7


@dataclass
class MockA2AOptions:
    """Behaviour switches; every field is live-patchable via ``set_options``."""

    #: Non-terminal ``tasks/get`` responses before the task completes.
    drop_polls: int = 0
    #: JSON-RPC error returned for ``tasks/send`` (``True`` uses TARGET_UNAVAILABLE).
    fail_on_send: bool | dict[str, Any] | None = None
    #: HTTP status returned for every request, with a non JSON-RPC body.
    http_error_status: int | None = None
    #: When set, requests without this exact Authorization header get 401.
    require_auth_header: str | None = None
    #: Reject every request with a JSON-RPC AUTHENTICATION_FAILED body.
    auth_reject: bool = False
    #: Artifact data attached to the completed task.
    complete_result: Any = field(default_factory=lambda: {"ok": True})
    #: Terminal state the task lands in once polling finishes.
    terminal_state: str = "completed"
    #: Task-level error object used when ``terminal_state`` is ``failed``.
    terminal_error: dict[str, Any] | None = None


class MockA2AServer:
    """Runs a :class:`ThreadingHTTPServer` on a loopback port in a daemon thread."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0, **options: Any) -> None:
        self.options = MockA2AOptions(**options)
        self.requests: list[dict[str, Any]] = []
        self.tasks: dict[str, dict[str, Any]] = {}
        self.polls: dict[str, int] = {}
        self._lock = threading.Lock()
        self._server = ThreadingHTTPServer((host, port), _make_handler(self))
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, name="mock-a2a", daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    @property
    def host(self) -> str:
        return str(self._server.server_address[0])

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/a2a"

    @property
    def origin(self) -> str:
        return f"http://{self.host}:{self.port}"

    def set_options(self, **patch: Any) -> None:
        for key, value in patch.items():
            if not hasattr(self.options, key):
                raise AttributeError(f"unknown mock option {key!r}")
            setattr(self.options, key, value)

    def force_state(self, remote_task_id: str, state: str, *, artifacts: Any = None) -> None:
        """Push a task into ``state`` directly (used by monotonicity tests)."""

        with self._lock:
            task = self.tasks.get(remote_task_id)
            if task is None:
                return
            task["status"] = {"state": state}
            if artifacts is not None:
                task["artifacts"] = artifacts

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    def __enter__(self) -> MockA2AServer:
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()


def create_mock_a2a_server(**options: Any) -> MockA2AServer:
    return MockA2AServer(**options)


def _make_handler(mock: MockA2AServer) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: Any) -> None:  # keep pytest output clean
            return

        def _write(self, status: int, body: bytes, content_type: str = "application/json") -> None:
            self.send_response(status)
            self.send_header("content-type", content_type)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _write_json(self, status: int, payload: dict[str, Any]) -> None:
            self._write(status, json.dumps(payload).encode("utf-8"))

        def _reply(self, request_id: Any, result: Any) -> None:
            self._write_json(200, {"jsonrpc": "2.0", "id": request_id, "result": result})

        def _fail(
            self,
            request_id: Any,
            code: int,
            message: str,
            data: dict[str, Any] | None = None,
            status: int = 200,
        ) -> None:
            error: dict[str, Any] = {"code": code, "message": message}
            if data is not None:
                error["data"] = data
            self._write_json(status, {"jsonrpc": "2.0", "id": request_id, "error": error})

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
            length = int(self.headers.get("content-length") or 0)
            raw = self.rfile.read(length) if length else b""
            options = mock.options

            try:
                body = json.loads(raw.decode("utf-8")) if raw else None
            except (ValueError, UnicodeDecodeError):
                self._fail(None, -32700, "Parse error")
                return

            with mock._lock:
                mock.requests.append(
                    {
                        "path": self.path,
                        "headers": {key.lower(): value for key, value in self.headers.items()},
                        "body": body,
                    }
                )

            if options.http_error_status:
                self._write(options.http_error_status, b"upstream failure", content_type="text/plain")
                return

            request_id = body.get("id") if isinstance(body, dict) else None

            if options.auth_reject or options.require_auth_header is not None:
                provided = self.headers.get("authorization")
                expected = options.require_auth_header
                if options.auth_reject or expected is None or provided != expected:
                    self._fail(
                        request_id,
                        -32001,
                        "Authentication failed",
                        {"polymesh_code": "AUTHENTICATION_FAILED"},
                        status=401,
                    )
                    return

            method = body.get("method") if isinstance(body, dict) else None
            params = body.get("params") if isinstance(body, dict) else None
            params = params if isinstance(params, dict) else {}

            if method == "tasks/send":
                self._handle_send(request_id, params, options)
            elif method == "tasks/get":
                self._handle_get(request_id, params, options)
            elif method == "tasks/cancel":
                self._handle_cancel(request_id, params)
            else:
                self._fail(request_id, -32601, "Method not found")

        def _handle_send(self, request_id: Any, params: dict[str, Any], options: MockA2AOptions) -> None:
            if options.fail_on_send:
                spec = options.fail_on_send if isinstance(options.fail_on_send, dict) else {}
                self._fail(
                    request_id,
                    int(spec.get("code", -32008)),
                    str(spec.get("message", "Target unavailable")),
                    spec.get("data", {"polymesh_code": "TARGET_UNAVAILABLE"}),
                    status=int(spec.get("status", 200)),
                )
                return

            remote_id = params.get("id") if isinstance(params.get("id"), str) else uuidv7()
            task = {
                "id": remote_id,
                "status": {"state": "working"},
                "metadata": dict(params.get("metadata") or {}),
            }
            with mock._lock:
                mock.tasks[remote_id] = task
                mock.polls[remote_id] = 0
            self._reply(request_id, task)

        def _handle_get(self, request_id: Any, params: dict[str, Any], options: MockA2AOptions) -> None:
            remote_id = str(params.get("id") or "")
            with mock._lock:
                task = mock.tasks.get(remote_id)
                if task is None:
                    self._fail(request_id, -32004, "Task not found", {"polymesh_code": "TASK_NOT_FOUND"})
                    return
                polls = mock.polls.get(remote_id, 0) + 1
                mock.polls[remote_id] = polls
                state = task.get("status", {}).get("state")
                if state not in {"completed", "failed", "canceled"}:
                    if polls > int(options.drop_polls):
                        task["status"] = {"state": options.terminal_state, "progress": 1.0}
                        if options.terminal_state == "failed":
                            task["status"]["error"] = options.terminal_error or {
                                "code": "EXECUTION_FAILED",
                                "message": "remote handler failed",
                            }
                        else:
                            task["artifacts"] = [
                                {
                                    "name": "result",
                                    "parts": [{"type": "data", "data": options.complete_result}],
                                }
                            ]
                    else:
                        task["status"] = {"state": "working", "progress": min(0.9, polls * 0.1)}
                snapshot = json.loads(json.dumps(task))
            self._reply(request_id, snapshot)

        def _handle_cancel(self, request_id: Any, params: dict[str, Any]) -> None:
            remote_id = str(params.get("id") or "")
            with mock._lock:
                task = mock.tasks.get(remote_id)
                if task is None:
                    self._fail(request_id, -32004, "Task not found", {"polymesh_code": "TASK_NOT_FOUND"})
                    return
                task["status"] = {"state": "canceled"}
                snapshot = json.loads(json.dumps(task))
            self._reply(request_id, snapshot)

    return Handler


__all__ = ["MockA2AOptions", "MockA2AServer", "create_mock_a2a_server"]

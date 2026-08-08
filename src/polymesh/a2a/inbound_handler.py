"""Inbound A2A JSON-RPC handler (§A.7, §A.8, §A.13, §A.16, §A.17).

Exposes ``tasks/send``, ``tasks/get``, ``tasks/cancel``, ``message/stream`` (SSE),
and an AgentCard publisher. A2A credentials terminate here; mesh credentials
never cross the dialect boundary. Remote A2A principals are second-class:
no rooms, no topology, published-skill surface only.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from ..protocol import uuidv7
from .auth_boundary import A2AAuthBoundary, MESH_CREDENTIAL_HEADERS
from .card_mapper import (
    capability_name_from_skill_name,
    is_publishable_skill,
    map_card_to_a2a,
    map_capabilities_to_skills,
)
from .errors import A2AError
from .event_log import AdapterEventLog
from .idempotency import IdempotencyStore
from .jsonrpc import A2A_METHODS, JSONRPC_VERSION, build_error_response, build_result_response
from .rate_limit import RateLimit
from .task_translator import POLYMESH_STATE_TO_A2A

ROOM_CAPABILITY_PREFIXES = (
    "org.polymesh.room.",
    "org.polymesh.mesh.join",
    "org.polymesh.mesh.leave",
    "org.polymesh.rooms.",
)

CAPABILITIES_LIST = "org.polymesh.capabilities.list"
MAX_REQUEST_BYTES = 1_048_576
DEFAULT_SSE_CLIENT_TIMEOUT_MS = 45_000


def project_mesh_to_a2a_task(
    *,
    task_id: str,
    state: str,
    capability_id: str | None = None,
    result: Any = None,
    error: Mapping[str, Any] | None = None,
    event_seq: int | None = None,
    progress: float | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    """Project a mesh-side task snapshot onto an A2A Task (§A.6.3)."""

    a2a_state = POLYMESH_STATE_TO_A2A.get(state, "working")
    status: dict[str, Any] = {"state": a2a_state}
    if progress is not None and a2a_state == "working":
        status["progress"] = progress
    if a2a_state == "failed" and error is not None:
        status["error"] = {
            "code": str(error.get("code") or "EXECUTION_FAILED"),
            "message": str(error.get("message") or "Execution failed"),
            "data": error.get("data"),
        }
    task: dict[str, Any] = {"id": task_id, "status": status}
    if session_id:
        task["sessionId"] = session_id
    metadata: dict[str, Any] = {"polymesh_state": state}
    if capability_id:
        metadata["polymesh_capability_id"] = capability_id
    if event_seq is not None:
        metadata["polymesh_last_event_seq"] = event_seq
    task["metadata"] = metadata
    if a2a_state == "completed" and result is not None:
        task["artifacts"] = [
            {
                "name": "result",
                "parts": [{"type": "data", "data": result, "mimeType": "application/json"}],
            }
        ]
    return task


class InboundHandler:
    """Inbound A2A JSON-RPC + AgentCard surface (§A.8)."""

    def __init__(
        self,
        config: Mapping[str, Any] | None = None,
        *,
        capabilities: Sequence[Mapping[str, Any]] | None = None,
        agent_card: Mapping[str, Any] | None = None,
        auth: Mapping[str, Any] | None = None,
        auth_boundary: A2AAuthBoundary | None = None,
        event_log: AdapterEventLog | None = None,
        idempotency: IdempotencyStore | None = None,
        rate_limit: RateLimit | None = None,
        on_submit: Callable[[dict[str, Any]], Any] | None = None,
        on_cancel: Callable[[str], Any] | None = None,
        now: Callable[[], float] | None = None,
        sse_client_timeout_ms: int = DEFAULT_SSE_CLIENT_TIMEOUT_MS,
        **_kwargs: Any,
    ) -> None:
        settings = dict(config or {})
        self.enabled = bool(settings.get("inbound_enabled", True))
        self._auth_cfg = dict(auth if auth is not None else settings.get("auth") or {"mode": "none"})
        self._allow_public = bool(settings.get("allow_public_unauthenticated", False))
        self._capabilities: list[dict[str, Any]] = [
            dict(c) for c in (capabilities or settings.get("capabilities") or []) if isinstance(c, Mapping)
        ]
        self._agent_card = dict(agent_card or settings.get("agent_card") or {})
        if self._capabilities and "capabilities" not in self._agent_card:
            self._agent_card["capabilities"] = list(self._capabilities)
        self.auth = auth_boundary or A2AAuthBoundary({"auth": self._auth_cfg})
        self.event_log = event_log or AdapterEventLog(cap=int(settings.get("event_log_cap", 1000)))
        self.idempotency = idempotency or IdempotencyStore()
        rl_cfg = dict(settings.get("rate_limit") or {"enabled": True})
        self.rate_limit = rate_limit if rate_limit is not None else RateLimit(rl_cfg, now=now)
        self._on_submit = on_submit
        self._on_cancel = on_cancel
        self._now = now or time.monotonic
        self._sse_client_timeout_ms = int(sse_client_timeout_ms)
        self._tasks: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.listen_host = str(settings.get("listen_host", "127.0.0.1"))
        self.listen_port = int(settings.get("listen_port") or 0)
        self.public_card_path = str(settings.get("public_card_path", "/.well-known/agent.json"))
        self.jsonrpc_path = str(settings.get("jsonrpc_path", "/a2a"))
        self.sse_enabled = bool(settings.get("sse_enabled", True))
        self._last_mesh_submit: dict[str, Any] | None = None

    @property
    def published_capabilities(self) -> list[dict[str, Any]]:
        return [c for c in self._capabilities if is_publishable_skill(c)]

    @property
    def published_capability_ids(self) -> set[str]:
        return {
            str(c.get("name") or c.get("capability") or "")
            for c in self.published_capabilities
            if c.get("name") or c.get("capability")
        }

    def published_skills(self) -> list[dict[str, Any]]:
        return map_capabilities_to_skills(self.published_capabilities, enforce_publish_gate=True)

    def handle_card_request(self) -> dict[str, Any]:
        card = dict(self._agent_card)
        card["capabilities"] = list(self.published_capabilities)
        card["sse_enabled"] = self.sse_enabled
        return map_card_to_a2a(card, enforce_publish_gate=True)

    def trust_scope_for(self, headers: Mapping[str, str] | None = None) -> dict[str, Any]:
        return self.auth.terminate_inbound_auth(
            headers or {},
            auth=self._auth_cfg,
            allow_public_unauthenticated=self._allow_public or self._auth_cfg.get("mode", "none") == "none",
        )

    async def handle(
        self,
        request: Mapping[str, Any] | None = None,
        *,
        headers: Mapping[str, str] | None = None,
        client_ip: str = "127.0.0.1",
    ) -> dict[str, Any]:
        """Handle one JSON-RPC request and return a JSON-RPC response envelope."""

        return self.handle_sync(request, headers=headers, client_ip=client_ip)

    def handle_sync(
        self,
        request: Mapping[str, Any] | None = None,
        *,
        headers: Mapping[str, str] | None = None,
        client_ip: str = "127.0.0.1",
    ) -> dict[str, Any]:
        if not self.enabled:
            return build_error_response(
                None if request is None else request.get("id"),
                A2AError("UNSUPPORTED_METHOD", "inbound A2A serving is disabled"),
            )
        if request is None or not isinstance(request, Mapping):
            return build_error_response(None, A2AError("MALFORMED", "Invalid request"))

        request_id = request.get("id")
        try:
            if request.get("jsonrpc") != JSONRPC_VERSION:
                raise A2AError("MALFORMED", "Invalid request")
            method = request.get("method")
            if not isinstance(method, str):
                raise A2AError("MALFORMED", "Invalid request")
            if method not in A2A_METHODS:
                raise A2AError("UNSUPPORTED_METHOD", "Method not found")

            # Auth terminates here; mesh headers are stripped and never forwarded.
            safe_headers = self.auth.strip_mesh_credentials_from_headers(headers or {})
            trust = self.auth.terminate_inbound_auth(
                headers or {},
                auth=self._auth_cfg,
                allow_public_unauthenticated=self._allow_public
                or str(self._auth_cfg.get("mode") or "none") == "none",
            )
            principal_id = str(trust["principal_id"])

            params = request.get("params")
            if params is None:
                params = {}
            if not isinstance(params, Mapping):
                raise A2AError("MALFORMED", "Invalid request")

            # Rate limit before heavy work (skill may be unknown yet).
            capability_hint = self._peek_capability(params) if method == "tasks/send" else None
            if not self.rate_limit.allow(
                ip=client_ip,
                principal=principal_id,
                capability=capability_hint,
            ):
                raise A2AError("RATE_LIMITED", "Rate limited", retry_after_ms=1000)

            if method == "tasks/send":
                result = self._tasks_send(params, principal_id=principal_id, safe_headers=safe_headers)
            elif method == "tasks/get":
                result = self._tasks_get(params, principal_id=principal_id)
            elif method == "tasks/cancel":
                result = self._tasks_cancel(params, principal_id=principal_id)
            elif method == "message/stream":
                result = self._message_stream(params, principal_id=principal_id)
            else:
                raise A2AError("UNSUPPORTED_METHOD", "Method not found")
            return build_result_response(request_id, result)
        except A2AError as exc:
            return build_error_response(request_id, exc)
        except Exception as exc:  # noqa: BLE001 - fail closed to JSON-RPC
            return build_error_response(
                request_id,
                A2AError("INTERNAL", f"Internal error: {exc}"),
            )

    def _peek_capability(self, params: Mapping[str, Any]) -> str | None:
        try:
            return self._resolve_skill(params)
        except A2AError:
            return None

    def _resolve_skill(self, params: Mapping[str, Any]) -> str:
        metadata = params.get("metadata")
        if isinstance(metadata, Mapping):
            cap = metadata.get("capability_id")
            if isinstance(cap, str) and cap.strip():
                return cap.strip()
            skill = metadata.get("skill")
            if isinstance(skill, str) and skill.strip():
                return capability_name_from_skill_name(skill.strip())
        message = params.get("message")
        if isinstance(message, Mapping):
            parts = message.get("parts")
            if isinstance(parts, Sequence):
                for part in parts:
                    if not isinstance(part, Mapping):
                        continue
                    data = part.get("data")
                    if isinstance(data, Mapping):
                        for key in ("capability_id", "capability", "skill"):
                            value = data.get(key)
                            if isinstance(value, str) and value.strip():
                                if key == "skill":
                                    return capability_name_from_skill_name(value.strip())
                                return value.strip()
        raise A2AError("UNSUPPORTED_CAPABILITY", "Skill unsupported")

    def _extract_input(self, message: Mapping[str, Any]) -> Any:
        parts = message.get("parts")
        if not isinstance(parts, Sequence) or not parts:
            raise A2AError("MALFORMED", "Invalid request")
        if len(parts) > 32:
            raise A2AError("MALFORMED", "Invalid request")
        for part in parts:
            if not isinstance(part, Mapping):
                raise A2AError("MALFORMED", "Invalid request")
            ptype = part.get("type")
            if ptype == "file":
                raise A2AError("MALFORMED", "Invalid request")
            if ptype == "data" and "data" in part:
                data = part["data"]
                if not isinstance(data, (dict, list)):
                    raise A2AError("MALFORMED", "Invalid request")
                # Strip skill routing keys from payload when present.
                if isinstance(data, dict):
                    payload = {
                        k: v
                        for k, v in data.items()
                        if k not in {"skill", "capability", "capability_id"}
                    }
                    return payload
                return data
        # Single text part with JSON object.
        text_parts = [p for p in parts if isinstance(p, Mapping) and p.get("type") == "text"]
        if len(parts) == 1 and text_parts:
            text = text_parts[0].get("text")
            if not isinstance(text, str):
                raise A2AError("MALFORMED", "Invalid request")
            try:
                parsed = json.loads(text)
            except ValueError as exc:
                raise A2AError("MALFORMED", "Invalid request") from exc
            if not isinstance(parsed, dict):
                raise A2AError("MALFORMED", "Invalid request")
            return parsed
        raise A2AError("MALFORMED", "Invalid request")

    def _validate_message(self, message: Any) -> Mapping[str, Any]:
        if not isinstance(message, Mapping):
            raise A2AError("MALFORMED", "Invalid request")
        # Fail closed on unknown fields (§A.16.2).
        allowed = {"messageId", "role", "parts"}
        extra = set(message) - allowed
        if extra:
            raise A2AError("MALFORMED", "Invalid request")
        role = message.get("role")
        if role not in ("user", "agent"):
            raise A2AError("MALFORMED", "Invalid request")
        parts = message.get("parts")
        if not isinstance(parts, Sequence) or len(parts) < 1:
            raise A2AError("MALFORMED", "Invalid request")
        return message

    def _validate_send_params(self, params: Mapping[str, Any]) -> None:
        allowed = {"id", "sessionId", "message", "metadata"}
        if set(params) - allowed:
            raise A2AError("MALFORMED", "Invalid request")
        if "message" not in params:
            raise A2AError("MALFORMED", "Invalid request")
        self._validate_message(params["message"])
        task_id = params.get("id")
        if task_id is not None and not isinstance(task_id, str):
            raise A2AError("MALFORMED", "Invalid request")
        if isinstance(task_id, str) and not (1 <= len(task_id) <= 128):
            raise A2AError("MALFORMED", "Invalid request")
        metadata = params.get("metadata")
        if metadata is not None and not isinstance(metadata, Mapping):
            raise A2AError("MALFORMED", "Invalid request")

    def _is_room_capability(self, capability_id: str) -> bool:
        return any(capability_id.startswith(prefix) for prefix in ROOM_CAPABILITY_PREFIXES)

    def _tasks_send(
        self,
        params: Mapping[str, Any],
        *,
        principal_id: str,
        safe_headers: Mapping[str, str],
    ) -> dict[str, Any]:
        self._validate_send_params(params)
        capability_id = self._resolve_skill(params)

        if self._is_room_capability(capability_id):
            raise A2AError("AUTHORIZATION_DENIED", "Authorization denied")

        if capability_id not in self.published_capability_ids:
            raise A2AError("UNSUPPORTED_CAPABILITY", "Skill unsupported")

        message = params["message"]
        assert isinstance(message, Mapping)
        payload = self._extract_input(message)

        # Built-in capabilities.list — published skills only (§A.16.5).
        if capability_id == CAPABILITIES_LIST:
            return self._complete_builtin_list(params, principal_id=principal_id, payload=payload)

        metadata = params.get("metadata") if isinstance(params.get("metadata"), Mapping) else {}
        idem_key = metadata.get("idempotency_key") if isinstance(metadata, Mapping) else None
        supplied_id = params.get("id") if isinstance(params.get("id"), str) else None
        task_id = supplied_id or uuidv7()

        keys = self.idempotency.compute_keys(
            capability_id=capability_id,
            payload=payload,
            task_id=task_id if supplied_id else None,
            principal_id=principal_id,
            idempotency_key=str(idem_key) if isinstance(idem_key, str) else None,
        )
        existing, _ = self.idempotency.check(
            capability_id=capability_id,
            payload=payload,
            task_id=task_id,
            principal_id=principal_id,
            idempotency_key=str(idem_key) if isinstance(idem_key, str) else None,
        )
        if existing is not None:
            return self._project_task(existing.task_id)

        # Collision: same id, different fingerprint / different owner.
        with self._lock:
            prior = self._tasks.get(task_id)
            if prior is not None and prior.get("principal_id") != principal_id:
                raise A2AError("IDEMPOTENCY_CONFLICT", "Idempotency conflict")
            if prior is not None and prior.get("fingerprint") not in (None, keys.fingerprint):
                raise A2AError("IDEMPOTENCY_CONFLICT", "Idempotency conflict")

        submit_envelope = {
            "task_id": task_id,
            "capability": capability_id,
            "payload": payload,
            "principal_id": principal_id,
            "idempotency_key": keys.dedup_key,
            "headers": dict(safe_headers),
            "dialect": "a2a",
            "rooms": [],
        }
        # Invariant: mesh credentials never appear on the mesh handoff.
        for name in submit_envelope["headers"]:
            if name.lower() in MESH_CREDENTIAL_HEADERS:
                raise A2AError("AUTHORIZATION_DENIED", "mesh credential must not cross boundary")
        self._last_mesh_submit = submit_envelope

        mesh_result: Any = None
        if self._on_submit is not None:
            mesh_result = self._on_submit(submit_envelope)
            if hasattr(mesh_result, "__await__"):
                # Sync path cannot await; callers using async submit should use handle().
                raise A2AError("INTERNAL", "async on_submit requires awaitable handle path")

        state = "SUBMITTED"
        result = None
        error = None
        if isinstance(mesh_result, Mapping):
            state = str(mesh_result.get("state") or state)
            result = mesh_result.get("result")
            error = mesh_result.get("error") if isinstance(mesh_result.get("error"), Mapping) else None

        self.idempotency.store(keys, task_id)
        self.event_log.ensure(task_id)
        self.event_log.append(task_id, "submitted", state="SUBMITTED", payload={"capability": capability_id})
        if state != "SUBMITTED":
            terminal = state in {"SUCCEEDED", "FAILED", "CANCELLED", "REJECTED"}
            self.event_log.append(
                task_id,
                "status",
                state=state,  # type: ignore[arg-type]
                payload={"result": result, "error": error},
                terminal=terminal,
            )

        with self._lock:
            self._tasks[task_id] = {
                "task_id": task_id,
                "principal_id": principal_id,
                "capability_id": capability_id,
                "state": state,
                "result": result,
                "error": error,
                "fingerprint": keys.fingerprint,
                "session_id": params.get("sessionId"),
                "payload": payload,
            }
        return self._project_task(task_id)

    def _complete_builtin_list(
        self,
        params: Mapping[str, Any],
        *,
        principal_id: str,
        payload: Any,
    ) -> dict[str, Any]:
        task_id = params.get("id") if isinstance(params.get("id"), str) else uuidv7()
        skills = self.published_skills()
        result = {"skills": skills, "capabilities": [s.get("name") for s in skills]}
        self.event_log.ensure(task_id)
        self.event_log.append(task_id, "submitted", state="SUBMITTED")
        self.event_log.append(
            task_id,
            "completed",
            state="SUCCEEDED",
            payload={"result": result},
            terminal=True,
        )
        with self._lock:
            self._tasks[task_id] = {
                "task_id": task_id,
                "principal_id": principal_id,
                "capability_id": CAPABILITIES_LIST,
                "state": "SUCCEEDED",
                "result": result,
                "error": None,
                "fingerprint": None,
                "session_id": params.get("sessionId"),
                "payload": payload,
            }
        return self._project_task(task_id)

    def _require_owned_task(self, task_id: str, principal_id: str) -> dict[str, Any]:
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None or task.get("principal_id") != principal_id:
                raise A2AError("TASK_NOT_FOUND", "Task not found")
            return dict(task)

    def _tasks_get(self, params: Mapping[str, Any], *, principal_id: str) -> dict[str, Any]:
        if set(params) - {"id", "historyLength"}:
            raise A2AError("MALFORMED", "Invalid request")
        task_id = params.get("id")
        if not isinstance(task_id, str) or not task_id:
            raise A2AError("MALFORMED", "Invalid request")
        self._require_owned_task(task_id, principal_id)
        return self._project_task(task_id)

    def _tasks_cancel(self, params: Mapping[str, Any], *, principal_id: str) -> dict[str, Any]:
        if set(params) - {"id", "reason"}:
            raise A2AError("MALFORMED", "Invalid request")
        task_id = params.get("id")
        if not isinstance(task_id, str) or not task_id:
            raise A2AError("MALFORMED", "Invalid request")
        task = self._require_owned_task(task_id, principal_id)
        state = str(task.get("state") or "SUBMITTED")
        if state in {"SUCCEEDED", "FAILED", "REJECTED"}:
            return self._project_task(task_id)
        if state != "CANCELLED":
            if self._on_cancel is not None:
                self._on_cancel(task_id)
            with self._lock:
                stored = self._tasks[task_id]
                stored["state"] = "CANCELLED"
            self.event_log.append(task_id, "canceled", state="CANCELLED", terminal=True)
        return self._project_task(task_id)

    def _message_stream(self, params: Mapping[str, Any], *, principal_id: str) -> dict[str, Any]:
        if set(params) - {"id", "from_event_seq"}:
            raise A2AError("MALFORMED", "Invalid request")
        task_id = params.get("id")
        if not isinstance(task_id, str) or not task_id:
            raise A2AError("MALFORMED", "Invalid request")
        self._require_owned_task(task_id, principal_id)
        from_seq = params.get("from_event_seq")
        if from_seq is not None and (not isinstance(from_seq, int) or from_seq < 1):
            raise A2AError("MALFORMED", "Invalid request")
        events = self.stream_events(
            task_id,
            from_event_seq=int(from_seq) if isinstance(from_seq, int) else None,
            principal_id=principal_id,
        )
        return {"events": events, "task": self._project_task(task_id)}

    def stream_events(
        self,
        task_id: str,
        *,
        from_event_seq: int | None = None,
        principal_id: str | None = None,
        client_timeout_ms: int | None = None,
    ) -> list[dict[str, Any]]:
        """Replay retained events for SSE (§A.7.6). Closed on client timeout."""

        if principal_id is not None:
            self._require_owned_task(task_id, principal_id)
        elif not self.event_log.contains(task_id):
            raise A2AError("TASK_NOT_FOUND", "Task not found")

        timeout_ms = self._sse_client_timeout_ms if client_timeout_ms is None else int(client_timeout_ms)
        if timeout_ms <= 0:
            # Client already timed out — close stream without leaking events.
            return []

        retained = self.event_log.get(task_id)
        if from_event_seq is not None:
            min_retained = min((int(e.get("event_seq", 0)) for e in retained), default=0)
            if from_event_seq < min_retained and min_retained > 0:
                raise A2AError("TASK_NOT_FOUND", "Task not found")
            retained = [e for e in retained if int(e.get("event_seq", 0)) >= from_event_seq]

        out: list[dict[str, Any]] = []
        for event in retained:
            seq = int(event.get("event_seq", 0))
            state = str(event.get("state") or "RUNNING")
            payload = event.get("payload") if isinstance(event.get("payload"), Mapping) else {}
            task = project_mesh_to_a2a_task(
                task_id=task_id,
                state=state,
                capability_id=self._tasks.get(task_id, {}).get("capability_id"),
                result=(payload or {}).get("result") if isinstance(payload, Mapping) else None,
                error=(payload or {}).get("error") if isinstance(payload, Mapping) else None,
                event_seq=seq,
            )
            event_name = "task.terminal" if event.get("terminal") else "task.status"
            out.append({"event": event_name, "task": task, "adapter_seq": seq})
        return out

    def apply_mesh_event(
        self,
        task_id: str,
        *,
        state: str,
        result: Any = None,
        error: Mapping[str, Any] | None = None,
        progress: float | None = None,
    ) -> dict[str, Any]:
        """Observe a native lifecycle event and project it (§A.8.3)."""

        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                raise A2AError("TASK_NOT_FOUND", "Task not found")
            task["state"] = state
            if result is not None:
                task["result"] = result
            if error is not None:
                task["error"] = dict(error)
            if progress is not None:
                task["progress"] = progress
        terminal = state in {"SUCCEEDED", "FAILED", "CANCELLED", "REJECTED"}
        self.event_log.append(
            task_id,
            "terminal" if terminal else "status",
            state=state,  # type: ignore[arg-type]
            payload={"result": result, "error": error, "progress": progress},
            terminal=terminal,
        )
        return self._project_task(task_id)

    def _project_task(self, task_id: str) -> dict[str, Any]:
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                raise A2AError("TASK_NOT_FOUND", "Task not found")
            snapshot = dict(task)
        return project_mesh_to_a2a_task(
            task_id=task_id,
            state=str(snapshot.get("state") or "SUBMITTED"),
            capability_id=snapshot.get("capability_id"),
            result=snapshot.get("result"),
            error=snapshot.get("error"),
            event_seq=self.event_log.last_seq(task_id),
            progress=snapshot.get("progress"),
            session_id=snapshot.get("session_id") if isinstance(snapshot.get("session_id"), str) else None,
        )

    def join_room(self, *_args: Any, **_kwargs: Any) -> None:
        """Second-class remotes cannot join rooms (§A.16.5)."""

        raise A2AError("AUTHORIZATION_DENIED", "Authorization denied")

    def list_mesh_members(self, *_args: Any, **_kwargs: Any) -> None:
        """Second-class remotes cannot enumerate mesh members (§A.16.5)."""

        raise A2AError("AUTHORIZATION_DENIED", "Authorization denied")

    @property
    def last_mesh_submit(self) -> dict[str, Any] | None:
        return dict(self._last_mesh_submit) if self._last_mesh_submit else None

    def start(self, host: str | None = None, port: int | None = None) -> "InboundHandler":
        if self._server is not None:
            return self
        bind_host = host or self.listen_host
        bind_port = self.listen_port if port is None else int(port)
        self._server = ThreadingHTTPServer((bind_host, bind_port), _make_http_handler(self))
        self._server.daemon_threads = True
        self.listen_host = str(self._server.server_address[0])
        self.listen_port = int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, name="a2a-inbound", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None

    @property
    def url(self) -> str:
        return f"http://{self.listen_host}:{self.listen_port}{self.jsonrpc_path}"

    @property
    def card_url(self) -> str:
        return f"http://{self.listen_host}:{self.listen_port}{self.public_card_path}"


def create_inbound_handler(*args: Any, **kwargs: Any) -> InboundHandler:
    return InboundHandler(*args, **kwargs)


def _make_http_handler(inbound: InboundHandler) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: Any) -> None:
            return

        def _write(self, status: int, body: bytes, content_type: str = "application/json") -> None:
            self.send_response(status)
            self.send_header("content-type", content_type)
            self.send_header("content-length", str(len(body)))
            # Never emit mesh credential headers on responses.
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path == inbound.public_card_path:
                body = json.dumps(inbound.handle_card_request()).encode("utf-8")
                self._write(200, body)
                return
            self._write(404, b'{"error":"not found"}')

        def do_POST(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            length = int(self.headers.get("content-length") or 0)
            if length > MAX_REQUEST_BYTES:
                payload = build_error_response(None, A2AError("MALFORMED", "Invalid request"))
                self._write(200, json.dumps(payload).encode("utf-8"))
                return
            raw = self.rfile.read(length) if length else b""
            try:
                body = json.loads(raw.decode("utf-8")) if raw else None
            except (ValueError, UnicodeDecodeError):
                payload = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32700,
                        "message": "Parse error",
                        "data": {"polymesh_code": "MALFORMED_JSON", "retryable": False},
                    },
                }
                self._write(200, json.dumps(payload).encode("utf-8"))
                return

            headers = {k: v for k, v in self.headers.items()}
            client_ip = self.client_address[0] if self.client_address else "127.0.0.1"

            if path != inbound.jsonrpc_path:
                self._write(404, b'{"error":"not found"}')
                return

            if isinstance(body, Mapping) and body.get("method") == "message/stream" and inbound.sse_enabled:
                self._handle_sse(body, headers, client_ip)
                return

            response = inbound.handle_sync(body if isinstance(body, Mapping) else None, headers=headers, client_ip=client_ip)
            self._write(200, json.dumps(response).encode("utf-8"))

        def _handle_sse(self, body: Mapping[str, Any], headers: Mapping[str, str], client_ip: str) -> None:
            # Auth + ACL first; errors before stream open use JSON-RPC envelope.
            prelude = inbound.handle_sync(body, headers=headers, client_ip=client_ip)
            if "error" in prelude:
                self._write(200, json.dumps(prelude).encode("utf-8"))
                return
            params = body.get("params") if isinstance(body.get("params"), Mapping) else {}
            task_id = str(params.get("id"))
            from_seq = params.get("from_event_seq")
            try:
                trust = inbound.trust_scope_for(headers)
                events = inbound.stream_events(
                    task_id,
                    from_event_seq=int(from_seq) if isinstance(from_seq, int) else None,
                    principal_id=str(trust["principal_id"]),
                )
            except A2AError as exc:
                self._write(200, json.dumps(build_error_response(body.get("id"), exc)).encode("utf-8"))
                return

            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.send_header("cache-control", "no-cache")
            self.send_header("connection", "close")
            self.end_headers()
            for event in events:
                data = json.dumps({"event": event["event"], "task": event["task"], "adapter_seq": event["adapter_seq"]})
                frame = f"event: task\ndata: {data}\n\n".encode("utf-8")
                try:
                    self.wfile.write(frame)
                    self.wfile.flush()
                except BrokenPipeError:
                    return
            # Stream closes after replay (test harness); live tail omitted.

    return Handler


__all__ = [
    "CAPABILITIES_LIST",
    "DEFAULT_SSE_CLIENT_TIMEOUT_MS",
    "InboundHandler",
    "create_inbound_handler",
    "project_mesh_to_a2a_task",
]

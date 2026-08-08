"""Outbound A2A JSON-RPC client over HTTP (§A.9.2).

Every failure leaves this module as a PolyMesh-coded :class:`A2AError`; raw
HTTP status codes and JSON-RPC codes never reach the routing engine.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from .auth_boundary import A2AAuthBoundary
from .errors import A2ADialectError, A2AError, error_from_http_status, error_from_json_rpc, error_from_transport
from .jsonrpc import build_request, extract_result, parse_response_body
from .types import A2AAdapterConfig, A2ATask

try:  # pragma: no cover - exercised indirectly by the import error path
    import httpx
except ModuleNotFoundError:  # pragma: no cover
    httpx = None  # type: ignore[assignment]

DEFAULT_REQUEST_TIMEOUT_MS = 30000


def _require_httpx() -> Any:
    if httpx is None:  # pragma: no cover - depends on the install extra
        raise A2ADialectError(
            "INTERNAL",
            "the A2A outbound client requires httpx: install latticeag-polymesh[a2a]",
        )
    return httpx


class OutboundClient:
    """Issues ``tasks/send``, ``tasks/get`` and ``tasks/cancel`` calls."""

    def __init__(
        self,
        *,
        config: A2AAdapterConfig | Mapping[str, Any] | None = None,
        auth: A2AAuthBoundary | None = None,
        client: Any = None,
        on_request: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self._config = dict(config or {})
        self._auth = auth if auth is not None else A2AAuthBoundary(self._config)
        self._client = client
        self._owns_client = client is None
        self._on_request = on_request
        self._closed = False

    @property
    def auth(self) -> A2AAuthBoundary:
        return self._auth

    @property
    def timeout_seconds(self) -> float:
        return float(self._config.get("request_timeout_ms", DEFAULT_REQUEST_TIMEOUT_MS)) / 1000.0

    def _ensure_client(self) -> Any:
        if self._client is None:
            module = _require_httpx()
            self._client = module.AsyncClient(timeout=self.timeout_seconds)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None and self._owns_client and not self._closed:
            await self._client.aclose()
        self._closed = True

    async def __aenter__(self) -> OutboundClient:
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.aclose()

    async def tasks_send(self, a2a_url: str, params: Mapping[str, Any], *, task_id: str | None = None) -> A2ATask:
        return await self.call(a2a_url, "tasks/send", params, task_id=task_id)

    async def tasks_get(self, a2a_url: str, remote_task_id: str, *, task_id: str | None = None) -> A2ATask:
        return await self.call(a2a_url, "tasks/get", {"id": remote_task_id}, task_id=task_id)

    async def tasks_cancel(self, a2a_url: str, remote_task_id: str, *, task_id: str | None = None) -> A2ATask:
        return await self.call(a2a_url, "tasks/cancel", {"id": remote_task_id}, task_id=task_id)

    async def call(
        self,
        a2a_url: str,
        method: str,
        params: Mapping[str, Any] | None = None,
        *,
        task_id: str | None = None,
    ) -> A2ATask:
        """Perform one JSON-RPC call and return the task object it carried."""

        headers = self._auth.outbound_headers(a2a_url)
        self._auth.assert_no_mesh_credentials(headers)
        request = build_request(method, params)
        if self._on_request is not None:
            self._on_request({"url": a2a_url, "headers": dict(headers), "body": dict(request)})

        client = self._ensure_client()
        try:
            response = await client.post(a2a_url, json=request, headers=headers)
        except Exception as exc:  # httpx transport failures and timeouts
            if httpx is not None and isinstance(exc, httpx.HTTPError):
                raise error_from_transport(exc, details={"a2a_url": a2a_url}) from exc
            if isinstance(exc, A2AError):
                raise
            raise error_from_transport(exc, details={"a2a_url": a2a_url}) from exc

        body = getattr(response, "content", b"") or b""
        status = int(response.status_code)

        parsed: dict[str, Any] | None
        try:
            parsed = parse_response_body(body) if body else None
        except A2AError:
            parsed = None

        if parsed is not None and isinstance(parsed.get("error"), Mapping):
            raise error_from_json_rpc(parsed["error"], task_id=task_id)
        if status >= 400:
            raise error_from_http_status(
                status,
                details={"a2a_url": a2a_url, "method": method},
                retry_after_ms=_retry_after_ms(response),
            )
        if parsed is None:
            raise A2ADialectError(
                "MALFORMED",
                "remote A2A response body was empty or not valid JSON",
                task_id=task_id,
            )

        result = extract_result(parsed, request_id=request["id"], task_id=task_id)
        if not isinstance(result, Mapping):
            raise A2ADialectError("MALFORMED", f"{method} result did not carry a task object", task_id=task_id)
        return dict(result)  # type: ignore[return-value]


def _retry_after_ms(response: Any) -> int | None:
    headers = getattr(response, "headers", None)
    if not headers:
        return None
    raw = headers.get("retry-after") if hasattr(headers, "get") else None
    if not raw:
        return None
    try:
        return int(float(raw) * 1000)
    except (TypeError, ValueError):
        return None


__all__ = ["DEFAULT_REQUEST_TIMEOUT_MS", "OutboundA2AClient", "OutboundClient"]

OutboundA2AClient = OutboundClient

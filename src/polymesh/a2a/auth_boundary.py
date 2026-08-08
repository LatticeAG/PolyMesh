"""A2A credential boundary (§A.13).

Invariant A.13-1: A2A credentials terminate at the adapter and mesh
credentials never cross the dialect boundary in either direction.  Two controls
enforce it -- an operator-declared endpoint allowlist that owns the outbound
credential, and payload hygiene that strips credential-shaped strings.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from typing import Any, NamedTuple
from urllib.parse import urlsplit

from .config import normalize_trusted_endpoint, resolve_auth_token
from .errors import A2AError
from .types import A2AAdapterConfig, TrustedEndpoint

#: Header names that would leak mesh-side credentials onto an A2A request.
MESH_CREDENTIAL_HEADERS: frozenset[str] = frozenset(
    {
        "x-polymesh-token",
        "x-polymesh-session",
        "x-polymesh-ticket",
        "x-polymesh-mesh-token",
        "x-mesh-token",
        "x-gateway-jwt",
        "x-room-token",
    }
)

REDACTED = "[REDACTED]"

#: JWT-shaped base64url triplet.  The 10-char segment minimum keeps dotted
#: capability ids and semantic versions out of the match (§A.13.5).
JWT_PATTERN = re.compile(r"[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")

BEARER_PATTERN = re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)


class Redaction(NamedTuple):
    path: str
    pattern: str


class HygieneResult(NamedTuple):
    value: Any
    redactions: list[Redaction]

    @property
    def redacted(self) -> bool:
        return bool(self.redactions)


def credential_thumbprint(secret: str) -> str:
    """Short digest for audit logs; raw credentials are never logged (§A.13.2)."""

    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:12]


def redact_credentials(value: Any, path: str = "$") -> HygieneResult:
    """Replace Bearer headers and JWT-shaped strings anywhere in ``value``."""

    redactions: list[Redaction] = []
    cleaned = _walk(value, path, redactions)
    return HygieneResult(cleaned, redactions)


def _walk(value: Any, path: str, redactions: list[Redaction]) -> Any:
    if isinstance(value, str):
        current = value
        after_bearer = BEARER_PATTERN.sub(REDACTED, current)
        if after_bearer != current:
            current = after_bearer
            redactions.append(Redaction(path, "bearer"))
        after_jwt = JWT_PATTERN.sub(REDACTED, current)
        if after_jwt != current:
            current = after_jwt
            redactions.append(Redaction(path, "jwt"))
        return current
    if isinstance(value, Mapping):
        return {key: _walk(item, f"{path}.{key}", redactions) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_walk(item, f"{path}[{index}]", redactions) for index, item in enumerate(value)]
    return value


def _origin(parts: Any) -> tuple[str, str]:
    return (parts.scheme.lower(), parts.netloc.lower())


def _normalize_path(path: str) -> str:
    if len(path) > 1 and path.endswith("/"):
        return path[:-1]
    return path or "/"


class A2AAuthBoundary:
    """Outbound credential store plus payload hygiene (§A.13.1, §A.13.5)."""

    def __init__(
        self,
        config: A2AAdapterConfig | Mapping[str, Any] | None = None,
        *,
        trusted_endpoints: Sequence[str | Mapping[str, Any]] | None = None,
        default_auth: Mapping[str, Any] | None = None,
        on_redaction: Any = None,
    ) -> None:
        source = dict(config or {})
        raw_endpoints = trusted_endpoints if trusted_endpoints is not None else source.get("trusted_endpoints", [])
        self._trusted: list[TrustedEndpoint] = [normalize_trusted_endpoint(entry) for entry in raw_endpoints or []]
        self._default_auth = dict(default_auth) if default_auth is not None else dict(source.get("auth") or {})
        self._on_redaction = on_redaction

    @property
    def trusted_endpoints(self) -> list[TrustedEndpoint]:
        return list(self._trusted)

    def resolve_endpoint(self, a2a_url: str) -> TrustedEndpoint | None:
        """Return the operator-declared endpoint matching ``a2a_url``, if any."""

        if not isinstance(a2a_url, str) or not a2a_url:
            return None
        try:
            parsed = urlsplit(a2a_url)
        except ValueError:
            return None
        if not parsed.scheme or not parsed.netloc:
            return None
        for endpoint in self._trusted:
            if self._matches(parsed, endpoint):
                return endpoint
        return None

    def _matches(self, parsed: Any, endpoint: TrustedEndpoint) -> bool:
        try:
            expected = urlsplit(endpoint["url"])
        except ValueError:
            return False
        if _origin(parsed) != _origin(expected):
            return False
        match = endpoint.get("match", "exact")
        if match == "origin":
            return True
        if match == "prefix":
            return _normalize_path(parsed.path).startswith(_normalize_path(expected.path))
        return _normalize_path(parsed.path) == _normalize_path(expected.path)

    def assert_trusted_endpoint(self, a2a_url: str) -> TrustedEndpoint:
        """§A.13.3.1: a discovered ``a2a_url`` must be preconfigured as trusted."""

        endpoint = self.resolve_endpoint(a2a_url)
        if endpoint is None:
            raise A2AError(
                "AUTHORIZATION_DENIED",
                f"A2A endpoint is not in the outbound credential allowlist: {a2a_url}",
                details={"a2a_url": a2a_url},
            )
        return endpoint

    def outbound_headers(self, a2a_url: str) -> dict[str, str]:
        """Headers for one outbound call: A2A-world credentials only (§A.13.1)."""

        endpoint = self.assert_trusted_endpoint(a2a_url)
        auth = endpoint.get("auth") or self._default_auth
        headers: dict[str, str] = {
            "content-type": "application/json",
            "accept": "application/json",
        }
        token = resolve_auth_token(auth)
        mode = (auth or {}).get("mode", "none")
        if not token or mode == "none":
            return headers
        if mode == "bearer":
            header_name = str(auth.get("header_name") or "Authorization").lower()
            headers[header_name] = f"Bearer {token}"
        else:
            header_name = str(auth.get("header_name") or "X-API-Key").lower()
            headers[header_name] = token
        self.assert_no_mesh_credentials(headers)
        return headers

    def assert_no_mesh_credentials(self, headers: Mapping[str, str]) -> None:
        """Fail closed if a mesh credential header reached the outbound path."""

        for name in headers:
            if name.lower() in MESH_CREDENTIAL_HEADERS:
                raise A2AError(
                    "AUTHORIZATION_DENIED",
                    f"mesh credential header {name} must not cross the A2A boundary",
                    details={"header": name.lower()},
                )

    def sanitize_outbound_payload(self, payload: Any, *, task_id: str | None = None) -> HygieneResult:
        """Apply payload hygiene and report every redaction (§A.13.5)."""

        result = redact_credentials(payload)
        if self._on_redaction is not None:
            for event in result.redactions:
                self._on_redaction({"path": event.path, "pattern": event.pattern, "task_id": task_id})
        return result


__all__ = [
    "A2AAuthBoundary",
    "BEARER_PATTERN",
    "HygieneResult",
    "JWT_PATTERN",
    "MESH_CREDENTIAL_HEADERS",
    "REDACTED",
    "Redaction",
    "credential_thumbprint",
    "redact_credentials",
]

"""A2A adapter configuration (§E.13).

The adapter fails closed: nothing is enabled by default, and an outbound call
is only possible once the operator has declared the target endpoint in
``trusted_endpoints`` (§A.13.3.1).
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .errors import A2AConfigError
from .types import A2AAdapterConfig, A2AAuthConfig, AuthMode, TrustedEndpoint

ENV_PREFIX = "POLYMESH_A2A_"

AUTH_MODES: frozenset[str] = frozenset({"none", "bearer", "api_key_header"})

MATCH_MODES: frozenset[str] = frozenset({"exact", "prefix", "origin"})

DEFAULT_CONFIG: A2AAdapterConfig = {
    "enabled": False,
    "inbound_enabled": False,
    "outbound_enabled": False,
    "listen_host": "127.0.0.1",
    "public_card_path": "/.well-known/agent.json",
    "jsonrpc_path": "/a2a",
    "sse_enabled": True,
    "poll_max_ms": 15000,
    "auth": {"mode": "none", "header_name": "Authorization"},
    "rate_limit": {"enabled": True, "capacity": 20.0, "refill_per_sec": 10.0},
    "trusted_endpoints": [],
    "allow_wildcard_endpoints": False,
    "allow_public_unauthenticated": False,
    "event_log_cap": 1000,
    "request_timeout_ms": 30000,
    "idempotency_retention_ms": 24 * 60 * 60 * 1000,
}

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


def _env_bool(env: Mapping[str, str], key: str) -> bool | None:
    raw = env.get(key)
    if raw is None or raw == "":
        return None
    lowered = raw.strip().lower()
    if lowered in _TRUE_VALUES:
        return True
    if lowered in _FALSE_VALUES:
        return False
    raise A2AConfigError("MALFORMED", f"{key} must be a boolean-ish value, got {raw!r}")


def _env_int(env: Mapping[str, str], key: str) -> int | None:
    raw = env.get(key)
    if raw is None or raw == "":
        return None
    try:
        return int(raw)
    except ValueError as exc:
        raise A2AConfigError("MALFORMED", f"{key} must be an integer, got {raw!r}") from exc


def normalize_trusted_endpoint(entry: str | Mapping[str, Any]) -> TrustedEndpoint:
    """Coerce one allowlist entry into a :class:`TrustedEndpoint` record."""

    if isinstance(entry, str):
        raw: dict[str, Any] = {"url": entry}
    elif isinstance(entry, Mapping):
        raw = dict(entry)
    else:
        raise A2AConfigError("MALFORMED", "trusted endpoint must be a URL string or mapping")

    url = raw.get("url")
    if not isinstance(url, str) or not url.strip():
        raise A2AConfigError("MALFORMED", "trusted endpoint requires a url")
    match = raw.get("match", "exact")
    if match not in MATCH_MODES:
        raise A2AConfigError("MALFORMED", f"trusted endpoint match must be one of {sorted(MATCH_MODES)}")

    endpoint: TrustedEndpoint = {"url": url.strip(), "match": match}
    auth = raw.get("auth")
    if isinstance(auth, Mapping):
        endpoint["auth"] = normalize_auth(auth)
    return endpoint


def normalize_auth(auth: Mapping[str, Any]) -> A2AAuthConfig:
    """Validate one credential block, leaving the secret itself untouched."""

    mode = auth.get("mode", "none")
    if mode not in AUTH_MODES:
        raise A2AConfigError("MALFORMED", f"auth mode must be one of {sorted(AUTH_MODES)}")
    resolved: A2AAuthConfig = {"mode": mode}
    token = auth.get("token")
    if isinstance(token, str) and token:
        resolved["token"] = token
    token_file = auth.get("token_file")
    if isinstance(token_file, str) and token_file:
        resolved["token_file"] = token_file
    header_name = auth.get("header_name")
    if isinstance(header_name, str) and header_name:
        resolved["header_name"] = header_name
    elif mode == "api_key_header":
        resolved["header_name"] = "X-API-Key"
    else:
        resolved["header_name"] = "Authorization"
    return resolved


def resolve_auth_token(auth: Mapping[str, Any] | None) -> str | None:
    """Return the credential for ``auth``, reading ``token_file`` when set."""

    if not isinstance(auth, Mapping) or auth.get("mode", "none") == "none":
        return None
    token = auth.get("token")
    if isinstance(token, str) and token:
        return token
    token_file = auth.get("token_file")
    if isinstance(token_file, str) and token_file:
        try:
            return Path(token_file).read_text("utf-8").strip() or None
        except OSError as exc:
            raise A2AConfigError("MALFORMED", f"unable to read A2A auth token_file {token_file!r}") from exc
    return None


def load_a2a_config(
    env: Mapping[str, str] | None = None,
    overrides: Mapping[str, Any] | None = None,
) -> A2AAdapterConfig:
    """Merge defaults, ``POLYMESH_A2A_*`` environment, and explicit overrides."""

    source: Mapping[str, str] = os.environ if env is None else env
    config: A2AAdapterConfig = {
        **DEFAULT_CONFIG,
        "auth": dict(DEFAULT_CONFIG["auth"]),
        "rate_limit": dict(DEFAULT_CONFIG["rate_limit"]),
        "trusted_endpoints": [],
    }

    for key, env_name in (
        ("enabled", "ENABLED"),
        ("inbound_enabled", "INBOUND_ENABLED"),
        ("outbound_enabled", "OUTBOUND_ENABLED"),
        ("sse_enabled", "SSE_ENABLED"),
        ("allow_wildcard_endpoints", "ALLOW_WILDCARD_ENDPOINTS"),
        ("allow_public_unauthenticated", "ALLOW_PUBLIC_UNAUTHENTICATED"),
    ):
        value = _env_bool(source, ENV_PREFIX + env_name)
        if value is not None:
            config[key] = value  # type: ignore[literal-required]

    for key, env_name in (
        ("listen_port", "LISTEN_PORT"),
        ("poll_max_ms", "POLL_MAX_MS"),
        ("event_log_cap", "EVENT_LOG_CAP"),
        ("request_timeout_ms", "REQUEST_TIMEOUT_MS"),
        ("idempotency_retention_ms", "IDEMPOTENCY_RETENTION_MS"),
    ):
        number = _env_int(source, ENV_PREFIX + env_name)
        if number is not None:
            config[key] = number  # type: ignore[literal-required]

    for key, env_name in (
        ("a2a_url", "URL"),
        ("listen_host", "LISTEN_HOST"),
        ("public_card_path", "CARD_PATH"),
        ("jsonrpc_path", "JSONRPC_PATH"),
        ("idempotency_store_path", "IDEMPOTENCY_STORE"),
        ("task_id_store_path", "TASK_ID_STORE"),
        ("event_log_path", "EVENT_LOG_PATH"),
    ):
        text = source.get(ENV_PREFIX + env_name)
        if text:
            config[key] = text  # type: ignore[literal-required]

    env_auth: dict[str, Any] = {"mode": source.get(ENV_PREFIX + "AUTH_MODE", "none")}
    if source.get(ENV_PREFIX + "AUTH_TOKEN"):
        env_auth["token"] = source[ENV_PREFIX + "AUTH_TOKEN"]
    if source.get(ENV_PREFIX + "AUTH_TOKEN_FILE"):
        env_auth["token_file"] = source[ENV_PREFIX + "AUTH_TOKEN_FILE"]
    if source.get(ENV_PREFIX + "AUTH_HEADER"):
        env_auth["header_name"] = source[ENV_PREFIX + "AUTH_HEADER"]
    config["auth"] = normalize_auth(env_auth)

    rate_limit_enabled = _env_bool(source, ENV_PREFIX + "RATE_LIMIT")
    if rate_limit_enabled is not None:
        config["rate_limit"] = {**config["rate_limit"], "enabled": rate_limit_enabled}

    trusted_raw = source.get(ENV_PREFIX + "TRUSTED_ENDPOINTS")
    if trusted_raw:
        config["trusted_endpoints"] = [
            normalize_trusted_endpoint(item.strip()) for item in trusted_raw.split(",") if item.strip()
        ]

    if overrides:
        for key, value in overrides.items():
            if key == "auth" and isinstance(value, Mapping):
                config["auth"] = normalize_auth({**config["auth"], **value})
            elif key == "rate_limit" and isinstance(value, Mapping):
                config["rate_limit"] = {**config["rate_limit"], **value}
            elif key == "trusted_endpoints":
                if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
                    raise A2AConfigError("MALFORMED", "trusted_endpoints must be a sequence")
                config["trusted_endpoints"] = [normalize_trusted_endpoint(item) for item in value]
            else:
                config[key] = value  # type: ignore[literal-required]

    if int(config.get("poll_max_ms", 0)) <= 0:
        raise A2AConfigError("MALFORMED", "poll_max_ms must be positive")
    if int(config.get("event_log_cap", 0)) <= 0:
        raise A2AConfigError("MALFORMED", "event_log_cap must be positive")
    return config


def redact_config(config: Mapping[str, Any]) -> dict[str, Any]:
    """Copy of ``config`` safe to log: every credential becomes a marker (§E.13.3)."""

    safe: dict[str, Any] = {}
    for key, value in config.items():
        if key == "auth" and isinstance(value, Mapping):
            safe[key] = _redact_auth(value)
        elif key == "trusted_endpoints" and isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            endpoints: list[Any] = []
            for entry in value:
                if isinstance(entry, Mapping):
                    copied = dict(entry)
                    if isinstance(copied.get("auth"), Mapping):
                        copied["auth"] = _redact_auth(copied["auth"])
                    endpoints.append(copied)
                else:
                    endpoints.append(entry)
            safe[key] = endpoints
        else:
            safe[key] = value
    return safe


def _redact_auth(auth: Mapping[str, Any]) -> dict[str, Any]:
    copied = dict(auth)
    if copied.get("token"):
        copied["token"] = "[REDACTED]"
    return copied


def auth_mode_of(config: Mapping[str, Any]) -> AuthMode:
    auth = config.get("auth")
    mode = auth.get("mode") if isinstance(auth, Mapping) else None
    return mode if mode in AUTH_MODES else "none"  # type: ignore[return-value]


__all__ = [
    "AUTH_MODES",
    "DEFAULT_CONFIG",
    "ENV_PREFIX",
    "MATCH_MODES",
    "auth_mode_of",
    "load_a2a_config",
    "normalize_auth",
    "normalize_trusted_endpoint",
    "redact_config",
    "resolve_auth_token",
]

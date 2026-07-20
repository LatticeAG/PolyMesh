"""Closed operational configuration for the PolyMesh command line tools.

Wire records intentionally remain JSON/Pydantic models in :mod:`polymesh.types`.
This module only handles local file paths and endpoint preferences; it never
accepts raw runtime tokens or private key material from a configuration value.
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ConfigError(ValueError):
    """Raised when local configuration is malformed or unsafe."""


class _ConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def _optional_path(value: str | None) -> str | None:
    if value is None:
        return None
    if not value:
        raise ValueError("path must not be empty")
    # Keep a caller supplied relative path relative.  The credential loader
    # makes it absolute without resolving symlinks, so it can still reject a
    # symlink token file instead of accidentally blessing its destination.
    return str(Path(value).expanduser())


def _validate_url(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        parsed = urlsplit(value)
        # ``urlsplit`` delays malformed and out-of-range port failures until
        # ``.port`` is accessed.  Configuration must reject those endpoints
        # here instead of deferring the error to connection time.
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("url must contain a valid WebSocket port") from exc
    if parsed.scheme not in {"ws", "wss"} or not hostname:
        raise ValueError("url must be an absolute ws:// or wss:// endpoint")
    # Empty ``?`` and ``#`` delimiters are still forbidden endpoint syntax:
    # accepting them would make the configured value differ from the exact
    # `/polymesh` endpoint the transport is required to use.
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "?" in value
        or "#" in value
    ):
        raise ValueError("url must not contain credentials, query, or fragment")
    if parsed.path not in {"", "/polymesh"}:
        raise ValueError("url path must be /polymesh")
    return value


class ClientConfig(_ConfigModel):
    url: str | None = None
    card_file: str | None = None
    token_file: str | None = None
    timeout_ms: int = Field(default=60_000, gt=0, le=86_400_000)
    insecure_loopback_dev: bool = False

    _path_fields = field_validator("card_file", "token_file")(_optional_path)
    _url = field_validator("url")(_validate_url)


class BrokerConfig(_ConfigModel):
    host: str = Field(default="127.0.0.1", min_length=1, max_length=255)
    port: int = Field(default=7337, ge=0, le=65535)
    token_file: str | None = None
    insecure_loopback_dev: bool = False
    mdns: bool = False

    _token_path = field_validator("token_file")(_optional_path)


class OutputConfig(_ConfigModel):
    format: Literal["json", "table", "plain"] = "json"


class SecurityConfig(_ConfigModel):
    ca_file: str | None = None
    cert_file: str | None = None
    key_file: str | None = None
    identity_key_file: str | None = None
    enrollments_file: str | None = None

    _path_fields = field_validator(
        "ca_file", "cert_file", "key_file", "identity_key_file", "enrollments_file"
    )(_optional_path)


class PolyMeshConfig(_ConfigModel):
    client: ClientConfig = Field(default_factory=ClientConfig)
    broker: BrokerConfig = Field(default_factory=BrokerConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)

    @model_validator(mode="after")
    def _reject_unsafe_inline_credentials(self) -> "PolyMeshConfig":
        # ``extra='forbid'`` catches ordinary inline fields. This defensive
        # check protects callers who construct nested models directly.
        return self


_RAW_SECRET_ENVIRONMENTS = (
    "POLYMESH_TOKEN",
    "POLYMESH_PRIVATE_KEY",
    "POLYMESH_TLS_KEY",
    "POLYMESH_IDENTITY_KEY",
)


def _default_user_config_path() -> Path:
    try:
        from platformdirs import user_config_dir

        return Path(user_config_dir("polymesh", "LatticeAG")) / "polymesh.toml"
    except ImportError:  # pragma: no cover - dependency is required in releases
        return Path.home() / ".config" / "polymesh" / "polymesh.toml"


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        # Bound the read itself, not only the parsed payload, so a malformed
        # local configuration cannot make the CLI allocate an arbitrary file.
        with path.open("rb") as handle:
            payload = handle.read(1_048_576 + 1)
    except (OSError, ValueError) as exc:
        raise ConfigError(f"cannot read configuration file: {path}") from exc
    if len(payload) > 1_048_576:
        raise ConfigError("configuration file exceeds 1 MiB")
    try:
        decoded = tomllib.loads(payload.decode("utf-8", "strict"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"invalid TOML configuration: {path}") from exc
    if not isinstance(decoded, dict):
        raise ConfigError("configuration root must be a TOML table")
    return decoded


def _deep_merge(base: dict[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), Mapping):
            merged[key] = _deep_merge(dict(merged[key]), value)
        else:
            merged[key] = value
    return merged


def _parse_bool(value: str, name: str) -> bool:
    if value in {"true", "1"}:
        return True
    if value in {"false", "0"}:
        return False
    raise ConfigError(f"{name} must be true, false, 1, or 0")


def environment_overrides(env: Mapping[str, str | None] | None = None) -> dict[str, Any]:
    """Return safe path/value-oriented configuration overrides from ``env``.

    Raw secrets are rejected even if a command line flag would otherwise take
    precedence: accepting them at all makes accidental credential leakage too
    easy and contradicts the SDK credential boundary.
    """

    values = os.environ if env is None else env
    for name in _RAW_SECRET_ENVIRONMENTS:
        if values.get(name) is not None:
            raise ConfigError(f"{name} is not supported; use a credential file path")

    data: dict[str, Any] = {}

    def set_value(section: str, field: str, name: str, transform: Any = None) -> None:
        raw = values.get(name)
        if raw is None:
            return
        target = data.setdefault(section, {})
        target[field] = transform(raw, name) if transform else raw

    set_value("client", "card_file", "POLYMESH_CARD")
    set_value("client", "token_file", "POLYMESH_TOKEN_FILE")
    set_value("client", "url", "POLYMESH_URL")
    set_value("client", "timeout_ms", "POLYMESH_TIMEOUT_MS", lambda value, _: _positive_int(value, "POLYMESH_TIMEOUT_MS"))
    set_value("client", "insecure_loopback_dev", "POLYMESH_INSECURE_LOOPBACK_DEV", _parse_bool)
    set_value("broker", "host", "POLYMESH_HOST")
    set_value("broker", "port", "POLYMESH_PORT", lambda value, _: _port(value, "POLYMESH_PORT"))
    set_value("broker", "token_file", "POLYMESH_TOKEN_FILE")
    set_value("broker", "insecure_loopback_dev", "POLYMESH_INSECURE_LOOPBACK_DEV", _parse_bool)
    set_value("broker", "mdns", "POLYMESH_MDNS", _parse_bool)
    set_value("output", "format", "POLYMESH_FORMAT")
    set_value("security", "ca_file", "POLYMESH_CA_FILE")
    set_value("security", "cert_file", "POLYMESH_CERT_FILE")
    set_value("security", "key_file", "POLYMESH_KEY_FILE")
    set_value("security", "identity_key_file", "POLYMESH_IDENTITY_KEY_FILE")
    set_value("security", "enrollments_file", "POLYMESH_ENROLLMENTS_FILE")
    return data


def _positive_int(value: str, name: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a positive integer") from exc
    if parsed <= 0:
        raise ConfigError(f"{name} must be a positive integer")
    return parsed


def _port(value: str, name: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer between 0 and 65535") from exc
    if not 0 <= parsed <= 65535:
        raise ConfigError(f"{name} must be an integer between 0 and 65535")
    return parsed


def discover_config_path(*, cwd: Path | None = None) -> Path | None:
    """Find the first automatic TOML config path without reading it."""

    project = (cwd or Path.cwd()) / "polymesh.toml"
    if project.is_file():
        return project
    user = _default_user_config_path()
    return user if user.is_file() else None


def load_config(
    *,
    config_path: str | Path | None = None,
    env: Mapping[str, str | None] | None = None,
    overrides: Mapping[str, Any] | None = None,
    cwd: Path | None = None,
) -> PolyMeshConfig:
    """Load config with flags/overrides > environment > file > defaults.

    Passing ``config_path`` intentionally disables automatic project/user
    discovery. An absent explicit path is an error rather than silently
    continuing with a surprising configuration.
    """

    selected: Path | None
    if config_path is not None:
        selected = Path(config_path).expanduser()
        if selected.suffix.lower() not in {".toml", ""}:
            raise ConfigError("only TOML configuration is installed; use a .toml file")
        if not selected.is_file():
            raise ConfigError(f"configuration file does not exist: {selected}")
    else:
        explicit_from_env = (os.environ if env is None else env).get("POLYMESH_CONFIG")
        selected = Path(explicit_from_env).expanduser() if explicit_from_env else discover_config_path(cwd=cwd)
        if selected is not None and selected.suffix.lower() not in {".toml", ""}:
            raise ConfigError("only TOML configuration is installed; use a .toml file")
        if explicit_from_env and not selected.is_file():
            raise ConfigError(f"configuration file does not exist: {selected}")

    merged: dict[str, Any] = {}
    if selected is not None:
        merged = _read_toml(selected)
    merged = _deep_merge(merged, environment_overrides(env))
    if overrides:
        merged = _deep_merge(merged, overrides)
    try:
        return PolyMeshConfig.model_validate(merged)
    except Exception as exc:
        # Do not expose a raw Pydantic repr with arbitrary config values.
        raise ConfigError("invalid PolyMesh configuration") from exc


__all__ = [
    "BrokerConfig",
    "ClientConfig",
    "ConfigError",
    "OutputConfig",
    "PolyMeshConfig",
    "SecurityConfig",
    "discover_config_path",
    "environment_overrides",
    "load_config",
]

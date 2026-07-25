"""The safe operational command-line interface for the PolyMesh SDK.

The command deliberately accepts credential *paths*, never raw bearer tokens
or private-key values. It is implemented with Click but keeps presentation and
configuration functions small enough to exercise directly in unit tests.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

import click

from .config import ConfigError, PolyMeshConfig, load_config


OutputFormat = Literal["json", "table", "plain"]


class CliFailure(click.ClickException):
    """A bounded CLI error with the stable exit-code contract."""

    def __init__(
        self,
        message: str,
        *,
        code: str,
        category: str,
        exit_code: int,
        retryable: bool = False,
        output_format: OutputFormat | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.category = category
        self.exit_code = exit_code
        self.retryable = retryable
        self.output_format = output_format

    def show(self, file: Any | None = None) -> None:
        stream = file or click.get_text_stream("stderr")
        ctx = click.get_current_context(silent=True)
        output_format = self.output_format or "json"
        if self.output_format is None and ctx is not None and isinstance(ctx.obj, _CommandContext):
            output_format = ctx.obj.output_format
        elif self.output_format is None and ctx is not None:
            # Group callback failures happen before ``ctx.obj`` can contain a
            # fully validated configuration.  Honour an explicit safe format
            # flag nevertheless, so ``--format plain`` does not unexpectedly
            # turn a local configuration diagnostic into JSON.
            requested = ctx.params.get("output_format")
            if requested in {"json", "table", "plain"}:
                output_format = requested
        message = _bounded_message(self.message)
        if output_format == "json":
            stream.write(
                json.dumps(
                    {
                        "ok": False,
                        "code": self.code,
                        "category": self.category,
                        "message": message,
                        "retryable": self.retryable,
                    },
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n"
            )
        else:
            stream.write(f"{self.code}: {message}\n")


class _CommandContext:
    def __init__(self, config: PolyMeshConfig, output_format: OutputFormat, quiet: bool = False) -> None:
        self.config = config
        self.output_format = output_format
        self.quiet = quiet


def _bounded_message(value: object) -> str:
    message = str(value).replace("\x00", "?").replace("\r", " ").replace("\n", " ")
    # Tokens use canonical base64url, normally 43 characters. Avoid placing a
    # plausible one into a terminal/log even when an underlying exception did.
    message = re.sub(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])", "[redacted]", message)
    return message[:8192]


def _model_to_value(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return _model_to_value(value.model_dump(mode="json", exclude_none=True))
    if isinstance(value, Mapping):
        return {str(key): _model_to_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_model_to_value(item) for item in value]
    return value


def render_output(value: Any, output_format: OutputFormat) -> str:
    """Render one successful value without terminal decoration or secrets."""

    normalized = _model_to_value(value)
    if output_format == "json":
        return json.dumps(normalized, indent=2, ensure_ascii=False, default=str) + "\n"
    if output_format == "plain":
        if isinstance(normalized, list):
            return "".join(_plain_line(item) + "\n" for item in normalized)
        return _plain_line(normalized) + "\n"
    return _render_table(normalized)


def _plain_line(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)) or value is None:
        return str(value).lower() if isinstance(value, bool) else str(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _render_table(value: Any) -> str:
    if not isinstance(value, list) or not all(isinstance(item, Mapping) for item in value):
        return json.dumps(value, indent=2, ensure_ascii=False, default=str) + "\n"
    rows = [dict(item) for item in value]
    if not rows:
        return "\n"
    headings = sorted({str(key) for row in rows for key in row})
    labels = {
        "agent_id": "Agent",
        "instance_id": "Instance",
        "id": "Capability",
        "version": "Version",
        "idempotency": "Idempotency",
        "side_effects": "Side effects",
        "cancellation": "Cancellation",
    }
    display_headings = [labels.get(column, column.replace("_", " ").title()) for column in headings]
    rendered = [[_plain_line(row.get(column, "")) for column in headings] for row in rows]
    widths = [
        max(len(display_headings[index]), *(len(row[index]) for row in rendered))
        for index in range(len(headings))
    ]
    header = "  ".join(display_headings[index].ljust(widths[index]) for index in range(len(headings)))
    separator = "  ".join("-" * width for width in widths)
    body = ["  ".join(row[index].ljust(widths[index]) for index in range(len(headings))) for row in rendered]
    return "\n".join([header, separator, *body]) + "\n"


def _option_overrides(
    *,
    output_format: str | None,
    card: str | None,
    token_file: str | None,
    url: str | None,
    timeout: int | None,
    insecure_loopback_dev: bool | None,
    gateway_url: str | None = None,
    api_key: str | None = None,
    api_key_file: str | None = None,
    mesh_id: str | None = None,
) -> dict[str, Any]:
    data: dict[str, Any] = {}
    client: dict[str, Any] = {}
    if card is not None:
        client["card_file"] = card
    if token_file is not None:
        client["token_file"] = token_file
    if url is not None:
        client["url"] = url
    if timeout is not None:
        client["timeout_ms"] = timeout
    if insecure_loopback_dev is not None:
        client["insecure_loopback_dev"] = insecure_loopback_dev
    if client:
        data["client"] = client
    # ``--token-file`` and ``--insecure-loopback-dev`` are global options;
    # start/listen therefore see the same explicit values as connect/call.
    # Command-local start/listen options still take precedence later.
    broker: dict[str, Any] = {}
    if token_file is not None:
        broker["token_file"] = token_file
    if insecure_loopback_dev is not None:
        broker["insecure_loopback_dev"] = insecure_loopback_dev
    if broker:
        data["broker"] = broker
    gateway: dict[str, Any] = {}
    if gateway_url is not None:
        gateway["url"] = gateway_url
    if api_key is not None:
        gateway["api_key"] = api_key
    if api_key_file is not None:
        gateway["api_key_file"] = api_key_file
    if mesh_id is not None:
        gateway["mesh_id"] = mesh_id
    if gateway:
        data["gateway"] = gateway
    if output_format is not None:
        data["output"] = {"format": output_format}
    return data


def _reject_raw_credential(_ctx: click.Context, _param: click.Parameter, value: str | None) -> None:
    if value is not None:
        raise CliFailure(
            "raw credentials are not supported; use a credential file path",
            code="USAGE",
            category="configuration",
            exit_code=2,
        )


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--config", "config_path", type=click.Path(path_type=Path, dir_okay=False), default=None, help="TOML config path")
@click.option("--format", "output_format", type=click.Choice(["json", "table", "plain"]), default=None)
@click.option("--card", type=click.Path(path_type=Path, dir_okay=False), default=None, help="Agent Card JSON path")
@click.option("--token-file", type=click.Path(path_type=Path, dir_okay=False), default=None, help="Runtime token file path (broker only; not gateway API keys)")
@click.option("--url", default=None, help="Broker WebSocket endpoint")
@click.option("--timeout", type=click.IntRange(min=1, max=86_400_000), default=None, help="Call timeout in milliseconds")
@click.option("--insecure-loopback-dev/--no-insecure-loopback-dev", default=None, help="Permit ws:// numeric loopback only")
@click.option("--gateway-url", default=None, help="PolyMesh Gateway base URL (ws/wss/http/https)")
@click.option("--api-key", default=None, help="Gateway API key (discouraged; prefer --api-key-file)")
@click.option("--api-key-file", type=click.Path(path_type=Path, dir_okay=False), default=None, help="Gateway API key file path")
@click.option("--mesh", "mesh_id", default=None, help="Default gateway mesh id")
@click.option("--quiet", is_flag=True, default=False, help="Suppress non-result diagnostics")
@click.option("--token", hidden=True, expose_value=False, callback=_reject_raw_credential)
@click.option("--private-key", hidden=True, expose_value=False, callback=_reject_raw_credential)
@click.option("--tls-key", hidden=True, expose_value=False, callback=_reject_raw_credential)
@click.pass_context
def main(
    ctx: click.Context,
    config_path: Path | None,
    output_format: str | None,
    card: Path | None,
    token_file: Path | None,
    url: str | None,
    timeout: int | None,
    insecure_loopback_dev: bool | None,
    gateway_url: str | None,
    api_key: str | None,
    api_key_file: Path | None,
    mesh_id: str | None,
    quiet: bool,
) -> None:
    """PolyMesh v0.1 command-line tools."""

    # Make a provisional context available to CliFailure while configuration
    # validation is running.  It contains no credentials and is replaced by
    # the validated configuration below.
    provisional_format = output_format if output_format is not None else os.environ.get("POLYMESH_FORMAT", "json")
    ctx.obj = _CommandContext(PolyMeshConfig(), provisional_format if provisional_format in {"json", "table", "plain"} else "json", quiet)
    try:
        config = load_config(
            config_path=config_path,
            overrides=_option_overrides(
                output_format=output_format,
                card=str(card) if card is not None else None,
                token_file=str(token_file) if token_file is not None else None,
                url=url,
                timeout=timeout,
                insecure_loopback_dev=insecure_loopback_dev,
                gateway_url=gateway_url,
                api_key=api_key,
                api_key_file=str(api_key_file) if api_key_file is not None else None,
                mesh_id=mesh_id,
            ),
        )
    except ConfigError as exc:
        raise CliFailure(
            _bounded_message(exc),
            code="CONFIGURATION_INVALID",
            category="configuration",
            exit_code=3,
            output_format=ctx.obj.output_format,
        ) from exc
    ctx.obj = _CommandContext(config, config.output.format, quiet)


def _context(ctx: click.Context) -> _CommandContext:
    if not isinstance(ctx.obj, _CommandContext):  # pragma: no cover - Click always sets it
        raise RuntimeError("PolyMesh command context is missing")
    return ctx.obj


def _emit(ctx: click.Context, value: Any) -> None:
    click.echo(render_output(value, _context(ctx).output_format), nl=False)


def _load_card(path: str | None):
    from .protocol import parse_strict_json
    from .types import AgentCard, AgentCardBuilder

    if path is None:
        return AgentCardBuilder("org.polymesh.cli").build()
    try:
        # Keep the 64 KiB Card budget effective before materialising a local
        # file in memory.  The strict JSON parser enforces the same limit at
        # the wire boundary.
        with Path(path).open("rb") as handle:
            raw = handle.read(64 * 1024 + 1)
    except (OSError, ValueError) as exc:
        raise CliFailure("cannot read Agent Card file", code="CARD_INVALID", category="configuration", exit_code=3) from exc
    if len(raw) > 64 * 1024:
        raise CliFailure("Agent Card is invalid", code="CARD_INVALID", category="configuration", exit_code=3)
    try:
        value = parse_strict_json(raw, max_bytes=64 * 1024)
        return AgentCard.model_validate(value)
    except Exception as exc:
        raise CliFailure("Agent Card is invalid", code="CARD_INVALID", category="configuration", exit_code=3) from exc


def _load_token(path: str | None) -> str | None:
    if path is None:
        return None
    try:
        from .auth import TokenStore

        # Do not call Path.resolve(): it follows a final symlink before
        # TokenStore can reject it.  Make relative CLI/config paths absolute
        # without dereferencing any filesystem component instead.
        candidate = Path(path).expanduser()
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        return TokenStore(candidate).read()
    except Exception as exc:
        raise CliFailure(
            "Runtime token file does not contain a valid PolyMesh token",
            code="AUTHENTICATION_FAILED",
            category="identity",
            exit_code=4,
        ) from exc


def _raise_for_cli_error(exc: BaseException) -> None:
    if isinstance(exc, CliFailure):
        raise exc
    name = type(exc).__name__
    raw_category = getattr(exc, "category", "")
    raw_code = getattr(exc, "code", name.upper())
    category = str(getattr(raw_category, "value", raw_category))
    code = str(getattr(raw_code, "value", raw_code))
    retryable = bool(getattr(exc, "retryable", False))
    if category in {"identity", "authentication"} or "Auth" in name or "Token" in name or "TLS" in name or "Enrollment" in name:
        exit_code = 4
    elif "Timeout" in name or category == "timeout":
        exit_code = 8
    elif "Transport" in name or "Handshake" in name or "Connection" in name:
        exit_code = 5
    elif "Protocol" in name or category in {"parse", "protocol"}:
        exit_code = 6
    elif "Task" in name or "Execution" in name or category in {"task", "execution"}:
        exit_code = 7
    elif isinstance(exc, (ValueError, TypeError, OSError, json.JSONDecodeError)):
        exit_code = 3
    else:
        exit_code = 1
    raise CliFailure(_bounded_message(exc), code=code, category=category or "internal", exit_code=exit_code, retryable=retryable) from exc


async def _connect_client(
    command: _CommandContext,
    *,
    url: str | None = None,
    card_file: str | Path | None = None,
    token_file: str | Path | None = None,
    timeout_ms: int | None = None,
    insecure_loopback_dev: bool | None = None,
):
    from .client import PolyMeshClient

    endpoint = url if url is not None else command.config.client.url
    if not endpoint:
        raise CliFailure("a broker URL is required", code="USAGE", category="configuration", exit_code=2)
    chosen_card = str(card_file) if card_file is not None else command.config.client.card_file
    chosen_token_file = str(token_file) if token_file is not None else command.config.client.token_file
    card = _load_card(chosen_card)
    token = _load_token(chosen_token_file)
    return PolyMeshClient(
        card=card,
        broker_url=endpoint,
        token=token,
        allow_insecure_loopback_development=(
            command.config.client.insecure_loopback_dev
            if insecure_loopback_dev is None
            else insecure_loopback_dev
        ),
        default_timeout=(timeout_ms if timeout_ms is not None else command.config.client.timeout_ms) / 1000,
    )


async def _call_with_result(client: Any, target: str, capability: str, input_value: dict[str, Any], *, timeout: float) -> Any:
    """Bridge the two supported task API spellings without changing wire work.

    The public SDK exposes ``call_with_result`` for callers that want the
    terminal JSON directly.  Early v0.1 implementations exposed ``call`` as
    either that convenience coroutine or a TaskHandle-producing coroutine.
    The CLI only needs the terminal value, so it can safely accept both while
    keeping all lifecycle handling inside the client.
    """

    direct = getattr(client, "call_with_result", None)
    if callable(direct):
        value = direct(target, capability, input_value, timeout=timeout)
        return await value if inspect.isawaitable(value) else value

    call = getattr(client, "call", None)
    if not callable(call):  # pragma: no cover - defensive package mismatch
        raise RuntimeError("installed PolyMeshClient has no call method")
    value = call(target, capability, input_value, timeout=timeout)
    value = await value if inspect.isawaitable(value) else value
    result = getattr(value, "result", None)
    if callable(result):
        terminal = result()
        return await terminal if inspect.isawaitable(terminal) else terminal
    return value


@main.command()
@click.argument("url", required=False)
@click.option("--url", "command_url", default=None, help="Broker WebSocket endpoint")
@click.option("--card", "command_card", type=click.Path(path_type=Path, dir_okay=False), default=None)
@click.option("--token-file", "command_token_file", type=click.Path(path_type=Path, dir_okay=False), default=None)
@click.option("--timeout", "command_timeout", type=click.IntRange(min=1, max=86_400_000), default=None)
@click.option("--insecure-loopback-dev/--no-insecure-loopback-dev", "command_insecure_loopback_dev", default=None)
@click.pass_context
def connect(
    ctx: click.Context,
    url: str | None,
    command_url: str | None,
    command_card: Path | None,
    command_token_file: Path | None,
    command_timeout: int | None,
    command_insecure_loopback_dev: bool | None,
) -> None:
    """Complete a broker handshake, print its identity, and disconnect."""

    async def run() -> dict[str, Any]:
        client = await _connect_client(
            _context(ctx),
            # A positional endpoint is canonical for this command and wins
            # over the compatibility --url spelling.
            url=url if url is not None else command_url,
            card_file=command_card,
            token_file=command_token_file,
            timeout_ms=command_timeout,
            insecure_loopback_dev=command_insecure_loopback_dev,
        )
        try:
            await client.connect()
            identity = client.broker_identity
            card = client.broker_card
            return {
                "connected": True,
                "peer": _model_to_value(identity),
                "card": _model_to_value(card),
            }
        finally:
            await client.disconnect(wait=True)

    try:
        _emit(ctx, asyncio.run(run()))
    except KeyboardInterrupt:
        raise click.exceptions.Exit(130) from None
    except Exception as exc:
        _raise_for_cli_error(exc)


@main.command()
@click.argument("agent")
@click.argument("capability")
@click.argument("json_input")
@click.option("--url", "command_url", default=None, help="Broker WebSocket endpoint")
@click.option("--card", "command_card", type=click.Path(path_type=Path, dir_okay=False), default=None)
@click.option("--token-file", "command_token_file", type=click.Path(path_type=Path, dir_okay=False), default=None)
@click.option("--timeout", "command_timeout", type=click.IntRange(min=1, max=86_400_000), default=None)
@click.option("--insecure-loopback-dev/--no-insecure-loopback-dev", "command_insecure_loopback_dev", default=None)
@click.pass_context
def call(
    ctx: click.Context,
    agent: str,
    capability: str,
    json_input: str,
    command_url: str | None,
    command_card: Path | None,
    command_token_file: Path | None,
    command_timeout: int | None,
    command_insecure_loopback_dev: bool | None,
) -> None:
    """Call one remote capability with a strict JSON-object input."""

    try:
        from .protocol import parse_strict_json

        parsed = parse_strict_json(json_input, max_bytes=256 * 1024)
        if not isinstance(parsed, dict):
            raise ValueError("JSON input must be an object")
    except KeyboardInterrupt:
        raise click.exceptions.Exit(130) from None
    except Exception as exc:
        _raise_for_cli_error(exc)
        return

    async def run() -> Any:
        command = _context(ctx)
        client = await _connect_client(
            command,
            url=command_url,
            card_file=command_card,
            token_file=command_token_file,
            timeout_ms=command_timeout,
            insecure_loopback_dev=command_insecure_loopback_dev,
        )
        try:
            await client.connect()
            return await _call_with_result(
                client,
                agent,
                capability,
                parsed,
                timeout=(command_timeout if command_timeout is not None else command.config.client.timeout_ms) / 1000,
            )
        finally:
            await client.disconnect(wait=True)

    try:
        _emit(ctx, asyncio.run(run()))
    except KeyboardInterrupt:
        raise click.exceptions.Exit(130) from None
    except Exception as exc:
        _raise_for_cli_error(exc)


@main.command()
@click.option("--agent", default=None, help="Optional remote agent for standard capabilities.list query")
@click.option("--url", "command_url", default=None, help="Broker WebSocket endpoint")
@click.option("--card", "command_card", type=click.Path(path_type=Path, dir_okay=False), default=None)
@click.option("--token-file", "command_token_file", type=click.Path(path_type=Path, dir_okay=False), default=None)
@click.option("--timeout", "command_timeout", type=click.IntRange(min=1, max=86_400_000), default=None)
@click.option("--insecure-loopback-dev/--no-insecure-loopback-dev", "command_insecure_loopback_dev", default=None)
@click.pass_context
def capabilities(
    ctx: click.Context,
    agent: str | None,
    command_url: str | None,
    command_card: Path | None,
    command_token_file: Path | None,
    command_timeout: int | None,
    command_insecure_loopback_dev: bool | None,
) -> None:
    """Print local capabilities or query the target's standard capability list."""

    if agent is None:
        try:
            _emit(ctx, _load_card(str(command_card) if command_card is not None else _context(ctx).config.client.card_file).capabilities)
        except KeyboardInterrupt:
            raise click.exceptions.Exit(130) from None
        except Exception as exc:
            _raise_for_cli_error(exc)
        return

    async def run() -> Any:
        command = _context(ctx)
        client = await _connect_client(
            command,
            url=command_url,
            card_file=command_card,
            token_file=command_token_file,
            timeout_ms=command_timeout,
            insecure_loopback_dev=command_insecure_loopback_dev,
        )
        try:
            await client.connect()
            return await _call_with_result(
                client,
                agent,
                "org.polymesh.capabilities.list",
                {},
                timeout=(command_timeout if command_timeout is not None else command.config.client.timeout_ms) / 1000,
            )
        finally:
            await client.disconnect(wait=True)

    try:
        _emit(ctx, asyncio.run(run()))
    except KeyboardInterrupt:
        raise click.exceptions.Exit(130) from None
    except Exception as exc:
        _raise_for_cli_error(exc)


@main.command()
@click.option("--mdns", is_flag=True, default=False, help="Request configured discovery provider")
@click.option("--wait", "wait_ms", type=click.IntRange(min=0, max=60_000), default=0, help="Discovery wait in milliseconds")
@click.pass_context
def peers(ctx: click.Context, mdns: bool, wait_ms: int) -> None:
    """Print the local discovery snapshot; no network connection is made."""

    # v0.1 ships no mDNS provider. Keep the explicit flag honest rather than
    # treating arbitrary discovery metadata as authenticated peers.
    if mdns and wait_ms:
        asyncio.run(asyncio.sleep(wait_ms / 1000))
    _emit(ctx, [])


def _run_broker(
    ctx: click.Context,
    *,
    host: str | None,
    port: int | None,
    token_file: Path | None,
    insecure_loopback_dev: bool | None,
    mdns: bool,
) -> None:
    command = _context(ctx)
    try:
        from .broker import PolyMeshBroker
    except ImportError as exc:
        raise CliFailure("local broker support is unavailable in this installation", code="UNSUPPORTED", category="internal", exit_code=1) from exc
    config = command.config.broker
    if mdns or config.mdns:
        raise CliFailure(
            "mDNS advertising requires an enrolled WSS broker and is not installed",
            code="CONFIGURATION_INVALID",
            category="configuration",
            exit_code=3,
        )
    chosen_host = host if host is not None else config.host
    chosen_port = config.port if port is None else port
    chosen_token_file = str(token_file) if token_file is not None else config.token_file
    allowed_insecure_loopback = (
        command.config.broker.insecure_loopback_dev
        if insecure_loopback_dev is None
        else insecure_loopback_dev
    )
    # Reject transport policy errors before touching the default credential
    # store.  A typo such as ``polymesh start --host 0.0.0.0`` must not create
    # or read ~/.polymesh/token as a side effect of a command that cannot run.
    if not allowed_insecure_loopback:
        raise CliFailure("plaintext start requires --insecure-loopback-dev", code="INSECURE_TRANSPORT_DISABLED", category="identity", exit_code=4)
    from .transport import is_numeric_loopback_host

    if not is_numeric_loopback_host(chosen_host):
        raise CliFailure(
            "plaintext start requires a numeric loopback host",
            code="INSECURE_TRANSPORT_DISABLED",
            category="identity",
            exit_code=4,
        )
    try:
        if not chosen_token_file:
            # ``start`` has a documented default, unlike direct client creation.
            from .auth import TokenStore

            store = TokenStore()
            token = store.read() if store.path.exists() else store.write_new()
        else:
            token = _load_token(chosen_token_file)
            if token is None:  # defensive; path is truthy above
                raise CliFailure("a runtime token file is required", code="AUTHENTICATION_FAILED", category="identity", exit_code=4)
    except CliFailure:
        raise
    except Exception as exc:
        _raise_for_cli_error(exc)

    async def run() -> None:
        broker = PolyMeshBroker(host=chosen_host, port=chosen_port, token=token, allow_insecure_loopback_development=True)
        await broker.start()
        try:
            _emit(ctx, {"url": broker.url, "port": broker.port, "agent_id": broker.card.agent_id})
            await asyncio.Event().wait()
        finally:
            await broker.close()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        raise click.exceptions.Exit(130) from None
    except Exception as exc:
        _raise_for_cli_error(exc)


@main.command()
@click.option("--host", default=None)
@click.option("--port", type=click.IntRange(min=0, max=65535), default=None)
@click.option("--token-file", type=click.Path(path_type=Path, dir_okay=False), default=None)
@click.option("--insecure-loopback-dev/--no-insecure-loopback-dev", default=None)
@click.option("--mdns", is_flag=True, default=False)
@click.pass_context
def start(
    ctx: click.Context,
    host: str | None,
    port: int | None,
    token_file: Path | None,
    insecure_loopback_dev: bool | None,
    mdns: bool,
) -> None:
    """Start a local loopback broker in the foreground."""

    _run_broker(
        ctx,
        host=host,
        port=port,
        token_file=token_file,
        insecure_loopback_dev=insecure_loopback_dev,
        mdns=mdns,
    )


@main.command()
@click.option("--host", default=None)
@click.option("--port", type=click.IntRange(min=0, max=65535), default=None)
@click.option("--token-file", type=click.Path(path_type=Path, dir_okay=False), default=None)
@click.option("--insecure-loopback-dev/--no-insecure-loopback-dev", default=None)
@click.option("--mdns", is_flag=True, default=False)
@click.pass_context
def listen(
    ctx: click.Context,
    host: str | None,
    port: int | None,
    token_file: Path | None,
    insecure_loopback_dev: bool | None,
    mdns: bool,
) -> None:
    """Alias for ``start``; it does not expose a direct peer listener."""

    _run_broker(
        ctx,
        host=host,
        port=port,
        token_file=token_file,
        insecure_loopback_dev=insecure_loopback_dev,
        mdns=mdns,
    )


_APP_PY = '''from __future__ import annotations

import asyncio
from polymesh import AgentCardBuilder, CapabilityBuilder, PolyMeshClient
from polymesh.auth import TokenStore


card = (
    AgentCardBuilder("example.my-agent")
    # Capability ID segments are lower-case alphanumeric (the agent ID may
    # still contain a hyphen); keep the starter valid under the wire grammar.
    .capability(CapabilityBuilder("example.myagent.echo").build())
    .build()
)

client = PolyMeshClient(
    card=card,
    broker_url="ws://127.0.0.1:7337/polymesh",
    # Runtime credentials stay in an owner-only file; never paste a token
    # into source, a URL, or a command line argument.
    token=TokenStore().read(),
    allow_insecure_loopback_development=True,
)


@client.handle("example.myagent.echo")
async def echo(input: dict, context):
    context.progress({"state": "running"})
    return input


async def main() -> None:
    async with client:
        await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
'''


@click.command(name="create-polymesh-app")
@click.argument("directory", type=click.Path(path_type=Path))
def create_polymesh_app(directory: Path) -> None:
    """Create a tiny, token-safe PolyMesh Python application template."""

    target = directory.expanduser()
    if target.exists():
        if not target.is_dir():
            raise click.UsageError("target path already exists and is not a directory")
        if any(target.iterdir()):
            raise click.UsageError("target directory already exists and is not empty")
    target.mkdir(parents=True, exist_ok=True)
    app = target / "app.py"
    requirements = target / "requirements.txt"
    config = target / "polymesh.toml"
    app.write_text(_APP_PY, encoding="utf-8")
    # The PyPI distribution is namespaced while its Python import remains
    # `polymesh`; generated projects must install the published artifact.
    requirements.write_text("latticeag-polymesh>=0.4.0\n", encoding="utf-8")
    config.write_text(
        "[client]\nurl = \"ws://127.0.0.1:7337/polymesh\"\ninsecure_loopback_dev = true\n",
        encoding="utf-8",
    )
    click.echo(str(target))


def _entrypoint() -> None:
    main(prog_name="polymesh")


if __name__ == "__main__":
    _entrypoint()


__all__ = ["CliFailure", "create_polymesh_app", "main", "render_output"]

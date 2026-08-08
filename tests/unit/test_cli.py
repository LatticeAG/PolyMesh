from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from types import ModuleType

import pytest
from click.testing import CliRunner

from polymesh.cli import _call_with_result, create_polymesh_app, main, render_output
from polymesh.config import ConfigError, load_config
from polymesh.types import AgentCardBuilder


def test_config_precedence_is_flags_then_environment_then_file(tmp_path: Path) -> None:
    config_path = tmp_path / "polymesh.toml"
    config_path.write_text(
        """
[client]
url = "ws://127.0.0.1:7337/polymesh"
timeout_ms = 1000
insecure_loopback_dev = true

[output]
format = "plain"
""".strip(),
        encoding="utf-8",
    )
    config = load_config(
        config_path=config_path,
        env={
            "POLYMESH_URL": "ws://127.0.0.1:7338/polymesh",
            "POLYMESH_TIMEOUT_MS": "2000",
            "POLYMESH_FORMAT": "table",
        },
        overrides={"client": {"timeout_ms": 3000}, "output": {"format": "json"}},
    )

    assert config.client.url == "ws://127.0.0.1:7338/polymesh"
    assert config.client.timeout_ms == 3000
    assert config.output.format == "json"


def test_raw_secret_environment_is_rejected() -> None:
    with pytest.raises(ConfigError, match="POLYMESH_TOKEN"):
        load_config(env={"POLYMESH_TOKEN": "must-not-be-accepted"})


@pytest.mark.parametrize(
    "url",
    [
        "ws://127.0.0.1:not-a-port/polymesh",
        "ws://127.0.0.1:65536/polymesh",
        "ws://127.0.0.1:7337/polymesh?",
        "ws://127.0.0.1:7337/polymesh#",
        "ws://@127.0.0.1:7337/polymesh",
    ],
)
def test_config_rejects_malformed_or_ambiguous_websocket_urls(url: str) -> None:
    with pytest.raises(ConfigError, match="invalid PolyMesh configuration"):
        load_config(env={"POLYMESH_URL": url})


def test_cli_errors_honor_the_requested_output_format() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--format", "plain", "--config", "missing.toml", "peers"])

    assert result.exit_code == 3
    assert result.output.startswith("CONFIGURATION_INVALID:")
    assert '"ok"' not in result.output


def test_connection_options_are_accepted_after_subcommand() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["call", "target", "org.example.echo", "{}", "--help"])

    assert result.exit_code == 0
    assert "--card FILE" in result.output
    assert "--token-file FILE" in result.output
    assert "--insecure-loopback-dev" in result.output


@pytest.mark.parametrize(
    "start_args",
    [
        ["start"],
        ["start", "--host", "0.0.0.0", "--insecure-loopback-dev"],
    ],
)
def test_start_rejects_invalid_plaintext_policy_before_touching_default_token_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, start_args: list[str]
) -> None:
    """Invalid start policy must not create/read a default runtime token."""

    import polymesh.auth as auth

    class UnexpectedTokenStore:
        def __init__(self, *_: object, **__: object) -> None:
            raise AssertionError("default token store must not be touched")

    config_path = tmp_path / "empty.toml"
    config_path.write_text("", encoding="utf-8")
    monkeypatch.setattr(auth, "TokenStore", UnexpectedTokenStore)

    result = CliRunner().invoke(main, ["--config", str(config_path), *start_args])

    assert result.exit_code == 4, result.output
    assert json.loads(result.output)["code"] == "INSECURE_TRANSPORT_DISABLED"


def test_connect_uses_command_local_connection_options(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    card_path = tmp_path / "card.json"
    card = AgentCardBuilder("example.cli").build()
    card_path.write_text(json.dumps(card.model_dump(mode="json", exclude_none=True)), encoding="utf-8")
    from polymesh.auth import generate_runtime_token
    from polymesh.types import AgentIdentity

    token_path = tmp_path / "token"
    token_path.write_text(generate_runtime_token(), encoding="ascii")
    token_path.chmod(0o600)
    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)
            self.broker_identity = AgentIdentity(agent_id="org.polymesh.broker", instance_id=card.instance_id)
            self.broker_card = card

        async def connect(self) -> "FakeClient":
            return self

        async def disconnect(self, *, wait: bool = True) -> None:
            assert wait is True

    fake_module = ModuleType("polymesh.client")
    fake_module.PolyMeshClient = FakeClient
    monkeypatch.setitem(sys.modules, "polymesh.client", fake_module)

    result = CliRunner().invoke(
        main,
        [
            "connect",
            "ws://127.0.0.1:7337/polymesh",
            "--card",
            str(card_path),
            "--token-file",
            str(token_path),
            "--timeout",
            "1234",
            "--insecure-loopback-dev",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["broker_url"] == "ws://127.0.0.1:7337/polymesh"
    assert captured["default_timeout"] == pytest.approx(1.234)
    assert captured["allow_insecure_loopback_development"] is True


def test_call_result_compatibility_supports_direct_and_task_handle_clients() -> None:
    class DirectClient:
        async def call_with_result(self, *_: object, **__: object) -> dict[str, bool]:
            return {"direct": True}

    class Handle:
        async def result(self) -> dict[str, bool]:
            return {"handle": True}

    class HandleClient:
        async def call(self, *_: object, **__: object) -> Handle:
            return Handle()

    assert asyncio.run(_call_with_result(DirectClient(), "target", "org.example.echo", {}, timeout=1)) == {"direct": True}
    assert asyncio.run(_call_with_result(HandleClient(), "target", "org.example.echo", {}, timeout=1)) == {"handle": True}


def test_capabilities_reads_a_command_local_card(tmp_path: Path) -> None:
    card_path = tmp_path / "card.json"
    card = AgentCardBuilder("example.cli").build()
    card_path.write_text(json.dumps(card.model_dump(mode="json", exclude_none=True)), encoding="utf-8")

    result = CliRunner().invoke(main, ["capabilities", "--card", str(card_path)])

    assert result.exit_code == 0
    value = json.loads(result.output)
    assert {item["id"] for item in value} >= {
        "org.polymesh.agent.ping",
        "org.polymesh.agent.info",
        "org.polymesh.capabilities.list",
    }


def test_output_formats_are_deterministic() -> None:
    value = [{"id": "org.example.echo", "version": "1.0.0", "side_effects": "none"}]

    assert render_output(value, "json") == json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    assert "Capability" in render_output(value, "table")
    assert render_output(["one", "two"], "plain") == "one\ntwo\n"


def test_create_polymesh_app_template_contains_no_runtime_token() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        target = Path("example-app")
        result = runner.invoke(create_polymesh_app, [str(target)])

        assert result.exit_code == 0
        app = (target / "app.py").read_text(encoding="utf-8")
        assert "TokenStore().read()" in app
        assert "POLYMESH_TOKEN" not in app
        assert (target / "requirements.txt").read_text(encoding="utf-8") == "latticeag-polymesh>=0.5.0\n"
        assert (target / "polymesh.toml").is_file()


@pytest.mark.skipif(os.name != "posix", reason="TokenStore requires POSIX owner-only checks")
def test_cli_token_loader_does_not_resolve_a_symlink(tmp_path: Path) -> None:
    from polymesh.auth import generate_runtime_token
    from polymesh.cli import CliFailure, _load_token

    target = tmp_path / "real-token"
    target.write_text(generate_runtime_token(), encoding="ascii")
    target.chmod(0o600)
    link = tmp_path / "token-link"
    link.symlink_to(target)

    with pytest.raises(CliFailure):
        _load_token(str(link))

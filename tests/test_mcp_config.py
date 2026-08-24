"""Safety checks for MCP discovery, enablement, and persistence."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from strix.config import loader
from strix.mcp import cli as mcp_cli
from strix.mcp import config


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def reset_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for key in (
        "STRIX_MCP_ENABLED",
        "STRIX_LLM",
        "LLM_API_KEY",
        "OPENAI_API_KEY",
        "LLM_API_BASE",
        "OPENAI_API_BASE",
        "OPENAI_BASE_URL",
        "LITELLM_BASE_URL",
        "OLLAMA_API_BASE",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(loader, "_override", tmp_path / "cli-config.json")
    monkeypatch.setattr(config, "user_mcp_path", lambda: tmp_path / "user.mcp.json")


def write_servers(path: Path, servers: dict[str, object]) -> None:
    path.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")


def enabled_record(definition: config.McpDefinition) -> dict[str, object]:
    return {
        "enabled": True,
        "source": str(definition.source),
        "definition_hash": definition.definition_hash,
        "allow_tools": ["read_*"],
    }


def test_project_shadowing_requires_reenablement(tmp_path: Path) -> None:
    user = tmp_path / "user.mcp.json"
    write_servers(user, {"scanner": {"command": "user-tool"}})
    user_definition = config.discover_servers(cwd=tmp_path)["scanner"]
    loader.update_mcp_config({"servers": {"scanner": enabled_record(user_definition)}})

    write_servers(tmp_path / ".mcp.json", {"scanner": {"command": "project-tool"}})

    assert config.server_statuses(cwd=tmp_path) == {"scanner": "changed — re-enable required"}
    with pytest.raises(config.McpConfigError, match="re-enable required"):
        config.enabled_servers(cwd=tmp_path)


def test_missing_environment_variable_fails_after_enablement(tmp_path: Path) -> None:
    write_servers(
        tmp_path / ".mcp.json",
        {"scanner": {"command": "tool", "env": {"TOKEN": "${MISSING_TOKEN}"}}},
    )
    definition = config.discover_servers(cwd=tmp_path)["scanner"]
    loader.update_mcp_config({"servers": {"scanner": enabled_record(definition)}})

    with pytest.raises(config.McpConfigError, match="MISSING_TOKEN"):
        config.enabled_servers(cwd=tmp_path)


def test_fingerprint_captures_raw_secret_configuration_not_process_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_servers(
        tmp_path / ".mcp.json",
        {
            "remote": {
                "url": "https://example.test/mcp",
                "env": {"MODE": "readonly"},
                "headers": {"Authorization": "Bearer ${TOKEN}"},
            }
        },
    )
    first = config.discover_servers(cwd=tmp_path)["remote"]
    monkeypatch.setenv("TOKEN", "first")
    assert config.discover_servers(cwd=tmp_path)["remote"].definition_hash == first.definition_hash
    monkeypatch.setenv("TOKEN", "rotated")
    assert config.discover_servers(cwd=tmp_path)["remote"].definition_hash == first.definition_hash
    write_servers(
        tmp_path / ".mcp.json",
        {
            "remote": {
                "url": "https://example.test/mcp",
                "env": {"MODE": "admin"},
                "headers": {"Authorization": "Bearer ${ADMIN_TOKEN}"},
            }
        },
    )
    second = config.discover_servers(cwd=tmp_path)["remote"]

    assert second.definition_hash != first.definition_hash


def test_invalid_disabled_definition_does_not_block_enabled_server(tmp_path: Path) -> None:
    write_servers(
        tmp_path / ".mcp.json",
        {"enabled": {"command": "tool"}, "disabled": {"command": "tool", "url": "bad"}},
    )
    definition = config.discover_servers(cwd=tmp_path)["enabled"]
    loader.update_mcp_config({"servers": {"enabled": enabled_record(definition)}})

    assert [server.definition.name for server in config.enabled_servers(cwd=tmp_path)] == [
        "enabled"
    ]


def test_invalid_user_definition_shadowed_by_valid_project_definition(tmp_path: Path) -> None:
    write_servers(tmp_path / "user.mcp.json", {"scanner": {"command": "tool", "url": "bad"}})
    write_servers(tmp_path / ".mcp.json", {"scanner": {"command": "tool"}})
    definition = config.discover_servers(cwd=tmp_path)["scanner"]
    loader.update_mcp_config({"servers": {"scanner": enabled_record(definition)}})

    assert [server.definition.name for server in config.enabled_servers(cwd=tmp_path)] == [
        "scanner"
    ]


def test_invalid_enabled_definition_fails_before_runtime_resolution(tmp_path: Path) -> None:
    write_servers(tmp_path / ".mcp.json", {"scanner": {"command": "tool", "url": "bad"}})
    definition = config.discover_servers(cwd=tmp_path)["scanner"]
    loader.update_mcp_config({"servers": {"scanner": enabled_record(definition)}})

    with pytest.raises(config.McpConfigError, match="exactly one"):
        config.enabled_servers(cwd=tmp_path)


def test_persist_current_preserves_mcp_and_unknown_top_level_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "cli-config.json"
    target.write_text(
        json.dumps({"env": {"OLD": "value"}, "mcp": {"enabled": False}, "unknown": 3}),
        encoding="utf-8",
    )
    monkeypatch.setenv("STRIX_LLM", "model")

    loader.persist_current()

    assert json.loads(target.read_text(encoding="utf-8")) == {
        "env": {"STRIX_LLM": "model"},
        "mcp": {"enabled": False},
        "unknown": 3,
    }


def test_update_mcp_config_uses_custom_override_and_invalidates_cache(tmp_path: Path) -> None:
    target = tmp_path / "custom.json"
    target.write_text(json.dumps({"env": {}, "unknown": True}), encoding="utf-8")
    loader.apply_config_override(target)
    assert loader.load_settings().mcp.enabled is True

    loader.update_mcp_config({"enabled": False, "servers": {}})

    assert loader.load_settings().mcp.enabled is False
    assert json.loads(target.read_text(encoding="utf-8"))["unknown"] is True


def test_enable_cli_writes_source_bound_record_to_custom_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    write_servers(tmp_path / ".mcp.json", {"scanner": {"command": "scan"}})
    target = tmp_path / "custom.json"

    assert mcp_cli.run_mcp(["--config", str(target), "enable", "scanner", "--allow", "read_*"]) == 0

    saved = json.loads(target.read_text(encoding="utf-8"))["mcp"]["servers"]["scanner"]
    definition = config.discover_servers(cwd=tmp_path)["scanner"]
    assert saved["source"] == str(definition.source)
    assert saved["definition_hash"] == definition.definition_hash
    assert saved["allow_tools"] == ["read_*"]


def test_enable_invalid_definition_does_not_change_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    write_servers(tmp_path / ".mcp.json", {"scanner": {"command": "scan", "url": "bad"}})
    target = tmp_path / "custom.json"
    original = b'{"env":{"KEEP":"value"}}'
    target.write_bytes(original)

    with pytest.raises(SystemExit):
        mcp_cli.run_mcp(["--config", str(target), "enable", "scanner", "--all-tools"])

    assert target.read_bytes() == original


def test_enable_rejects_malformed_strix_config_without_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    write_servers(tmp_path / ".mcp.json", {"scanner": {"command": "scan"}})
    target = tmp_path / "custom.json"
    original = b'{"env": '
    target.write_bytes(original)

    with pytest.raises(SystemExit) as error:
        mcp_cli.run_mcp(["--config", str(target), "enable", "scanner", "--all-tools"])

    assert error.value.code != 0
    assert target.read_bytes() == original
    assert "Traceback" not in capsys.readouterr().err


def test_enable_does_not_persist_global_environment_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("STRIX_MCP_ENABLED", "false")
    write_servers(tmp_path / ".mcp.json", {"scanner": {"command": "scan"}})
    target = tmp_path / "custom.json"

    assert mcp_cli.run_mcp(["--config", str(target), "enable", "scanner", "--all-tools"]) == 0
    assert "enabled" not in json.loads(target.read_text(encoding="utf-8"))["mcp"]

    monkeypatch.delenv("STRIX_MCP_ENABLED")
    monkeypatch.setattr(loader, "_cached", None)
    assert loader.load_settings().mcp.enabled is True
    assert loader.load_settings().mcp.servers["scanner"].enabled is True


def test_server_update_preserves_persisted_global_mcp_enabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    write_servers(tmp_path / ".mcp.json", {"scanner": {"command": "scan"}})
    target = tmp_path / "custom.json"
    target.write_text(
        json.dumps(
            {
                "mcp": {"enabled": False, "servers": {"other": {"enabled": False}}},
                "unknown": True,
            }
        ),
        encoding="utf-8",
    )

    assert mcp_cli.run_mcp(["--config", str(target), "enable", "scanner", "--all-tools"]) == 0

    persisted = json.loads(target.read_text(encoding="utf-8"))["mcp"]
    assert persisted["enabled"] is False
    assert persisted["servers"]["scanner"]["enabled"] is True
    assert persisted["servers"]["other"] == {"enabled": False}
    assert json.loads(target.read_text(encoding="utf-8"))["unknown"] is True


def test_disable_missing_saved_enablement_and_list_it(capsys: pytest.CaptureFixture[str]) -> None:
    loader.update_mcp_config({"servers": {"gone": {"enabled": True}}})

    assert mcp_cli.run_mcp(["list"]) == 0
    assert "gone: missing" in capsys.readouterr().out
    assert mcp_cli.run_mcp(["disable", "gone"]) == 0
    assert loader.load_settings().mcp.servers["gone"].enabled is False
    assert mcp_cli.run_mcp(["list"]) == 0
    assert "gone: missing — disabled" in capsys.readouterr().out


def test_update_mcp_config_rejects_malformed_document_without_overwrite(tmp_path: Path) -> None:
    target = tmp_path / "cli-config.json"
    original = b'{"env": '
    target.write_bytes(original)

    with pytest.raises(ValueError, match="malformed Strix configuration"):
        loader.update_mcp_config({"enabled": False})

    assert target.read_bytes() == original

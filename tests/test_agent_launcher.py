from __future__ import annotations

from argparse import Namespace
from types import SimpleNamespace
from typing import TYPE_CHECKING

from strix.interface import agent_launcher


if TYPE_CHECKING:
    import pytest


def _args(**overrides: object) -> Namespace:
    values: dict[str, object] = {
        "agent": "codex",
        "target": ["./app"],
        "mount": None,
        "scan_mode": "standard",
        "instruction": "Focus on authorization",
        "resume": None,
        "non_interactive": False,
        "max_budget_usd": None,
        "scope_mode": "auto",
        "diff_base": None,
    }
    values.update(overrides)
    return Namespace(**values)


def test_auto_uses_coding_agent_without_strix_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        agent_launcher,
        "load_settings",
        lambda: SimpleNamespace(llm=SimpleNamespace(model=None)),
    )

    assert agent_launcher.uses_coding_agent(_args(agent="auto")) is True


def test_explicit_legacy_mode_does_not_launch_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        agent_launcher,
        "load_settings",
        lambda: SimpleNamespace(llm=SimpleNamespace(model=None)),
    )

    assert agent_launcher.uses_coding_agent(_args(agent="legacy")) is False


def test_codex_command_embeds_ephemeral_mcp_config() -> None:
    command = agent_launcher.build_agent_command(_args(non_interactive=True), "codex")

    assert command[:2] == ["codex", "exec"]
    assert any("mcp_servers.strix.command" in item for item in command)
    assert any("strix.mcp.server" in item for item in command)
    assert "start_scan" in command[-1]
    assert "Focus on authorization" in command[-1]


def test_claude_command_uses_stdio_mcp_config() -> None:
    command = agent_launcher.build_agent_command(
        _args(agent="claude", non_interactive=True, max_budget_usd=5.0),
        "claude",
    )

    assert command[0] == "claude"
    assert "--mcp-config" in command
    assert "strix.mcp.server" in command[command.index("--mcp-config") + 1]
    assert "--print" in command
    assert command[command.index("--max-budget-usd") + 1] == "5.0"
    assert command[-2] == "--"
    assert "start_scan" in command[-1]

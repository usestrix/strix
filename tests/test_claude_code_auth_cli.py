"""``strix auth ... claude`` provider dispatch — every verb delegates to the CLI."""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING, Any

import pytest

from strix.config import claude_code, codex
from strix.interface import auth_cli


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _tmp_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(codex, "AUTH_PATH", tmp_path / "home" / ".strix" / "subscription-auth.json")


def _ok(_args: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=["claude", *_args], returncode=0, stdout="", stderr="")


def _fail(_args: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=["claude", *_args], returncode=3, stdout="", stderr="")


def test_usage_lists_claude() -> None:
    assert "login claude" in auth_cli._USAGE
    assert claude_code.PROVIDER in auth_cli._CLAUDE_PROVIDERS


def test_login_claude_missing_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(claude_code, "binary_path", lambda: None)
    assert auth_cli.run_auth(["login", "claude"]) == 1


def test_login_claude_delegates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(claude_code, "binary_path", lambda: "/usr/bin/claude")
    seen: dict[str, Any] = {}

    def _run(args: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["args"] = args
        return _ok(args)

    monkeypatch.setattr(auth_cli, "_run_claude", _run)
    assert auth_cli.run_auth(["login", "claude"]) == 0
    assert seen["args"] == ["auth", "login"]


def test_login_claude_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(claude_code, "binary_path", lambda: "/usr/bin/claude")
    monkeypatch.setattr(auth_cli, "_run_claude", _ok)
    assert auth_cli.run_auth(["login", "claude-code"]) == 0


def test_login_claude_propagates_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(claude_code, "binary_path", lambda: "/usr/bin/claude")
    monkeypatch.setattr(auth_cli, "_run_claude", _fail)
    assert auth_cli.run_auth(["login", "claude"]) == 3


def test_logout_claude_delegates(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def _run(args: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["args"] = args
        return _ok(args)

    monkeypatch.setattr(auth_cli, "_run_claude", _run)
    assert auth_cli.run_auth(["logout", "claude"]) == 0
    assert seen["args"] == ["auth", "logout"]


def test_logout_default_still_chatgpt(monkeypatch: pytest.MonkeyPatch) -> None:
    called = {"codex": False}

    def _codex_logout() -> None:
        called["codex"] = True

    monkeypatch.setattr(codex, "logout", _codex_logout)
    assert auth_cli.run_auth(["logout"]) == 0
    assert called["codex"] is True


def test_status_reports_claude_subscription(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(codex, "read_record", lambda: None)
    monkeypatch.setattr(claude_code, "session_state", lambda: "subscription")
    assert auth_cli.run_auth(["status"]) == 0


def test_status_claude_api_key_warns_but_signed_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(codex, "read_record", lambda: None)
    monkeypatch.setattr(claude_code, "session_state", lambda: "api_key")
    assert auth_cli.run_auth(["status"]) == 0


def test_status_none_signed_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(codex, "read_record", lambda: None)
    monkeypatch.setattr(claude_code, "session_state", lambda: "signed_out")
    assert auth_cli.run_auth(["status"]) == 1

"""Claude Code provider metadata: slug parsing, version floor, auth state."""

from __future__ import annotations

import json
import subprocess
from typing import TYPE_CHECKING

import pytest

from strix.config import claude_code, subscription


if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture(autouse=True)
def _clear_version_cache() -> Iterator[None]:
    claude_code._raw_version.cache_clear()
    yield
    claude_code._raw_version.cache_clear()


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        ("claude-code/claude-opus-4-8", "claude-opus-4-8"),
        ("CLAUDE-CODE/claude-opus-4-8", "claude-opus-4-8"),
        ("  claude-code/claude-sonnet-4-6  ", "claude-sonnet-4-6"),
        ("claude-code/", None),
        ("anthropic/claude-opus-4-8", None),
        ("chatgpt/gpt-5.4", None),
        ("", None),
        (None, None),
    ],
)
def test_claude_code_model(model: str | None, expected: str | None) -> None:
    assert claude_code.claude_code_model(model) == expected


def test_auth_mode() -> None:
    assert claude_code.auth_mode("claude-code/claude-opus-4-8") == "subscription"
    assert claude_code.auth_mode("anthropic/claude-opus-4-8") == "api_key"
    assert claude_code.auth_mode(None) == "api_key"


def test_subscription_resolver_covers_both_backends() -> None:
    assert subscription.auth_mode("claude-code/claude-opus-4-8") == "subscription"
    assert subscription.auth_mode("chatgpt/gpt-5.4") == "subscription"
    assert subscription.auth_mode("anthropic/claude-opus-4-8") == "api_key"
    assert subscription.auth_mode(None) == "api_key"
    assert subscription.is_subscription("claude-code/x") is True
    assert subscription.is_subscription("openai/gpt-5.4") is False


def test_subscription_label() -> None:
    assert subscription.label("claude-code/claude-opus-4-8") == "Claude subscription"
    assert subscription.label("chatgpt/gpt-5.4") == "ChatGPT subscription"
    assert subscription.label("anthropic/claude-opus-4-8") == "subscription"


def test_reasoning_flags() -> None:
    assert claude_code.reasoning_flags(None) == []
    assert claude_code.reasoning_flags("none") == []
    assert claude_code.reasoning_flags("minimal") == ["--effort", "low"]
    assert claude_code.reasoning_flags("low") == ["--effort", "low"]
    assert claude_code.reasoning_flags("high") == ["--effort", "high"]
    assert claude_code.reasoning_flags("max") == ["--effort", "max"]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2.1.234 (Claude Code)", (2, 1, 234)),
        ("2.0.0", (2, 0, 0)),
        ("1.9.5 (Claude Code)", (1, 9, 5)),
        ("", None),
        ("garbage", None),
        (None, None),
    ],
)
def test_parse_version(raw: str | None, expected: tuple[int, int, int] | None) -> None:
    assert claude_code._parse_version(raw) == expected


def test_meets_min_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(claude_code, "version", lambda: "2.1.234 (Claude Code)")
    assert claude_code.meets_min_version() is True
    monkeypatch.setattr(claude_code, "version", lambda: "1.9.9")
    assert claude_code.meets_min_version() is False
    monkeypatch.setattr(claude_code, "version", lambda: None)
    assert claude_code.meets_min_version() is False


def _fake_status(payload: dict[str, object]) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["claude", "auth", "status"], returncode=0, stdout=json.dumps(payload), stderr=""
    )


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({"loggedIn": True, "authMethod": "claude.ai", "subscriptionType": "max"}, "subscription"),
        (
            {"loggedIn": True, "apiProvider": "firstParty", "subscriptionType": "pro"},
            "subscription",
        ),
        ({"loggedIn": True, "authMethod": "apiKey"}, "api_key"),
        ({"loggedIn": False}, "signed_out"),
    ],
)
def test_session_state(
    monkeypatch: pytest.MonkeyPatch, payload: dict[str, object], expected: str
) -> None:
    monkeypatch.setattr(claude_code, "binary_path", lambda: "/usr/bin/claude")
    monkeypatch.setattr(claude_code, "_run_claude", lambda _args: _fake_status(payload))
    assert claude_code.session_state() == expected


def test_session_state_unknown_on_probe_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(claude_code, "binary_path", lambda: "/usr/bin/claude")

    def _boom(_args: list[str]) -> subprocess.CompletedProcess[str]:
        raise OSError("cannot spawn")

    monkeypatch.setattr(claude_code, "_run_claude", _boom)
    assert claude_code.session_state() == "unknown"


def test_session_state_tolerates_wrapped_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(claude_code, "binary_path", lambda: "/usr/bin/claude")
    noisy = 'log line\n{"loggedIn": true, "authMethod": "claude.ai"}\ntrailing'
    result = subprocess.CompletedProcess(args=["claude"], returncode=0, stdout=noisy, stderr="")
    monkeypatch.setattr(claude_code, "_run_claude", lambda _args: result)
    assert claude_code.session_state() == "subscription"


def test_is_authenticated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(claude_code, "session_state", lambda: "subscription")
    assert claude_code.is_authenticated() is True
    monkeypatch.setattr(claude_code, "session_state", lambda: "api_key")
    assert claude_code.is_authenticated() is True
    monkeypatch.setattr(claude_code, "session_state", lambda: "signed_out")
    assert claude_code.is_authenticated() is False

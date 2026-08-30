"""Claude Code provider metadata: slug parsing, version floor, auth state."""

from __future__ import annotations

import json
import subprocess
from typing import TYPE_CHECKING

import pytest

from strix.config import claude_code, subscription


if TYPE_CHECKING:
    from collections.abc import Iterator


def _clear_probe_caches() -> None:
    """Drop the memoized CLI probes, tolerating a monkeypatched replacement.

    A test may swap ``session_state`` for a plain stub, and fixture teardown can
    run before ``monkeypatch`` undoes that, so the stub has no ``cache_clear``.
    """
    for probe in (claude_code._raw_version, claude_code._status_payload, claude_code.session_state):
        cache_clear = getattr(probe, "cache_clear", None)
        if cache_clear is not None:
            cache_clear()


@pytest.fixture(autouse=True)
def _clear_caches() -> Iterator[None]:
    _clear_probe_caches()
    yield
    _clear_probe_caches()


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


def test_subscription_resolver_covers_both_backends(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(claude_code, "session_state", lambda: "subscription")
    assert subscription.auth_mode("claude-code/claude-opus-4-8") == "subscription"
    assert subscription.auth_mode("chatgpt/gpt-5.4") == "subscription"
    assert subscription.auth_mode("anthropic/claude-opus-4-8") == "api_key"
    assert subscription.auth_mode(None) == "api_key"
    assert subscription.is_subscription("claude-code/x") is True
    assert subscription.is_subscription("openai/gpt-5.4") is False


def test_claude_code_on_api_key_is_not_subscription(monkeypatch: pytest.MonkeyPatch) -> None:
    # A claude-code/ run whose CLI is signed in on an API key meters normally, so
    # it must report api_key (never $0), or the budget guard would be defeated.
    monkeypatch.setattr(claude_code, "session_state", lambda: "api_key")
    assert subscription.auth_mode("claude-code/claude-opus-4-8") == "api_key"
    assert subscription.is_subscription("claude-code/claude-opus-4-8") is False
    # ChatGPT is unaffected: its OAuth can only yield a subscription session.
    assert subscription.auth_mode("chatgpt/gpt-5.4") == "subscription"


def test_subscription_label() -> None:
    assert subscription.label("claude-code/claude-opus-4-8") == "Claude subscription"
    assert subscription.label("chatgpt/gpt-5.4") == "ChatGPT subscription"
    assert subscription.label("anthropic/claude-opus-4-8") == "subscription"


def test_reasoning_flags() -> None:
    assert claude_code.reasoning_flags(None) == []
    assert claude_code.reasoning_flags("none") == ["--effort", "low"]
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


@pytest.mark.parametrize(
    "raw",
    [
        # Verified against the published npm bundles: none of these carry the
        # whole contract. 2.0.0 has no --json-schema at all (it lands in 2.0.45),
        # and api_error_status -- what the retry policy classifies a 429/529 on --
        # is still missing at 2.1.100. Letting them through preflight buys a
        # cryptic runtime failure instead of an actionable "update your CLI".
        "2.0.0 (Claude Code)",
        "2.0.44 (Claude Code)",
        "2.1.100 (Claude Code)",
        "2.1.219 (Claude Code)",
    ],
)
def test_versions_without_the_full_contract_are_rejected(
    monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    monkeypatch.setattr(claude_code, "version", lambda: raw)
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
        # An ANTHROPIC_API_KEY overrides a perfectly good claude.ai login while
        # authMethod still reads "claude.ai"; only apiKeySource gives it away.
        # Reading this as a subscription would zero a real bill.
        (
            {
                "loggedIn": True,
                "authMethod": "claude.ai",
                "apiProvider": "firstParty",
                "subscriptionType": None,
                "apiKeySource": "ANTHROPIC_API_KEY",
            },
            "api_key",
        ),
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


def test_api_key_source_names_the_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(claude_code, "binary_path", lambda: "/usr/bin/claude")
    monkeypatch.setattr(
        claude_code,
        "_run_claude",
        lambda _args: _fake_status(
            {"loggedIn": True, "authMethod": "claude.ai", "apiKeySource": "ANTHROPIC_API_KEY"}
        ),
    )
    assert claude_code.api_key_source() == "ANTHROPIC_API_KEY"


def test_api_key_source_is_none_on_a_subscription(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(claude_code, "binary_path", lambda: "/usr/bin/claude")
    monkeypatch.setattr(
        claude_code,
        "_run_claude",
        lambda _args: _fake_status(
            {"loggedIn": True, "authMethod": "claude.ai", "subscriptionType": "max"}
        ),
    )
    assert claude_code.api_key_source() is None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2.1.220 (Claude Code)", "ok"),
        ("2.1.251 (Claude Code)", "ok"),
        ("2.1.219 (Claude Code)", "too_old"),
        ("2.0.0", "too_old"),
        (None, "unknown"),
        ("not-a-version", "unknown"),
    ],
)
def test_version_state(monkeypatch: pytest.MonkeyPatch, raw: str | None, expected: str) -> None:
    # "update your CLI" is the wrong advice for a binary that would not run at
    # all, so a failed probe has to stay distinguishable from an old version.
    monkeypatch.setattr(claude_code, "version", lambda: raw)
    assert claude_code.version_state() == expected
    assert claude_code.meets_min_version() is (expected == "ok")


def test_probes_decode_as_utf8_whatever_the_host_locale(monkeypatch: pytest.MonkeyPatch) -> None:
    # text=True alone decodes with the locale codec, so a console on cp1252/cp932
    # would raise UnicodeDecodeError out of a probe that only answers a question.
    recorded: dict[str, object] = {}

    def _run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        recorded.update(kwargs)
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="{}", stderr="")

    monkeypatch.setattr(claude_code, "binary_path", lambda: "/usr/bin/claude")
    monkeypatch.setattr(subprocess, "run", _run)
    claude_code._run_claude(["--version"])
    assert recorded["encoding"] == "utf-8"
    assert recorded["errors"] == "replace"


def test_transport_errors_are_recognised_through_the_cause_chain() -> None:
    # The retry policy asks this to keep a missing binary or a turn timeout out
    # of the statusless-retry fallback, which would spend five attempts on it.
    error = claude_code.ClaudeCodeError("the `claude` CLI is not on PATH")
    assert claude_code.is_transport_error(error) is True
    try:
        try:
            raise error
        except claude_code.ClaudeCodeError as exc:
            raise RuntimeError("wrapped") from exc
    except RuntimeError as wrapped:
        assert claude_code.is_transport_error(wrapped) is True
    assert claude_code.is_transport_error(RuntimeError("unrelated")) is False

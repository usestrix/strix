"""Tests for the `strix auth` CLI: subcommand routing and provider naming."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from strix.config import claude, codex
from strix.interface import auth_cli


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _tmp_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = tmp_path / "home" / ".strix" / "subscription-auth.json"
    monkeypatch.setattr(codex, "AUTH_PATH", store)
    monkeypatch.setattr(claude, "AUTH_PATH", store)


def test_default_provider_is_chatgpt() -> None:
    assert auth_cli.DEFAULT_PROVIDER.key == "chatgpt"
    assert auth_cli._resolve_provider(None) is auth_cli._CODEX_PROVIDER
    assert auth_cli._resolve_provider("chatgpt") is auth_cli._CODEX_PROVIDER
    assert auth_cli._resolve_provider("codex") is auth_cli._CODEX_PROVIDER
    assert auth_cli._resolve_provider("claude") is auth_cli._CLAUDE_PROVIDER
    assert auth_cli._resolve_provider("anthropic") is auth_cli._CLAUDE_PROVIDER
    assert auth_cli._resolve_provider("gemini") is None


def test_unknown_subcommand_returns_usage_error() -> None:
    assert auth_cli.run_auth(["bogus"]) == 2


def test_help_returns_zero() -> None:
    assert auth_cli.run_auth(["--help"]) == 0


def test_status_not_signed_in() -> None:
    assert auth_cli.run_auth(["status"]) == 1


def test_login_rejects_unsupported_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    def _should_not_run(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        msg = "OAuth flow must not start for an unsupported provider"
        raise AssertionError(msg)

    monkeypatch.setattr(auth_cli, "_run_oauth_flow", _should_not_run)
    assert auth_cli.run_auth(["login", "gemini"]) == 2


def test_finish_requires_state_on_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(codex, "exchange_code", lambda *_: {"ok": True})
    prov = auth_cli._CODEX_PROVIDER

    # Loopback (require_state=True): missing or mismatched state is rejected.
    with pytest.raises(codex.CodexAuthError) as missing:
        auth_cli._finish(prov, "code", None, "verifier", "expected", require_state=True)
    assert missing.value.code == "state_mismatch"
    with pytest.raises(codex.CodexAuthError) as mismatch:
        auth_cli._finish(prov, "code", "wrong", "verifier", "expected", require_state=True)
    assert mismatch.value.code == "state_mismatch"

    # Matching state proceeds to the exchange.
    assert auth_cli._finish(
        prov, "code", "expected", "verifier", "expected", require_state=True
    ) == {"ok": True}


def test_finish_manual_paste_allows_absent_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(codex, "exchange_code", lambda *_: {"ok": True})
    prov = auth_cli._CODEX_PROVIDER
    # Manual paste (require_state=False): a bare code with no state is accepted,
    # but a present-and-wrong state is still rejected.
    assert auth_cli._finish(prov, "code", None, "verifier", "expected", require_state=False) == {
        "ok": True
    }
    with pytest.raises(codex.CodexAuthError):
        auth_cli._finish(prov, "code", "wrong", "verifier", "expected", require_state=False)


def test_finish_rejects_missing_code() -> None:
    with pytest.raises(codex.CodexAuthError) as exc:
        auth_cli._finish(
            auth_cli._CODEX_PROVIDER, None, "expected", "verifier", "expected", require_state=True
        )
    assert exc.value.code == "no_code"


def test_finish_claude_passes_state_to_exchange(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def _fake_exchange(code: str, verifier: str, state: str | None = None) -> dict[str, Any]:
        captured.update(code=code, verifier=verifier, state=state)
        return {"ok": True}

    monkeypatch.setattr(claude, "exchange_code", _fake_exchange)
    result = auth_cli._finish(
        auth_cli._CLAUDE_PROVIDER, "code", "st", "verifier", "st", require_state=False
    )
    assert result == {"ok": True}
    # The Claude token exchange receives the state, unlike the Codex one.
    assert captured == {"code": "code", "verifier": "verifier", "state": "st"}


def test_claude_provider_is_manual_only() -> None:
    # Claude's public OAuth client registers only the console callback, so there
    # is no loopback server and sign-in is manual paste.
    assert auth_cli._CLAUDE_PROVIDER.supports_callback is False
    assert auth_cli._CODEX_PROVIDER.supports_callback is True


def test_model_subcommand_removed() -> None:
    assert auth_cli.run_auth(["model", "gpt-5.5"]) == 2


@pytest.mark.parametrize("provider", ["chatgpt", "codex", "ChatGPT"])
def test_login_accepts_provider_aliases(provider: str, monkeypatch: pytest.MonkeyPatch) -> None:
    reached = {"flow": False}

    def _fake_flow(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        reached["flow"] = True
        return {
            "type": "oauth",
            "provider": "codex",
            "access": "a",
            "refresh": "r",
            "account_id": "acct",
            "expires_at": 0,
        }

    monkeypatch.setattr(auth_cli, "_run_oauth_flow", _fake_flow)
    monkeypatch.setattr(codex, "save_record", lambda _record: None)

    assert auth_cli.run_auth(["login", provider]) == 0
    assert reached["flow"] is True


@pytest.mark.parametrize("provider", ["claude", "anthropic", "Claude"])
def test_login_accepts_claude_provider(provider: str, monkeypatch: pytest.MonkeyPatch) -> None:
    saved: dict[str, Any] = {}

    def _fake_flow(
        _console: Any, prov: auth_cli._AuthProvider, *_a: Any, **_k: Any
    ) -> dict[str, Any]:
        # The resolved provider must be the Claude one.
        assert prov is auth_cli._CLAUDE_PROVIDER
        return {"type": "oauth", "provider": "claude", "access": "a", "refresh": "r"}

    monkeypatch.setattr(auth_cli, "_run_oauth_flow", _fake_flow)
    monkeypatch.setattr(claude, "save_record", saved.update)

    assert auth_cli.run_auth(["login", provider]) == 0
    assert saved["provider"] == "claude"


def test_status_reports_claude_subscription() -> None:
    claude.save_record(
        {"type": "oauth", "provider": "claude", "access": "a", "refresh": "r", "expires_at": 0}
    )
    assert auth_cli.run_auth(["status"]) == 0


def test_logout_specific_provider_leaves_other() -> None:
    claude.save_record({"type": "oauth", "provider": "claude", "access": "a", "refresh": "r"})
    codex.save_record(
        {"type": "oauth", "provider": "codex", "access": "a", "refresh": "r", "account_id": "x"}
    )
    assert auth_cli.run_auth(["logout", "claude"]) == 0
    assert claude.is_authenticated() is False
    assert codex.is_authenticated() is True

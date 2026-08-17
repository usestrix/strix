"""Tests for the `strix auth` CLI: subcommand routing and provider naming."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from strix.config import codex, grok
from strix.interface import auth_cli


if TYPE_CHECKING:
    from pathlib import Path

_CHATGPT = auth_cli._PROVIDERS["chatgpt"]


@pytest.fixture(autouse=True)
def _tmp_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = tmp_path / "home" / ".strix" / "subscription-auth.json"
    monkeypatch.setattr(codex, "AUTH_PATH", store)
    monkeypatch.setattr(grok, "AUTH_PATH", store)


def test_default_provider_is_chatgpt() -> None:
    assert auth_cli._DEFAULT_PROVIDER == "chatgpt"
    assert set(auth_cli._PROVIDERS) == {"chatgpt", "grok"}


def test_provider_aliases_resolve() -> None:
    assert auth_cli._resolve_provider(codex.PROVIDER) is _CHATGPT
    assert auth_cli._resolve_provider("ChatGPT") is _CHATGPT
    assert auth_cli._resolve_provider("grok") is auth_cli._PROVIDERS["grok"]
    assert auth_cli._resolve_provider("xai") is auth_cli._PROVIDERS["grok"]
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

    # Loopback (require_state=True): missing or mismatched state is rejected.
    with pytest.raises(codex.CodexAuthError) as missing:
        auth_cli._finish(_CHATGPT, "code", None, "verifier", "expected", require_state=True)
    assert missing.value.code == "state_mismatch"
    with pytest.raises(codex.CodexAuthError) as mismatch:
        auth_cli._finish(_CHATGPT, "code", "wrong", "verifier", "expected", require_state=True)
    assert mismatch.value.code == "state_mismatch"

    # Matching state proceeds to the exchange.
    assert auth_cli._finish(
        _CHATGPT, "code", "expected", "verifier", "expected", require_state=True
    ) == {"ok": True}


def test_finish_manual_paste_allows_absent_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(codex, "exchange_code", lambda *_: {"ok": True})
    # Manual paste (require_state=False): a bare code with no state is accepted,
    # but a present-and-wrong state is still rejected.
    assert auth_cli._finish(
        _CHATGPT, "code", None, "verifier", "expected", require_state=False
    ) == {"ok": True}
    with pytest.raises(codex.CodexAuthError):
        auth_cli._finish(_CHATGPT, "code", "wrong", "verifier", "expected", require_state=False)


def test_finish_rejects_missing_code() -> None:
    with pytest.raises(codex.CodexAuthError) as exc:
        auth_cli._finish(_CHATGPT, None, "expected", "verifier", "expected", require_state=True)
    assert exc.value.code == "no_code"


def test_model_subcommand_removed() -> None:
    assert auth_cli.run_auth(["model", "gpt-5.5"]) == 2


def _sign_in_both() -> None:
    codex.save_record({"type": "oauth", "access": "c", "refresh": "r", "account_id": "a"})
    grok.save_record({"type": "oauth", "access": "g", "refresh": "r"})


def test_logout_all_removes_every_provider() -> None:
    _sign_in_both()
    assert codex.is_authenticated()
    assert grok.is_authenticated()

    assert auth_cli.run_auth(["logout"]) == 0

    assert not codex.is_authenticated()
    assert not grok.is_authenticated()


def test_logout_single_provider_leaves_the_other() -> None:
    _sign_in_both()

    assert auth_cli.run_auth(["logout", "grok"]) == 0

    assert codex.is_authenticated()
    assert not grok.is_authenticated()


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

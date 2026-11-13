"""Tests for the `strix auth` CLI: subcommand routing and provider naming."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import pytest

from strix.config import codex, mistral, subscriptions
from strix.interface import auth_cli


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _tmp_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "home" / ".strix" / "subscription-auth.json"
    monkeypatch.setattr(codex, "AUTH_PATH", path)
    monkeypatch.setattr(mistral, "AUTH_PATH", path)


def test_login_provider_is_chatgpt() -> None:
    assert auth_cli.LOGIN_PROVIDER == "chatgpt"
    assert codex.PROVIDER in auth_cli._ACCEPTED_PROVIDERS
    assert "chatgpt" in auth_cli._ACCEPTED_PROVIDERS
    assert mistral.PROVIDER in auth_cli._ACCEPTED_PROVIDERS


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
        auth_cli._finish("code", None, "verifier", "expected", require_state=True)
    assert missing.value.code == "state_mismatch"
    with pytest.raises(codex.CodexAuthError) as mismatch:
        auth_cli._finish("code", "wrong", "verifier", "expected", require_state=True)
    assert mismatch.value.code == "state_mismatch"

    # Matching state proceeds to the exchange.
    assert auth_cli._finish("code", "expected", "verifier", "expected", require_state=True) == {
        "ok": True
    }


def test_finish_manual_paste_allows_absent_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(codex, "exchange_code", lambda *_: {"ok": True})
    # Manual paste (require_state=False): a bare code with no state is accepted,
    # but a present-and-wrong state is still rejected.
    assert auth_cli._finish("code", None, "verifier", "expected", require_state=False) == {
        "ok": True
    }
    with pytest.raises(codex.CodexAuthError):
        auth_cli._finish("code", "wrong", "verifier", "expected", require_state=False)


def test_finish_rejects_missing_code() -> None:
    with pytest.raises(codex.CodexAuthError) as exc:
        auth_cli._finish(None, "expected", "verifier", "expected", require_state=True)
    assert exc.value.code == "no_code"


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


@pytest.mark.parametrize("provider", ["mistral", "Mistral"])
def test_login_accepts_mistral(provider: str, monkeypatch: pytest.MonkeyPatch) -> None:
    seen = {"sub": None}

    def _fake_flow(_console: Any, sub: Any, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
        seen["sub"] = sub
        return {
            "type": "oauth",
            "provider": "mistral",
            "access": "a",
            "refresh": "r",
            "account_id": "sub-1",
            "expires_at": 0,
        }

    monkeypatch.setattr(auth_cli, "_run_oauth_flow", _fake_flow)
    saved: list[dict[str, Any]] = []
    monkeypatch.setattr(mistral, "save_record", saved.append)

    assert auth_cli.run_auth(["login", provider]) == 0
    assert seen["sub"] is subscriptions.MISTRAL
    assert saved and saved[0]["provider"] == "mistral"


def test_status_lists_every_signed_in_provider() -> None:
    codex.save_record(
        {
            "type": "oauth",
            "provider": "codex",
            "access": "a",
            "refresh": "r",
            "account_id": "acct-codex",
            "expires_at": time.time() + 3600,
        }
    )
    mistral.save_record(
        {
            "type": "oauth",
            "provider": "mistral",
            "access": "a",
            "refresh": "r",
            "account_id": "sub-1",
            "expires_at": time.time() + 3600,
        }
    )
    assert auth_cli.run_auth(["status"]) == 0


def test_logout_without_provider_clears_all(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_LLM", raising=False)
    for module, account in ((codex, "acct-codex"), (mistral, "sub-1")):
        module.save_record(
            {
                "type": "oauth",
                "provider": module.PROVIDER,
                "access": "a",
                "refresh": "r",
                "account_id": account,
                "expires_at": time.time() + 3600,
            }
        )
    assert auth_cli.run_auth(["logout"]) == 0
    assert codex.read_record() is None
    assert mistral.read_record() is None


def test_logout_with_provider_clears_only_that_one() -> None:
    for module, account in ((codex, "acct-codex"), (mistral, "sub-1")):
        module.save_record(
            {
                "type": "oauth",
                "provider": module.PROVIDER,
                "access": "a",
                "refresh": "r",
                "account_id": account,
                "expires_at": time.time() + 3600,
            }
        )
    assert auth_cli.run_auth(["logout", "mistral"]) == 0
    assert mistral.read_record() is None
    assert codex.read_record() is not None


def test_logout_rejects_unknown_provider() -> None:
    assert auth_cli.run_auth(["logout", "gemini"]) == 2

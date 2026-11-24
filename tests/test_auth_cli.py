"""Tests for the `strix auth` CLI: subcommand routing and provider naming."""

from __future__ import annotations

import base64
import json
import time
from typing import TYPE_CHECKING, Any

import pytest

from strix.config import anthropic_wif, codex, entra_user, loader
from strix.interface import auth_cli


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _tmp_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(codex, "AUTH_PATH", tmp_path / "home" / ".strix" / "subscription-auth.json")
    monkeypatch.setattr(entra_user, "AUTH_PATH", tmp_path / "home" / ".strix" / "entra-auth.json")
    for key in ("STRIX_ENTRA_TENANT_ID", "STRIX_ENTRA_APP_ID"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(loader, "_override", tmp_path / "missing-config.json")
    monkeypatch.setattr(loader, "_cached", None)


def test_login_provider_is_chatgpt() -> None:
    assert auth_cli.LOGIN_PROVIDER == "chatgpt"
    assert codex.PROVIDER in auth_cli._ACCEPTED_PROVIDERS
    assert "chatgpt" in auth_cli._ACCEPTED_PROVIDERS


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


def _entra_record(**overrides: Any) -> dict[str, Any]:
    record = {
        "type": "oauth",
        "provider": "entra",
        "tenant": "tenant-id",
        "app": "app-id",
        "access": "entra-access",
        "refresh": "entra-refresh",
        "username": "user@example.com",
        "expires_at": time.time() + 3600,
    }
    record.update(overrides)
    return record


def _codex_record() -> dict[str, Any]:
    return {
        "type": "oauth",
        "provider": "codex",
        "access": "a",
        "refresh": "r",
        "account_id": "acct",
        "expires_at": time.time() + 3600,
    }


def test_login_entra_manual_paste_saves_the_sign_in(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, ...]] = []

    def _exchange(tenant: str, app: str, code: str, verifier: str) -> dict[str, Any]:
        calls.append((tenant, app, code))
        assert verifier
        return _entra_record(tenant=tenant, app=app)

    monkeypatch.setattr(entra_user, "exchange_code", _exchange)
    monkeypatch.setattr(
        auth_cli.Console, "input", lambda *_args, **_kwargs: "http://localhost:8400/?code=abc"
    )

    argv = ["login", "entra", "--manual", "--tenant", "tenant-id", "--app", "app-id"]
    assert auth_cli.run_auth(argv) == 0
    assert calls == [("tenant-id", "app-id", "abc")]
    saved = entra_user.read_record()
    assert saved is not None
    assert saved["tenant"] == "tenant-id"


def test_login_entra_uses_settings_for_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_ENTRA_TENANT_ID", "tenant-from-env")
    monkeypatch.setenv("STRIX_ENTRA_APP_ID", "app-from-env")
    seen: dict[str, str] = {}

    def _fake_flow(_console: Any, url: str, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
        seen["url"] = url
        return _entra_record()

    monkeypatch.setattr(auth_cli, "_run_oauth_flow", _fake_flow)
    assert auth_cli.run_auth(["login", "entra"]) == 0
    assert "/tenant-from-env/oauth2/v2.0/authorize" in seen["url"]
    assert "client_id=app-from-env" in seen["url"]


def test_login_entra_without_ids_is_a_usage_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _should_not_run(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        msg = "OAuth flow must not start without Entra IDs"
        raise AssertionError(msg)

    monkeypatch.setattr(auth_cli, "_run_oauth_flow", _should_not_run)
    assert auth_cli.run_auth(["login", "entra"]) == 2


def test_status_reports_both_providers(capsys: pytest.CaptureFixture[str]) -> None:
    entra_user.save_record(_entra_record())
    assert auth_cli.run_auth(["status"]) == 0
    out = capsys.readouterr().out
    assert "ChatGPT subscription" in out
    assert "Not signed in" in out
    assert "Microsoft Entra ID" in out
    assert "user@example.com" in out


def test_logout_signs_out_of_every_provider(capsys: pytest.CaptureFixture[str]) -> None:
    codex.save_record(_codex_record())
    entra_user.save_record(_entra_record())
    assert auth_cli.run_auth(["logout"]) == 0
    out = capsys.readouterr().out
    assert "ChatGPT subscription and Microsoft Entra ID" in out
    assert codex.read_record() is None
    assert entra_user.read_record() is None


def test_logout_when_signed_out(capsys: pytest.CaptureFixture[str]) -> None:
    assert auth_cli.run_auth(["logout"]) == 0
    assert "Not signed in" in capsys.readouterr().out


_WIF_ENV = {
    "ANTHROPIC_FEDERATION_RULE_ID": "fdrl_test",
    "ANTHROPIC_ORGANIZATION_ID": "org-test",
    "ANTHROPIC_SERVICE_ACCOUNT_ID": "svac_test",
    "STRIX_LLM": "anthropic/claude-sonnet-4-6",
}


def _fake_jwt(claims: dict[str, Any]) -> str:
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"e30.{payload}.sig"


@pytest.fixture
def wif_env(monkeypatch: pytest.MonkeyPatch) -> str:
    for key in (
        "ANTHROPIC_WORKSPACE_ID",
        "ANTHROPIC_IDENTITY_TOKEN_FILE",
        "ANTHROPIC_IDENTITY_TOKEN_COMMAND",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
    ):
        monkeypatch.delenv(key, raising=False)
    for key, value in _WIF_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("LLM_API_KEY", "")
    jwt = _fake_jwt({"iss": "https://idp.example", "sub": "subject-123"})
    monkeypatch.setenv("ANTHROPIC_IDENTITY_TOKEN", jwt)
    return jwt


def test_test_reports_source_claims_and_prefix_only(
    wif_env: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    seen: list[str | None] = []

    def _exchange(assertion: str | None = None) -> tuple[str, float]:
        seen.append(assertion)
        return "sk-ant-oat01-SECRETPART", time.time() + 600

    monkeypatch.setattr(anthropic_wif, "exchange", _exchange)
    assert auth_cli.run_auth(["test"]) == 0
    out = capsys.readouterr().out
    assert seen == [wif_env]
    assert "ANTHROPIC_IDENTITY_TOKEN" in out
    assert "subject-123" in out
    assert "sk-ant-oat01-…" in out
    assert "SECRETPART" not in out
    assert wif_env not in out
    assert "Note:" not in out


def test_test_without_federation_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in _WIF_ENV:
        monkeypatch.delenv(key, raising=False)
    assert auth_cli.run_auth(["test"]) == 1


def test_test_reports_exchange_failure(
    wif_env: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    del wif_env

    def _fail(_assertion: str | None = None) -> tuple[str, float]:
        raise anthropic_wif.WifAuthError("token exchange failed: HTTP 401")

    monkeypatch.setattr(anthropic_wif, "exchange", _fail)
    assert auth_cli.run_auth(["test"]) == 1
    assert "HTTP 401" in capsys.readouterr().out


def test_test_warns_when_an_api_key_wins(
    wif_env: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    del wif_env
    monkeypatch.setenv("LLM_API_KEY", "sk-ant-api-key")
    monkeypatch.setattr(anthropic_wif, "exchange", lambda _a=None: ("sk-ant-oat01-x", time.time()))
    assert auth_cli.run_auth(["test"]) == 0
    assert "LLM_API_KEY is set" in capsys.readouterr().out


def test_test_reads_settings_from_config(
    wif_env: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del wif_env
    config = tmp_path / "strix-config.json"
    config.write_text(json.dumps({"env": _WIF_ENV}), encoding="utf-8")
    for key in _WIF_ENV:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(anthropic_wif, "exchange", lambda _a=None: ("sk-ant-oat01-x", time.time()))
    assert auth_cli.run_auth(["test"]) == 1
    monkeypatch.setattr(loader, "_cached", None)
    assert auth_cli.run_auth(["test", "--config", str(config)]) == 0

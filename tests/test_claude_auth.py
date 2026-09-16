"""Tests for Claude (Anthropic) subscription auth: PKCE, token handling, store."""

from __future__ import annotations

import base64
import hashlib
import time
from typing import TYPE_CHECKING, Any
from unittest import mock

import pytest
import requests

from strix.config import claude, subscription


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _tmp_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "home" / ".strix" / "subscription-auth.json"
    monkeypatch.setattr(claude, "AUTH_PATH", path)
    return path


def test_pkce_challenge_matches_verifier_and_is_unpadded() -> None:
    verifier, challenge = claude.generate_pkce()
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    assert challenge == expected
    assert "=" not in verifier
    assert "=" not in challenge


def test_authorize_url_carries_pkce_and_client() -> None:
    url = claude.build_authorize_url("chal", "st8")
    assert claude.AUTHORIZE_URL in url
    assert "code_challenge=chal" in url
    assert "code_challenge_method=S256" in url
    assert f"client_id={claude.CLIENT_ID}" in url
    assert "state=st8" in url


def test_post_json_returns_parsed_body() -> None:
    resp = mock.MagicMock()
    resp.status_code = 200
    resp.content = b'{"access_token": "sk-ant-oat-tok"}'
    resp.__enter__.return_value = resp

    with mock.patch.object(requests, "post", return_value=resp) as post:
        data = claude._post_json({"grant_type": "refresh_token"})

    assert data == {"access_token": "sk-ant-oat-tok"}
    assert post.call_args.kwargs["timeout"] == claude._TOKEN_TIMEOUT
    # OAuth token endpoint is posted as JSON, not form-encoded.
    assert "json" in post.call_args.kwargs


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://console.anthropic.com/oauth/code/callback?code=AAA&state=BBB", ("AAA", "BBB")),
        ("AAA#BBB", ("AAA", "BBB")),
        ("code=AAA&state=BBB", ("AAA", "BBB")),
        ("AAA", ("AAA", None)),
        ("", (None, None)),
    ],
)
def test_parse_redirect_input(value: str, expected: tuple[str | None, str | None]) -> None:
    assert claude.parse_redirect_input(value) == expected


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        ("claude/opus-5", "opus-5"),
        ("Claude/Opus-5", "Opus-5"),
        ("  claude/sonnet-5  ", "sonnet-5"),
        ("anthropic/claude-opus-4-8", None),  # metered API-key path, not subscription
        ("chatgpt/gpt-5.4", None),
        ("claude-opus-5", None),
        ("claude/", None),
        ("", None),
        (None, None),
    ],
)
def test_subscription_model(model: str | None, expected: str | None) -> None:
    assert claude.subscription_model(model) == expected


def test_auth_mode() -> None:
    assert claude.auth_mode("claude/opus-5") == "subscription"
    assert claude.auth_mode("anthropic/claude-opus-5") == "api_key"
    assert claude.auth_mode(None) == "api_key"


def test_exchange_code_includes_state_and_reads_account(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def _fake_post(payload: dict[str, str]) -> dict[str, Any]:
        captured.update(payload)
        return {
            "access_token": "sk-ant-oat-abc",
            "refresh_token": "sk-ant-ort-xyz",
            "expires_in": 3600,
            "account": {"email_address": "dev@example.com"},
        }

    monkeypatch.setattr(claude, "_post_json", _fake_post)
    record = claude.exchange_code("the-code", "the-verifier", "the-state")
    assert captured["grant_type"] == "authorization_code"
    assert captured["code"] == "the-code"
    assert captured["code_verifier"] == "the-verifier"
    assert captured["state"] == "the-state"
    assert record["access"] == "sk-ant-oat-abc"
    assert record["refresh"] == "sk-ant-ort-xyz"
    assert record["account_label"] == "dev@example.com"


def test_store_roundtrip_and_logout() -> None:
    assert claude.read_record() is None
    assert claude.is_authenticated() is False

    claude.save_record(
        {
            "type": "oauth",
            "provider": "claude",
            "access": "sk-ant-oat-abc",
            "refresh": "sk-ant-ort-xyz",
            "expires_at": time.time() + 3600,
        }
    )
    assert claude.is_authenticated() is True
    claude.logout()
    assert claude.read_record() is None
    claude.logout()  # no-op when already gone


def test_read_record_rejects_incomplete_records() -> None:
    claude.save_record({"type": "oauth", "access": "a"})  # missing refresh
    assert claude.read_record() is None
    assert claude.is_authenticated() is False


def test_get_valid_token_returns_stored_when_fresh(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(_payload: dict[str, str]) -> dict[str, Any]:
        msg = "should not refresh a fresh token"
        raise AssertionError(msg)

    monkeypatch.setattr(claude, "_post_json", _boom)
    claude.save_record(
        {
            "type": "oauth",
            "provider": "claude",
            "access": "sk-ant-oat-fresh",
            "refresh": "r1",
            "expires_at": time.time() + 3600,
        }
    )
    assert claude.get_valid_token() == "sk-ant-oat-fresh"
    assert claude.oauth_api_key() == "sk-ant-oat-fresh"


def test_get_valid_token_refreshes_and_persists_rotation(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}

    def _fake_post(payload: dict[str, str]) -> dict[str, Any]:
        calls["n"] += 1
        assert payload["grant_type"] == "refresh_token"
        assert payload["refresh_token"] == "r1"
        return {"access_token": "sk-ant-oat-new", "refresh_token": "r2", "expires_in": 3600}

    monkeypatch.setattr(claude, "_post_json", _fake_post)
    claude.save_record(
        {
            "type": "oauth",
            "provider": "claude",
            "access": "stale",
            "refresh": "r1",
            "expires_at": time.time() - 10,  # already expired
        }
    )
    assert claude.get_valid_token() == "sk-ant-oat-new"
    assert calls["n"] == 1
    record = claude.read_record()
    assert record is not None
    assert record["refresh"] == "r2"  # rotation written back


def test_get_valid_token_raises_when_not_signed_in() -> None:
    with pytest.raises(claude.ClaudeAuthError) as exc:
        claude.get_valid_token()
    assert exc.value.code == "not_authenticated"


def test_subscription_facade_dispatches_across_providers() -> None:
    assert subscription.subscription_model("claude/opus-5") == "opus-5"
    assert subscription.subscription_model("chatgpt/gpt-5.4") == "gpt-5.4"
    assert subscription.subscription_model("anthropic/claude-opus-5") is None
    assert subscription.provider_name("claude/opus-5") == "claude"
    assert subscription.provider_name("chatgpt/gpt-5.4") == "codex"
    assert subscription.auth_mode("claude/opus-5") == "subscription"
    assert subscription.auth_mode("openai/gpt-5.4") == "api_key"

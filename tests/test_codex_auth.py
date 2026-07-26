"""Tests for ChatGPT (Codex) subscription auth: PKCE, token handling, store."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import TYPE_CHECKING, Any

import pytest

from strix.config import codex


if TYPE_CHECKING:
    from pathlib import Path


def _fake_jwt(account_id: str) -> str:
    def seg(obj: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    header = seg({"alg": "none"})
    payload = seg({"https://api.openai.com/auth": {"chatgpt_account_id": account_id}})
    return f"{header}.{payload}.sig"


@pytest.fixture(autouse=True)
def _tmp_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "home" / ".strix" / "subscription-auth.json"
    monkeypatch.setattr(codex, "AUTH_PATH", path)
    return path


def test_pkce_challenge_matches_verifier_and_is_unpadded() -> None:
    verifier, challenge = codex.generate_pkce()
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    assert challenge == expected
    assert "=" not in verifier
    assert "=" not in challenge


def test_authorize_url_carries_pkce_and_client() -> None:
    url = codex.build_authorize_url("chal", "st8")
    assert codex.AUTHORIZE_URL in url
    assert "code_challenge=chal" in url
    assert "code_challenge_method=S256" in url
    assert f"client_id={codex.CLIENT_ID}" in url
    assert "state=st8" in url


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("http://localhost:1455/auth/callback?code=AAA&state=BBB", ("AAA", "BBB")),
        ("AAA#BBB", ("AAA", "BBB")),
        ("code=AAA&state=BBB", ("AAA", "BBB")),
        ("AAA", ("AAA", None)),
        ("", (None, None)),
    ],
)
def test_parse_redirect_input(value: str, expected: tuple[str | None, str | None]) -> None:
    assert codex.parse_redirect_input(value) == expected


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        ("chatgpt/gpt-5.4", "gpt-5.4"),
        ("ChatGPT/GPT-5.5", "GPT-5.5"),
        ("  chatgpt/gpt-5.4  ", "gpt-5.4"),
        ("openai/gpt-5.4", None),  # metered API path
        ("anthropic/claude-opus-4-8", None),
        ("gpt-5.4", None),
        ("chatgpt/", None),
        ("", None),
        (None, None),
    ],
)
def test_subscription_model(model: str | None, expected: str | None) -> None:
    assert codex.subscription_model(model) == expected


def test_auth_mode() -> None:
    assert codex.auth_mode("chatgpt/gpt-5.4") == "subscription"
    assert codex.auth_mode("openai/gpt-5.4") == "api_key"
    assert codex.auth_mode("anthropic/claude-opus-4-8") == "api_key"
    assert codex.auth_mode(None) == "api_key"


def test_is_content_guardrail_error() -> None:
    # The backend's real wording (from a live gpt-5.6-sol block).
    raw = RuntimeError(
        "This content was flagged for possible cybersecurity risk. If this seems "
        "wrong, try rephrasing. To get authorized, join the Trusted Access for Cyber program."
    )
    assert codex.is_content_guardrail_error(raw) is True
    # The already-typed error is recognized regardless of its message wording.
    assert codex.is_content_guardrail_error(codex.CodexContentGuardrailError("gpt-5.6-sol")) is True
    # Unrelated errors are not misclassified.
    assert codex.is_content_guardrail_error(RuntimeError("rate limit exceeded")) is False


def test_content_guardrail_error_message() -> None:
    err = codex.CodexContentGuardrailError("gpt-5.6-sol")
    assert err.model == "gpt-5.6-sol"
    assert "gpt-5.6-sol" in str(err)
    assert "STRIX_LLM" in str(err)


def test_account_id_from_jwt() -> None:
    assert codex._account_id_from_jwt(_fake_jwt("acct-42")) == "acct-42"
    assert codex._account_id_from_jwt("not-a-jwt") is None
    assert codex._account_id_from_jwt("") is None


def test_store_roundtrip_and_logout() -> None:
    assert codex.read_record() is None
    assert codex.is_authenticated() is False

    codex.save_record(
        {
            "type": "oauth",
            "provider": "codex",
            "access": _fake_jwt("acct-42"),
            "refresh": "r1",
            "account_id": "acct-42",
            "expires_at": time.time() + 3600,
        }
    )
    record = codex.read_record()
    assert record is not None
    assert record["account_id"] == "acct-42"
    assert codex.is_authenticated() is True

    codex.logout()
    assert codex.read_record() is None
    codex.logout()  # no-op when already gone


def test_read_record_rejects_incomplete_records() -> None:
    codex.save_record({"type": "oauth", "access": "a"})  # missing refresh/account
    assert codex.read_record() is None
    assert codex.is_authenticated() is False


def test_get_valid_token_returns_stored_when_fresh(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(_payload: dict[str, str]) -> dict[str, Any]:
        msg = "should not refresh a fresh token"
        raise AssertionError(msg)

    monkeypatch.setattr(codex, "_post_form", _boom)
    codex.save_record(
        {
            "type": "oauth",
            "provider": "codex",
            "access": "access-fresh",
            "refresh": "r1",
            "account_id": "acct-42",
            "expires_at": time.time() + 3600,
        }
    )
    assert codex.get_valid_token() == ("access-fresh", "acct-42")


def test_get_valid_token_refreshes_and_persists_rotation(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}

    def _fake_post(payload: dict[str, str]) -> dict[str, Any]:
        calls["n"] += 1
        assert payload["grant_type"] == "refresh_token"
        assert payload["refresh_token"] == "r1"
        return {"access_token": _fake_jwt("acct-42"), "refresh_token": "r2", "expires_in": 3600}

    monkeypatch.setattr(codex, "_post_form", _fake_post)
    codex.save_record(
        {
            "type": "oauth",
            "provider": "codex",
            "access": "stale",
            "refresh": "r1",
            "account_id": "acct-42",
            "expires_at": time.time() - 10,  # already expired
        }
    )
    _access, account_id = codex.get_valid_token()
    assert calls["n"] == 1
    assert account_id == "acct-42"
    # Rotated refresh token was written back to the store.
    record = codex.read_record()
    assert record is not None
    assert record["refresh"] == "r2"


def test_get_valid_token_uses_token_rotated_by_another_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Simulate a parallel Strix process rotating the token while we wait for the
    # refresh guard: the pre-guard read sees the stale token, the in-guard read
    # sees the winner's fresh one, so we must NOT exchange the now-dead refresh.
    records = [
        {
            "type": "oauth",
            "provider": "codex",
            "access": "stale",
            "refresh": "r1",
            "account_id": "acct",
            "expires_at": time.time() - 10,
        },
        {
            "type": "oauth",
            "provider": "codex",
            "access": "fresh-from-other-process",
            "refresh": "r2",
            "account_id": "acct",
            "expires_at": time.time() + 3600,
        },
    ]
    calls = {"n": 0}

    def _fake_read() -> dict[str, Any]:
        record = records[min(calls["n"], len(records) - 1)]
        calls["n"] += 1
        return record

    def _boom(_payload: dict[str, str]) -> dict[str, Any]:
        msg = "must not refresh a token another process already rotated"
        raise AssertionError(msg)

    monkeypatch.setattr(codex, "read_record", _fake_read)
    monkeypatch.setattr(codex, "_post_form", _boom)

    access, account_id = codex.get_valid_token()
    assert access == "fresh-from-other-process"
    assert account_id == "acct"


def _expired_record(refresh: str, access: str) -> dict[str, Any]:
    return {
        "type": "oauth",
        "provider": "codex",
        "access": access,
        "refresh": refresh,
        "account_id": "acct-42",
        "expires_at": time.time() - 10,
    }


def test_get_valid_token_recovers_when_refresh_loses_race(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Lock failed open: our in-guard read still saw the stale token, so we tried to
    # refresh and lost the race (invalid_grant). By then a peer has saved a fresh
    # token — recover from it instead of failing the scan on the dead one.
    codex.save_record(_expired_record("r1", "stale"))

    def _fake_post(_payload: dict[str, str]) -> dict[str, Any]:
        codex.save_record(
            {
                "type": "oauth",
                "provider": "codex",
                "access": "fresh-from-peer",
                "refresh": "r2",
                "account_id": "acct-42",
                "expires_at": time.time() + 3600,
            }
        )
        raise codex.CodexAuthError("token_http_error", "HTTP 400: invalid_grant")

    monkeypatch.setattr(codex, "_post_form", _fake_post)
    assert codex.get_valid_token() == ("fresh-from-peer", "acct-42")


def test_get_valid_token_reraises_refresh_error_without_rotation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Refresh fails and no peer rotated the token: surface the error, don't mask it.
    codex.save_record(_expired_record("r1", "stale"))

    def _fake_post(_payload: dict[str, str]) -> dict[str, Any]:
        raise codex.CodexAuthError("token_http_error", "HTTP 400: invalid_grant")

    monkeypatch.setattr(codex, "_post_form", _fake_post)
    with pytest.raises(codex.CodexAuthError):
        codex.get_valid_token()


def test_get_valid_token_raises_when_not_signed_in() -> None:
    with pytest.raises(codex.CodexAuthError) as exc:
        codex.get_valid_token()
    assert exc.value.code == "not_authenticated"

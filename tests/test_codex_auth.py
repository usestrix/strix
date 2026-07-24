"""Tests for ChatGPT (Codex) subscription auth: PKCE, token handling, store."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import TYPE_CHECKING, Any

import pytest

from strix.auth import codex, store


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path
    from typing import Self


def _fake_jwt(account_id: str) -> str:
    def seg(obj: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    header = seg({"alg": "none"})
    payload = seg({"https://api.openai.com/auth": {"chatgpt_account_id": account_id}})
    return f"{header}.{payload}.sig"


@pytest.fixture(autouse=True)
def _tmp_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "home" / ".strix" / "subscription-auth.json"
    monkeypatch.setattr(store, "AUTH_PATH", path)
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
        ("openai/subscription", True),
        ("OpenAI/Subscription", True),  # case-insensitive
        ("  openai/subscription  ", True),  # surrounding whitespace
        ("openai/gpt-5.4", False),
        ("anthropic/claude-opus-4-8", False),
        ("openai/subscription/gpt-5.5", True),  # model-selecting form
        ("OpenAI/Subscription/GPT-5.5", True),  # case-insensitive
        ("openai/subscription-x", False),  # not the switch or a suffix of it
        ("", False),
        (None, False),
    ],
)
def test_is_subscription(model: str | None, expected: bool) -> None:
    assert codex.is_subscription(model) is expected


def test_resolve_and_label() -> None:
    assert codex.resolve_subscription_model() == codex.DEFAULT_CODEX_MODEL
    assert codex.resolve_subscription_model("openai/subscription") == codex.DEFAULT_CODEX_MODEL
    assert codex.resolve_subscription_model("openai/subscription/gpt-5.5") == "gpt-5.5"
    # Case-insensitive; every advertised slug resolves to itself.
    assert codex.resolve_subscription_model("OpenAI/Subscription/GPT-5.6-Sol") == "gpt-5.6-sol"
    for slug in codex.SUBSCRIPTION_MODELS:
        assert codex.resolve_subscription_model(f"openai/subscription/{slug}") == slug
    assert codex.auth_mode_label("openai/subscription") == "subscription"
    assert codex.auth_mode_label("openai/subscription/gpt-5.5") == "subscription"
    assert codex.auth_mode_label("openai/gpt-5.4") == "api_key"
    assert codex.auth_mode_label(None) == "api_key"


def test_resolve_unknown_model_fails_loud() -> None:
    with pytest.raises(codex.CodexAuthError) as exc_info:
        codex.resolve_subscription_model("openai/subscription/gpt-4o")
    # The error names the offending slug and lists the valid choices.
    assert "gpt-4o" in str(exc_info.value)
    assert "gpt-5.4" in str(exc_info.value)


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
    # Actionable: names the blocked model and points at the safe default.
    assert "gpt-5.6-sol" in str(err)
    assert codex.DEFAULT_CODEX_MODEL in str(err)


@pytest.fixture(autouse=True)
def _reset_model_cache() -> Iterator[None]:
    # Keep the module-level live-catalog cache from leaking across tests.
    codex._subscription_models_cache = None
    yield
    codex._subscription_models_cache = None


def test_get_subscription_models_falls_back_when_uncached() -> None:
    assert codex._subscription_models_cache is None
    assert codex.get_subscription_models() == codex.SUBSCRIPTION_MODELS


def test_refresh_caches_live_catalog(monkeypatch: pytest.MonkeyPatch) -> None:
    live = ("gpt-5.4", "gpt-5.7-nova")
    monkeypatch.setattr(codex, "fetch_subscription_models", lambda: live)
    assert codex.refresh_subscription_models() == live
    assert codex.get_subscription_models() == live
    # A model only in the live catalog now validates; the stale fallback doesn't gate it.
    assert codex.resolve_subscription_model("openai/subscription/gpt-5.7-nova") == "gpt-5.7-nova"


def test_refresh_keeps_fallback_on_fetch_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom() -> tuple[str, ...]:
        raise codex.CodexAuthError("network", "unreachable")

    monkeypatch.setattr(codex, "fetch_subscription_models", _boom)
    # Best-effort: no raise, and the static fallback stays in force.
    assert codex.refresh_subscription_models() == codex.SUBSCRIPTION_MODELS
    assert codex.resolve_subscription_model("openai/subscription/gpt-5.5") == "gpt-5.5"


def test_subscription_model_label() -> None:
    default_label = codex.subscription_model_label("gpt-5.4")
    assert default_label is not None
    assert "default" in default_label
    assert "recommended" in default_label
    guardrail = codex.subscription_model_label("gpt-5.6-sol")
    assert guardrail is not None
    assert "guardrail" in guardrail
    # Only the default is recommended; others are left unlabeled, not endorsed.
    assert codex.subscription_model_label("gpt-5.5") is None
    assert codex.subscription_model_label("gpt-5.4-mini") is None
    assert codex.subscription_model_label("gpt-5.7-unknown") is None


def test_fetch_parses_catalog_and_excludes_internal(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "models": [
            {"slug": "gpt-5.4", "display_name": "GPT-5.4"},
            {"slug": "codex-auto-review"},  # internal helper — excluded
            {"slug": "gpt-5.6-sol"},
            {"display_name": "malformed, no slug"},  # skipped
        ]
    }

    class _Resp:
        def __enter__(self) -> Self:
            return self

        def __exit__(self, *args: object) -> bool:
            return False

        def read(self) -> bytes:
            return json.dumps(payload).encode()

    monkeypatch.setattr(codex, "get_valid_token", lambda: ("tok", "acct"))
    monkeypatch.setattr(codex.urllib.request, "urlopen", lambda *_a, **_k: _Resp())

    assert codex.fetch_subscription_models() == ("gpt-5.4", "gpt-5.6-sol")


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
    store.write_provider("codex", {"type": "oauth", "access": "a"})  # missing refresh/account
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
    assert codex.read_record()["refresh"] == "r2"


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


def test_get_valid_token_raises_when_not_signed_in() -> None:
    with pytest.raises(codex.CodexAuthError) as exc:
        codex.get_valid_token()
    assert exc.value.code == "not_authenticated"

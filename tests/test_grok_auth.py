"""Tests for Grok (xAI) subscription auth: PKCE, token handling, store."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import TYPE_CHECKING, Any
from unittest import mock

import pytest
import requests

from strix.config import grok


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _tmp_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "home" / ".strix" / "subscription-auth.json"
    monkeypatch.setattr(grok, "AUTH_PATH", path)
    return path


def test_pkce_challenge_matches_verifier_and_is_unpadded() -> None:
    verifier, challenge = grok.generate_pkce()
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    assert challenge == expected
    assert "=" not in verifier
    assert "=" not in challenge


def test_authorize_url_carries_pkce_client_and_grok_scope() -> None:
    url = grok.build_authorize_url("chal", "st8")
    assert grok.AUTHORIZE_URL in url
    assert "code_challenge=chal" in url
    assert "code_challenge_method=S256" in url
    assert f"client_id={grok.CLIENT_ID}" in url
    assert "state=st8" in url
    # The Grok-CLI scope is what unlocks subscription inference.
    assert "grok-cli%3Aaccess" in url
    assert "offline_access" in url


def test_redirect_uri_is_loopback() -> None:
    assert grok.REDIRECT_URI == "http://127.0.0.1:56121/callback"


def test_post_form_returns_parsed_body() -> None:
    resp = mock.MagicMock()
    resp.status_code = 200
    resp.content = b'{"access_token": "tok"}'
    resp.__enter__.return_value = resp

    with mock.patch.object(requests, "post", return_value=resp) as post:
        data = grok._post_form({"grant_type": "refresh_token"})

    assert data == {"access_token": "tok"}
    assert post.call_args.kwargs["timeout"] == grok._TOKEN_TIMEOUT


def test_post_form_raises_on_http_error() -> None:
    resp = mock.MagicMock()
    resp.status_code = 400
    resp.text = "invalid_grant"
    resp.__enter__.return_value = resp

    with (
        mock.patch.object(requests, "post", return_value=resp),
        pytest.raises(grok.GrokAuthError) as exc,
    ):
        grok._post_form({"grant_type": "refresh_token"})
    assert exc.value.code == "token_http_error"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("http://127.0.0.1:56121/callback?code=AAA&state=BBB", ("AAA", "BBB")),
        ("AAA#BBB", ("AAA", "BBB")),
        ("code=AAA&state=BBB", ("AAA", "BBB")),
        ("AAA", ("AAA", None)),
        ("", (None, None)),
    ],
)
def test_parse_redirect_input(value: str, expected: tuple[str | None, str | None]) -> None:
    assert grok.parse_redirect_input(value) == expected


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        ("grok/grok-4", "grok-4"),
        ("Grok/Grok-4", "Grok-4"),
        ("  grok/grok-4  ", "grok-4"),
        ("xai/grok-4", None),  # metered API path
        ("chatgpt/gpt-5.4", None),
        ("grok-4", None),
        ("grok/", None),
        ("", None),
        (None, None),
    ],
)
def test_subscription_model(model: str | None, expected: str | None) -> None:
    assert grok.subscription_model(model) == expected


def test_auth_mode() -> None:
    assert grok.auth_mode("grok/grok-4") == "subscription"
    assert grok.auth_mode("xai/grok-4") == "api_key"
    assert grok.auth_mode("chatgpt/gpt-5.4") == "api_key"
    assert grok.auth_mode(None) == "api_key"


def _record(access: str, refresh: str, expires_at: float) -> dict[str, Any]:
    return {
        "type": "oauth",
        "provider": "grok",
        "access": access,
        "refresh": refresh,
        "expires_at": expires_at,
    }


def test_store_roundtrip_and_logout() -> None:
    assert grok.read_record() is None
    assert grok.is_authenticated() is False

    grok.save_record(_record("a1", "r1", time.time() + 3600))
    record = grok.read_record()
    assert record is not None
    assert record["access"] == "a1"
    assert grok.is_authenticated() is True

    grok.logout()
    assert grok.read_record() is None
    grok.logout()  # no-op when already gone


def test_store_file_permissions_are_owner_only(_tmp_store: Path) -> None:
    grok.save_record(_record("a1", "r1", time.time() + 3600))
    assert (_tmp_store.stat().st_mode & 0o777) == 0o600


def test_store_shares_file_with_other_providers(_tmp_store: Path) -> None:
    # Grok must not clobber a co-resident ChatGPT record in the shared store.
    _tmp_store.parent.mkdir(parents=True, exist_ok=True)
    _tmp_store.write_text(json.dumps({"codex": {"type": "oauth", "access": "x"}}))

    grok.save_record(_record("a1", "r1", time.time() + 3600))
    on_disk = json.loads(_tmp_store.read_text())
    assert on_disk["codex"] == {"type": "oauth", "access": "x"}
    assert on_disk["grok"]["access"] == "a1"

    grok.logout()
    # Removing grok leaves the other provider's record and the file intact.
    assert json.loads(_tmp_store.read_text()) == {"codex": {"type": "oauth", "access": "x"}}


def test_read_record_rejects_incomplete_records() -> None:
    grok.save_record({"type": "oauth", "access": "a"})  # missing refresh
    assert grok.read_record() is None
    assert grok.is_authenticated() is False


def test_get_valid_token_returns_stored_when_fresh(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(_payload: dict[str, str]) -> dict[str, Any]:
        msg = "should not refresh a fresh token"
        raise AssertionError(msg)

    monkeypatch.setattr(grok, "_post_form", _boom)
    grok.save_record(_record("access-fresh", "r1", time.time() + 3600))
    assert grok.get_valid_token() == "access-fresh"


def test_get_valid_token_refreshes_and_persists_rotation(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}

    def _fake_post(payload: dict[str, str]) -> dict[str, Any]:
        calls["n"] += 1
        assert payload["grant_type"] == "refresh_token"
        assert payload["refresh_token"] == "r1"
        return {"access_token": "access-new", "refresh_token": "r2", "expires_in": 3600}

    monkeypatch.setattr(grok, "_post_form", _fake_post)
    grok.save_record(_record("stale", "r1", time.time() - 10))  # already expired

    assert grok.get_valid_token() == "access-new"
    assert calls["n"] == 1
    record = grok.read_record()
    assert record is not None
    assert record["refresh"] == "r2"  # rotated refresh written back


def test_refresh_keeps_old_refresh_when_response_omits_it(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake_post(_payload: dict[str, str]) -> dict[str, Any]:
        return {"access_token": "access-new", "expires_in": 3600}  # no refresh_token

    monkeypatch.setattr(grok, "_post_form", _fake_post)
    grok.save_record(_record("stale", "r1", time.time() - 10))

    assert grok.get_valid_token() == "access-new"
    record = grok.read_record()
    assert record is not None
    assert record["refresh"] == "r1"  # fell back to the prior refresh token


def test_get_valid_token_uses_token_rotated_by_another_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = [
        _record("stale", "r1", time.time() - 10),
        _record("fresh-from-other-process", "r2", time.time() + 3600),
    ]
    calls = {"n": 0}

    def _fake_read() -> dict[str, Any]:
        record = records[min(calls["n"], len(records) - 1)]
        calls["n"] += 1
        return record

    def _boom(_payload: dict[str, str]) -> dict[str, Any]:
        msg = "must not refresh a token another process already rotated"
        raise AssertionError(msg)

    monkeypatch.setattr(grok, "read_record", _fake_read)
    monkeypatch.setattr(grok, "_post_form", _boom)

    assert grok.get_valid_token() == "fresh-from-other-process"


def test_get_valid_token_recovers_when_refresh_loses_race(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    grok.save_record(_record("stale", "r1", time.time() - 10))

    def _fake_post(_payload: dict[str, str]) -> dict[str, Any]:
        grok.save_record(_record("fresh-from-peer", "r2", time.time() + 3600))
        raise grok.GrokAuthError("token_http_error", "HTTP 400: invalid_grant")

    monkeypatch.setattr(grok, "_post_form", _fake_post)
    assert grok.get_valid_token() == "fresh-from-peer"


def test_get_valid_token_reraises_refresh_error_without_rotation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    grok.save_record(_record("stale", "r1", time.time() - 10))

    def _fake_post(_payload: dict[str, str]) -> dict[str, Any]:
        raise grok.GrokAuthError("token_http_error", "HTTP 400: invalid_grant")

    monkeypatch.setattr(grok, "_post_form", _fake_post)
    with pytest.raises(grok.GrokAuthError):
        grok.get_valid_token()


def test_get_valid_token_raises_when_not_signed_in() -> None:
    with pytest.raises(grok.GrokAuthError) as exc:
        grok.get_valid_token()
    assert exc.value.code == "not_authenticated"

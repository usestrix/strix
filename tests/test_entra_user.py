"""Tests for Microsoft Entra ID user sign-in (the `strix auth login entra` token store)."""

from __future__ import annotations

import base64
import json
import threading
import time
import urllib.parse
from typing import TYPE_CHECKING, Any
from unittest import mock

import pytest

from strix.config import entra_user, loader


if TYPE_CHECKING:
    from pathlib import Path


TENANT = "11111111-1111-1111-1111-111111111111"
APP = "22222222-2222-2222-2222-222222222222"


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(entra_user, "AUTH_PATH", tmp_path / ".strix" / "entra-auth.json")
    for key in ("STRIX_ENTRA_TENANT_ID", "STRIX_ENTRA_APP_ID"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(loader, "_override", tmp_path / "missing-config.json")
    monkeypatch.setattr(loader, "_cached", None)


def _jwt(claims: dict[str, Any]) -> str:
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"e30.{payload}.sig"


def _response(status: int, body: dict[str, Any]) -> Any:
    resp = mock.MagicMock()
    resp.status_code = status
    resp.json.return_value = body
    return resp


def _record(**overrides: Any) -> dict[str, Any]:
    record = {
        "type": "oauth",
        "provider": "entra",
        "tenant": TENANT,
        "app": APP,
        "access": "access-1",
        "refresh": "refresh-1",
        "username": "user@example.com",
        "expires_at": time.time() + 3600,
    }
    record.update(overrides)
    return record


def test_authorize_url_requests_the_app_scope_with_pkce() -> None:
    url = urllib.parse.urlparse(entra_user.build_authorize_url(TENANT, APP, "chal", "st"))
    params = dict(urllib.parse.parse_qsl(url.query))
    assert url.netloc == "login.microsoftonline.com"
    assert url.path == f"/{TENANT}/oauth2/v2.0/authorize"
    assert params["client_id"] == APP
    assert params["scope"] == f"api://{APP}/user_impersonation offline_access openid profile"
    assert params["redirect_uri"] == "http://localhost:8400"
    assert params["response_mode"] == "query"
    assert params["code_challenge"] == "chal"
    assert params["code_challenge_method"] == "S256"
    assert params["state"] == "st"


def test_exchange_code_builds_a_record() -> None:
    body = {
        "access_token": "access-1",
        "refresh_token": "refresh-1",
        "expires_in": 3600,
        "id_token": _jwt({"preferred_username": "user@example.com"}),
    }
    with mock.patch.object(entra_user.requests, "post", return_value=_response(200, body)) as post:
        record = entra_user.exchange_code(TENANT, APP, "the-code", "the-verifier")
    sent = post.call_args.kwargs["data"]
    assert post.call_args.args[0] == f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"
    assert sent["grant_type"] == "authorization_code"
    assert sent["client_id"] == APP
    assert sent["code"] == "the-code"
    assert sent["code_verifier"] == "the-verifier"
    assert record["tenant"] == TENANT
    assert record["app"] == APP
    assert record["username"] == "user@example.com"
    assert record["expires_at"] > time.time() + 3000


@pytest.mark.parametrize(
    ("returned", "expected"), [("refresh-2", "refresh-2"), (None, "refresh-1")]
)
def test_refresh_keeps_or_rotates_the_refresh_token(returned: str | None, expected: str) -> None:
    body: dict[str, Any] = {"access_token": "access-2", "expires_in": 3600}
    if returned:
        body["refresh_token"] = returned
    with mock.patch.object(entra_user.requests, "post", return_value=_response(200, body)) as post:
        record = entra_user.refresh_tokens(_record())
    assert post.call_args.kwargs["data"]["grant_type"] == "refresh_token"
    assert record["access"] == "access-2"
    assert record["refresh"] == expected
    assert record["username"] == "user@example.com"


def test_token_errors_name_the_reason_but_not_tokens_or_trace() -> None:
    body = {
        "error": "invalid_grant",
        "error_description": "AADSTS70000: Provided grant is invalid.\r\nTrace ID: abc\r\n",
    }
    with (
        mock.patch.object(entra_user.requests, "post", return_value=_response(400, body)),
        pytest.raises(entra_user.EntraAuthError) as exc,
    ):
        entra_user.refresh_tokens(_record())
    assert exc.value.code == "invalid_grant"
    assert "AADSTS70000" in str(exc.value)
    assert "Trace ID" not in str(exc.value)
    assert "refresh-1" not in str(exc.value)


def test_valid_token_is_served_from_the_store() -> None:
    entra_user.save_record(_record())
    with mock.patch.object(entra_user.requests, "post") as post:
        assert entra_user.get_valid_token() == "access-1"
    post.assert_not_called()


def test_token_near_expiry_is_refreshed_and_saved() -> None:
    entra_user.save_record(_record(expires_at=time.time() + 60))
    body = {"access_token": "access-2", "refresh_token": "refresh-2", "expires_in": 3600}
    with mock.patch.object(entra_user.requests, "post", return_value=_response(200, body)):
        assert entra_user.get_valid_token() == "access-2"
    saved = entra_user.read_record()
    assert saved is not None
    assert saved["refresh"] == "refresh-2"


@pytest.mark.parametrize("action", ["logout", "login"])
def test_logout_and_login_wait_for_a_refresh_in_flight(action: str) -> None:
    entra_user.save_record(_record(expires_at=time.time() + 60))
    started, release = threading.Event(), threading.Event()
    body = {"access_token": "access-2", "refresh_token": "refresh-2", "expires_in": 3600}

    def _slow_post(*_args: Any, **_kwargs: Any) -> Any:
        started.set()
        assert release.wait(5)
        return _response(200, body)

    with mock.patch.object(entra_user.requests, "post", side_effect=_slow_post):
        refresher = threading.Thread(target=entra_user.get_valid_token)
        refresher.start()
        assert started.wait(5)
        if action == "logout":
            other = threading.Thread(target=entra_user.logout)
        else:
            other = threading.Thread(
                target=entra_user.save_record, args=(_record(access="new-login"),)
            )
        other.start()
        other.join(0.2)
        assert other.is_alive()  # blocked until the refresh has saved
        release.set()
        refresher.join(5)
        other.join(5)

    saved = entra_user.read_record()
    if action == "logout":
        assert saved is None
    else:
        assert saved is not None
        assert saved["access"] == "new-login"


def test_not_signed_in_raises() -> None:
    with pytest.raises(entra_user.EntraAuthError, match="strix auth login entra"):
        entra_user.get_valid_token()


def test_store_is_private() -> None:
    entra_user.save_record(_record())
    assert entra_user.AUTH_PATH.stat().st_mode & 0o777 == 0o600


def test_configured_only_for_the_signed_in_tenant_and_app(monkeypatch: pytest.MonkeyPatch) -> None:
    assert not entra_user.is_configured()
    entra_user.save_record(_record())
    assert entra_user.is_configured()
    monkeypatch.setenv("STRIX_ENTRA_TENANT_ID", TENANT)
    monkeypatch.setenv("STRIX_ENTRA_APP_ID", APP)
    monkeypatch.setattr(loader, "_cached", None)
    assert entra_user.is_configured()
    monkeypatch.setenv("STRIX_ENTRA_APP_ID", "33333333-3333-3333-3333-333333333333")
    monkeypatch.setattr(loader, "_cached", None)
    assert not entra_user.is_configured()


def test_logout_reports_whether_there_was_a_sign_in() -> None:
    assert entra_user.logout() is False
    entra_user.save_record(_record())
    assert entra_user.logout() is True
    assert entra_user.read_record() is None

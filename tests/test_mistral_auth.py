"""Tests for Mistral subscription auth: PKCE, OIDC token handling, store."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import TYPE_CHECKING, Any
from unittest import mock

import httpx
import pytest
import requests

from strix.config import codex, mistral, subscriptions


if TYPE_CHECKING:
    from pathlib import Path


def _fake_jwt(sub: str | None, exp: float | None = None) -> str:
    def seg(obj: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    claims: dict[str, Any] = {"iss": mistral.ISSUER, "aud": [mistral.CLIENT_ID]}
    if sub is not None:
        claims["sub"] = sub
    if exp is not None:
        claims["exp"] = exp
    return f"{seg({'alg': 'RS256'})}.{seg(claims)}.sig"


def _http_response(payload: dict[str, Any], status_code: int = 200) -> mock.MagicMock:
    resp = mock.MagicMock()
    resp.status_code = status_code
    resp.content = json.dumps(payload).encode()
    resp.text = json.dumps(payload)
    resp.json.return_value = payload
    resp.__enter__.return_value = resp
    return resp


_WORKSPACES = {"workspaces": [{"id": "ws-1", "organization_id": "org-1"}]}


def _record(**overrides: Any) -> dict[str, Any]:
    record = {
        "type": "oauth",
        "provider": "mistral",
        "access": "ory_at_access",
        "refresh": "r1",
        "id_token": "id-fresh",
        "account_id": "sub-42",
        "organization_id": "org-1",
        "workspace_id": "ws-1",
        "expires_at": time.time() + 3600,
    }
    record.update(overrides)
    return record


@pytest.fixture(autouse=True)
def _tmp_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "home" / ".strix" / "subscription-auth.json"
    # Both providers share the store file; point them at the same tmp path.
    monkeypatch.setattr(mistral, "AUTH_PATH", path)
    monkeypatch.setattr(codex, "AUTH_PATH", path)
    return path


def test_pkce_challenge_matches_verifier_and_is_unpadded() -> None:
    verifier, challenge = mistral.generate_pkce()
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    assert challenge == expected
    assert "=" not in verifier
    assert "=" not in challenge


def test_authorize_url_carries_pkce_audience_and_registered_redirect() -> None:
    url = mistral.build_authorize_url("chal", "st8")
    assert url.startswith(mistral.AUTHORIZE_URL + "?")
    assert "code_challenge=chal" in url
    assert "code_challenge_method=S256" in url
    assert f"client_id={mistral.CLIENT_ID}" in url
    assert f"audience={mistral.AUDIENCE.replace(':', '%3A').replace('/', '%2F')}" in url
    assert "state=st8" in url
    assert f"redirect_uri={mistral.REDIRECT_URI.replace(':', '%3A').replace('/', '%2F')}" in url
    assert "nonce=" in url


def test_post_form_returns_parsed_body() -> None:
    resp = mock.MagicMock()
    resp.status_code = 200
    resp.content = b'{"access_token": "tok"}'
    resp.__enter__.return_value = resp

    with mock.patch.object(requests, "post", return_value=resp) as post:
        data = mistral._post_form({"grant_type": "refresh_token"})

    assert data == {"access_token": "tok"}
    assert post.call_args.kwargs["timeout"] == mistral._TOKEN_TIMEOUT
    # Public client: no client secret is ever sent to the token endpoint.
    assert "client_secret" not in post.call_args.kwargs["data"]


def test_exchange_code_posts_pkce_and_redirect() -> None:
    id_exp = time.time() + 900
    id_token = _fake_jwt("sub-1", exp=id_exp)
    resp = _http_response(
        {
            "access_token": "ory_at_opaque",
            "refresh_token": "r1",
            "id_token": id_token,
            "expires_in": 3600,
        }
    )

    with (
        mock.patch.object(requests, "post", return_value=resp) as post,
        mock.patch.object(requests, "get", return_value=_http_response(_WORKSPACES)) as get,
    ):
        record = mistral.exchange_code("the-code", "the-verifier")

    payload = post.call_args.kwargs["data"]
    assert payload["grant_type"] == "authorization_code"
    assert payload["client_id"] == mistral.CLIENT_ID
    assert payload["code"] == "the-code"
    assert payload["code_verifier"] == "the-verifier"
    assert payload["redirect_uri"] == mistral.REDIRECT_URI
    assert post.call_args.args[0] == mistral.TOKEN_URL
    assert record["provider"] == "mistral"
    assert record["account_id"] == "sub-1"
    assert record["refresh"] == "r1"
    # The API authenticates the ID token, so the record expires with it, not
    # with the longer-lived access token.
    assert record["id_token"] == id_token
    assert record["expires_at"] == id_exp
    # The tenant is discovered once at sign-in with the ID token.
    assert get.call_args.args[0] == f"{mistral.AUDIENCE}/v1/users/me/workspaces"
    assert get.call_args.kwargs["headers"] == {"Authorization": f"Bearer {id_token}"}
    assert record["organization_id"] == "org-1"
    assert record["workspace_id"] == "ws-1"


def test_exchange_code_fails_when_the_user_has_no_workspace() -> None:
    resp = _http_response(
        {"access_token": "a", "refresh_token": "r1", "id_token": _fake_jwt("sub-1")}
    )
    with (
        mock.patch.object(requests, "post", return_value=resp),
        mock.patch.object(requests, "get", return_value=_http_response({"workspaces": []})),
        pytest.raises(mistral.MistralAuthError) as exc,
    ):
        mistral.exchange_code("the-code", "the-verifier")
    assert exc.value.code == "no_workspace"


def test_token_response_without_id_token_is_rejected() -> None:
    resp = _http_response({"access_token": "a", "refresh_token": "r2", "expires_in": 3600})
    with (
        mock.patch.object(requests, "post", return_value=resp),
        pytest.raises(mistral.MistralAuthError) as exc,
    ):
        mistral.refresh_tokens("r1", "sub-1")
    assert exc.value.code == "bad_response"


def test_refresh_tokens_keeps_old_refresh_when_not_rotated() -> None:
    resp = _http_response({"access_token": "a", "id_token": _fake_jwt("sub-1"), "expires_in": 3600})

    with mock.patch.object(requests, "post", return_value=resp) as post:
        record = mistral.refresh_tokens("r-old", "sub-1")

    payload = post.call_args.kwargs["data"]
    assert payload["grant_type"] == "refresh_token"
    assert payload["refresh_token"] == "r-old"
    assert record["refresh"] == "r-old"


def test_refresh_keeps_account_id_when_response_has_no_jwt_sub() -> None:
    resp = _http_response(
        {
            "access_token": "ory_at_opaque",
            "refresh_token": "r2",
            "id_token": _fake_jwt(None),
            "expires_in": 3600,
        }
    )

    with mock.patch.object(requests, "post", return_value=resp):
        record = mistral.refresh_tokens("r1", "sub-1")

    assert record["access"] == "ory_at_opaque"
    assert record["account_id"] == "sub-1"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("http://127.0.0.1:8766/callback?code=AAA&state=BBB", ("AAA", "BBB")),
        ("AAA#BBB", ("AAA", "BBB")),
        ("code=AAA&state=BBB", ("AAA", "BBB")),
        ("AAA", ("AAA", None)),
        ("", (None, None)),
    ],
)
def test_parse_redirect_input(value: str, expected: tuple[str | None, str | None]) -> None:
    assert mistral.parse_redirect_input(value) == expected


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        ("lechat/mistral-large-latest", "mistral-large-latest"),
        ("LeChat/Mistral-Large", "Mistral-Large"),
        ("  lechat/devstral-latest  ", "devstral-latest"),
        ("mistral/mistral-large-latest", None),  # LiteLLM's API-key provider
        ("chatgpt/gpt-5.4", "gpt-5.4"),
        ("lechat/", None),
        ("", None),
        (None, None),
    ],
)
def test_subscription_slug(model: str | None, expected: str | None) -> None:
    assert subscriptions.subscription_slug(model) == expected


def test_registry_maps_prefixes_and_names_to_providers() -> None:
    found = subscriptions.subscription_for("lechat/mistral-large-latest")
    assert found == (subscriptions.MISTRAL, "mistral-large-latest")
    assert subscriptions.subscription_for("chatgpt/gpt-5.4") == (subscriptions.CHATGPT, "gpt-5.4")
    assert subscriptions.subscription_for("openai/gpt-5.4") is None
    assert subscriptions.auth_mode("lechat/mistral-large-latest") == "subscription"
    assert subscriptions.auth_mode("mistral/mistral-large-latest") == "api_key"
    assert subscriptions.subscription_label("lechat/mistral-large-latest") == "Mistral subscription"
    assert subscriptions.subscription_label("chatgpt/gpt-5.4") == "ChatGPT subscription"
    assert subscriptions.by_name("Mistral") is subscriptions.MISTRAL
    assert subscriptions.by_name("codex") is subscriptions.CHATGPT
    assert subscriptions.by_name("gemini") is None


def test_account_id_from_jwt_reads_sub() -> None:
    assert mistral._account_id_from_jwt(_fake_jwt("sub-42")) == "sub-42"
    assert mistral._account_id_from_jwt("not-a-jwt") is None
    assert mistral._account_id_from_jwt("") is None


def test_store_roundtrip_logout_and_codex_coexistence() -> None:
    assert mistral.read_record() is None
    assert mistral.is_authenticated() is False

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
            "access": _fake_jwt("sub-42"),
            "refresh": "r1",
            "account_id": "sub-42",
            "expires_at": time.time() + 3600,
        }
    )
    # Both providers live in the same store file, keyed by provider.
    assert mistral.read_record() is not None
    assert mistral.read_record()["account_id"] == "sub-42"
    assert codex.read_record() is not None
    assert mistral.is_authenticated() is True

    mistral.logout()
    assert mistral.read_record() is None
    assert codex.read_record() is not None  # codex record survives
    mistral.logout()  # no-op when already gone

    codex.logout()
    assert codex.read_record() is None


def test_read_record_rejects_incomplete_records() -> None:
    mistral.save_record({"type": "oauth", "access": "a"})  # missing refresh/account
    assert mistral.read_record() is None
    assert mistral.is_authenticated() is False


def _no_refresh(_payload: dict[str, str]) -> dict[str, Any]:
    msg = "must not refresh"
    raise AssertionError(msg)


def test_request_headers_send_the_id_token_and_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mistral, "_post_form", _no_refresh)
    mistral.save_record(_record())
    assert mistral.request_headers() == {
        "Authorization": "Bearer id-fresh",
        "x-external-organization-id": "org-1",
        "x-external-workspace-id": "ws-1",
    }


def test_request_headers_refresh_and_keep_the_known_tenant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"n": 0}
    new_id = _fake_jwt("sub-42", exp=time.time() + 900)

    def _fake_post(payload: dict[str, str]) -> dict[str, Any]:
        calls["n"] += 1
        assert payload["grant_type"] == "refresh_token"
        assert payload["refresh_token"] == "r1"
        return {"access_token": "a2", "refresh_token": "r2", "id_token": new_id}

    monkeypatch.setattr(mistral, "_post_form", _fake_post)
    mistral.save_record(_record(id_token="id-stale", expires_at=time.time() - 10))

    with mock.patch.object(requests, "get", side_effect=AssertionError("no rediscovery")):
        headers = mistral.request_headers()

    assert calls["n"] == 1
    assert headers["Authorization"] == f"Bearer {new_id}"
    assert headers["x-external-organization-id"] == "org-1"
    record = mistral.read_record()
    assert record is not None
    assert record["refresh"] == "r2"
    assert record["workspace_id"] == "ws-1"


def test_record_without_id_token_is_upgraded_on_first_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    new_id = _fake_jwt("sub-42", exp=time.time() + 900)
    monkeypatch.setattr(
        mistral,
        "_post_form",
        lambda _payload: {"access_token": "a2", "refresh_token": "r2", "id_token": new_id},
    )
    legacy = _record(expires_at=time.time() + 3600)
    for key in ("id_token", "organization_id", "workspace_id"):
        del legacy[key]
    mistral.save_record(legacy)
    assert mistral.is_authenticated() is True

    with mock.patch.object(requests, "get", return_value=_http_response(_WORKSPACES)):
        headers = mistral.request_headers()

    assert headers == {
        "Authorization": f"Bearer {new_id}",
        "x-external-organization-id": "org-1",
        "x-external-workspace-id": "ws-1",
    }


def test_request_headers_use_token_rotated_by_another_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = [
        _record(id_token="id-stale", expires_at=time.time() - 10),
        _record(id_token="id-from-other-process", refresh="r2"),
    ]
    calls = {"n": 0}

    def _fake_read() -> dict[str, Any]:
        record = records[min(calls["n"], len(records) - 1)]
        calls["n"] += 1
        return record

    monkeypatch.setattr(mistral, "read_record", _fake_read)
    monkeypatch.setattr(mistral, "_post_form", _no_refresh)

    assert mistral.request_headers()["Authorization"] == "Bearer id-from-other-process"


def test_request_headers_recover_when_refresh_loses_race(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mistral.save_record(_record(id_token="id-stale", expires_at=time.time() - 10))

    def _fake_post(_payload: dict[str, str]) -> dict[str, Any]:
        mistral.save_record(_record(id_token="id-from-peer", refresh="r2"))
        raise mistral.MistralAuthError("token_http_error", "HTTP 400: invalid_grant")

    monkeypatch.setattr(mistral, "_post_form", _fake_post)
    assert mistral.request_headers()["Authorization"] == "Bearer id-from-peer"


def test_request_headers_raise_when_not_signed_in() -> None:
    with pytest.raises(mistral.MistralAuthError) as exc:
        mistral.request_headers()
    assert exc.value.code == "not_authenticated"
    assert "strix auth login mistral" in str(exc.value)


@pytest.mark.asyncio
async def test_client_sends_the_subscription_headers_on_every_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[httpx.Headers] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers)
        return httpx.Response(200, json={"object": "list", "data": []})

    class _MockTransportClient(httpx.AsyncClient):
        def __init__(self, **kwargs: Any) -> None:
            super().__init__(transport=httpx.MockTransport(_handler), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _MockTransportClient)
    monkeypatch.setattr(mistral, "_post_form", _no_refresh)
    mistral.save_record(_record())

    client = mistral.build_mistral_client()
    await client.models.list()

    assert seen[0]["authorization"] == "Bearer id-fresh"
    assert seen[0]["x-external-organization-id"] == "org-1"
    assert seen[0]["x-external-workspace-id"] == "ws-1"

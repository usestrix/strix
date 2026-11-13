"""Mistral subscription auth: OIDC login, token refresh, and the OpenAI-compatible
client that routes inference through ``api.mistral.ai`` with a Bearer token.

Mirrors the ChatGPT (Codex) path in ``strix.config.codex``, but against Mistral's
OIDC issuer ``auth.mistral.ai``: OAuth 2.0 + PKCE as a public client (token auth
method ``none``), with the ``audience`` parameter naming the API the access token
is minted for. The OAuth constants are the public CLI client registration shared
with Mistral's own CLI (the issuer only accepts registered clients). Using a
Mistral subscription through this path is the supported way to call
``api.mistral.ai`` with subscription credentials.

The API authenticates the OIDC ID token, not the access token, and needs the
caller's organization and workspace in ``x-external-*`` headers (as Mistral's
CLI sends them). The tenant is discovered once with the ID token at sign-in.
"""

from __future__ import annotations

import base64
import contextlib
import json
import logging
import secrets
import threading
import time
import urllib.parse
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import requests

from strix.config import codex
from strix.utils.secret_files import write_secret_text


if TYPE_CHECKING:
    from collections.abc import Iterator

    from openai import AsyncOpenAI


logger = logging.getLogger(__name__)


PROVIDER = "mistral"

ISSUER = "https://auth.mistral.ai"
AUTHORIZE_URL = f"{ISSUER}/oauth2/auth"
TOKEN_URL = "https://auth.mistral.ai/oauth2/token"  # noqa: S105  # nosec B105 - URL, not a secret
# Public CLI client registration (issuer enforces the registered redirect URI;
# loopback ports are flexible, the path is not).
CLIENT_ID = "829da7e7-628f-4795-829a-8cca609c76d4"
AUDIENCE = "https://api.mistral.ai"
CALLBACK_HOST = "127.0.0.1"
CALLBACK_PORT = 8766
CALLBACK_PATH = "/callback"
REDIRECT_URI = f"http://{CALLBACK_HOST}:{CALLBACK_PORT}{CALLBACK_PATH}"
SCOPE = "openid profile email offline_access"

API_BASE = "https://api.mistral.ai/v1"

_TOKEN_TIMEOUT = 30
_EXPIRY_SKEW_S = 300

_refresh_lock = threading.Lock()

# Kept separate from cli-config.json so OAuth tokens never land in the env-var config.
# Shared with the Codex provider: records are keyed by PROVIDER.
AUTH_PATH = Path.home() / ".strix" / "subscription-auth.json"


def _read_store() -> dict[str, Any]:
    try:
        data = json.loads(AUTH_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_store(data: dict[str, Any]) -> None:
    write_secret_text(AUTH_PATH, json.dumps(data, indent=2))


def read_record() -> dict[str, Any] | None:
    record = _read_store().get(PROVIDER)
    if not isinstance(record, dict) or record.get("type") != "oauth":
        return None
    if not (record.get("access") and record.get("refresh") and record.get("account_id")):
        return None
    return record


def is_authenticated() -> bool:
    return read_record() is not None


def save_record(record: dict[str, Any]) -> None:
    data = _read_store()
    data[PROVIDER] = record
    _write_store(data)


def logout() -> None:
    data = _read_store()
    if PROVIDER not in data:
        return
    del data[PROVIDER]
    if data:
        _write_store(data)
        return
    with contextlib.suppress(OSError):
        AUTH_PATH.unlink()


@contextlib.contextmanager
def _refresh_guard() -> Iterator[None]:
    """Serialize token refresh within (lock) and across (flock) Strix processes,
    so concurrent runs can't both spend the single-use refresh token."""
    with _refresh_lock:
        try:
            import fcntl

            lock_path = AUTH_PATH.with_suffix(".lock")
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            handle = lock_path.open("w")
        except (ImportError, OSError):
            yield
            return
        try:
            with contextlib.suppress(OSError):
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()


class MistralAuthError(Exception):
    def __init__(self, code: str, message: str | None = None) -> None:
        self.code = code
        super().__init__(message or code)


# PKCE, state and redirect parsing are plain OAuth, shared with the ChatGPT flow.
generate_pkce = codex.generate_pkce
create_state = codex.create_state
parse_redirect_input = codex.parse_redirect_input


def build_authorize_url(challenge: str, state: str) -> str:
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        # Mints the access token for the API audience; the issuer (Ory Hydra)
        # takes it on the authorization request, not the token exchange.
        "audience": AUDIENCE,
        "nonce": secrets.token_hex(16),
    }
    return f"{AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"


def _post_form(payload: dict[str, str]) -> dict[str, Any]:
    detail = ""
    try:
        with requests.post(
            TOKEN_URL,
            data=payload,
            headers={"Accept": "application/json"},
            timeout=_TOKEN_TIMEOUT,
        ) as response:
            status_code = response.status_code
            body = response.content
            if status_code >= 400:
                detail = response.text[:300]
    except requests.RequestException as exc:
        raise MistralAuthError("unavailable", str(exc)) from exc
    if status_code >= 400:
        raise MistralAuthError("token_http_error", f"HTTP {status_code}: {detail}")
    data = json.loads(body or b"{}")
    if not isinstance(data, dict):
        raise MistralAuthError("bad_response", "token endpoint returned non-object")
    return data


def _record_from_token_response(
    data: dict[str, Any],
    refresh_fallback: str | None = None,
    account_fallback: str | None = None,
) -> dict[str, Any]:
    access = data.get("access_token")
    # A refresh response may omit refresh_token when it isn't rotated; keep the old one.
    refresh = data.get("refresh_token") or refresh_fallback
    id_token = data.get("id_token")
    expires_in = data.get("expires_in")
    if not isinstance(access, str) or not access:
        raise MistralAuthError("bad_response", "token response missing access_token")
    if not isinstance(refresh, str) or not refresh:
        raise MistralAuthError("bad_response", "token response missing refresh_token")
    if not isinstance(id_token, str) or not id_token:
        raise MistralAuthError("bad_response", "token response missing id_token")
    # Hydra access tokens are opaque, and an ID token may lack sub, so a
    # refresh keeps the account id it already had.
    account_id = _account_id_from_jwt(access) or _account_id_from_jwt(id_token) or account_fallback
    if not account_id:
        raise MistralAuthError("no_account_id", "could not read sub from token")
    # The ID token is the API credential and outlives neither the access token
    # nor its own exp claim.
    id_exp = _jwt_claims(id_token).get("exp")
    ttl = expires_in if isinstance(expires_in, int | float) else 3600
    expires_at = id_exp if isinstance(id_exp, int | float) else time.time() + ttl
    return {
        "type": "oauth",
        "provider": PROVIDER,
        "access": access,
        "refresh": refresh,
        "id_token": id_token,
        "account_id": account_id,
        "expires_at": expires_at,
    }


def _discover_tenant(id_token: str) -> dict[str, str]:
    """The first workspace the user belongs to, the one Mistral's CLI picks by default."""
    try:
        with requests.get(
            f"{AUDIENCE}/v1/users/me/workspaces",
            params={"limit": 1},
            headers={"Authorization": f"Bearer {id_token}"},
            timeout=_TOKEN_TIMEOUT,
        ) as response:
            status_code = response.status_code
            body = response.content
            detail = response.text[:300] if status_code >= 400 else ""
    except requests.RequestException as exc:
        raise MistralAuthError("unavailable", str(exc)) from exc
    if status_code >= 400:
        raise MistralAuthError("workspace_http_error", f"HTTP {status_code}: {detail}")
    data: Any = json.loads(body or b"{}")
    workspaces: Any = data.get("workspaces") if isinstance(data, dict) else None
    if not isinstance(workspaces, list) or not workspaces or not isinstance(workspaces[0], dict):
        raise MistralAuthError("no_workspace", "this Mistral account has no workspace")
    workspace = cast("dict[str, Any]", workspaces[0])
    return {
        "organization_id": str(workspace.get("organization_id") or ""),
        "workspace_id": str(workspace.get("id") or ""),
    }


def _with_tenant(record: dict[str, Any], previous: dict[str, Any] | None = None) -> dict[str, Any]:
    if previous and previous.get("organization_id"):
        tenant = {
            "organization_id": previous["organization_id"],
            "workspace_id": previous.get("workspace_id", ""),
        }
    else:
        tenant = _discover_tenant(record["id_token"])
    return {**record, **tenant}


def exchange_code(code: str, verifier: str) -> dict[str, Any]:
    data = _post_form(
        {
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": REDIRECT_URI,
        }
    )
    return _with_tenant(_record_from_token_response(data))


def refresh_tokens(refresh_token: str, account_id: str) -> dict[str, Any]:
    data = _post_form(
        {
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "refresh_token": refresh_token,
        }
    )
    return _record_from_token_response(
        data, refresh_fallback=refresh_token, account_fallback=account_id
    )


def _jwt_claims(token: str | None) -> dict[str, Any]:
    """Read JWT claims without verifying the signature (the server enforces
    authenticity on use); they only label the account and time the refresh."""
    if not token or token.count(".") != 2:
        return {}
    payload_b64 = token.split(".")[1]
    padding = "=" * (-len(payload_b64) % 4)
    try:
        payload: Any = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
    except (ValueError, json.JSONDecodeError):
        return {}
    return cast("dict[str, Any]", payload) if isinstance(payload, dict) else {}


def _account_id_from_jwt(token: str | None) -> str | None:
    sub = _jwt_claims(token).get("sub")
    return sub if isinstance(sub, str) and sub else None


def _near_expiry(record: dict[str, Any]) -> bool:
    expires_at = record.get("expires_at")
    if not isinstance(expires_at, int | float):
        return True
    return expires_at - _EXPIRY_SKEW_S <= time.time()


def _usable(record: dict[str, Any]) -> bool:
    # Records saved before the ID token was the API credential lack it and the
    # tenant; refreshing fills both in.
    return bool(record.get("id_token") and record.get("organization_id")) and not _near_expiry(
        record
    )


def _valid_record() -> dict[str, Any]:
    """The signed-in record, refreshed under the cross-process guard if needed."""
    record = read_record()
    if record is None:
        raise MistralAuthError("not_authenticated", "not signed in; run: strix auth login mistral")
    if _usable(record):
        return record
    with _refresh_guard():
        record = read_record()
        if record is None:
            raise MistralAuthError(
                "not_authenticated", "not signed in; run: strix auth login mistral"
            )
        if _usable(record):
            return record
        try:
            refreshed = refresh_tokens(record["refresh"], record["account_id"])
        except MistralAuthError:
            # A peer process may have already spent this single-use refresh token.
            latest = read_record()
            if latest and latest["refresh"] != record["refresh"] and _usable(latest):
                return latest
            raise
        refreshed = _with_tenant(refreshed, record)
        save_record(refreshed)
        return refreshed


def request_headers() -> dict[str, str]:
    """The headers ``api.mistral.ai`` authenticates a subscription request by."""
    record = _valid_record()
    headers = {
        "Authorization": f"Bearer {record['id_token']}",
        "x-external-organization-id": record["organization_id"],
    }
    if record.get("workspace_id"):
        headers["x-external-workspace-id"] = record["workspace_id"]
    return headers


def build_mistral_client() -> AsyncOpenAI:
    """An ``AsyncOpenAI`` for ``api.mistral.ai``. A per-request hook re-stamps a
    fresh bearer token so long scans survive token expiry."""
    import asyncio

    import httpx
    from openai import AsyncOpenAI

    from strix.llm import request_log

    request_headers()  # fail fast at configure time if the sign-in is dead

    async def _auth_hook(request: httpx.Request) -> None:
        request.headers.update(await asyncio.to_thread(request_headers))

    http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(600.0, connect=30.0),
        event_hooks={"request": [_auth_hook]},
    )
    request_log.observe_http_client(http_client)
    return AsyncOpenAI(
        api_key="strix-mistral-oauth",  # placeholder; the hook overwrites Authorization
        base_url=API_BASE,
        http_client=http_client,
    )


_subscription_client: AsyncOpenAI | None = None


def get_subscription_client() -> AsyncOpenAI:
    global _subscription_client  # noqa: PLW0603
    if _subscription_client is None:
        _subscription_client = build_mistral_client()
    return _subscription_client


# Not ``mistral/``: that is LiteLLM's Mistral API-key provider, which keeps working.
SUBSCRIPTION_PREFIX = "lechat/"

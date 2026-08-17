"""Grok (xAI) subscription auth: OAuth login, token refresh, and the OpenAI
client that routes inference through xAI's API.

Mirrors xAI's Grok CLI: OAuth 2.0 + PKCE against ``auth.x.ai``, with the access
token sent as a ``Bearer`` token to ``api.x.ai/v1`` (OpenAI-compatible, so the
subscription and a metered API key share one endpoint — only the bearer differs).
Using a Grok/SuperGrok subscription outside xAI's own products is not officially
supported by xAI; the user chooses this path knowingly. The OAuth constants are
xAI's own Grok CLI values (the backend only accepts that client).
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import logging
import secrets
import time
import urllib.parse
from pathlib import Path
from typing import TYPE_CHECKING, Any

import requests

from strix.config import subscription_store


if TYPE_CHECKING:
    from collections.abc import Iterator

    from openai import AsyncOpenAI


logger = logging.getLogger(__name__)


PROVIDER = "grok"

CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
AUTHORIZE_URL = "https://auth.x.ai/oauth2/authorize"
TOKEN_URL = "https://auth.x.ai/oauth2/token"  # noqa: S105  # nosec B105 - URL, not a secret
CALLBACK_HOST = "127.0.0.1"
CALLBACK_PORT = 56121
CALLBACK_PATH = "/callback"
REDIRECT_URI = f"http://{CALLBACK_HOST}:{CALLBACK_PORT}{CALLBACK_PATH}"
SCOPE = "openid profile email offline_access grok-cli:access api:access"

XAI_BASE_URL = "https://api.x.ai/v1"

_TOKEN_TIMEOUT = 30
_EXPIRY_SKEW_S = 300

# Shared with the other subscription providers; kept separate from cli-config.json
# so OAuth tokens never land in the env-var config.
AUTH_PATH = Path.home() / ".strix" / "subscription-auth.json"


def read_record() -> dict[str, Any] | None:
    record = subscription_store.read(AUTH_PATH).get(PROVIDER)
    if not isinstance(record, dict) or record.get("type") != "oauth":
        return None
    if not (record.get("access") and record.get("refresh")):
        return None
    return record


def is_authenticated() -> bool:
    return read_record() is not None


def save_record(record: dict[str, Any]) -> None:
    with subscription_store.guard(AUTH_PATH):
        data = subscription_store.read(AUTH_PATH)
        data[PROVIDER] = record
        subscription_store.write(AUTH_PATH, data)


def logout() -> None:
    with subscription_store.guard(AUTH_PATH):
        data = subscription_store.read(AUTH_PATH)
        if PROVIDER not in data:
            return
        del data[PROVIDER]
        if data:
            subscription_store.write(AUTH_PATH, data)
            return
        with contextlib.suppress(OSError):
            AUTH_PATH.unlink()


@contextlib.contextmanager
def _refresh_guard() -> Iterator[None]:
    """Serialize token refresh within (lock) and across (flock) Strix processes,
    so concurrent runs can't both spend the single-use refresh token."""
    with subscription_store.guard(AUTH_PATH):
        yield


class GrokAuthError(Exception):
    def __init__(self, code: str, message: str | None = None) -> None:
        self.code = code
        super().__init__(message or code)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def generate_pkce() -> tuple[str, str]:
    verifier = _b64url(secrets.token_bytes(64))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def create_state() -> str:
    return secrets.token_hex(16)


def build_authorize_url(challenge: str, state: str) -> str:
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    return f"{AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"


def parse_redirect_input(value: str) -> tuple[str | None, str | None]:
    """Extract ``(code, state)`` from a pasted redirect URL, ``code#state``,
    query string, or bare code."""
    value = (value or "").strip()
    if not value:
        return None, None
    with contextlib.suppress(ValueError):
        parsed = urllib.parse.urlparse(value)
        if parsed.scheme and parsed.query:
            query = urllib.parse.parse_qs(parsed.query)
            return _first(query, "code"), _first(query, "state")
    if "#" in value:
        code, _, state = value.partition("#")
        return code or None, state or None
    if "code=" in value:
        query = urllib.parse.parse_qs(value)
        return _first(query, "code"), _first(query, "state")
    return value, None


def _first(query: dict[str, list[str]], key: str) -> str | None:
    values = query.get(key)
    return values[0] if values else None


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
        raise GrokAuthError("unavailable", str(exc)) from exc
    if status_code >= 400:
        raise GrokAuthError("token_http_error", f"HTTP {status_code}: {detail}")
    data = json.loads(body or b"{}")
    if not isinstance(data, dict):
        raise GrokAuthError("bad_response", "token endpoint returned non-object")
    return data


def _record_from_token_response(
    data: dict[str, Any], refresh_fallback: str | None = None
) -> dict[str, Any]:
    access = data.get("access_token")
    # A refresh response may omit refresh_token when it isn't rotated; keep the old one.
    refresh = data.get("refresh_token") or refresh_fallback
    expires_in = data.get("expires_in")
    if not isinstance(access, str) or not access:
        raise GrokAuthError("bad_response", "token response missing access_token")
    if not isinstance(refresh, str) or not refresh:
        raise GrokAuthError("bad_response", "token response missing refresh_token")
    ttl = expires_in if isinstance(expires_in, int | float) else 3600
    return {
        "type": "oauth",
        "provider": PROVIDER,
        "access": access,
        "refresh": refresh,
        "expires_at": time.time() + ttl,
    }


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
    return _record_from_token_response(data)


def refresh_tokens(refresh_token: str) -> dict[str, Any]:
    data = _post_form(
        {
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "refresh_token": refresh_token,
        }
    )
    return _record_from_token_response(data, refresh_fallback=refresh_token)


def _access_token(record: dict[str, Any]) -> str:
    access = record["access"]
    if not isinstance(access, str) or not access:
        raise GrokAuthError("bad_response", "stored access token is missing or malformed")
    return access


def _near_expiry(record: dict[str, Any]) -> bool:
    expires_at = record.get("expires_at")
    if not isinstance(expires_at, int | float):
        return True
    return expires_at - _EXPIRY_SKEW_S <= time.time()


def get_valid_token() -> str:
    """Return a valid access token, refreshing under the cross-process guard if
    near expiry."""
    record = read_record()
    if record is None:
        raise GrokAuthError("not_authenticated", "not signed in; run: strix auth login grok")
    if not _near_expiry(record):
        return _access_token(record)
    with _refresh_guard():
        record = read_record()
        if record is None:
            raise GrokAuthError("not_authenticated", "not signed in; run: strix auth login grok")
        if not _near_expiry(record):
            return _access_token(record)
        try:
            refreshed = refresh_tokens(record["refresh"])
        except GrokAuthError:
            # A peer process may have already spent this single-use refresh token.
            latest = read_record()
            if latest and latest["refresh"] != record["refresh"] and not _near_expiry(latest):
                return _access_token(latest)
            raise
        save_record(refreshed)
        return _access_token(refreshed)


def build_openai_client() -> AsyncOpenAI:
    """An ``AsyncOpenAI`` for xAI's API. A per-request hook re-stamps a fresh
    bearer token so long scans survive token expiry."""
    import asyncio

    import httpx
    from openai import AsyncOpenAI

    get_valid_token()  # fail fast at configure time if the sign-in is dead

    async def _auth_hook(request: httpx.Request) -> None:
        access = await asyncio.to_thread(get_valid_token)
        request.headers["Authorization"] = f"Bearer {access}"

    http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(600.0, connect=30.0),
        event_hooks={"request": [_auth_hook]},
    )
    return AsyncOpenAI(
        api_key="strix-grok-oauth",  # placeholder; the hook overwrites Authorization
        base_url=XAI_BASE_URL,
        http_client=http_client,
    )


_subscription_client: AsyncOpenAI | None = None


def get_subscription_client() -> AsyncOpenAI:
    global _subscription_client  # noqa: PLW0603
    if _subscription_client is None:
        _subscription_client = build_openai_client()
    return _subscription_client


SUBSCRIPTION_PREFIX = "grok/"


def subscription_model(model_name: str | None) -> str | None:
    """The model slug behind a ``grok/<model>`` STRIX_LLM, or None."""
    name = (model_name or "").strip()
    if not name.lower().startswith(SUBSCRIPTION_PREFIX):
        return None
    return name[len(SUBSCRIPTION_PREFIX) :] or None


def auth_mode(model_name: str | None) -> str:
    return "subscription" if subscription_model(model_name) else "api_key"

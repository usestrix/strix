"""Claude (Anthropic) subscription auth: OAuth login, token refresh, and the
OAuth access token that routes inference through a Claude Pro/Max plan.

Mirrors Claude Code's sign-in: OAuth 2.0 + PKCE against Anthropic, with the
resulting ``sk-ant-oat…`` access token sent as a ``Bearer`` token to the Messages
API. LiteLLM already special-cases that token prefix (``ANTHROPIC_OAUTH_TOKEN_PREFIX``)
and switches to ``Authorization: Bearer`` plus the ``oauth-2025-04-20`` beta header,
so a ``claude/<model>`` STRIX_LLM only has to hand LiteLLM a fresh access token.

Using a Claude subscription outside Anthropic's own products is not officially
supported by Anthropic; the user chooses this path knowingly. The OAuth constants
are Claude Code's own public client values (the backend only accepts that client),
and are reverse-engineered rather than documented — verify them against a live
sign-in before relying on this path.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import logging
import secrets
import threading
import time
import urllib.parse
from pathlib import Path
from typing import TYPE_CHECKING, Any

import requests

from strix.utils.secret_files import write_secret_text


if TYPE_CHECKING:
    from collections.abc import Iterator


logger = logging.getLogger(__name__)


PROVIDER = "claude"

# Claude Code's public OAuth client. Reverse-engineered, not documented by Anthropic.
CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
AUTHORIZE_URL = "https://claude.ai/oauth/authorize"
TOKEN_URL = "https://console.anthropic.com/v1/oauth/token"  # noqa: S105 # nosec B105 - URL
# The public client registers the console callback, which renders ``code#state``
# for the user to copy. There is no loopback redirect, so sign-in is manual paste.
REDIRECT_URI = "https://console.anthropic.com/oauth/code/callback"
SCOPE = "org:create_api_key user:profile user:inference"

_TOKEN_TIMEOUT = 30
_EXPIRY_SKEW_S = 300

_refresh_lock = threading.Lock()

# Shared with the ChatGPT (codex) path, keyed by provider so both can coexist.
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
    if not (record.get("access") and record.get("refresh")):
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

            lock_path = AUTH_PATH.with_suffix(".claude.lock")
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


class ClaudeAuthError(Exception):
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
        "code": "true",
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


def _post_json(payload: dict[str, str]) -> dict[str, Any]:
    detail = ""
    try:
        with requests.post(
            TOKEN_URL,
            json=payload,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            timeout=_TOKEN_TIMEOUT,
        ) as response:
            status_code = response.status_code
            body = response.content
            if status_code >= 400:
                detail = response.text[:300]
    except requests.RequestException as exc:
        raise ClaudeAuthError("unavailable", str(exc)) from exc
    if status_code >= 400:
        raise ClaudeAuthError("token_http_error", f"HTTP {status_code}: {detail}")
    data = json.loads(body or b"{}")
    if not isinstance(data, dict):
        raise ClaudeAuthError("bad_response", "token endpoint returned non-object")
    return data


def _record_from_token_response(
    data: dict[str, Any], refresh_fallback: str | None = None
) -> dict[str, Any]:
    access = data.get("access_token")
    # A refresh response may omit refresh_token when it isn't rotated; keep the old one.
    refresh = data.get("refresh_token") or refresh_fallback
    expires_in = data.get("expires_in")
    if not isinstance(access, str) or not access:
        raise ClaudeAuthError("bad_response", "token response missing access_token")
    if not isinstance(refresh, str) or not refresh:
        raise ClaudeAuthError("bad_response", "token response missing refresh_token")
    ttl = expires_in if isinstance(expires_in, int | float) else 3600
    account = data.get("account")
    account_label = account.get("email_address") if isinstance(account, dict) else None
    return {
        "type": "oauth",
        "provider": PROVIDER,
        "access": access,
        "refresh": refresh,
        "account_label": account_label,
        "expires_at": time.time() + ttl,
    }


def exchange_code(code: str, verifier: str, state: str | None = None) -> dict[str, Any]:
    payload = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": REDIRECT_URI,
    }
    if state:
        payload["state"] = state
    return _record_from_token_response(_post_json(payload))


def refresh_tokens(refresh_token: str) -> dict[str, Any]:
    data = _post_json(
        {
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "refresh_token": refresh_token,
        }
    )
    return _record_from_token_response(data, refresh_fallback=refresh_token)


def _near_expiry(record: dict[str, Any]) -> bool:
    expires_at = record.get("expires_at")
    if not isinstance(expires_at, int | float):
        return True
    return expires_at - _EXPIRY_SKEW_S <= time.time()


def _access(record: dict[str, Any]) -> str:
    access = record["access"]
    if not isinstance(access, str) or not access:
        raise ClaudeAuthError("bad_record", "stored access token is malformed")
    return access


def get_valid_token() -> str:
    """Return a valid OAuth access token, refreshing under the cross-process
    guard if near expiry."""
    record = read_record()
    if record is None:
        raise ClaudeAuthError("not_authenticated", "not signed in; run: strix auth login claude")
    if not _near_expiry(record):
        return _access(record)
    with _refresh_guard():
        record = read_record()
        if record is None:
            raise ClaudeAuthError(
                "not_authenticated", "not signed in; run: strix auth login claude"
            )
        if not _near_expiry(record):
            return _access(record)
        try:
            refreshed = refresh_tokens(record["refresh"])
        except ClaudeAuthError:
            # A peer process may have already spent this single-use refresh token.
            latest = read_record()
            if latest and latest["refresh"] != record["refresh"] and not _near_expiry(latest):
                return _access(latest)
            raise
        save_record(refreshed)
        return _access(refreshed)


def oauth_api_key() -> str:
    """The current OAuth access token, for LiteLLM's ``anthropic`` route.

    LiteLLM detects the ``sk-ant-oat`` prefix and sends it as a bearer token with
    the OAuth beta header, so it is passed as the ``api_key``, not ``x-api-key``.
    """
    return get_valid_token()


SUBSCRIPTION_PREFIX = "claude/"


def subscription_model(model_name: str | None) -> str | None:
    """The model slug behind a ``claude/<model>`` STRIX_LLM, or None."""
    name = (model_name or "").strip()
    if not name.lower().startswith(SUBSCRIPTION_PREFIX):
        return None
    return name[len(SUBSCRIPTION_PREFIX) :] or None


def auth_mode(model_name: str | None) -> str:
    return "subscription" if subscription_model(model_name) else "api_key"

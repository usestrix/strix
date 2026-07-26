"""ChatGPT (Codex) subscription auth: OAuth login, token refresh, and the OpenAI
client that routes inference through the ChatGPT backend.

Mirrors OpenAI's Codex CLI: OAuth 2.0 + PKCE against ``auth.openai.com``, with the
access token sent as a ``Bearer`` token to ``chatgpt.com/backend-api/codex``. Using
a ChatGPT subscription outside OpenAI's own products is not officially supported by
OpenAI; the user chooses this path knowingly. The OAuth constants are OpenAI's own
Codex CLI values (the backend only accepts that client).
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
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from collections.abc import Iterator

    from openai import AsyncOpenAI


logger = logging.getLogger(__name__)


PROVIDER = "codex"

CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
AUTHORIZE_URL = "https://auth.openai.com/oauth/authorize"
TOKEN_URL = "https://auth.openai.com/oauth/token"  # noqa: S105  # nosec B105 - URL, not a secret
CALLBACK_HOST = "localhost"
CALLBACK_PORT = 1455
CALLBACK_PATH = "/auth/callback"
REDIRECT_URI = f"http://{CALLBACK_HOST}:{CALLBACK_PORT}{CALLBACK_PATH}"
SCOPE = "openid profile email offline_access"

CODEX_BASE_URL = "https://chatgpt.com/backend-api/codex"
ORIGINATOR = "codex_cli_rs"
_ACCOUNT_CLAIM = "https://api.openai.com/auth"

_TOKEN_TIMEOUT = 30
_EXPIRY_SKEW_S = 300

_refresh_lock = threading.Lock()

# Kept separate from cli-config.json so OAuth tokens never land in the env-var config.
AUTH_PATH = Path.home() / ".strix" / "subscription-auth.json"


def _read_store() -> dict[str, Any]:
    try:
        data = json.loads(AUTH_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_store(data: dict[str, Any]) -> None:
    AUTH_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = AUTH_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    with contextlib.suppress(OSError):
        tmp.chmod(0o600)
    tmp.replace(AUTH_PATH)
    with contextlib.suppress(OSError):
        AUTH_PATH.chmod(0o600)


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


class CodexAuthError(Exception):
    def __init__(self, code: str, message: str | None = None) -> None:
        self.code = code
        super().__init__(message or code)


class CodexContentGuardrailError(Exception):
    """The ChatGPT backend refused a request via its content guardrail.
    Terminal — retrying identical content never clears the block."""

    def __init__(self, model: str, original: BaseException | None = None) -> None:
        self.model = model
        self.original = original
        super().__init__(
            f"'{model}' was blocked by ChatGPT's content guardrails "
            f"(flagged as a possible cybersecurity risk). "
            f"Set STRIX_LLM to a model that isn't blocked and re-run."
        )


_GUARDRAIL_MARKERS = (
    "flagged for possible cybersecurity risk",
    "trusted access for cyber",
)


def is_content_guardrail_error(exc: BaseException) -> bool:
    if isinstance(exc, CodexContentGuardrailError):
        return True
    text = str(exc).lower()
    return any(marker in text for marker in _GUARDRAIL_MARKERS)


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
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
        "originator": ORIGINATOR,
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
    body = urllib.parse.urlencode(payload).encode("ascii")
    request = urllib.request.Request(  # noqa: S310 - fixed https OAuth endpoint
        TOKEN_URL,
        data=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(  # noqa: S310  # nosec B310 - fixed https endpoint
            request, timeout=_TOKEN_TIMEOUT
        ) as response:
            data = json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise CodexAuthError("token_http_error", f"HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CodexAuthError("unavailable", str(exc)) from exc
    if not isinstance(data, dict):
        raise CodexAuthError("bad_response", "token endpoint returned non-object")
    return data


def _record_from_token_response(
    data: dict[str, Any], refresh_fallback: str | None = None
) -> dict[str, Any]:
    access = data.get("access_token")
    # A refresh response may omit refresh_token when it isn't rotated; keep the old one.
    refresh = data.get("refresh_token") or refresh_fallback
    expires_in = data.get("expires_in")
    if not isinstance(access, str) or not access:
        raise CodexAuthError("bad_response", "token response missing access_token")
    if not isinstance(refresh, str) or not refresh:
        raise CodexAuthError("bad_response", "token response missing refresh_token")
    account_id = _account_id_from_jwt(access) or _account_id_from_jwt(
        data.get("id_token") if isinstance(data.get("id_token"), str) else ""
    )
    if not account_id:
        raise CodexAuthError("no_account_id", "could not read chatgpt_account_id from token")
    ttl = expires_in if isinstance(expires_in, int | float) else 3600
    return {
        "type": "oauth",
        "provider": PROVIDER,
        "access": access,
        "refresh": refresh,
        "account_id": account_id,
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


def _account_id_from_jwt(token: str | None) -> str | None:
    """Read the account id claim without verifying the JWT (the server enforces
    authenticity on use); it feeds the ``chatgpt-account-id`` header."""
    if not token or token.count(".") != 2:
        return None
    payload_b64 = token.split(".")[1]
    padding = "=" * (-len(payload_b64) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    auth = payload.get(_ACCOUNT_CLAIM)
    if isinstance(auth, dict):
        account_id = auth.get("chatgpt_account_id")
        if isinstance(account_id, str) and account_id:
            return account_id
    organizations = payload.get("organizations")
    if isinstance(organizations, list) and organizations and isinstance(organizations[0], dict):
        org_id = organizations[0].get("id")
        if isinstance(org_id, str) and org_id:
            return org_id
    return None


def _near_expiry(record: dict[str, Any]) -> bool:
    expires_at = record.get("expires_at")
    if not isinstance(expires_at, int | float):
        return True
    return expires_at - _EXPIRY_SKEW_S <= time.time()


def get_valid_token() -> tuple[str, str]:
    """Return ``(access_token, account_id)``, refreshing under the cross-process
    guard if near expiry."""
    record = read_record()
    if record is None:
        raise CodexAuthError("not_authenticated", "not signed in; run: strix auth login")
    if not _near_expiry(record):
        return record["access"], record["account_id"]
    with _refresh_guard():
        record = read_record()
        if record is None:
            raise CodexAuthError("not_authenticated", "not signed in; run: strix auth login")
        if not _near_expiry(record):
            return record["access"], record["account_id"]
        try:
            refreshed = refresh_tokens(record["refresh"])
        except CodexAuthError:
            # A peer process may have already spent this single-use refresh token.
            latest = read_record()
            if latest and latest["refresh"] != record["refresh"] and not _near_expiry(latest):
                return latest["access"], latest["account_id"]
            raise
        save_record(refreshed)
        return refreshed["access"], refreshed["account_id"]


def build_openai_client() -> AsyncOpenAI:
    """An ``AsyncOpenAI`` for the ChatGPT backend. A per-request hook re-stamps a
    fresh bearer token so long scans survive token expiry."""
    import asyncio

    import httpx
    from openai import AsyncOpenAI

    get_valid_token()  # fail fast at configure time if the sign-in is dead

    async def _auth_hook(request: httpx.Request) -> None:
        access, account_id = await asyncio.to_thread(get_valid_token)
        request.headers["Authorization"] = f"Bearer {access}"
        request.headers["chatgpt-account-id"] = account_id

    http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(600.0, connect=30.0),
        event_hooks={"request": [_auth_hook]},
    )
    return AsyncOpenAI(
        api_key="strix-codex-oauth",  # placeholder; the hook overwrites Authorization
        base_url=CODEX_BASE_URL,
        http_client=http_client,
        default_headers={
            "OpenAI-Beta": "responses=experimental",
            "originator": ORIGINATOR,
        },
    )


_subscription_client: AsyncOpenAI | None = None


def get_subscription_client() -> AsyncOpenAI:
    global _subscription_client  # noqa: PLW0603
    if _subscription_client is None:
        _subscription_client = build_openai_client()
    return _subscription_client


SUBSCRIPTION_PREFIX = "chatgpt/"


def subscription_model(model_name: str | None) -> str | None:
    """The model slug behind a ``chatgpt/<model>`` STRIX_LLM, or None."""
    name = (model_name or "").strip()
    if not name.lower().startswith(SUBSCRIPTION_PREFIX):
        return None
    return name[len(SUBSCRIPTION_PREFIX) :] or None


def auth_mode(model_name: str | None) -> str:
    return "subscription" if subscription_model(model_name) else "api_key"

"""Microsoft Entra ID user sign-in, as an identity source for Anthropic WIF.

``strix auth login entra`` signs the user in with OAuth 2.0 + PKCE against their
own Entra tenant, as an app registration that is both the OAuth client and the
token audience (``api://<app>/user_impersonation``). The refresh token is kept in
``~/.strix/entra-auth.json``; Anthropic Workload Identity Federation then
exchanges the user's Entra access token for a short-lived Anthropic token.

Because the client and the audience are the same app, the stored refresh token
can only mint tokens for that audience -- not Microsoft Graph or Azure
management, as a refresh token issued to the Azure CLI could.
"""

from __future__ import annotations

import base64
import contextlib
import json
import logging
import threading
import time
import urllib.parse
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import requests

from strix.config.loader import load_settings
from strix.utils.secret_files import write_secret_text


if TYPE_CHECKING:
    from collections.abc import Generator


logger = logging.getLogger(__name__)


PROVIDER = "entra"

LOGIN_BASE_URL = "https://login.microsoftonline.com"
CALLBACK_HOST = "localhost"
CALLBACK_PORT = 8400
# Entra matches loopback redirects on scheme, host and path (any port), so this must
# stay the bare ``http://localhost`` registered as the app's public-client redirect.
CALLBACK_PATH = "/"
REDIRECT_URI = f"http://{CALLBACK_HOST}:{CALLBACK_PORT}"

_TOKEN_TIMEOUT = 30
_EXPIRY_SKEW_S = 300

_refresh_lock = threading.Lock()

# Kept separate from cli-config.json so OAuth tokens never land in the env-var config.
AUTH_PATH = Path.home() / ".strix" / "entra-auth.json"


class EntraAuthError(Exception):
    def __init__(self, code: str, message: str | None = None) -> None:
        self.code = code
        super().__init__(message or code)


def scope_for(app_id: str) -> str:
    return f"api://{app_id}/user_impersonation"


def configured_ids() -> tuple[str | None, str | None]:
    """``(tenant, app)`` from ``STRIX_ENTRA_TENANT_ID`` / ``STRIX_ENTRA_APP_ID``."""
    wif = load_settings().anthropic_wif
    return (wif.entra_tenant_id or "").strip() or None, (wif.entra_app_id or "").strip() or None


def read_record() -> dict[str, Any] | None:
    try:
        data = json.loads(AUTH_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    record = cast("dict[str, Any]", data)
    if record.get("provider") != PROVIDER:
        return None
    if not all(record.get(key) for key in ("tenant", "app", "access", "refresh")):
        return None
    return record


def save_record(record: dict[str, Any]) -> None:
    """Store a new sign-in, after any refresh in flight (this or another process)."""
    with _refresh_guard():
        _write_record(record)


def _write_record(record: dict[str, Any]) -> None:
    write_secret_text(AUTH_PATH, json.dumps(record, indent=2))


def is_authenticated() -> bool:
    return read_record() is not None


def logout() -> bool:
    """Delete the stored sign-in; return whether there was one.

    Waits for any refresh in flight, so the refresh can't recreate the file.
    """
    with _refresh_guard():
        existed = AUTH_PATH.exists()
        with contextlib.suppress(OSError):
            AUTH_PATH.unlink()
        return existed


def is_configured() -> bool:
    """Signed in, for the tenant and app the settings name (when they name one)."""
    record = read_record()
    if record is None:
        return False
    tenant, app = configured_ids()
    return (tenant is None or tenant == record["tenant"]) and (app is None or app == record["app"])


def build_authorize_url(tenant: str, app: str, challenge: str, state: str) -> str:
    params = {
        "client_id": app,
        "response_type": "code",
        # Query (not form_post), so a pasted redirect URL carries the code.
        "response_mode": "query",
        "redirect_uri": REDIRECT_URI,
        "scope": f"{scope_for(app)} offline_access openid profile",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        "prompt": "select_account",
    }
    return f"{_tenant_url(tenant)}/oauth2/v2.0/authorize?{urllib.parse.urlencode(params)}"


def exchange_code(tenant: str, app: str, code: str, verifier: str) -> dict[str, Any]:
    data = _post_form(
        tenant,
        {
            "grant_type": "authorization_code",
            "client_id": app,
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": REDIRECT_URI,
            "scope": f"{scope_for(app)} offline_access",
        },
    )
    return _record_from_token_response(data, tenant, app)


def refresh_tokens(record: dict[str, Any]) -> dict[str, Any]:
    data = _post_form(
        record["tenant"],
        {
            "grant_type": "refresh_token",
            "client_id": record["app"],
            "refresh_token": record["refresh"],
            "scope": f"{scope_for(record['app'])} offline_access",
        },
    )
    return _record_from_token_response(
        data,
        record["tenant"],
        record["app"],
        refresh_fallback=record["refresh"],
        username=record.get("username"),
    )


def get_valid_token() -> str:
    """A usable Entra access token, refreshed under a cross-process guard when near expiry."""
    record = _require_record()
    if not _near_expiry(record):
        return str(record["access"])
    with _refresh_guard():
        record = _require_record()
        if not _near_expiry(record):
            return str(record["access"])
        try:
            refreshed = refresh_tokens(record)
        except EntraAuthError:
            # A peer process may have refreshed (and rotated the refresh token) first.
            latest = read_record()
            if latest and latest["refresh"] != record["refresh"] and not _near_expiry(latest):
                return str(latest["access"])
            raise
        _write_record(refreshed)
        return str(refreshed["access"])


def jwt_claims(token: str | None) -> dict[str, Any]:
    """Unverified JWT payload, for display only (Entra and Anthropic verify on use)."""
    if not token or token.count(".") != 2:
        return {}
    payload = token.split(".")[1]
    try:
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except ValueError:
        return {}
    return cast("dict[str, Any]", data) if isinstance(data, dict) else {}


def _tenant_url(tenant: str) -> str:
    return f"{LOGIN_BASE_URL}/{urllib.parse.quote(tenant, safe='')}"


def _require_record() -> dict[str, Any]:
    record = read_record()
    if record is None:
        raise EntraAuthError("not_authenticated", "not signed in; run: strix auth login entra")
    return record


def _near_expiry(record: dict[str, Any]) -> bool:
    expires_at = record.get("expires_at")
    if not isinstance(expires_at, int | float):
        return True
    return expires_at - _EXPIRY_SKEW_S <= time.time()


def _post_form(tenant: str, payload: dict[str, str]) -> dict[str, Any]:
    try:
        response = requests.post(
            f"{_tenant_url(tenant)}/oauth2/v2.0/token",
            data=payload,
            headers={"Accept": "application/json"},
            timeout=_TOKEN_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise EntraAuthError("unavailable", str(exc)) from exc
    try:
        data: object = response.json()
    except ValueError:
        data = {}
    body = cast("dict[str, Any]", data) if isinstance(data, dict) else {}
    if response.status_code >= 400:
        raise EntraAuthError(str(body.get("error") or "token_http_error"), _describe_error(body))
    return body


def _describe_error(body: dict[str, Any]) -> str:
    """Entra's ``error: AADSTSxxxx: description``, without the trace and correlation lines."""
    error = str(body.get("error") or "token request failed")
    description = str(body.get("error_description") or "").strip().splitlines()
    return f"{error}: {description[0][:300]}" if description else error


def _record_from_token_response(
    data: dict[str, Any],
    tenant: str,
    app: str,
    *,
    refresh_fallback: str | None = None,
    username: str | None = None,
) -> dict[str, Any]:
    access = data.get("access_token")
    # Entra rotates refresh tokens; keep the old one if a response omits it.
    refresh = data.get("refresh_token") or refresh_fallback
    if not isinstance(access, str) or not access:
        raise EntraAuthError("bad_response", "token response missing access_token")
    if not isinstance(refresh, str) or not refresh:
        raise EntraAuthError("bad_response", "token response missing refresh_token")
    id_claims = jwt_claims(data.get("id_token") if isinstance(data.get("id_token"), str) else None)
    expires_in = data.get("expires_in")
    ttl = expires_in if isinstance(expires_in, int | float) else 3600
    return {
        "type": "oauth",
        "provider": PROVIDER,
        "tenant": tenant,
        "app": app,
        "access": access,
        "refresh": refresh,
        "username": id_claims.get("preferred_username") or username,
        "expires_at": time.time() + float(ttl),
    }


@contextlib.contextmanager
def _refresh_guard() -> Generator[None]:
    """Serialize refreshes, sign-ins and sign-outs within (lock) and across (flock)
    Strix processes. A refresh holds it from reading the record to saving the new
    one, so a login or logout can't land in between and be overwritten."""
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

"""OrcaRouter: API-key and OAuth 2.0 + PKCE sign-in, and the ``orcarouter/`` route.

`OrcaRouter <https://www.orcarouter.ai>`_ is an OpenAI-compatible gateway. A
``STRIX_LLM`` of ``orcarouter/<model id>`` (e.g. ``orcarouter/openai/gpt-5.5``)
runs through LiteLLM's OpenAI-compatible client against the OrcaRouter API.

Two ways to supply the credential, both ending in the same ordinary
``sk-orca-…`` key:

- an existing API key (``ORCAROUTER_API_KEY``, or ``LLM_API_KEY``);
- ``strix auth login orcarouter``, which runs OAuth 2.0 + PKCE in the browser and
  stores the issued key next to the ChatGPT sign-in in
  ``~/.strix/subscription-auth.json``.

The key issued by the login flow is durable: there is no refresh token and no
refresh grant. It is reused until the user revokes it; a ``401`` marks that
exact stored key as needing a new sign-in.
"""

from __future__ import annotations

import contextlib
import hmac
import ipaddress
import json
import logging
import os
import threading
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, cast

import requests

from strix.config import codex
from strix.utils.secret_files import write_secret_text


logger = logging.getLogger(__name__)


PROVIDER = "orcarouter"
MODEL_PREFIX = "orcarouter/"

DEFAULT_AUTH_BASE = "https://www.orcarouter.ai"
DEFAULT_API_BASE = "https://api.orcarouter.ai/v1"
AUTHORIZE_PATH = "/auth"
EXCHANGE_PATH = "/api/v1/auth/keys"
OOB_CALLBACK = "oob"
CALLBACK_PATH = "/callback"
SCOPE = "api"
APP_NAME = "Strix"

HOMEPAGE_URL = "https://www.orcarouter.ai"
AUTHORIZED_APPS_URL = "https://www.orcarouter.ai/console/authorized-apps"

API_KEY_ENV = "ORCAROUTER_API_KEY"
SHARED_BASE_ENV = "ORCA_BASE_URL"
AUTH_BASE_ENV = "ORCA_AUTH_BASE_URL"
API_BASE_ENV = "ORCA_API_BASE_URL"

# Credential sources, in resolution order.
SOURCE_ENV = "env"
SOURCE_LOGIN = "login"
SOURCE_LLM_API_KEY = "llm_api_key"

# Used when the live catalog is slow or unavailable, so a fresh install can
# still suggest a working model.
SEED_MODELS = (
    "openai/gpt-5.5",
    "anthropic/claude-opus-4.8",
    "google/gemini-3.5-flash",
    "deepseek/deepseek-v4-pro",
    "orcarouter/auto",
)

_EXCHANGE_TIMEOUT_S = 30
_CATALOG_TIMEOUT_S = 10
_CATALOG_MAX_BYTES = 4 * 1024 * 1024
_CATALOG_MAX_ITEMS = 2000
_MODEL_ID_MAX_LEN = 200

_store_lock = threading.Lock()


class OrcaRouterAuthError(Exception):
    def __init__(self, code: str, message: str | None = None) -> None:
        self.code = code
        super().__init__(message or code)


@dataclass(frozen=True)
class Credential:
    """An OrcaRouter API key and where it came from."""

    key: str = ""
    source: str = ""

    def __repr__(self) -> str:  # never render the key
        return f"Credential(source={self.source!r})"


# --- Model route -------------------------------------------------------------


def route_model(model_name: str | None) -> str | None:
    """The OrcaRouter model id behind an ``orcarouter/<model>`` STRIX_LLM, or None."""
    name = (model_name or "").strip()
    if not name.lower().startswith(MODEL_PREFIX):
        return None
    return name[len(MODEL_PREFIX) :] or None


def litellm_model_name(model_id: str) -> str:
    """LiteLLM's name for an OrcaRouter model: its OpenAI-compatible client."""
    return f"openai/{model_id}"


# --- Origins -----------------------------------------------------------------


def _clean_env(name: str) -> str:
    return (os.environ.get(name) or "").strip().rstrip("/")


def _require_secure_origin(url: str, env_name: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme == "https" and parsed.hostname:
        return url
    if parsed.scheme == "http" and _is_loopback(parsed.hostname):
        return url
    raise OrcaRouterAuthError(
        "insecure_origin",
        f"{env_name} must be an https:// URL (http:// is allowed for loopback only)",
    )


def _is_loopback(host: str | None) -> bool:
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def auth_base() -> str:
    """Origin of the consent screen and code exchange (``www``, not ``api``)."""
    if explicit := _clean_env(AUTH_BASE_ENV):
        return _require_secure_origin(explicit, AUTH_BASE_ENV)
    if shared := _clean_env(SHARED_BASE_ENV):
        return _require_secure_origin(shared, SHARED_BASE_ENV)
    return DEFAULT_AUTH_BASE


def api_base() -> str:
    """Base URL of the OpenAI-compatible inference API, including ``/v1``."""
    if explicit := _clean_env(API_BASE_ENV):
        return _require_secure_origin(explicit, API_BASE_ENV)
    if shared := _clean_env(SHARED_BASE_ENV):
        return _require_secure_origin(shared, SHARED_BASE_ENV) + "/v1"
    return DEFAULT_API_BASE


# --- OAuth 2.0 + PKCE --------------------------------------------------------


def generate_pkce() -> tuple[str, str]:
    """A fresh ``(verifier, S256 challenge)`` pair from the OS CSPRNG."""
    return codex.generate_pkce()


def create_state() -> str:
    return codex.create_state()


def build_authorize_url(challenge: str, state: str, callback_url: str) -> str:
    """The consent-screen URL. ``callback_url`` is a loopback URL or ``"oob"``.

    Only the challenge travels on the URL; the verifier stays in this process.
    """
    params = {
        "callback_url": callback_url,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        "app_name": APP_NAME,
        "scope": SCOPE,
    }
    return f"{auth_base()}{AUTHORIZE_PATH}?{urllib.parse.urlencode(params)}"


def state_matches(returned: str | None, expected: str) -> bool:
    return returned is not None and hmac.compare_digest(returned, expected)


_EXCHANGE_ERRORS = {
    400: ("bad_request", "OrcaRouter rejected the sign-in request. Start a new sign-in."),
    403: (
        "invalid_code",
        "The authorization code is invalid, expired, or was already used. "
        "Run `strix auth login orcarouter` again.",
    ),
    429: (
        "rate_limited",
        "Too many OrcaRouter sign-ins in the last 24 hours. Reuse the existing sign-in, "
        "or use an API key (ORCAROUTER_API_KEY) instead.",
    ),
}


def exchange_code(code: str, verifier: str) -> dict[str, Any]:
    """Redeem an authorization code for a durable OrcaRouter API key record."""
    try:
        with requests.post(
            f"{auth_base()}{EXCHANGE_PATH}",
            json={"code": code, "code_verifier": verifier, "code_challenge_method": "S256"},
            headers={"Accept": "application/json"},
            timeout=_EXCHANGE_TIMEOUT_S,
        ) as response:
            status_code = response.status_code
            body = response.content
    except requests.RequestException as exc:
        # The exception text can echo the request; keep only its type.
        raise OrcaRouterAuthError(
            "unavailable", f"could not reach OrcaRouter ({type(exc).__name__})"
        ) from None
    if status_code in _EXCHANGE_ERRORS:
        raise OrcaRouterAuthError(*_EXCHANGE_ERRORS[status_code])
    if status_code >= 400:
        raise OrcaRouterAuthError("exchange_http_error", f"key exchange failed: HTTP {status_code}")
    try:
        data = json.loads(body or b"{}")
    except (ValueError, UnicodeDecodeError):
        raise OrcaRouterAuthError("bad_response", "key exchange returned invalid JSON") from None
    if not isinstance(data, dict):
        raise OrcaRouterAuthError("bad_response", "key exchange returned a non-object")
    grant = cast("dict[str, Any]", data)
    key = grant.get("key")
    if not isinstance(key, str) or not key.strip():
        raise OrcaRouterAuthError("bad_response", "key exchange response has no key")
    # Read back what was granted, not what was asked for.
    scope = grant.get("scope") or SCOPE
    if scope != SCOPE:
        raise OrcaRouterAuthError(
            "scope_mismatch", f"OrcaRouter granted scope {scope!r}; Strix needs {SCOPE!r}"
        )
    user_id = grant.get("user_id")
    return {
        "type": "api_key",
        "provider": PROVIDER,
        "key": key.strip(),
        "scope": scope,
        "user_id": str(user_id) if user_id is not None else None,
        "created_at": time.time(),
        "needs_reauth": False,
    }


# --- Stored sign-in ----------------------------------------------------------
# Shares the ChatGPT sign-in file (one entry per provider) rather than adding a
# second secret store.


def _read_store() -> dict[str, Any]:
    try:
        data = json.loads(codex.AUTH_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return cast("dict[str, Any]", data) if isinstance(data, dict) else {}


def _write_store(data: dict[str, Any]) -> None:
    write_secret_text(codex.AUTH_PATH, json.dumps(data, indent=2))


def read_record() -> dict[str, Any] | None:
    record = _read_store().get(PROVIDER)
    if not isinstance(record, dict):
        return None
    entry = cast("dict[str, Any]", record)
    key = entry.get("key")
    if entry.get("type") != "api_key" or not isinstance(key, str) or not key:
        return None
    return entry


def save_record(record: dict[str, Any]) -> None:
    with _store_lock:
        data = _read_store()
        data[PROVIDER] = record
        _write_store(data)


def logout() -> bool:
    """Forget the stored sign-in. Returns whether there was one."""
    with _store_lock:
        data = _read_store()
        if PROVIDER not in data:
            return False
        del data[PROVIDER]
        if data:
            _write_store(data)
        else:
            with contextlib.suppress(OSError):
                codex.AUTH_PATH.unlink()
        return True


def mark_needs_reauth(rejected_key: str) -> bool:
    """Flag the stored sign-in as revoked, if it still holds ``rejected_key``.

    Compares the exact key so a late ``401`` from an old credential never
    flags a newer sign-in. The key is kept until a new sign-in replaces it.
    """
    with _store_lock:
        data = _read_store()
        record = data.get(PROVIDER)
        if not isinstance(record, dict):
            return False
        entry = cast("dict[str, Any]", record)
        stored_key = entry.get("key")
        if not isinstance(stored_key, str) or not hmac.compare_digest(stored_key, rejected_key):
            return False
        entry["needs_reauth"] = True
        _write_store(data)
        return True


# --- Credential resolution ---------------------------------------------------


def resolve_credential(llm_api_key: str | None = None) -> Credential:
    """The key an ``orcarouter/`` request runs with.

    ``ORCAROUTER_API_KEY`` wins, then a usable ``strix auth login orcarouter``
    sign-in, then ``LLM_API_KEY``. The sign-in outranks ``LLM_API_KEY`` because
    that variable is persisted across runs and often still holds another
    provider's key.
    """
    if env_key := (os.environ.get(API_KEY_ENV) or "").strip():
        return Credential(env_key, SOURCE_ENV)
    record = read_record()
    if record is not None and not record.get("needs_reauth"):
        return Credential(record["key"], SOURCE_LOGIN)
    if explicit := (llm_api_key or "").strip():
        return Credential(explicit, SOURCE_LLM_API_KEY)
    if record is not None:
        raise OrcaRouterAuthError(
            "needs_reauth",
            "Your OrcaRouter sign-in was revoked or expired. Sign in again:\n"
            "  strix auth login orcarouter",
        )
    raise OrcaRouterAuthError(
        "not_authenticated",
        "No OrcaRouter credential. Either sign in:\n"
        "  strix auth login orcarouter\n"
        f"or set an API key: export {API_KEY_ENV}='sk-orca-...'",
    )


_active: Credential | None = None


def remember_active(credential: Credential) -> None:
    """Record the credential the current run's requests are sent with."""
    global _active  # noqa: PLW0603
    _active = credential


def handle_unauthorized() -> str:
    """React to a ``401`` from OrcaRouter and return an actionable hint."""
    credential = _active
    if credential is not None and credential.source == SOURCE_LOGIN:
        mark_needs_reauth(credential.key)
        return (
            "OrcaRouter rejected the signed-in key (it was likely revoked). Sign in again:\n"
            "  strix auth login orcarouter"
        )
    variable = API_KEY_ENV if credential and credential.source == SOURCE_ENV else "LLM_API_KEY"
    return (
        f"OrcaRouter rejected the API key in {variable}. Check or replace it at "
        f"{HOMEPAGE_URL}, or sign in instead with: strix auth login orcarouter"
    )


# --- Model catalog -----------------------------------------------------------


def fetch_models(api_key: str | None = None) -> list[str]:
    """Chat-capable model ids from the live catalog, or ``[]`` if unavailable.

    The request is bounded in time and size; entries that are malformed or
    cannot be served over the OpenAI-compatible chat API are dropped.
    """
    headers = {"Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    try:
        with requests.get(
            f"{api_base()}/models", headers=headers, timeout=_CATALOG_TIMEOUT_S, stream=True
        ) as response:
            if response.status_code != 200:
                return []
            body = response.raw.read(_CATALOG_MAX_BYTES + 1, decode_content=True)
    except (requests.RequestException, OrcaRouterAuthError, OSError):
        return []
    if len(body) > _CATALOG_MAX_BYTES:
        return []
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return []
    items: Any = cast("dict[str, Any]", data).get("data") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return []
    entries = cast("list[object]", items)
    models: list[str] = []
    for raw in entries[:_CATALOG_MAX_ITEMS]:
        if not isinstance(raw, dict):
            continue
        item = cast("dict[str, Any]", raw)
        model_id = item.get("id")
        if not isinstance(model_id, str) or not 0 < len(model_id) <= _MODEL_ID_MAX_LEN:
            continue
        endpoint_types = item.get("supported_endpoint_types")
        if isinstance(endpoint_types, list) and "openai" not in endpoint_types:
            continue
        models.append(model_id)
    return models


def available_models(api_key: str | None = None) -> tuple[list[str], bool]:
    """``(model ids, is_live)``: the live catalog, or the verified seed."""
    live = fetch_models(api_key)
    if live:
        return live, True
    return list(SEED_MODELS), False


def mask_key(key: str) -> str:
    return f"{key[:8]}…{key[-4:]}" if len(key) > 16 else "…"


__all__ = [
    "API_KEY_ENV",
    "MODEL_PREFIX",
    "PROVIDER",
    "SEED_MODELS",
    "Credential",
    "OrcaRouterAuthError",
    "api_base",
    "auth_base",
    "available_models",
    "build_authorize_url",
    "exchange_code",
    "fetch_models",
    "handle_unauthorized",
    "litellm_model_name",
    "logout",
    "mark_needs_reauth",
    "read_record",
    "resolve_credential",
    "route_model",
    "save_record",
]

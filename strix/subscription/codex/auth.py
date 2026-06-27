"""
Codex OAuth token handling.

Vendored from simonw/llm-openai-via-codex (Apache-2.0):
https://github.com/simonw/llm-openai-via-codex/blob/main/llm_openai_via_codex.py
"""
from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.request

REFRESH_URL = "https://auth.openai.com/oauth/token"
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
REFRESH_SKEW_SECONDS = 30
CODEX_BASE_URL = "https://chatgpt.com/backend-api/codex"


class BorrowKeyError(Exception):
    pass


def borrow_codex_key() -> tuple[str, str | None]:
    """Return (access_token, account_id) from local Codex CLI OAuth state.

    Refreshes via auth.openai.com if the access token is expired or near-expiry.
    Persists refreshed tokens back to ~/.codex/auth.json.
    """
    auth_path = _auth_path()
    data = _read_auth(auth_path)

    tokens = data.get("tokens")
    if not tokens or not tokens.get("access_token"):
        raise BorrowKeyError(
            "No ChatGPT tokens found in auth.json. Run `codex login` first."
        )

    access_token = tokens["access_token"]
    account_id = tokens.get("account_id")
    exp = _jwt_exp(access_token)

    if exp is not None and time.time() < (exp - REFRESH_SKEW_SECONDS):
        return access_token, account_id

    refresh_token = tokens.get("refresh_token")
    if not refresh_token:
        raise BorrowKeyError(
            "No refresh token available. Run `codex login` to re-authenticate."
        )

    new_tokens = _refresh(refresh_token)

    if new_tokens.get("access_token"):
        tokens["access_token"] = new_tokens["access_token"]
    if new_tokens.get("id_token"):
        tokens["id_token"] = new_tokens["id_token"]
    if new_tokens.get("refresh_token"):
        tokens["refresh_token"] = new_tokens["refresh_token"]

    data["tokens"] = tokens
    data["last_refresh"] = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())

    _write_auth(auth_path, data)
    return tokens["access_token"], account_id


def get_token_and_account() -> tuple[str, str | None]:
    """Public alias for borrow_codex_key()."""
    return borrow_codex_key()


def _auth_path() -> str:
    codex_home = os.environ.get("CODEX_HOME", os.path.expanduser("~/.codex"))
    path = os.path.join(codex_home, "auth.json")
    if not os.path.exists(path):
        raise BorrowKeyError(
            f"Codex auth file not found at {path}. Run `codex login` first."
        )
    return path


def _read_auth(path: str) -> dict:
    with open(path) as f:
        data = json.load(f)
    mode = data.get("auth_mode")
    # Some codex builds omit auth_mode. Accept missing/None as long as ChatGPT-style
    # OAuth tokens are present. Reject only when the mode is explicitly something else
    # (e.g. "apikey").
    if mode not in (None, "chatgpt"):
        raise BorrowKeyError(
            f"auth_mode '{mode}' is not supported. This proxy needs ChatGPT OAuth "
            "tokens (run `codex login` and pick the ChatGPT option)."
        )
    return data


def _write_auth(path: str, data: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def _jwt_exp(token: str) -> int | None:
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (4 - len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        return payload.get("exp")
    except Exception:
        return None


def _refresh(refresh_token: str) -> dict:
    body = json.dumps(
        {
            "client_id": CLIENT_ID,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
    ).encode()

    req = urllib.request.Request(
        REFRESH_URL,
        data=body,
        headers={"Content-Type": "application/json"},
    )

    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        error_body = e.read().decode(errors="replace")
        try:
            error_code = json.loads(error_body).get("error")
        except Exception:
            error_code = None
        if error_code in (
            "refresh_token_expired",
            "refresh_token_reused",
            "refresh_token_invalidated",
        ):
            raise BorrowKeyError(
                f"Refresh token is no longer valid ({error_code}). "
                "Run `codex login` to re-authenticate."
            ) from None
        raise BorrowKeyError(
            f"Token refresh failed (HTTP {e.code}): {error_body}"
        ) from None
    except urllib.error.URLError as e:
        raise BorrowKeyError(f"Token refresh failed (network error): {e}") from None

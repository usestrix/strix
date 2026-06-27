"""
Claude Code OAuth token handling for the Strix subscription proxy.

Borrows the OAuth access token that the Claude Code CLI stores locally
(~/.claude/.credentials.json) and refreshes it when expired, so the proxy can
authenticate to api.anthropic.com on the user's Claude *subscription* instead of
a paid API key.

This mirrors the token-borrowing approach in strix.subscription.codex.auth (which borrows
ChatGPT/Codex tokens from ~/.codex/auth.json), adapted to Anthropic's OAuth
scheme. No third-party deps — stdlib urllib only.

Note: Anthropic's subscription OAuth tokens are intended for use within Claude
Code / Claude.ai. Reusing them in another tool may violate the Consumer Terms.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

# Overridable via env so the refresh endpoint / client id / UA can be swapped
# without code changes if Anthropic moves them.
REFRESH_URL = os.environ.get(
    "STRIX_SUB_CLAUDE_REFRESH_URL", "https://console.anthropic.com/v1/oauth/token"
)
CLIENT_ID = os.environ.get(
    "STRIX_SUB_CLAUDE_OAUTH_CLIENT_ID", "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
)
CLAUDE_CODE_USER_AGENT = os.environ.get(
    "STRIX_SUB_CLAUDE_USER_AGENT", "claude-cli/2.0.0 (external)"
)

REFRESH_SKEW_SECONDS = 60

ANTHROPIC_BASE_URL = os.environ.get(
    "STRIX_SUB_CLAUDE_ANTHROPIC_BASE_URL", "https://api.anthropic.com"
)
ANTHROPIC_VERSION = "2023-06-01"
ANTHROPIC_OAUTH_BETA = "oauth-2025-04-20"

# The subscription credential is only accepted on /v1/messages when the request
# presents as Claude Code: the first system block must be exactly this string.
CLAUDE_CODE_SYSTEM_PROMPT = "You are Claude Code, Anthropic's official CLI for Claude."


class BorrowKeyError(Exception):
    pass


def _auth_path() -> str:
    config_dir = os.environ.get("CLAUDE_CONFIG_DIR", os.path.expanduser("~/.claude"))
    path = os.path.join(config_dir, ".credentials.json")
    if not os.path.exists(path):
        raise BorrowKeyError(
            f"Claude Code credentials not found at {path}. "
            "Log in with the `claude` CLI first."
        )
    return path


def _read_auth(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def _write_auth(path: str, data: dict) -> None:
    tmp = path + ".tmp"
    with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def borrow_claude_key() -> str:
    """Return a valid Claude Code OAuth access token.

    Reads ~/.claude/.credentials.json, refreshes via Anthropic's OAuth token
    endpoint if the access token is expired or near-expiry, and persists the
    rotated tokens back to the credentials file (preserving any other fields).
    """
    # Prefer an explicit long-lived token (from `claude setup-token`) when set:
    # no file dependency and no refresh, ideal for long unattended runs.
    env_token = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN")
    if env_token and env_token.strip():
        return env_token.strip()

    path = _auth_path()
    data = _read_auth(path)

    oauth = data.get("claudeAiOauth")
    if not isinstance(oauth, dict) or not oauth.get("accessToken"):
        raise BorrowKeyError(
            "No Claude Code OAuth tokens found in credentials file. "
            "Log in with the `claude` CLI first."
        )

    access_token = oauth["accessToken"]
    expires_at_ms = oauth.get("expiresAt")

    # expiresAt is epoch milliseconds. If absent we cannot check expiry; assume a
    # running Claude Code keeps it fresh and use it as-is.
    if not expires_at_ms:
        return access_token
    if time.time() * 1000 < (expires_at_ms - REFRESH_SKEW_SECONDS * 1000):
        return access_token

    refresh_token = oauth.get("refreshToken")
    if not refresh_token:
        raise BorrowKeyError(
            "Access token expired and no refresh token available. "
            "Log in with the `claude` CLI again."
        )

    new = _refresh(refresh_token)

    oauth["accessToken"] = new["access_token"]
    if new.get("refresh_token"):
        oauth["refreshToken"] = new["refresh_token"]
    if new.get("expires_in"):
        oauth["expiresAt"] = int(time.time() * 1000) + int(new["expires_in"]) * 1000

    data["claudeAiOauth"] = oauth
    _write_auth(path, data)
    return oauth["accessToken"]


def get_token() -> str:
    """Public alias for borrow_claude_key()."""
    return borrow_claude_key()


def _refresh(refresh_token: str) -> dict:
    body = json.dumps(
        {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": CLIENT_ID,
        }
    ).encode()

    req = urllib.request.Request(
        REFRESH_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": CLAUDE_CODE_USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        error_body = e.read().decode(errors="replace")
        hint = ""
        if e.code in (403, 503) and "<html" in error_body.lower():
            hint = (
                " (endpoint returned an HTML block page; the refresh User-Agent "
                "may be rejected; try setting STRIX_SUB_CLAUDE_USER_AGENT)"
            )
        try:
            code = json.loads(error_body).get("error")
        except Exception:
            code = None
        if code in ("invalid_grant", "refresh_token_expired", "refresh_token_revoked"):
            raise BorrowKeyError(
                f"Refresh token is no longer valid ({code}). "
                "Log in with the `claude` CLI again."
            ) from None
        raise BorrowKeyError(
            f"Token refresh failed (HTTP {e.code}): {error_body[:300]}{hint}"
        ) from None
    except urllib.error.URLError as e:
        raise BorrowKeyError(f"Token refresh failed (network error): {e}") from None

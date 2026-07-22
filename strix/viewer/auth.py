"""Viewer email verification state and the relay client.

The local viewer proxies email verification and encrypted-report delivery to
the Strix relay (``STRIX_APP_URL``). The browser never talks to the relay
directly, and the report password generated locally is never sent to it.

State lives in ``~/.strix/viewer-auth.json`` (0600). ``is_verified`` is a local
flag that unlocks browsing the run history list; the relay still enforces token
expiry when a report is actually sent.
"""

from __future__ import annotations

import base64
import contextlib
import json
import logging
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from strix.config.loader import load_settings


logger = logging.getLogger(__name__)

AUTH_PATH = Path.home() / ".strix" / "viewer-auth.json"

_OTP_TIMEOUT = 15
_SEND_TIMEOUT = 30


class RelayError(Exception):
    """A relay call failed. ``code`` is a stable, machine-readable reason."""

    def __init__(self, code: str, message: str | None = None) -> None:
        self.code = code
        super().__init__(message or code)


# --- local state ------------------------------------------------------------


def read_auth() -> dict[str, Any] | None:
    """Return the stored ``{email, token, verified_at}`` record, or None."""
    try:
        data = json.loads(AUTH_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    email = data.get("email")
    token = data.get("token")
    if not isinstance(email, str) or not email or not isinstance(token, str) or not token:
        return None
    return data


def parse_expiry(raw: object) -> datetime | None:
    """Parse a relay ``expires_at`` value into an aware UTC datetime.

    Accepts both ISO 8601 strings and epoch seconds (as a number or numeric
    string) so a valid relay expiry is not misread as missing. Returns None only
    when it is genuinely absent or unparseable; both the local gate (see
    ``is_verified``) and OTP verification (see ``otp_verify``) fail closed on such
    values, matching the relay, which rejects a token with no valid expiry.
    """
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int | float):
        return _from_epoch(raw)
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return _from_epoch(float(raw))
    except ValueError:
        pass
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _expiry(record: dict[str, Any]) -> datetime | None:
    """The stored ``verified_at`` parsed to a datetime, or None if unusable."""
    return parse_expiry(record.get("verified_at"))


def _from_epoch(seconds: float) -> datetime | None:
    """Epoch seconds → aware UTC datetime, or None if out of range."""
    try:
        return datetime.fromtimestamp(seconds, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def is_verified() -> bool:
    """True when a usable email + token record with a valid future expiry exists.

    The expiry returned by OTP verification is enforced here so history stops
    unlocking once the token lapses. It fails closed: a record whose expiry is
    absent, blank, or unparseable requires re-verification rather than unlocking
    forever, keeping the local gate in step with the relay (which rejects an
    expired token on report send).
    """
    record = read_auth()
    if record is None:
        return False
    expiry = _expiry(record)
    return expiry is not None and expiry > datetime.now(UTC)


def write_auth(email: str, token: str, verified_at: str) -> None:
    """Atomically persist the auth record with 0600 permissions."""
    AUTH_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"email": email, "token": token, "verified_at": verified_at})
    tmp = AUTH_PATH.with_suffix(".json.tmp")
    tmp.write_text(payload, encoding="utf-8")
    with contextlib.suppress(OSError):
        tmp.chmod(0o600)
    tmp.replace(AUTH_PATH)
    with contextlib.suppress(OSError):
        AUTH_PATH.chmod(0o600)


def forget() -> None:
    """Delete the stored auth record. No-op if it is absent."""
    with contextlib.suppress(OSError):
        AUTH_PATH.unlink()


# --- relay client -----------------------------------------------------------


def _app_url() -> str:
    return load_settings().viewer.app_url.rstrip("/")


def _post_json(path: str, payload: dict[str, Any], *, timeout: int) -> tuple[int, dict[str, Any]]:
    """POST JSON to the relay. Returns (status, parsed body).

    Raises RelayError("unavailable") for network/transport failures. HTTP
    error responses (4xx/5xx) are returned as (status, body) for the caller to
    map, not raised.
    """
    url = f"{_app_url()}{path}"
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 - fixed https relay URL
        url,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return response.status, _parse_body(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, _parse_body(exc.read())
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        logger.warning("relay request to %s failed: %s", path, exc)
        raise RelayError("unavailable") from exc


def _parse_body(raw: bytes) -> dict[str, Any]:
    try:
        data = json.loads(raw or b"{}")
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def otp_start(email: str) -> None:
    """Ask the relay to email a verification code. Raises RelayError on failure."""
    status, data = _post_json("/api/oss/otp/start", {"email": email}, timeout=_OTP_TIMEOUT)
    if status == 200:
        return
    if status == 429:
        raise RelayError("rate_limited")
    if status == 400:
        # The relay uses 400 both for a malformed address and, separately, to
        # reject a free/personal email domain (it wants a work email).
        if data.get("error") == "work_email_required":
            raise RelayError("work_email_required")
        raise RelayError("invalid_email")
    raise RelayError("unavailable")


def otp_verify(email: str, code: str) -> dict[str, Any]:
    """Verify a code. Returns ``{token, email, expires_at}`` or raises RelayError."""
    status, data = _post_json(
        "/api/oss/otp/verify",
        {"email": email, "code": code},
        timeout=_OTP_TIMEOUT,
    )
    if status == 200 and isinstance(data.get("token"), str):
        # A token with no usable expiry cannot unlock history locally (the gate
        # fails closed), so treat such a response as a failed verification rather
        # than reporting success and then leaving the user stuck unverified.
        if parse_expiry(data.get("expires_at")) is None:
            raise RelayError("unavailable")
        return data
    if status == 403:
        raise RelayError("invalid_code")
    raise RelayError("unavailable")


def feedback_submit(email: str, message: str) -> None:
    """Relay a feedback message + email to Strix. No verification is required;
    the email is taken as given. Raises RelayError on failure."""
    status, data = _post_json(
        "/api/oss/feedback",
        {"email": email, "message": message},
        timeout=_OTP_TIMEOUT,
    )
    if status == 200:
        return
    if status == 429:
        raise RelayError("rate_limited")
    if status == 400:
        code = data.get("error")
        if code in ("invalid_email", "invalid_message"):
            raise RelayError(str(code))
        raise RelayError("invalid_message")
    raise RelayError("unavailable")


def report_send(
    token: str,
    pdf_bytes: bytes,
    filename: str,
    run_name: str,
    target: str,
) -> None:
    """Forward the encrypted PDF to the relay for delivery.

    The report password is NEVER part of this payload; only the encrypted PDF
    bytes travel to the relay.
    """
    payload = {
        "token": token,
        "pdf_base64": base64.b64encode(pdf_bytes).decode("ascii"),
        "filename": filename,
        "run_name": run_name,
        "target": target,
    }
    status, _ = _post_json("/api/oss/report/send", payload, timeout=_SEND_TIMEOUT)
    if status == 200:
        return
    if status == 401:
        raise RelayError("reverify")
    if status == 413:
        raise RelayError("too_large")
    if status == 403:
        raise RelayError("forbidden")
    raise RelayError("unavailable")


__all__ = [
    "AUTH_PATH",
    "RelayError",
    "feedback_submit",
    "forget",
    "is_verified",
    "otp_start",
    "otp_verify",
    "read_auth",
    "report_send",
    "write_auth",
]

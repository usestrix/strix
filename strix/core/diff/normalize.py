"""Volatile-field normalizer for deterministic response diffing."""

from __future__ import annotations

import re
from typing import Any

from strix.core.diff.models import NormalizedResponse


_VOLATILE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "timestamp",
        re.compile(
            r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?"
            r"(Z|[+-]\d{2}:\d{2})?"
        ),
    ),
    (
        "csrf_token",
        re.compile(
            r"(?i)(csrf[_-]?token|csrfmiddlewaretoken)"
            r'["\']?\s*[:=]\s*["\']?[a-zA-Z0-9+/=]{8,}'
        ),
    ),
    (
        "nonce",
        re.compile(
            r"(?i)(nonce|state|code_challenge|code_verifier)"
            r'["\']?\s*[:=]\s*["\']?[a-zA-Z0-9+/=]{8,}'
        ),
    ),
    (
        "request_id",
        re.compile(
            r"(?i)(request[_-]?id|x-request-id|trace[_-]?id|correlation[_-]?id)"
            r'["\']?\s*[:=]\s*["\']?[a-zA-Z0-9-]{8,}'
        ),
    ),
    (
        "session_id",
        re.compile(
            r"(?i)(sessionid|session[_-]?id|sid|jsessionid)"
            r'["\']?\s*[:=]\s*["\']?[a-zA-Z0-9-]{8,}'
        ),
    ),
]

_VOLATILE_HEADER_NAMES = frozenset(
    {
        "date",
        "etag",
        "x-request-id",
        "x-correlation-id",
        "x-trace-id",
    }
)

_SESSION_COOKIE_NAMES = frozenset(
    {
        "sessionid",
        "session_id",
        "session-id",
        "sid",
        "jsessionid",
        "auth_token",
        "token",
    }
)


_REPLACEMENTS: dict[str, str] = {
    "timestamp": "<TS>",
    # These markers are canonicalization placeholders, not secrets. The dict
    # itself is intentionally conservative and only touches declared patterns.
    "csrf_token": "<CSRF>",  # nosec B105
    "nonce": "<NONCE>",  # nosec B105
    "request_id": "<REQID>",  # nosec B105
    "session_id": "<SESSID>",  # nosec B105
}


def _canonicalize_body(body: str, normalized_fields: list[str]) -> tuple[str, list[str]]:
    """Replace declared volatile patterns in the body."""
    result = body
    seen: set[str] = set()
    for label, pattern in _VOLATILE_PATTERNS:
        if pattern.search(result):
            seen.add(label)
            result = pattern.sub(_REPLACEMENTS.get(label, f"<{label.upper()}>"), result)
    normalized_fields.extend(sorted(seen))
    return result, normalized_fields


def _canonicalize_headers(
    headers: dict[str, str],
    normalized_fields: list[str],
) -> tuple[dict[str, str], list[str]]:
    """Canonicalize volatile header values while preserving structure."""
    cleaned: dict[str, str] = {}
    seen: set[str] = set()
    for name, value in headers.items():
        lowered = name.lower()
        if lowered in _VOLATILE_HEADER_NAMES:
            seen.add(lowered)
            cleaned[name] = "<VOLATILE>"
        elif "set-cookie" in lowered:
            value_lower = value.lower()
            if any(session in value_lower for session in _SESSION_COOKIE_NAMES):
                seen.add("set-cookie-session")
                # Preserve cookie name and flags; mask only the value.
                parts = value.split(";")
                first = parts[0]
                if "=" in first:
                    key, _ = first.split("=", 1)
                    first = f"{key}=<VALUE>"
                cleaned[name] = "; ".join([first, *parts[1:]])
            else:
                cleaned[name] = value
        else:
            cleaned[name] = value
    normalized_fields.extend(sorted(seen))
    return cleaned, normalized_fields


def _set_cookie_names(headers: dict[str, str]) -> list[str]:
    """Extract Set-Cookie names from response headers."""
    names: list[str] = []
    for name, value in headers.items():
        if name.lower() == "set-cookie" and "=" in value:
            key, _ = value.split("=", 1)
            names.append(key.strip())
    return sorted(names)


def status_class(status_code: int) -> str:
    """Bucket a status code into its class (e.g. ``2xx``)."""
    if 100 <= status_code < 200:
        return "1xx"
    if 200 <= status_code < 300:
        return "2xx"
    if 300 <= status_code < 400:
        return "3xx"
    if 400 <= status_code < 500:
        return "4xx"
    if 500 <= status_code < 600:
        return "5xx"
    return "unknown"


def normalize_response(
    response: dict[str, Any],
    volatile_patterns: list[tuple[str, re.Pattern[str]]] | None = None,
) -> NormalizedResponse:
    """Return a response with volatile fields canonicalized.

    Args:
        response: Dict with ``status_code``, ``headers``, and ``body``.
        volatile_patterns: Optional extra (label, pattern) pairs.
    """
    status_code: int = int(response.get("status_code", 0))
    headers: dict[str, str] = dict(response.get("headers", {}))
    body: str = str(response.get("body", ""))

    normalized_fields: list[str] = []
    headers, normalized_fields = _canonicalize_headers(headers, normalized_fields)
    body, normalized_fields = _canonicalize_body(body, normalized_fields)

    if volatile_patterns:
        for label, pattern in volatile_patterns:
            if pattern.search(body):
                normalized_fields.append(label)
                body = pattern.sub(f"<{label.upper()}>", body)

    normalized_fields = sorted(set(normalized_fields))
    return NormalizedResponse(
        status_code=status_code,
        status_class=status_class(status_code),
        headers=headers,
        body=body,
        body_length=len(body.encode("utf-8")),
        set_cookie_names=_set_cookie_names(headers),
        normalized_fields=normalized_fields,
    )

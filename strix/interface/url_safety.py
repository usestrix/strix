"""Validation for URLs printed or opened on behalf of a remote service."""

from __future__ import annotations

import ipaddress
from urllib.parse import SplitResult, urlsplit

from strix.interface.terminal_text import has_terminal_control


def is_safe_web_url(
    value: object,
    *,
    trusted_origin: str | None = None,
    require_trusted_origin: bool = False,
) -> bool:
    """Accept a strict HTTP(S) URL, optionally only on a pre-trusted origin."""
    parsed = _parse(value)
    if parsed is None:
        return False
    trusted = _parse(trusted_origin) if trusted_origin is not None else None
    same_origin = trusted is not None and _origin(parsed) == _origin(trusted)
    if require_trusted_origin:
        return same_origin
    if same_origin:
        return True
    return _is_safe_external_https(parsed)


def _is_safe_external_https(parsed: SplitResult) -> bool:
    """Reject local, numeric-looking, or otherwise ambiguous external hosts."""
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if (
        parsed.scheme != "https"
        or hostname == "localhost"
        or hostname.endswith((".localhost", ".local"))
    ):
        return False
    try:
        return ipaddress.ip_address(hostname).is_global
    except ValueError:
        pass
    labels = hostname.split(".")
    return len(labels) >= 2 and not all(_looks_numeric(label) for label in labels)


def _parse(value: object) -> SplitResult | None:
    if not isinstance(value, str) or not value or has_terminal_control(value):
        return None
    if "\\" in value or any(character.isspace() for character in value):
        return None
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return None
    hostname = parsed.hostname
    if (
        parsed.scheme not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or "%" in parsed.netloc
    ):
        return None
    try:
        hostname.encode("ascii")
    except UnicodeEncodeError:
        return None
    return parsed if port is None or 1 <= port <= 65535 else None


def _origin(parsed: SplitResult) -> tuple[str, str, int]:
    default_port = 443 if parsed.scheme == "https" else 80
    return parsed.scheme, (parsed.hostname or "").lower().rstrip("."), parsed.port or default_port


def _looks_numeric(label: str) -> bool:
    lowered = label.lower()
    if lowered.startswith("0x"):
        return len(lowered) > 2 and all(
            character in "0123456789abcdef" for character in lowered[2:]
        )
    return bool(lowered) and all(character.isdigit() for character in lowered)

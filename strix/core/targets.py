"""Canonical host identities shared by target ingestion and prompt scope."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit


_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_URI_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


def canonical_network_host(value: str) -> tuple[str, str]:
    """Return ``(web_host|ip_address, canonical value)`` for a network input."""
    raw = value.strip()
    if not raw or any(char.isspace() or ord(char) < 0x20 or ord(char) == 0x7F for char in raw):
        raise ValueError(f"Network target '{value}' contains an invalid host")

    # Parse exact IPs before treating colons as URL authority syntax. URL forms
    # containing IPv6 still use the standard bracketed authority parser below.
    try:
        return "ip_address", str(ipaddress.ip_address(raw))
    except ValueError:
        pass

    try:
        parsed = urlsplit(raw if _URI_SCHEME.match(raw) else f"//{raw}")
        hostname = (parsed.hostname or "").rstrip(".").lower()
        # Accessing port validates both its syntax and range while keeping it
        # out of the canonical host identity.
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(f"Network target '{value}' contains an invalid host") from exc
    if not hostname:
        raise ValueError(f"Network target '{value}' does not contain a valid host")

    try:
        return "ip_address", str(ipaddress.ip_address(hostname))
    except ValueError:
        pass

    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Network target '{value}' contains an invalid host") from exc
    if len(hostname) > 253 or any(not _DNS_LABEL.fullmatch(label) for label in hostname.split(".")):
        raise ValueError(f"Network target '{value}' contains an invalid host")
    return "web_host", hostname

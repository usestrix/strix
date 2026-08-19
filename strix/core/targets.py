"""Canonical host identities shared by target ingestion and prompt scope."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit


_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def canonical_network_host(value: str) -> tuple[str, str]:
    """Return ``(web_host|ip_address, canonical value)`` for a network input."""
    parsed = urlsplit(value if "://" in value else f"//{value}")
    hostname = (parsed.hostname or "").rstrip(".").lower()
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

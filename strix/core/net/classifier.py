"""Classify hosts as internal, metadata, or external/public."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from strix.core.net.ip_decoder import decode_ip_address


_CLOUD_METADATA_HOSTS: frozenset[str] = frozenset(
    {
        "169.254.169.254",
        "fd00:ec2::254",
        "metadata.google.internal",
        "metadata.azure.internal",
    }
)


def _host_from_url(url: str) -> str | None:
    """Extract the host component from a URL or bare host string."""
    url = url.strip()
    if "//" not in url and "://" not in url:
        url = f"http://{url}"
    parsed = urlparse(url)
    host = parsed.hostname
    return host.lower() if host else None


def _is_metadata_host(host: str) -> bool:
    """True if the host is a known cloud-metadata endpoint."""
    return (
        host in _CLOUD_METADATA_HOSTS
        or host == "169.254.169.254"
        or host.endswith(".metadata.azure.internal")
    )


# CGNAT 100.64.0.0/10 is not classified as private by Python's ipaddress
# module in all versions, so we check it explicitly.
_CGNAT_NETWORK = ipaddress.IPv4Network("100.64.0.0/10")


def classify_ip_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if the IP address is internal/special-use."""
    if isinstance(ip, ipaddress.IPv4Address):
        return bool(
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip in _CGNAT_NETWORK
        )
    return bool(
        ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast
    )


def is_internal_target(target: str) -> bool:
    """Return True if ``target`` resolves to an internal or metadata host.

    Accepts URLs, bare hostnames, or IP addresses. Handles canonical and
    alternate IP notations (decimal, octal, hex, IPv4-mapped IPv6).
    """
    host = _host_from_url(target)
    if host is None:
        return False

    # Intentional localhost detection; these are valid internal-host markers.
    if host in ("localhost", "0.0.0.0", "::"):  # nosec B104
        return True

    if _is_metadata_host(host):
        return True

    # Try to decode as an IP address (canonical or alternate notation).
    ip = decode_ip_address(host)
    if ip is not None:
        return classify_ip_address(ip)

    return host.startswith("localhost.") or host.endswith(".localhost")


__all__ = ["classify_ip_address", "is_internal_target"]

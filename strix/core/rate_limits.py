"""Per-domain request rate limits enforced by the sandbox proxy.

A rate-limit map pairs a domain with the most requests per second the proxy
sends to that domain and its subdomains, such as ``{"example.com": 5}``. The
sandbox receives it as the ``STRIX_RATE_LIMITS`` environment variable.
"""

from __future__ import annotations

import ipaddress
import math
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from strix.core.inputs import build_scope_context


if TYPE_CHECKING:
    from collections.abc import Mapping


RATE_LIMITS_ENV = "STRIX_RATE_LIMITS"


def normalize_rate_limits(raw: Mapping[str, Any] | None) -> dict[str, float]:
    """Keep the entries that name a host and a finite rate above zero."""
    limits: dict[str, float] = {}
    for domain, rate in (raw or {}).items():
        host = str(domain).strip().lower().removeprefix("*.").rstrip(".")
        try:
            per_second = float(rate)
        except (TypeError, ValueError):
            continue
        if host and math.isfinite(per_second) and per_second > 0:
            limits[host] = per_second
    return limits


def _target_host(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    parsed = urlparse(value if "://" in value else f"//{value}")
    return parsed.hostname


def rate_limits_for_targets(scan_config: dict[str, Any], per_second: float) -> dict[str, float]:
    """Apply one rate to the host of every web, IP and API-spec target."""
    limits: dict[str, float] = {}
    for target in build_scope_context(scan_config)["authorized_targets"]:
        if target["type"] not in {"web_application", "ip_address"}:
            continue
        host = _target_host(target["value"])
        if host:
            limits[host] = per_second
    return normalize_rate_limits(limits)

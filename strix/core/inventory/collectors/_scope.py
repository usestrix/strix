"""Shared scope-bounding helper for inventory collectors."""

from __future__ import annotations

from urllib.parse import urlparse


def host_in_scope(url: str, scope_rules: list[str] | None) -> bool:
    """Return True when no scope rules are defined or the URL host matches."""
    if not scope_rules:
        return True
    host = urlparse(url).hostname or ""
    return any(
        host == rule
        or (rule.startswith("*.") and host.endswith(rule[1:]))
        or (rule.startswith("*") and host.endswith(rule[1:]))
        for rule in scope_rules
    )

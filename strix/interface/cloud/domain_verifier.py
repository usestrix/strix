"""Classify provider-managed domains for cloud verification.

Provider default hostnames are not proof of ownership by themselves.  This
module only selects the verification strategy; the managed API remains the
authority that checks the authenticated provider integration.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class ProviderDomain:
    """Metadata for a provider-owned default hostname suffix."""

    provider: str
    requires_dns: bool = False


PROVIDER_DEFAULT_DOMAINS: Final[dict[str, ProviderDomain]] = {
    "vercel.app": ProviderDomain("vercel"),
    "netlify.app": ProviderDomain("netlify"),
    "github.io": ProviderDomain("github"),
    "herokuapp.com": ProviderDomain("heroku"),
}


def _normalise(domain: str | None) -> str:
    """Return a comparable hostname, without a trailing root dot."""
    if not isinstance(domain, str):
        return ""
    return domain.strip().lower().rstrip(".")


def get_provider_info(domain: str | None) -> ProviderDomain | None:
    """Return provider metadata when *domain* is a provider default hostname.

    Matching is label-aware: ``notvercel.app`` and ``example.vercel.app.evil``
    do not match ``vercel.app``.
    """
    hostname = _normalise(domain)
    if not hostname or any(len(label) > 63 for label in hostname.split(".")):
        return None
    for suffix, info in PROVIDER_DEFAULT_DOMAINS.items():
        if hostname.endswith(f".{suffix}"):
            return info
    return None


def is_provider_default_domain(domain: str | None) -> bool:
    """Return whether *domain* is hosted under a known provider suffix."""
    return get_provider_info(domain) is not None


def validate_domain_verification_method(domain: str | None) -> tuple[bool, str]:
    """Select ``provider`` for default hostnames and ``dns`` otherwise."""
    hostname = _normalise(domain)
    if not hostname or any(not label for label in hostname.split(".")):
        return False, "unknown"
    info = get_provider_info(hostname)
    if info is not None and not info.requires_dns:
        return True, "provider"
    return True, "dns"


async def verify_provider_domain(
    domain: str | None,
    provider_token: str | None = None,
) -> tuple[bool, str]:
    """Return the provider verification decision for API callers.

    The CLI cannot prove that a hostname belongs to the user without calling
    the managed API.  ``provider_token`` is intentionally accepted for API
    integrations, but is never logged or sent anywhere by this helper.
    """
    del provider_token
    info = get_provider_info(domain)
    if info is None:
        return False, f"Domain {domain} is not a recognized provider domain"
    return (
        True,
        f"{info.provider} domain {domain} requires provider-account verification",
    )

"""Compile a :class:`BountyProgram` into a fail-closed :class:`ScopePolicy`.

This is the bridge between the bounty layer and Strix 2's existing authorization
engine: a program's published ``in_scope`` / ``out_of_scope`` assets become an
allowlist (web / api / network / cloud) plus an exclusion deny-list, so every tool
boundary already wired to the scope engine confines a bounty run for free.

The mapping is deliberately conservative. An asset the network scope engine cannot
represent — a mobile app, a source bundle, a binary — is *not* forced into a scope
entry; it is reported as unmapped so the operator and the agent know it is in the
program's scope but not auto-gated here. Unknown-but-URL-shaped assets are mapped by
a heuristic on the identifier, which an explicit ``asset_type`` overrides.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from strix.scope.schema import (
    ApiScope,
    CloudScope,
    ExclusionScope,
    NetworkScope,
    ScopePolicy,
    WebScope,
)


if TYPE_CHECKING:
    from strix.bounty.schema import BountyProgram, ScopeAsset


# Category the scope engine understands, plus a value in that category's native form.
# ``skip`` means the asset is not gatable by the network scope engine.
_Category = str  # one of: web, api, network_host, cidr, aws, azure, gcp, skip


@dataclass
class CompiledScope:
    """The result of compiling a program: the policy plus what could not be mapped."""

    policy: ScopePolicy
    unmapped: list[str] = field(default_factory=list)


def _dedup(seq: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in seq:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _parse_cloud(identifier: str) -> tuple[_Category, str] | None:
    low = identifier.lower().strip()
    if low.startswith("arn:aws:"):
        parts = identifier.split(":")
        return ("aws", parts[4]) if len(parts) > 4 and parts[4] else None
    for provider in ("aws", "azure", "gcp"):
        if low.startswith(provider + ":"):
            ident = identifier.split(":", 1)[1].strip()
            return (provider, ident) if ident else None
    if low.isdigit() and len(low) == 12:
        return ("aws", low)
    return None


def _split_url(identifier: str) -> tuple[str, str, str]:
    """Return ``(scheme, host, path)`` for a URL-ish identifier, path normalized."""
    scheme = "https"
    rest = identifier.strip()
    if "://" in rest:
        scheme, rest = rest.split("://", 1)
    rest = rest.split("@")[-1]  # drop any userinfo
    if "/" in rest:
        hostport, tail = rest.split("/", 1)
        path = "/" + tail.rstrip("/")
    else:
        hostport, path = rest, ""
    host = hostport.split(":")[0].strip().lower().rstrip(".")
    return scheme.lower(), host, "" if path in ("", "/") else path


def _classify_ip(identifier: str, at: str) -> tuple[_Category, str] | None:
    """Classify a CIDR / single IP from the raw identifier, before any path split.

    Returns the mapping, or ``None`` to let the caller try the next form (and the
    caller turns ``None`` into ``skip`` when the asset was explicitly typed ip/cidr).
    """
    if at == "cidr" or (at == "other" and "/" in identifier and "://" not in identifier):
        try:
            ipaddress.ip_network(identifier, strict=False)
        except ValueError:
            return None
        return ("cidr", identifier)
    if at in {"ip", "other"}:
        try:
            ipaddress.ip_address(identifier)
        except ValueError:
            return None
        return ("network_host", identifier)
    return None


def _classify_url(identifier: str, at: str) -> tuple[_Category, str | None]:
    scheme, host, path = _split_url(identifier)
    if not host:
        return ("skip", None)
    if at in {"wildcard", "domain"} or (at == "other" and "*" in host):
        return ("web", host)
    if at == "api" or path:  # an explicit API asset, or any URL carrying a path
        return ("api", f"{scheme}://{host}{path}")
    return ("web", host)


def classify_asset(asset: ScopeAsset) -> tuple[_Category, str | None]:
    """Classify an asset into a scope category and its native value.

    An explicit ``asset_type`` wins; ``other`` falls back to a heuristic on the
    identifier. Returns ``("skip", None)`` for an asset the scope engine cannot gate.
    """
    identifier = asset.identifier.strip()
    at = asset.asset_type

    if at in {"android", "ios", "source", "executable"}:
        return ("skip", None)
    if at in {"cloud_aws", "cloud_azure", "cloud_gcp", "other"}:
        cloud = _parse_cloud(identifier)
        if cloud is not None:
            return cloud
        if at != "other":
            return ("skip", None)  # typed cloud but unparseable

    net = _classify_ip(identifier, at)
    if net is not None:
        return net
    if at in {"cidr", "ip"}:
        return ("skip", None)

    return _classify_url(identifier, at)


def compile_to_scope(program: BountyProgram, *, intrusive_policy: str = "auto") -> CompiledScope:
    """Compile a program's scope into a :class:`ScopePolicy` plus unmapped assets.

    ``intrusive_policy`` controls ``allow_intrusive`` on the compiled policy:
    ``"auto"`` mirrors the program's ``state_changing_poc_allowed`` rule (so intrusive
    proofs are permitted only when the program says so), and ``"never"`` forces it
    off regardless. The operator's ``--allow-intrusive`` flag can still force it on at
    load time; this only sets the compiled default.
    """
    web: list[str] = []
    api: list[str] = []
    hosts: list[str] = []
    cidrs: list[str] = []
    aws: list[str] = []
    azure: list[str] = []
    gcp: list[str] = []
    unmapped: list[str] = []

    buckets: dict[str, list[str]] = {
        "web": web,
        "api": api,
        "network_host": hosts,
        "cidr": cidrs,
        "aws": aws,
        "azure": azure,
        "gcp": gcp,
    }

    for asset in program.in_scope:
        category, value = classify_asset(asset)
        if category == "skip" or value is None:
            unmapped.append(asset.identifier)
            continue
        buckets[category].append(value)

    excl_hosts: list[str] = []
    excl_urls: list[str] = []
    excl_cidrs: list[str] = []
    for asset in program.out_of_scope:
        category, value = classify_asset(asset)
        if value is None:
            continue
        if category in {"web", "network_host"}:
            excl_hosts.append(value)
        elif category == "api":
            excl_urls.append(value)
        elif category == "cidr":
            excl_cidrs.append(value)
        # cloud / skip exclusions are not represented (account allowlisting controls cloud).

    allow_intrusive = (
        program.roe.state_changing_poc_allowed if intrusive_policy == "auto" else False
    )

    authorized_by = f"{program.platform} bug-bounty program '{program.handle}'"
    if program.managed_by:
        authorized_by += f" (managed by {program.managed_by})"

    policy = ScopePolicy(
        name=program.name or program.handle,
        authorized_by=authorized_by,
        notes=(
            f"Compiled from {program.platform} program {program.handle}. "
            "Scope + rules of engagement are the program's; stay within them."
        ),
        allow_intrusive=allow_intrusive,
        web=WebScope(domains=_dedup(web)),
        api=ApiScope(base_urls=_dedup(api)),
        network=NetworkScope(hosts=_dedup(hosts), cidrs=_dedup(cidrs)),
        cloud=CloudScope(
            aws_account_ids=_dedup(aws),
            azure_subscription_ids=_dedup(azure),
            gcp_project_ids=_dedup(gcp),
        ),
        exclusions=ExclusionScope(
            hosts=_dedup(excl_hosts),
            urls=_dedup(excl_urls),
            cidrs=_dedup(excl_cidrs),
        ),
    )
    return CompiledScope(policy=policy, unmapped=_dedup(unmapped))

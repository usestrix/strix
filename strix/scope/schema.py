"""The ``scope.yaml`` schema and the pure scope evaluator.

``ScopePolicy`` is the authorization contract every domain tool builds against. It
models what the engagement is allowed to touch per domain, plus the
``allow_intrusive`` gate for state-changing actions. ``evaluate`` classifies a
target string and returns an allow/deny :class:`ScopeDecision` with a
human-readable reason — fail-closed: anything not matched is denied.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, field_validator


TargetKind = Literal["web", "api", "network", "cloud", "unknown"]


@dataclass(frozen=True)
class ScopeDecision:
    """Outcome of a scope check.

    ``allowed`` is the only thing a caller must gate on; ``reason`` is for logs and
    for the message the agent shows when it refuses. ``category`` records which
    domain section (if any) matched, and ``matched`` the specific entry. Build these
    with :meth:`allow` / :meth:`deny` rather than a positional boolean.
    """

    allowed: bool
    reason: str
    kind: TargetKind = "unknown"
    category: str | None = None
    matched: str | None = None

    def __bool__(self) -> bool:
        return self.allowed

    @classmethod
    def allow(
        cls,
        reason: str,
        kind: TargetKind = "unknown",
        category: str | None = None,
        matched: str | None = None,
    ) -> ScopeDecision:
        return cls(allowed=True, reason=reason, kind=kind, category=category, matched=matched)

    @classmethod
    def deny(
        cls,
        reason: str,
        kind: TargetKind = "unknown",
        category: str | None = None,
        matched: str | None = None,
    ) -> ScopeDecision:
        return cls(allowed=False, reason=reason, kind=kind, category=category, matched=matched)


def _norm_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def _host_matches(host: str, pattern: str) -> bool:
    """Exact host match, or a leading ``*.`` wildcard covering subdomains.

    ``*.example.com`` matches ``a.example.com`` and ``example.com`` itself, but not
    an unrelated ``notexample.com``.
    """
    host = _norm_host(host)
    pattern = _norm_host(pattern)
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)
    return host == pattern


class WebScope(BaseModel):
    """Authorized web origins. ``domains`` accepts ``example.com`` or ``*.example.com``."""

    model_config = ConfigDict(extra="forbid")

    domains: list[str] = []


class ApiScope(BaseModel):
    """Authorized API base URLs (prefix-matched against a request URL)."""

    model_config = ConfigDict(extra="forbid")

    base_urls: list[str] = []


class NetworkScope(BaseModel):
    """Authorized network targets: single hosts/IPs, CIDR ranges, and optional ports.

    ``ports`` is a port allowlist; ``None`` (the default) authorizes every port on an
    in-scope host, while ``[]`` authorizes none.
    """

    model_config = ConfigDict(extra="forbid")

    hosts: list[str] = []
    cidrs: list[str] = []
    ports: list[int] | None = None

    @field_validator("cidrs")
    @classmethod
    def _validate_cidrs(cls, value: list[str]) -> list[str]:
        for cidr in value:
            ipaddress.ip_network(cidr, strict=False)  # raises ValueError on garbage
        return value

    @field_validator("ports")
    @classmethod
    def _validate_ports(cls, value: list[int] | None) -> list[int] | None:
        if value is None:
            return None
        for port in value:
            if not 1 <= port <= 65535:
                msg = f"port out of range 1-65535: {port}"
                raise ValueError(msg)
        return value


class CloudScope(BaseModel):
    """Authorized cloud principals/accounts and optional region allowlist.

    A target is named as ``<provider>:<id>`` (e.g. ``aws:123456789012``), a bare
    12-digit AWS account id, or an AWS ARN — the evaluator normalizes these.
    """

    model_config = ConfigDict(extra="forbid")

    aws_account_ids: list[str] = []
    azure_subscription_ids: list[str] = []
    gcp_project_ids: list[str] = []
    regions: list[str] | None = None

    @field_validator("aws_account_ids")
    @classmethod
    def _validate_aws(cls, value: list[str]) -> list[str]:
        for acct in value:
            if not (acct.isdigit() and len(acct) == 12):
                msg = f"AWS account id must be 12 digits: {acct!r}"
                raise ValueError(msg)
        return value


class ScopePolicy(BaseModel):
    """The full authorized-scope policy loaded from ``scope.yaml``.

    Metadata (``name``, ``authorized_by``, ``notes``) is for the record and the
    report header; the domain sections drive :meth:`evaluate`.
    """

    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    authorized_by: str | None = None
    notes: str | None = None

    allow_intrusive: bool = False

    web: WebScope = WebScope()
    api: ApiScope = ApiScope()
    network: NetworkScope = NetworkScope()
    cloud: CloudScope = CloudScope()

    # ---- evaluation ------------------------------------------------------

    def evaluate(self, target: str, *, intrusive: bool = False) -> ScopeDecision:
        """Return an allow/deny decision for ``target``.

        Fail-closed: a target that matches no authorized entry is denied. An
        ``intrusive`` action is denied unless ``allow_intrusive`` is set, even when
        the target itself is in scope.
        """
        raw = (target or "").strip()
        if not raw:
            return ScopeDecision.deny("empty target")

        if intrusive and not self.allow_intrusive:
            return ScopeDecision.deny(
                "intrusive/state-changing action refused: allow_intrusive is false "
                "(re-run with --allow-intrusive once authorized)",
                self._classify(raw),
            )

        kind = self._classify(raw)
        if kind == "cloud":
            return self._check_cloud(raw)
        if kind in ("web", "api"):
            return self._check_url(raw)
        return self._check_network(raw)

    # ---- classification --------------------------------------------------

    def _classify(self, target: str) -> TargetKind:
        low = target.lower()
        if low.startswith(("aws:", "azure:", "gcp:", "arn:")):
            return "cloud"
        if "://" in low:
            return "web"
        if target.isdigit() and len(target) == 12:  # bare AWS account id
            return "cloud"
        return "network"

    # ---- per-domain checks ----------------------------------------------

    def _check_url(self, target: str) -> ScopeDecision:
        parsed = urlsplit(target if "://" in target else f"//{target}", scheme="https")
        host = parsed.hostname
        if not host:
            return ScopeDecision.deny(f"could not parse host from URL: {target!r}", "web")

        for base in self.api.base_urls:
            if _url_prefix_matches(target, base):
                reason = f"matches api.base_urls entry {base!r}"
                return ScopeDecision.allow(reason, "api", "api", base)

        for domain in self.web.domains:
            if _host_matches(host, domain):
                port_ok, port_reason = self._port_ok(parsed.port)
                if not port_ok:
                    return ScopeDecision.deny(port_reason, "web", "web", domain)
                return ScopeDecision.allow(
                    f"host {host} matches web.domains entry {domain!r}", "web", "web", domain
                )

        # A URL can also point at an authorized network host/IP. When the host
        # matched a network entry (``matched`` set) we return that decision even if
        # it denied — so a specific port refusal isn't masked by the generic reason.
        net = self._check_network(host, port=parsed.port)
        if net.allowed or net.matched is not None:
            return net
        return ScopeDecision.deny(f"host {host} is not in web/api/network scope", "web")

    def _check_network(self, target: str, *, port: int | None = None) -> ScopeDecision:
        host = _norm_host(target.split("/", 1)[0])
        ip = _as_ip(host)

        if ip is not None:
            for cidr in self.network.cidrs:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    return self._net_ok(f"{ip} in CIDR {cidr}", cidr, port)
            for entry in self.network.hosts:
                entry_ip = _as_ip(_norm_host(entry))
                if entry_ip is not None and entry_ip == ip:
                    return self._net_ok(f"{ip} matches network.hosts entry", entry, port)
            return ScopeDecision.deny(f"{ip} is not in any authorized CIDR or host", "network")

        for entry in self.network.hosts:
            if _host_matches(host, entry):
                return self._net_ok(f"{host} matches network.hosts entry {entry!r}", entry, port)
        for domain in self.web.domains:  # a hostname may be authorized as a web domain
            if _host_matches(host, domain):
                return self._net_ok(f"{host} matches web.domains entry {domain!r}", domain, port)
        return ScopeDecision.deny(f"host {host} is not in network/web scope", "network")

    def _net_ok(self, reason: str, matched: str, port: int | None) -> ScopeDecision:
        port_ok, port_reason = self._port_ok(port)
        if not port_ok:
            return ScopeDecision.deny(port_reason, "network", "network", matched)
        return ScopeDecision.allow(reason, "network", "network", matched)

    def _port_ok(self, port: int | None) -> tuple[bool, str]:
        if port is None or self.network.ports is None:
            return True, ""
        if port in self.network.ports:
            return True, ""
        return False, f"port {port} is not in the authorized port allowlist {self.network.ports}"

    def _check_cloud(self, target: str) -> ScopeDecision:
        provider, ident = _parse_cloud_target(target)
        table = {
            "aws": self.cloud.aws_account_ids,
            "azure": self.cloud.azure_subscription_ids,
            "gcp": self.cloud.gcp_project_ids,
        }
        allowed = table.get(provider, [])
        if ident and ident in allowed:
            return ScopeDecision.allow(
                f"{provider} account {ident} is authorized", "cloud", provider, ident
            )
        return ScopeDecision.deny(
            f"{provider} account {ident or '?'} is not in cloud.{provider}_* scope",
            "cloud",
            provider,
        )


def _as_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _url_prefix_matches(target: str, base: str) -> bool:
    """Whether ``target`` is at or under the authorized ``base`` URL.

    A plain ``startswith`` is too loose for an authorization boundary: it lets an
    authorized base like ``https://api.example.com/v1`` also match
    ``https://api.example.com/v1extra`` (same-host path-scope widening), and a
    base with no path match a look-alike host such as
    ``https://api.example.com.evil.com``. So after the prefix check we require the
    remainder to start on a path/query/fragment boundary (or be empty).
    """

    def norm(u: str) -> str:
        u = u.strip()
        if "://" not in u:
            u = f"https://{u}"
        return u.rstrip("/").lower()

    normalized_target = norm(target)
    normalized_base = norm(base)
    if not normalized_target.startswith(normalized_base):
        return False
    remainder = normalized_target[len(normalized_base) :]
    return remainder == "" or remainder[0] in "/?#"


def _parse_cloud_target(target: str) -> tuple[str, str | None]:
    """Normalize a cloud target to ``(provider, identifier)``.

    Accepts ``aws:123456789012``, a bare 12-digit AWS id, or an AWS ARN
    (``arn:aws:...:123456789012:...`` — the account id is field 5).
    """
    low = target.lower()
    if low.startswith("arn:aws:"):
        parts = target.split(":")
        acct = parts[4] if len(parts) > 4 and parts[4] else None
        return "aws", acct
    for provider in ("aws", "azure", "gcp"):
        if low.startswith(provider + ":"):
            return provider, target.split(":", 1)[1].strip() or None
    if target.isdigit() and len(target) == 12:
        return "aws", target
    return "unknown", target

"""Deterministic version-range verify for dependency-CVE findings.

The code-sink verifier (report/verify.py) answers a REASONING question — is the
sink reachable + the control complete. A dependency-CVE false positive is a
different, FACTUAL question: is the installed version actually in the advisory's
vulnerable range? That's deterministic — a range check, no LLM — and more reliable
than any model for this sub-class (version-range containment is exact). This is
the "promote to a deterministic control" pattern.

FP shape this catches: an agent files "CVE-XXXX in pkg@1.2.3" but 1.2.3 is OUT of
the advisory's affected range (already patched, or the CVE was mis-attributed to
the package). The provider is asked "which advisories affect pkg@version"; if the
finding's CVE/GHSA isn't among them, the installed version is not vulnerable → reject.

PROVIDER-PLUGGABLE (Strix is global FOSS — not everyone can/will call a hosted
advisory API: air-gapped scans, data-residency rules, orgs with their own advisory
DB). The provider is selected by DepVerifySettings.provider:
  "osv"  -> query an OSV-schema endpoint (default api.osv.dev; override
            STRIX_OSV_URL for a self-hosted OSV mirror — identical /v1/query
            contract, so no code change, just the URL).
  "none" -> disabled.
An AdvisoryProvider returns the set of advisory ids/aliases affecting a given
package@version, or None when it cannot answer (→ fail-open, emit).

SAFETY (fail-open, asymmetric — never suppress a real dep finding):
  - reject ONLY when the provider gives a definitive, non-empty answer AND the
    finding's CVE/GHSA is provably absent from it;
  - any uncertainty EMITS: provider disabled/unreachable/errors, package/version/
    ecosystem unparseable, non-CVE/GHSA id, empty result (coverage gap), or the
    provider lists the CVE → return None (emit).

No LLM. No extra package (OSV provider uses `requests`, already a core dep).
"""

from __future__ import annotations

import logging
import os
from typing import Any, Protocol

import requests

from strix.config import load_settings


logger = logging.getLogger(__name__)

# Map common ecosystem strings (as agents/trivy emit them) to OSV's canonical set.
_ECOSYSTEM = {
    "npm": "npm", "node": "npm", "javascript": "npm", "yarn": "npm",
    "pypi": "PyPI", "pip": "PyPI", "python": "PyPI",
    "go": "Go", "golang": "Go", "gomod": "Go",
    "maven": "Maven", "java": "Maven", "gradle": "Maven",
    "cargo": "crates.io", "rust": "crates.io", "crates.io": "crates.io",
    "rubygems": "RubyGems", "ruby": "RubyGems", "gem": "RubyGems",
    "nuget": "NuGet", "composer": "Packagist", "packagist": "Packagist",
}


def _norm_ecosystem(eco: str | None) -> str | None:
    return _ECOSYSTEM.get((eco or "").strip().lower())


def _ids_for(vuln: dict) -> set[str]:
    """All identifiers an OSV advisory is known by (its id + aliases), upper-cased."""
    ids = {str(vuln.get("id", "")).upper()}
    ids.update(str(a).upper() for a in (vuln.get("aliases") or []))
    return {i for i in ids if i}


class AdvisoryProvider(Protocol):
    """Given a package coordinate, return the set of advisory ids/aliases (upper-
    cased, e.g. {'CVE-...','GHSA-...'}) affecting THAT exact version — or None when
    the provider cannot answer (→ caller fails open and emits the finding).

    An empty set means a definitive "no advisories affect this version"; None means
    "don't know" (unreachable / error / not covered). The distinction matters: the
    caller only rejects on a definitive, non-empty answer that omits the cited id."""

    def affecting(self, pkg: str, ecosystem: str, version: str) -> set[str] | None: ...


class OsvProvider:
    """AdvisoryProvider backed by an OSV-schema /v1/query endpoint. Default
    api.osv.dev; point `url` at a self-hosted OSV mirror (identical contract) for
    air-gapped / data-residency deployments. Uses `requests` (a core dep) — no
    extra package."""

    def __init__(self, url: str) -> None:
        self.url = url

    def affecting(self, pkg: str, ecosystem: str, version: str) -> set[str] | None:
        try:
            ca = os.environ.get("REQUESTS_CA_BUNDLE")
            resp = requests.post(
                self.url, timeout=20,
                json={"package": {"name": pkg, "ecosystem": ecosystem}, "version": version},
                verify=ca if ca else True,
            )
            if resp.status_code != 200:
                logger.info("dep-verify: OSV %s for %s@%s; can't answer",
                            resp.status_code, pkg, version)
                return None
            vulns = resp.json().get("vulns", []) or []
        except Exception:  # noqa: BLE001 — advisory; a hiccup must never suppress a finding
            logger.info("dep-verify: OSV query failed for %s@%s; can't answer",
                        pkg, version, exc_info=True)
            return None
        affecting: set[str] = set()
        for v in vulns:
            affecting |= _ids_for(v)
        return affecting


def _resolve_provider(dep_settings: Any) -> AdvisoryProvider | None:
    """Build the AdvisoryProvider from DepVerifySettings. None => disabled/unknown
    provider => the check is a no-op (fail-open)."""
    provider = (getattr(dep_settings, "provider", "osv") or "").strip().lower()
    if provider in ("", "none", "off"):
        return None
    if provider == "osv":
        return OsvProvider(getattr(dep_settings, "osv_url", "https://api.osv.dev/v1/query"))
    logger.info("dep-verify: unknown provider %r; check disabled", provider)
    return None


def verify_dependency(  # noqa: PLR0911 — the returns are deliberate fail-open guard clauses
    candidate: dict[str, Any], provider: AdvisoryProvider | None = None
) -> dict[str, Any] | None:
    """Deterministically check a dep-CVE finding's version is in the CVE's range.

    candidate needs: cve (or ghsa), package_name, installed_version, package_ecosystem.
    `provider` overrides the settings-resolved one (used by tests); when omitted it
    is built from DepVerifySettings. Returns a REJECT dict when the installed
    version is provably NOT affected by the cited advisory; None (emit) on any
    uncertainty (fail-open)."""
    cve = str(candidate.get("cve") or "").strip().upper()
    ghsa = str(candidate.get("ghsa") or "").strip().upper()
    ident = cve or ghsa
    pkg = str(candidate.get("package_name") or "").strip()
    version = str(candidate.get("installed_version") or "").strip()
    eco = _norm_ecosystem(candidate.get("package_ecosystem"))

    # Need all four to make a definitive call; otherwise emit.
    if not (ident and pkg and version and eco):
        return None
    # Only CVE/GHSA identifiers are resolvable by advisory providers.
    if not ident.startswith(("CVE-", "GHSA-")):
        return None

    if provider is None:
        provider = _resolve_provider(load_settings().dep_verify)
        if provider is None:
            return None  # disabled / unknown provider → emit

    affecting = provider.affecting(pkg, eco, version)
    if affecting is None:
        return None  # provider couldn't answer → fail open, emit
    if ident in affecting:
        return None  # confirmed: installed version IS in the CVE's range → emit (real)
    if not affecting:
        # definitive "no advisories affect this version" is still a coverage-gap
        # risk (private/vendored pkg, provider lag) → fail open, emit.
        logger.info("dep-verify: provider lists NO advisories for %s@%s; emitting "
                    "(coverage gap, not a confident FP)", pkg, version)
        return None

    # Provider knows advisories for this version but NOT the cited one → the
    # installed version is out of the cited CVE's range → false positive.
    return {
        "success": False,
        "error": (
            f"Version-range verify rejected this dependency finding: {ident} does "
            f"not affect {pkg}@{version} per the advisory provider (installed "
            f"version is outside the advisory's vulnerable range — likely already "
            f"patched or the CVE is mis-attributed to this package). Advisories "
            f"affecting {pkg}@{version}: {sorted(affecting)}. If you believe the "
            f"version IS vulnerable, cite the exact affected range."
        ),
        "verify_rejected": True,
        "dep_version_out_of_range": True,
        "installed_version": version,
        "cited_advisory": ident,
    }

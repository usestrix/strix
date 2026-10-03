"""The bug-bounty program model: scope, rules of engagement, and metadata.

A :class:`BountyProgram` is the platform-neutral record a loader produces for one
HackerOne / Bugcrowd program. It carries the two things the engine needs to run a
bounty engagement safely:

* **scope** — the ``in_scope`` / ``out_of_scope`` assets, which
  :func:`strix.bounty.compile.compile_to_scope` turns into a fail-closed
  :class:`~strix.scope.schema.ScopePolicy`; and
* **rules of engagement** (:class:`RulesOfEngagement`) — what the program allows and
  forbids (automated testing, intrusive proofs, rate limits, prohibited techniques,
  ineligible bug classes), which :func:`strix.bounty.roe.evaluate_roe` turns into a
  go/no-go gate plus the constraint block the agents must obey.

The model is deliberately pure and dependency-light (pydantic only) so it is easy to
load from a saved file, to synthesize in a test, or to build from a platform API
response, and so it stays trivially rebaseable.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


BountyPlatform = Literal["hackerone", "bugcrowd", "other"]

# How an in-scope / out-of-scope asset should be interpreted when compiling a
# ScopePolicy. ``other`` (the default) means "not a target the network scope engine
# can gate" — mobile apps, source bundles, binaries — recorded for the agent to read
# but not mapped to a scope entry.
AssetType = Literal[
    "wildcard",  # *.example.com
    "domain",  # example.com
    "url",  # https://example.com/app
    "api",  # an API base URL, prefix-matched
    "ip",  # a single IPv4/IPv6
    "cidr",  # an IP range
    "cloud_aws",
    "cloud_azure",
    "cloud_gcp",
    "android",
    "ios",
    "source",
    "executable",
    "other",
]


class ScopeAsset(BaseModel):
    """One asset the program lists as in or out of scope.

    ``identifier`` is the raw string the program published (``*.example.com``,
    ``https://api.example.com``, ``10.0.0.0/24``, ``aws:123456789012``, a package
    name, …). ``asset_type`` is the loader's classification; when it is left at the
    default ``other`` the compiler falls back to a heuristic on the identifier.
    """

    model_config = ConfigDict(extra="forbid")

    identifier: str
    asset_type: AssetType = "other"
    eligible_for_bounty: bool = True
    instruction: str | None = None


class RulesOfEngagement(BaseModel):
    """What the program permits and forbids — the behavioral contract for a run.

    Unknowns are expressed as ``None`` rather than a guessed default, so the ROE gate
    can treat "the program did not say" conservatively instead of silently assuming
    permission. ``automated_testing_allowed=None`` means unstated (many programs are
    silent); ``False`` means the program explicitly bans scanners/automation.
    """

    model_config = ConfigDict(extra="forbid")

    automated_testing_allowed: bool | None = None
    state_changing_poc_allowed: bool = False
    rate_limit_rps: float | None = None
    required_headers: dict[str, str] = {}
    prohibited_actions: list[str] = []
    eligible_vuln_types: list[str] = []
    ineligible_vuln_types: list[str] = []
    pii_handling: str | None = None
    safe_harbor: bool | None = None
    notes: str | None = None


class BountyProgram(BaseModel):
    """A platform-neutral bug-bounty program: scope + rules + metadata."""

    model_config = ConfigDict(extra="forbid")

    platform: BountyPlatform
    handle: str
    name: str | None = None
    url: str | None = None
    managed_by: str | None = None

    in_scope: list[ScopeAsset] = []
    out_of_scope: list[ScopeAsset] = []
    roe: RulesOfEngagement = RulesOfEngagement()

    fetched_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    @property
    def slug(self) -> str:
        """A filesystem-safe ``platform_handle`` identifier for run artifacts."""
        safe = "".join(c if c.isalnum() or c in "-_" else "-" for c in self.handle.strip())
        return f"{self.platform}_{safe or 'program'}"

    def eligible_in_scope(self) -> list[ScopeAsset]:
        """In-scope assets that are eligible for a bounty (what to prioritize)."""
        return [a for a in self.in_scope if a.eligible_for_bounty]

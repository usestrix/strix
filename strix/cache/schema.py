"""Schema + key derivation for a cross-run recon cache entry.

A recon result — an enumeration/mapping output that is relatively stable across runs
(a port scan, subdomain enumeration, a cloud resource listing) — keyed by
``(tool, normalized target, params)`` so a later run can reuse it instead of
re-running the expensive scan. This pays off most over an LLM gateway with no prompt
caching (e.g. 9Router), where every recon turn the agent *doesn't* have to repeat is
full context it isn't re-billed for.

The entry records when it was captured and its TTL so a consumer can judge staleness.
It is advisory evidence of a prior observation, never a substitute for re-verifying
time-sensitive state before acting on it.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

# Reuse the finding/candidate target normalization so the cache keys the same way the
# rest of Strix 2 does (scheme- and trailing-slash-insensitive).
from strix.candidates.schema import normalize_target


# 24h: recon drifts, so a cached result is reused by default only for a day.
DEFAULT_TTL_SECONDS = 24 * 60 * 60


def normalize_tool(tool: str) -> str:
    """Normalize a tool name for keying: lowercase, collapsed whitespace."""
    return " ".join((tool or "").strip().lower().split())


def normalize_params(params: str) -> str:
    """Normalize a params string for keying: trimmed, collapsed whitespace."""
    return " ".join((params or "").strip().split())


def cache_key(tool: str, target: str, params: str = "") -> str:
    """Stable cache key for a ``(tool, target, params)`` recon triple."""
    composite = "\x00".join(
        (normalize_tool(tool), normalize_target(target), normalize_params(params))
    )
    return hashlib.sha256(composite.encode("utf-8")).hexdigest()[:40]


def _now() -> datetime:
    return datetime.now(UTC)


class ReconCacheEntry(BaseModel):
    """One cached recon result, persisted as a single JSON file by its ``key``."""

    model_config = ConfigDict(extra="forbid")

    key: str
    tool: str
    target: str
    normalized_target: str
    params: str = ""
    result: str
    size_bytes: int = 0
    created_at: str = Field(default_factory=lambda: _now().isoformat())
    ttl_seconds: int = DEFAULT_TTL_SECONDS
    run_id: str | None = None
    agent_id: str | None = None
    agent_name: str | None = None

    def age_seconds(self, *, now: datetime | None = None) -> float:
        ref = now or _now()
        try:
            created = datetime.fromisoformat(self.created_at)
        except ValueError:
            return float("inf")
        if created.tzinfo is None:
            created = created.replace(tzinfo=UTC)
        return max(0.0, (ref - created).total_seconds())

    def is_fresh(
        self, *, now: datetime | None = None, max_age_seconds: int | None = None
    ) -> bool:
        """Whether this entry is within its TTL (and an optional stricter ``max_age``)."""
        limit = self.ttl_seconds
        if max_age_seconds is not None:
            limit = min(limit, max_age_seconds)
        if limit <= 0:
            return False
        return self.age_seconds(now=now) <= limit

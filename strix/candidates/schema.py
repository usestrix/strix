"""The candidate (lead) record schema.

A ``Candidate`` is a lead a tool or recon step produced whose impact is not yet
demonstrated. It carries just enough to be triaged, deduped, and later promoted to
a validated finding or dismissed — deliberately a *low* bar (no PoC), the opposite
of the validated gate in ``strix/tools/reporting/tool.py``.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


CandidateDomain = Literal["web", "api", "network", "cloud", "infra", "dependency", "other"]
CandidateStatus = Literal["open", "promoted", "dismissed"]

_WS = re.compile(r"\s+")


def normalize_target(target: str) -> str:
    """Normalize a target for dedup: lowercase, no scheme, no trailing slash."""
    text = (target or "").strip().lower()
    text = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", text)
    return _WS.sub(" ", text).rstrip("/")


def _normalize_title(title: str) -> str:
    return _WS.sub(" ", (title or "").strip().lower())


class Candidate(BaseModel):
    """A lead awaiting validation.

    ``dedup_key`` (domain + normalized target + normalized title) makes structural
    duplicate detection deterministic. ``status`` moves ``open`` → ``promoted``
    (with ``promoted_to`` naming the validated report) or ``dismissed`` (with
    ``resolution`` stating why it was ruled out).
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    target: str
    domain: CandidateDomain
    source: str
    rationale: str

    status: CandidateStatus = "open"
    promoted_to: str | None = None
    resolution: str | None = None

    agent_id: str | None = None
    agent_name: str | None = None
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    @property
    def dedup_key(self) -> str:
        return f"{self.domain}|{normalize_target(self.target)}|{_normalize_title(self.title)}"

    def touch(self) -> None:
        self.updated_at = datetime.now(UTC).isoformat()


def structural_match(title: str, target: str, other_title: str, other_target: str) -> bool:
    """Whether two records describe the same lead on the same asset (structural)."""
    return (
        normalize_target(target) == normalize_target(other_target)
        and _normalize_title(title) == _normalize_title(other_title)
    )

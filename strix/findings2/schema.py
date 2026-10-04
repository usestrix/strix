"""Schema for a finding annotation (optional framework/domain metadata).

An annotation hangs off a validated finding by its ``vuln_report_id`` and carries the
*optional* fields from validator semantics §6 — never anything that would gate a
finding. CVSS + CWE stay the required rating on the finding itself; these are the
"nice to have, prompt per class" additions (decision 6a).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Runtime import (not TYPE_CHECKING): pydantic resolves the field annotation at
# model-build time, so CandidateDomain must be in the runtime namespace.
from strix.candidates.schema import CandidateDomain  # noqa: TC001


_MITRE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def parse_ids(raw: str) -> list[str]:
    """Split a comma/space-separated id string into a de-duplicated, ordered list."""
    seen: dict[str, None] = {}
    for token in re.split(r"[,\s]+", (raw or "").strip()):
        if token:
            seen.setdefault(token, None)
    return list(seen)


def invalid_mitre_ids(ids: list[str]) -> list[str]:
    """Return the ids that are not well-formed MITRE ATT&CK technique ids."""
    return [technique for technique in ids if not _MITRE_RE.match(technique)]


class FindingAnnotation(BaseModel):
    """Optional framework/domain metadata attached to one validated finding."""

    model_config = ConfigDict(extra="forbid")

    vuln_report_id: str
    domain: CandidateDomain | None = None
    mitre_attack: list[str] = []
    cis_benchmark: list[str] = []
    notes: str = ""

    agent_id: str | None = None
    agent_name: str | None = None
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    @field_validator("mitre_attack")
    @classmethod
    def _validate_mitre(cls, value: list[str]) -> list[str]:
        for technique in value:
            if not _MITRE_RE.match(technique):
                msg = (
                    f"invalid MITRE ATT&CK technique id: {technique!r} "
                    "(expected e.g. T1530 or T1078.001)"
                )
                raise ValueError(msg)
        return value

    def touch(self) -> None:
        self.updated_at = datetime.now(UTC).isoformat()

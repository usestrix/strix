"""Two-tier finding model — the candidate (lead) tier.

Phase 4 (see ``docs/strix2/04-validator-semantics.md``, decisions accepted) splits
findings into **candidates** (scanner/recon/static leads, impact not yet
demonstrated) and **validated** findings (upstream's ``ReportState``, unchanged).
Candidates are first-class, deduped, persisted records that render in a separate
"Leads" section and never count as findings — so scanner noise can never be
laundered into a report.

Kept as a self-contained package (no edits to ``strix.report.state``) so it stays
rebaseable; the store reads the run directory from the global report state but
never mutates it.
"""

from __future__ import annotations

from strix.candidates.schema import Candidate, CandidateStatus, normalize_target
from strix.candidates.store import (
    CandidateStore,
    get_candidate_store,
    reset_candidate_store,
    set_candidate_store,
)


__all__ = [
    "Candidate",
    "CandidateStatus",
    "CandidateStore",
    "get_candidate_store",
    "normalize_target",
    "reset_candidate_store",
    "set_candidate_store",
]

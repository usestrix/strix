"""In-run storage for candidate (lead) records.

Mirrors the shape of ``ReportState`` for validated findings but stays separate: it
persists ``candidates.json`` into the run directory and never mutates the report
state. The store is dependency-light — callers pass in the current validated
findings for cross-tier dedup, so this module imports nothing from
``strix.report``.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from strix.candidates.schema import Candidate, CandidateStatus, structural_match
from strix.candidates.writer import write_leads


if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)

_CANDIDATES_FILENAME = "candidates.json"


class CandidateStore:
    """Holds this run's candidate leads and persists them to ``candidates.json``."""

    def __init__(self, run_dir: Path | None = None) -> None:
        self.run_dir = run_dir
        self.candidates: list[Candidate] = []
        self._counter = 0

    # ---- reads -----------------------------------------------------------

    def get(self, candidate_id: str) -> Candidate | None:
        cid = (candidate_id or "").strip()
        return next((c for c in self.candidates if c.id == cid), None)

    def all_candidates(self, status: CandidateStatus | None = None) -> list[Candidate]:
        if status is None:
            return list(self.candidates)
        return [c for c in self.candidates if c.status == status]

    # ---- writes ----------------------------------------------------------

    def add(
        self,
        *,
        title: str,
        target: str,
        domain: str,
        source: str,
        rationale: str,
        agent_id: str | None = None,
        agent_name: str | None = None,
        existing_validated: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """File a new candidate, or report a structural duplicate instead.

        A duplicate of an existing open/promoted candidate, or of a validated
        finding on the same asset, is refused (deduped) rather than stored twice.
        """
        probe = Candidate(
            id="cand-pending",
            title=title,
            target=target,
            domain=domain,  # type: ignore[arg-type]  # validated by the model
            source=source,
            rationale=rationale,
        )

        for existing in self.candidates:
            if existing.status != "dismissed" and existing.dedup_key == probe.dedup_key:
                return {
                    "status": "duplicate_candidate",
                    "duplicate_of": existing.id,
                    "message": f"Already filed as candidate {existing.id}; not duplicated.",
                }

        for finding in existing_validated if existing_validated else []:
            if structural_match(title, target, finding.get("title", ""), finding.get("target", "")):
                return {
                    "status": "already_validated",
                    "duplicate_of": finding.get("id"),
                    "message": (
                        f"A validated finding ({finding.get('id')}) already covers this on the "
                        "same asset; file evidence there, not as a lead."
                    ),
                }

        self._counter += 1
        candidate = probe.model_copy(
            update={
                "id": f"cand-{self._counter:04d}",
                "agent_id": agent_id,
                "agent_name": agent_name,
            }
        )
        self.candidates.append(candidate)
        self._persist()
        logger.info(
            "Candidate filed: id=%s domain=%s source=%s target=%s",
            candidate.id,
            candidate.domain,
            candidate.source,
            candidate.target,
        )
        return {"status": "created", "candidate": candidate.model_dump()}

    def promote(self, candidate_id: str, vuln_report_id: str, note: str = "") -> Candidate | None:
        """Mark a candidate promoted to a validated finding (which was filed separately)."""
        candidate = self.get(candidate_id)
        if candidate is None:
            return None
        candidate.status = "promoted"
        candidate.promoted_to = vuln_report_id.strip()
        candidate.resolution = note.strip() or f"promoted to {vuln_report_id.strip()}"
        candidate.touch()
        self._persist()
        return candidate

    def dismiss(self, candidate_id: str, reason: str) -> Candidate | None:
        """Rule a candidate out (kept for the coverage/recall record, not shown as a finding)."""
        candidate = self.get(candidate_id)
        if candidate is None:
            return None
        candidate.status = "dismissed"
        candidate.resolution = reason.strip()
        candidate.touch()
        self._persist()
        return candidate

    # ---- persistence -----------------------------------------------------

    def _persist(self) -> None:
        if self.run_dir is None:
            return
        try:
            self.run_dir.mkdir(parents=True, exist_ok=True)
            path = self.run_dir / _CANDIDATES_FILENAME
            payload = [c.model_dump() for c in self.candidates]
            path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            write_leads(self.run_dir, self.candidates)
        except OSError:
            logger.warning("Could not persist candidates to %s", self.run_dir, exc_info=True)


_global_candidate_store: CandidateStore | None = None


def get_candidate_store() -> CandidateStore | None:
    return _global_candidate_store


def set_candidate_store(store: CandidateStore | None) -> None:
    global _global_candidate_store  # noqa: PLW0603
    _global_candidate_store = store


def reset_candidate_store(run_dir: Path | None = None) -> CandidateStore:
    """Create and register a fresh store for a run, bound to ``run_dir``.

    Called once at run start (by ``strix.strix2_ext``) with the known run
    directory so ``candidates.json`` lands beside ``vulnerabilities.json``.
    Rebinds only when the run directory changes, so calling it again is safe.
    """
    existing = get_candidate_store()
    if existing is not None and existing.run_dir == run_dir:
        return existing
    store = CandidateStore(run_dir=run_dir)
    set_candidate_store(store)
    return store

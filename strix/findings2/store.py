"""In-run storage for finding annotations.

Mirrors :class:`~strix.candidates.store.CandidateStore`: a separate, additive store
that persists ``finding_annotations.json`` (+ ``FRAMEWORK_MAP.md``) into the run
directory and never mutates ``ReportState``. Keyed by ``vuln_report_id`` — one
annotation per finding, merged on repeat so tags accumulate.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from strix.findings2.schema import FindingAnnotation
from strix.findings2.writer import write_framework_map


if TYPE_CHECKING:
    from pathlib import Path

    from strix.candidates.schema import CandidateDomain


logger = logging.getLogger(__name__)

_ANNOTATIONS_FILENAME = "finding_annotations.json"


def _merge(existing: list[str], new: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for item in (*existing, *new):
        seen.setdefault(item, None)
    return list(seen)


class FindingAnnotationStore:
    """Holds this run's finding annotations and persists them to disk."""

    def __init__(self, run_dir: Path | None = None) -> None:
        self.run_dir = run_dir
        self.annotations: dict[str, FindingAnnotation] = {}

    def get(self, vuln_report_id: str) -> FindingAnnotation | None:
        return self.annotations.get((vuln_report_id or "").strip())

    def all_annotations(self) -> list[FindingAnnotation]:
        return list(self.annotations.values())

    def upsert(
        self,
        *,
        vuln_report_id: str,
        domain: CandidateDomain | None = None,
        mitre_attack: list[str] | None = None,
        cis_benchmark: list[str] | None = None,
        notes: str = "",
        agent_id: str | None = None,
        agent_name: str | None = None,
    ) -> FindingAnnotation:
        """Create or merge the annotation for ``vuln_report_id``.

        Tag lists accumulate (union, order preserved); ``domain`` and ``notes`` are
        overwritten only when a non-empty value is supplied.
        """
        report_id = (vuln_report_id or "").strip()
        mitre = mitre_attack or []
        cis = cis_benchmark or []
        existing = self.annotations.get(report_id)
        if existing is not None:
            updated = existing.model_copy(
                update={
                    "domain": domain or existing.domain,
                    "mitre_attack": _merge(existing.mitre_attack, mitre),
                    "cis_benchmark": _merge(existing.cis_benchmark, cis),
                    "notes": notes.strip() or existing.notes,
                }
            )
            updated.touch()
            self.annotations[report_id] = updated
        else:
            self.annotations[report_id] = FindingAnnotation(
                vuln_report_id=report_id,
                domain=domain,
                mitre_attack=mitre,
                cis_benchmark=cis,
                notes=notes.strip(),
                agent_id=agent_id,
                agent_name=agent_name,
            )
        self._persist()
        return self.annotations[report_id]

    def _persist(self) -> None:
        if self.run_dir is None:
            return
        try:
            self.run_dir.mkdir(parents=True, exist_ok=True)
            payload = [a.model_dump() for a in self.annotations.values()]
            (self.run_dir / _ANNOTATIONS_FILENAME).write_text(
                json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            write_framework_map(self.run_dir, self.annotations.values())
        except OSError:
            logger.warning(
                "Could not persist finding annotations to %s", self.run_dir, exc_info=True
            )


_global_annotation_store: FindingAnnotationStore | None = None


def get_annotation_store() -> FindingAnnotationStore | None:
    return _global_annotation_store


def set_annotation_store(store: FindingAnnotationStore | None) -> None:
    global _global_annotation_store  # noqa: PLW0603
    _global_annotation_store = store


def reset_annotation_store(run_dir: Path | None = None) -> FindingAnnotationStore:
    """Create and register a fresh store for a run, bound to ``run_dir``. Idempotent."""
    existing = get_annotation_store()
    if existing is not None and existing.run_dir == run_dir:
        return existing
    store = FindingAnnotationStore(run_dir=run_dir)
    set_annotation_store(store)
    return store

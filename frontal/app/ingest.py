"""Fold a finished run directory into Postgres.

Runs in k8s write into an emptyDir that the Job reaps, so everything the
frontal needs long-term has to be pulled out here: the run record and the
vulnerability list. The run directory itself is kept on the artifacts volume
and is what the embedded viewer SPA reads back.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from frontal.app.fingerprint import finding_fingerprint
from frontal.app.models import Finding, FindingObservation, Scan
from frontal.app.runfiles import read_run_summary, read_vulnerabilities


logger = logging.getLogger(__name__)


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _coerce_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def apply_run_record(scan: Scan, record: dict[str, Any]) -> None:
    scan.run_name = record.get("run_name") or scan.run_name
    scan.started_at = _parse_time(record.get("start_time")) or scan.started_at
    scan.ended_at = _parse_time(record.get("end_time")) or scan.ended_at
    usage = record.get("llm_usage")
    if isinstance(usage, dict):
        scan.llm_usage = usage


def upsert_finding(session: Session, scan: Scan, vuln: dict[str, Any]) -> Finding:
    """Create or refresh the app-level finding this vulnerability belongs to."""
    fingerprint = finding_fingerprint(vuln)
    finding = session.scalar(
        select(Finding).where(Finding.app_id == scan.app_id, Finding.fingerprint == fingerprint)
    )
    if finding is None:
        finding = Finding(
            app_id=scan.app_id,
            fingerprint=fingerprint,
            first_seen_scan_id=scan.id,
        )
        session.add(finding)

    finding.title = str(vuln.get("title") or "Untitled finding")
    finding.severity = str(vuln.get("severity") or "low").lower().strip()
    finding.cvss = _coerce_float(vuln.get("cvss"))
    finding.cwe = (str(vuln.get("cwe")) or None) if vuln.get("cwe") else None
    finding.endpoint = vuln.get("endpoint") or None
    finding.method = (str(vuln.get("method")).upper() or None) if vuln.get("method") else None
    finding.last_seen_scan_id = scan.id
    finding.data = vuln
    # Seeing it again in any scan reopens it; an operator decision
    # (accepted / false_positive) is deliberately not overridden.
    if finding.status == "fixed":
        finding.status = "open"
    return finding


def record_observation(
    session: Session,
    scan: Scan,
    finding: Finding,
    vuln: dict[str, Any],
    verdict: str,
) -> FindingObservation:
    session.flush()
    existing = session.scalar(
        select(FindingObservation).where(
            FindingObservation.finding_id == finding.id,
            FindingObservation.scan_id == scan.id,
        )
    )
    observation = existing or FindingObservation(finding_id=finding.id, scan_id=scan.id)
    observation.vuln_id = vuln.get("id")
    observation.verdict = verdict
    observation.confidence = vuln.get("confidence")
    observation.evidence = vuln.get("evidence")
    observation.raw = vuln
    if existing is None:
        session.add(observation)
    return observation


def ingest_run(
    session: Session, scan: Scan, run_dir: Path, *, verdict: str = "observed"
) -> list[Finding]:
    """Ingest the run record + vulnerabilities; return the touched findings."""
    apply_run_record(scan, read_run_summary(run_dir))

    touched: list[Finding] = []
    for vuln in read_vulnerabilities(run_dir):
        if not isinstance(vuln, dict):
            continue
        finding = upsert_finding(session, scan, vuln)
        record_observation(session, scan, finding, vuln, verdict)
        touched.append(finding)

    logger.info("scan %s ingested %d findings", scan.id, len(touched))
    return touched

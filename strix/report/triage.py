"""Local human finding triage shared by the terminal UI and web viewer.

Scan evidence is never changed. The overlay is scoped to a run and reviewed
evidence digest; updated evidence becomes active until it is reviewed again.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections import Counter
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, cast

from strix.report.triage_store import (
    TriageError,
    can_write_triage,
    locked_store,
    read_json,
    triage_stamp,
    write_store,
)


if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path


REASON_CODES = (
    "unspecified",
    "incorrect_assumption",
    "existing_protection",
    "not_affected",
    "expected_behavior",
    "other",
)
MAX_NOTE_LENGTH = 2000
logger = logging.getLogger(__name__)
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
# Evidence, impact and scope determine what was reviewed. Titles, suggested
# fixes, timestamps and display formatting do not invalidate a human review.
_EVIDENCE_FIELDS = (
    "description",
    "impact",
    "technical_analysis",
    "evidence",
    "assumptions",
    "counterevidence",
    "confidence",
    "confidence_rationale",
    "severity_change_conditions",
    "poc_description",
    "poc_script_code",
    "target",
    "endpoint",
    "method",
    "cwe",
    "cve",
    "severity",
    "cvss",
    "code_locations",
    "dependency_metadata",
    "http_exchange_ids",
)


def _normalized(value: Any) -> Any:
    if isinstance(value, str):
        return value.replace("\r\n", "\n").strip()
    if isinstance(value, dict):
        return {key: _normalized(item) for key, item in cast("dict[str, Any]", value).items()}
    if isinstance(value, list):
        items = cast("Sequence[Any]", value)
        return [_normalized(item) for item in items]
    return value


def finding_digest(finding: dict[str, Any]) -> str:
    evidence = {key: _normalized(finding.get(key)) for key in _EVIDENCE_FIELDS}
    # Remediation suggestions inside locations are not evidence changes.
    locations = evidence.get("code_locations")
    if isinstance(locations, list):
        code_locations = cast("Sequence[Any]", locations)
        evidence["code_locations"] = [
            {
                key: value
                for key, value in cast("dict[str, Any]", location).items()
                if key not in {"fix_before", "fix_after"}
            }
            if isinstance(location, dict)
            else location
            for location in code_locations
        ]
    payload = json.dumps(evidence, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _run_identity(run_dir: Path) -> dict[str, Any]:
    record = read_json(run_dir / "run.json", default={})
    if not isinstance(record, dict):
        raise TriageError("invalid_triage", "The run record is malformed.")
    record = cast("dict[str, Any]", record)
    return {
        "run_id": record.get("run_id") or record.get("run_name") or run_dir.name,
        "start_time": record.get("start_time"),
    }


def _valid_id(value: Any) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _validate_decision(decision: Any) -> None:
    if not isinstance(decision, dict):
        raise TriageError("invalid_triage", "A saved review is malformed.")
    decision = cast("dict[str, Any]", decision)
    status = decision.get("status")
    if (
        not isinstance(status, str)
        or status not in {"open", "closed"}
        or type(decision.get("revision")) is not int
        or decision["revision"] < 1
        or decision.get("reason_code") not in REASON_CODES
        or not isinstance(decision.get("note"), str)
        or len(decision["note"]) > MAX_NOTE_LENGTH
        or not isinstance(decision.get("changed_at"), str)
        or decision.get("changed_by") != "local_operator"
        or not isinstance(decision.get("reviewed_digest"), str)
        or not _DIGEST.fullmatch(decision["reviewed_digest"])
        or decision.get("resolution_reason") != ("false_positive" if status == "closed" else None)
    ):
        raise TriageError("invalid_triage", "A saved review has unsupported fields.")


def _read_store(run_dir: Path) -> dict[str, Any]:
    identity = _run_identity(run_dir)
    missing = object()
    document = read_json(run_dir / "triage.json", default=missing)
    if document is missing:
        return {"schema_version": 1, "run_identity": identity, "findings": {}}
    if not isinstance(document, dict):
        raise TriageError("invalid_triage", "Review data belongs to another run or is unsupported.")
    document = cast("dict[str, Any]", document)
    if (
        type(document.get("schema_version")) is not int
        or document["schema_version"] != 1
        or document.get("run_identity") != identity
        or not isinstance(document.get("findings"), dict)
    ):
        raise TriageError("invalid_triage", "Review data belongs to another run or is unsupported.")
    for finding_id, raw_decision in cast("dict[str, Any]", document["findings"]).items():
        if not _valid_id(finding_id):
            raise TriageError("invalid_triage", "A saved finding ID is invalid.")
        _validate_decision(raw_decision)
        decision = cast("dict[str, Any]", raw_decision)
        history = decision.get("history")
        if not isinstance(history, list):
            raise TriageError("invalid_triage", "Review history is malformed.")
        entries = cast("Sequence[Any]", history)
        if len(entries) != decision["revision"]:
            raise TriageError("invalid_triage", "Review history is malformed.")
        for index, entry in enumerate(entries, 1):
            _validate_decision(entry)
            if entry["revision"] != index:
                raise TriageError("invalid_triage", "Review history revisions are inconsistent.")
        if {key: value for key, value in decision.items() if key != "history"} != entries[-1]:
            raise TriageError("invalid_triage", "Review history does not match the saved decision.")
    return document


def _read_findings(run_dir: Path) -> list[dict[str, Any]]:
    reports = read_json(run_dir / "vulnerabilities.json", default=[], limit=128 * 1024 * 1024)
    if not isinstance(reports, list):
        raise TriageError("invalid_triage", "The finding list is malformed.")
    records = cast("Sequence[Any]", reports)
    if any(not isinstance(item, dict) for item in records):
        raise TriageError("invalid_triage", "The finding list is malformed.")
    return cast("list[dict[str, Any]]", records)


def _project(
    report: dict[str, Any], decision: dict[str, Any] | None, *, writable: bool
) -> dict[str, Any]:
    saved = decision or {}
    digest = finding_digest(report)
    stored_status = saved.get("status", "open")
    stale = stored_status == "closed" and saved.get("reviewed_digest") != digest
    return {
        **report,
        "status": "open" if stale else stored_status,
        "triage_status": stored_status,
        "resolution_reason": saved.get("resolution_reason"),
        "reason_code": saved.get("reason_code", "unspecified"),
        "status_note": saved.get("note") or None,
        "status_changed_at": saved.get("changed_at"),
        "status_changed_by": saved.get("changed_by"),
        "triage_revision": saved.get("revision", 0),
        "finding_digest": digest,
        "review_stale": stale,
        "can_triage": writable,
        "triage_history": saved.get("history", []),
    }


def read_triaged_vulnerabilities(
    run_dir: Path, reports: list[dict[str, Any]] | None = None
) -> list[dict[str, Any]]:
    """Join a validated sidecar with disk or in-memory evidence without mutating it."""
    document = _read_store(run_dir)
    raw = _read_findings(run_dir) if reports is None else reports
    ids = Counter(item.get("id") for item in raw if _valid_id(item.get("id")))
    writable = can_write_triage(run_dir)
    return [
        _project(
            report,
            document["findings"].get(report.get("id")) if _valid_id(report.get("id")) else None,
            writable=writable and _valid_id(report.get("id")) and ids[report["id"]] == 1,
        )
        for report in raw
    ]


def _validate_request(
    finding_id: Any,
    status: Any,
    expected_revision: Any,
    reviewed_digest: Any,
    reason_code: Any,
    note: Any,
    surface: Any,
) -> None:
    if (
        not _valid_id(finding_id)
        or not isinstance(status, str)
        or status not in {"open", "closed"}
        or type(expected_revision) is not int
        or expected_revision < 0
        or not isinstance(reviewed_digest, str)
        or not _DIGEST.fullmatch(reviewed_digest)
        or not isinstance(reason_code, str)
        or reason_code not in REASON_CODES
        or not isinstance(note, str)
        or len(note) > MAX_NOTE_LENGTH
        or not isinstance(surface, str)
        or surface not in {"viewer", "tui"}
    ):
        raise TriageError("invalid_request", "Invalid finding review request.")


def triage_finding(
    run_dir: Path,
    finding_id: str,
    *,
    status: str,
    expected_revision: int,
    reviewed_digest: str,
    reason_code: str = "unspecified",
    note: str = "",
    surface: str,
) -> dict[str, Any]:
    """Commit a human decision, then enqueue only its bounded classification metadata."""
    _validate_request(
        finding_id, status, expected_revision, reviewed_digest, reason_code, note, surface
    )
    with locked_store(run_dir):
        if not (run_dir / "run.json").is_file():
            raise TriageError("unknown_finding", "The run record is missing.")
        document = _read_store(run_dir)
        reports = _read_findings(run_dir)
        matches = [report for report in reports if report.get("id") == finding_id]
        if len(matches) != 1:
            raise TriageError("unknown_finding", "The finding is missing or its ID is ambiguous.")
        report = matches[0]
        old = document["findings"].get(finding_id)
        previous = _project(report, old, writable=True)
        if previous["finding_digest"] != reviewed_digest:
            raise TriageError("conflict", "Finding evidence changed. Reload and review it again.")
        reason = reason_code if status == "closed" else "unspecified"
        saved_note = note.strip() if status == "closed" else ""
        same = (
            previous["status"] == status
            and not previous["review_stale"]
            and previous["reason_code"] == reason
            and (previous["status_note"] or "") == saved_note
        )
        # A retry with the immediately preceding revision is an idempotent no-op.
        revision = previous["triage_revision"]
        if expected_revision != revision:
            if same and old is not None and expected_revision == revision - 1:
                return {"changed": False, "finding": previous}
            raise TriageError(
                "conflict", "This finding was reviewed elsewhere. Reload before saving."
            )
        if same:
            return {"changed": False, "finding": previous}
        decision: dict[str, Any] = {
            "status": status,
            "resolution_reason": "false_positive" if status == "closed" else None,
            "reason_code": reason,
            "note": saved_note,
            "changed_at": datetime.now(UTC).isoformat(),
            "changed_by": "local_operator",
            "revision": revision + 1,
            "reviewed_digest": reviewed_digest,
        }
        history: list[dict[str, Any]] = [*(old["history"] if old else []), decision.copy()]
        document["findings"][finding_id] = {**decision, "history": history}
        write_store(run_dir, document)
        result = _project(report, document["findings"][finding_id], writable=True)
    # Notes-only edits remain entirely local. Never allow analytics failure to
    # turn a committed local review into an apparent save failure.
    if (
        previous["status"] != status
        or previous["reason_code"] != reason
        or previous["review_stale"]
    ):
        try:
            from strix.telemetry.triage import record_triage  # noqa: PLC0415

            record_triage(previous, result, run_dir=run_dir, surface=surface)
        except Exception:  # noqa: BLE001
            logger.debug("Saved review metric was skipped")
    return {"changed": True, "finding": result}


__all__ = [
    "MAX_NOTE_LENGTH",
    "REASON_CODES",
    "TriageError",
    "can_write_triage",
    "finding_digest",
    "read_triaged_vulnerabilities",
    "triage_finding",
    "triage_stamp",
]

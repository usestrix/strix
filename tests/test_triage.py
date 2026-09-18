"""Persistence, concurrency and evidence invariants for local human review."""

from __future__ import annotations

import json
import multiprocessing
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from strix.report import triage, triage_store
from strix.report.triage import TriageError, read_triaged_vulnerabilities, triage_finding
from strix.report.triage_store import triage_stamp
from strix.telemetry import triage as metrics


@pytest.fixture
def run_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    path = tmp_path / "run"
    path.mkdir()
    (path / "run.json").write_text(json.dumps({"run_id": "run", "start_time": "2026-09-16"}))
    reports = [
        {
            "id": f"vuln-{i:04d}",
            "title": f"Finding {i}",
            "evidence": f"Evidence {i}",
            "severity": "high",
            "timestamp": "2026-09-16 12:00:00 UTC",
        }
        for i in (1, 2)
    ]
    (path / "vulnerabilities.json").write_text(json.dumps(reports))
    monkeypatch.setattr(metrics, "record_triage", Mock())
    return path


def close(run_dir: Path, finding_id: str = "vuln-0001", **kwargs: Any) -> dict[str, Any]:
    finding = next(
        item for item in read_triaged_vulnerabilities(run_dir) if item["id"] == finding_id
    )
    values = {
        "status": "closed",
        "expected_revision": finding["triage_revision"],
        "reviewed_digest": finding["finding_digest"],
        "reason_code": "incorrect_assumption",
        "surface": "tui",
        **kwargs,
    }
    return triage_finding(run_dir, finding_id, **values)


def test_legacy_read_is_open_and_does_not_write(run_dir: Path) -> None:
    before = {p.name: p.read_bytes() for p in run_dir.iterdir()}
    findings = read_triaged_vulnerabilities(run_dir)
    assert all(item["status"] == "open" and item["can_triage"] for item in findings)
    assert all(item["triage_revision"] == 0 for item in findings)
    assert before == {p.name: p.read_bytes() for p in run_dir.iterdir()}


def test_close_reopen_preserves_evidence_and_history(run_dir: Path) -> None:
    evidence = (run_dir / "vulnerabilities.json").read_bytes()
    result = close(run_dir, note="My private explanation")
    assert result["changed"] is True
    finding = read_triaged_vulnerabilities(run_dir)[0]
    assert finding["status"] == "closed"
    assert finding["status_note"] == "My private explanation"
    reopened = close(run_dir, status="open")["finding"]
    assert reopened["status"] == "open"
    assert reopened["status_note"] is None
    assert reopened["resolution_reason"] is None
    assert [event["status"] for event in reopened["triage_history"]] == ["closed", "open"]
    assert reopened["triage_history"][0]["note"] == "My private explanation"
    assert (run_dir / "vulnerabilities.json").read_bytes() == evidence
    assert metrics.record_triage.call_count == 2  # type: ignore[attr-defined]


def test_repeated_request_is_idempotent_and_note_edits_stay_local(run_dir: Path) -> None:
    first = read_triaged_vulnerabilities(run_dir)[0]
    closed = close(run_dir)
    assert close(run_dir)["changed"] is False
    assert close(run_dir, expected_revision=0)["changed"] is False
    assert closed["finding"]["triage_revision"] == 1
    updated = close(run_dir, note="Local note only")
    assert updated["finding"]["triage_revision"] == 2
    assert metrics.record_triage.call_count == 1  # type: ignore[attr-defined]
    with pytest.raises(TriageError, match="reviewed elsewhere"):
        close(run_dir, status="open", expected_revision=first["triage_revision"])


def test_evidence_changes_require_new_review(run_dir: Path) -> None:
    old = read_triaged_vulnerabilities(run_dir)[0]
    close(run_dir)
    raw = json.loads((run_dir / "vulnerabilities.json").read_text())
    raw[0]["evidence"] = "New evidence changes the claim"
    (run_dir / "vulnerabilities.json").write_text(json.dumps(raw))
    finding = read_triaged_vulnerabilities(run_dir)[0]
    assert finding["status"] == "open" and finding["review_stale"]
    assert finding["triage_status"] == "closed"
    assert len(finding["triage_history"]) == 1
    with pytest.raises(TriageError, match="evidence changed"):
        close(run_dir, reviewed_digest=old["finding_digest"])
    result = close(run_dir)["finding"]
    assert result["triage_revision"] == 2
    assert result["status"] == "closed" and not result["review_stale"]


def test_presentation_and_fix_changes_do_not_invalidate_review(run_dir: Path) -> None:
    close(run_dir)
    raw = json.loads((run_dir / "vulnerabilities.json").read_text())
    raw[0].update(title="Clearer title", remediation_steps="A better fix", timestamp="later")
    (run_dir / "vulnerabilities.json").write_text(json.dumps(raw))
    assert read_triaged_vulnerabilities(run_dir)[0]["status"] == "closed"


def test_projection_does_not_modify_in_memory_agent_reports(run_dir: Path) -> None:
    close(run_dir)
    raw = json.loads((run_dir / "vulnerabilities.json").read_text())
    before = json.dumps(raw)
    assert read_triaged_vulnerabilities(run_dir, raw)[0]["status"] == "closed"
    assert json.dumps(raw) == before
    assert len(raw) == 2 and "status" not in raw[0]


@pytest.mark.parametrize("payload", ["{", "[]", '{"schema_version": 99}', "null"])
def test_invalid_sidecar_is_never_overwritten(run_dir: Path, payload: str) -> None:
    finding = read_triaged_vulnerabilities(run_dir)[0]
    (run_dir / "triage.json").write_text(payload)
    with pytest.raises(TriageError):
        triage_finding(
            run_dir,
            "vuln-0001",
            status="closed",
            expected_revision=0,
            reviewed_digest=finding["finding_digest"],
            surface="tui",
        )
    assert (run_dir / "triage.json").read_text() == payload
    metrics.record_triage.assert_not_called()  # type: ignore[attr-defined]


def test_reused_run_identity_cannot_inherit_decision(run_dir: Path) -> None:
    close(run_dir)
    (run_dir / "run.json").write_text(json.dumps({"run_id": "run", "start_time": "new scan"}))
    with pytest.raises(TriageError, match="another run"):
        read_triaged_vulnerabilities(run_dir)


@pytest.mark.parametrize(
    "field,value",
    [
        ("status", []),
        ("reason_code", {}),
        ("expected_revision", True),
        ("expected_revision", -1),
        ("reviewed_digest", "arbitrary"),
        ("note", "a" * 2001),
        ("note", []),
        ("surface", "untrusted"),
    ],
)
def test_bad_requests_are_rejected(run_dir: Path, field: str, value: Any) -> None:
    with pytest.raises(TriageError) as error:
        close(run_dir, **{field: value})
    assert error.value.code == "invalid_request"
    assert not (run_dir / "triage.json").exists()


def test_duplicate_and_synthetic_ids_are_not_writable(run_dir: Path) -> None:
    raw = json.loads((run_dir / "vulnerabilities.json").read_text())
    raw[1]["id"] = raw[0]["id"]
    raw.append({"title": "No ID"})
    (run_dir / "vulnerabilities.json").write_text(json.dumps(raw))
    assert not any(item["can_triage"] for item in read_triaged_vulnerabilities(run_dir))
    with pytest.raises(TriageError) as error:
        close(run_dir)
    assert error.value.code == "unknown_finding"


@pytest.mark.parametrize("name", ["triage.json", "triage.lock"])
def test_symlink_cannot_redirect_writes(run_dir: Path, name: str) -> None:
    finding = read_triaged_vulnerabilities(run_dir)[0]
    outside = run_dir.parent / "outside"
    outside.write_text("unchanged")
    (run_dir / name).symlink_to(outside)
    with pytest.raises(TriageError):
        triage_finding(
            run_dir,
            "vuln-0001",
            status="closed",
            expected_revision=0,
            reviewed_digest=finding["finding_digest"],
            surface="tui",
        )
    assert outside.read_text() == "unchanged"


def test_read_only_directory_still_displays_findings(run_dir: Path) -> None:
    run_dir.chmod(0o555)
    try:
        assert not any(item["can_triage"] for item in read_triaged_vulnerabilities(run_dir))
        with pytest.raises(TriageError) as error:
            close(run_dir)
        assert error.value.code == "read_only"
    finally:
        run_dir.chmod(0o755)


def test_failed_save_has_no_success_event(run_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(triage, "write_store", Mock(side_effect=OSError("disk unavailable")))
    with pytest.raises(TriageError):
        close(run_dir)
    assert not (run_dir / "triage.json").exists()
    metrics.record_triage.assert_not_called()  # type: ignore[attr-defined]


def test_telemetry_exception_cannot_fail_committed_review(
    run_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(metrics, "record_triage", Mock(side_effect=RuntimeError("offline")))
    assert close(run_dir)["changed"]
    assert read_triaged_vulnerabilities(run_dir)[0]["status"] == "closed"


def test_change_token_tracks_evidence_and_sidecar(run_dir: Path) -> None:
    initial = triage_stamp(run_dir)
    close(run_dir)
    reviewed = triage_stamp(run_dir)
    assert reviewed != initial
    reports = json.loads((run_dir / "vulnerabilities.json").read_text())
    reports[0]["evidence"] = "Changed"
    (run_dir / "vulnerabilities.json").write_text(json.dumps(reports))
    assert triage_stamp(run_dir) != reviewed
    assert all(0 <= value < 2**53 for value in triage_stamp(run_dir))


def _process_close(path: str, finding_id: str) -> None:
    # Spawned processes inherit STRIX_TELEMETRY=0 from the parent fixture.
    run = Path(path)
    finding = next(item for item in read_triaged_vulnerabilities(run) if item["id"] == finding_id)
    triage_finding(
        run,
        finding_id,
        status="closed",
        expected_revision=0,
        reviewed_digest=finding["finding_digest"],
        surface="tui",
    )


def test_separate_processes_preserve_both_decisions(run_dir: Path) -> None:
    context = multiprocessing.get_context("spawn")
    processes = [
        context.Process(target=_process_close, args=(str(run_dir), f"vuln-{i:04d}")) for i in (1, 2)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=20)
        if process.is_alive():
            process.terminate()
            pytest.fail("Review process did not finish")
        assert process.exitcode == 0
    findings = read_triaged_vulnerabilities(run_dir)
    assert all(item["status"] == "closed" for item in findings)
    assert all(item["triage_revision"] == 1 for item in findings)


def test_atomic_replace_failure_preserves_prior_decision(
    run_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    close(run_dir)
    saved = (run_dir / "triage.json").read_bytes()
    monkeypatch.setattr(Path, "replace", Mock(side_effect=OSError("replace failed")))
    with pytest.raises(TriageError):
        close(run_dir, status="open")
    assert (run_dir / "triage.json").read_bytes() == saved
    assert not list(run_dir.glob(".triage-*"))
    assert metrics.record_triage.call_count == 1  # type: ignore[attr-defined]


def test_lock_failure_never_saves_unlocked(run_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(triage_store, "LOCK_TIMEOUT", 0)
    monkeypatch.setattr(triage_store, "_file_lock", Mock(side_effect=OSError("lock unavailable")))
    with pytest.raises(TriageError, match="lock review data"):
        close(run_dir)
    assert not (run_dir / "triage.json").exists()
    metrics.record_triage.assert_not_called()  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "field,value",
    [
        ("counterevidence", "New contrary evidence"),
        ("http_exchange_ids", ["new-archived-exchange"]),
        ("confidence_rationale", "Previously assumed protection disproved"),
    ],
)
def test_additional_evidence_fields_invalidate_review(
    run_dir: Path, field: str, value: Any
) -> None:
    close(run_dir)
    reports = json.loads((run_dir / "vulnerabilities.json").read_text())
    reports[0][field] = value
    (run_dir / "vulnerabilities.json").write_text(json.dumps(reports))
    assert read_triaged_vulnerabilities(run_dir)[0]["review_stale"]


def test_resume_and_scanner_artifact_rewrite_preserve_review(run_dir: Path) -> None:
    from strix.report.state import ReportState  # noqa: PLC0415
    from strix.report.writer import write_vulnerabilities  # noqa: PLC0415

    close(run_dir)
    state = ReportState(run_name="run")
    state._run_dir = run_dir
    state.hydrate_from_run_dir()
    assert len(state.vulnerability_reports) == 2
    assert "status" not in state.vulnerability_reports[0]
    write_vulnerabilities(run_dir, state.vulnerability_reports, set())
    assert read_triaged_vulnerabilities(run_dir)[0]["status"] == "closed"
    assert state.add_vulnerability_report(title="Third finding", severity="low") == "vuln-0003"
    assert len(state.vulnerability_reports) == 3
    assert read_triaged_vulnerabilities(run_dir)[0]["status"] == "closed"

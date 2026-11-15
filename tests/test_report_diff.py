"""Unit tests for run-to-run finding matching (strix.report.diff)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from strix.report.diff import (
    DiffError,
    compare_runs,
    load_run,
    match_findings,
    resolve_run_spec,
)
from strix.report.sarif import fingerprints_for_finding, write_sarif
from strix.report.state import ReportState
from strix.report.writer import write_run_record, write_vulnerabilities


if TYPE_CHECKING:
    from pathlib import Path


def sample_finding(
    vuln_id: str,
    title: str,
    *,
    severity: str = "high",
    file: str = "app.py",
    line: int = 4,
    cwe: str = "CWE-89",
    timestamp: str = "2026-11-01T10:00:00+00:00",
) -> dict[str, Any]:
    return {
        "id": vuln_id,
        "title": title,
        "severity": severity,
        "cwe": cwe,
        "timestamp": timestamp,
        "code_locations": [{"file": file, "start_line": line}],
    }


def write_fixture_run(
    parent: Path,
    name: str,
    reports: list[dict[str, Any]],
    *,
    under_strix_runs: bool = True,
    targets: list[str] | None = None,
    scan_mode: str = "quick",
    start_time: str = "2026-11-01T10:00:00+00:00",
    status: str = "completed",
) -> Path:
    """Write a run directory with the real artifact writers."""
    run_dir = parent / "strix_runs" / name if under_strix_runs else parent / name
    run_dir.mkdir(parents=True, exist_ok=True)
    write_run_record(
        run_dir,
        {
            "run_id": name,
            "run_name": name,
            "start_time": start_time,
            "end_time": start_time if status == "completed" else None,
            "status": status,
            "scan_mode": scan_mode,
            "targets_info": [
                {"original": target} for target in (targets or ["https://app.example.com"])
            ],
        },
    )
    # A real clean completed run does not write vulnerabilities.json.
    if reports:
        write_vulnerabilities(run_dir, reports, set())
    write_sarif(run_dir, reports)
    return run_dir


def _retest_reports() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    baseline = [
        sample_finding(
            "vuln-0001", "SQL Injection in get_user", file="app.py", line=4, cwe="CWE-89"
        ),
        sample_finding(
            "vuln-0002",
            "Cross-site scripting in search",
            file="search.py",
            line=18,
            cwe="CWE-79",
        ),
        sample_finding(
            "vuln-0003",
            "CSRF on settings form",
            severity="high",
            file="settings.py",
            line=22,
            cwe="CWE-352",
        ),
        sample_finding(
            "vuln-0004",
            "IDOR in user profile",
            severity="medium",
            file="users.py",
            line=9,
            cwe="CWE-639",
        ),
    ]
    current = [
        sample_finding(
            "vuln-0001",
            "SQL Injection in get_user",
            file="db/query.py",
            line=12,
            cwe="CWE-89",
        ),
        sample_finding(
            "vuln-0002",
            "CSRF on settings form",
            severity="medium",
            file="settings.py",
            line=22,
            cwe="CWE-352",
        ),
        sample_finding(
            "vuln-0003",
            "Command injection in upload handler",
            severity="high",
            file="upload.py",
            line=40,
            cwe="CWE-77",
        ),
    ]
    return baseline, current


def test_fingerprints_for_finding_match_sarif_emission(tmp_path: Path) -> None:
    report = sample_finding("vuln-0001", "SQL Injection in get_user")
    write_sarif(tmp_path, [report])
    doc = json.loads((tmp_path / "findings.sarif").read_text(encoding="utf-8"))
    result = doc["runs"][0]["results"][0]
    fingerprints = fingerprints_for_finding(report)

    assert fingerprints.primary == result["partialFingerprints"]["primaryLocationLineHash"]
    assert fingerprints.vuln_class == result["properties"]["strix_vuln_class_hash"]


def test_moved_file_changes_primary_but_not_class_fingerprint() -> None:
    original = sample_finding("vuln-0001", "SQL Injection in get_user", file="app.py", line=4)
    moved = sample_finding("vuln-0001", "SQL Injection in get_user", file="db/query.py", line=12)
    left = fingerprints_for_finding(original)
    right = fingerprints_for_finding(moved)

    assert left.primary != right.primary
    assert left.vuln_class == right.vuln_class
    assert left.vuln_class is not None


def test_match_findings_new_fixed_and_still_present(tmp_path: Path) -> None:
    baseline = [
        sample_finding("vuln-0001", "SQL Injection in get_user"),
        sample_finding("vuln-0002", "CSRF on settings form", cwe="CWE-352", file="form.py"),
    ]
    current = [
        sample_finding("vuln-0001", "SQL Injection in get_user"),
        sample_finding(
            "vuln-0009",
            "Command injection in upload handler",
            file="upload.py",
            cwe="CWE-77",
        ),
    ]
    _, snapshots_a = load_run(write_fixture_run(tmp_path, "a", baseline))
    _, snapshots_b = load_run(write_fixture_run(tmp_path, "b", current))
    new, fixed, still = match_findings(snapshots_a, snapshots_b, match="strict")

    assert [item.title for item in new] == ["Command injection in upload handler"]
    assert [item.title for item in fixed] == ["CSRF on settings form"]
    assert [item.title for item in still] == ["SQL Injection in get_user"]
    assert still[0].id_baseline == "vuln-0001"
    assert still[0].id_current == "vuln-0001"


def test_match_findings_marks_severity_change(tmp_path: Path) -> None:
    baseline = [
        sample_finding("vuln-0003", "CSRF on settings form", severity="high", cwe="CWE-352")
    ]
    current = [
        sample_finding("vuln-0001", "CSRF on settings form", severity="medium", cwe="CWE-352")
    ]
    _, snapshots_a = load_run(write_fixture_run(tmp_path, "a", baseline))
    _, snapshots_b = load_run(write_fixture_run(tmp_path, "b", current))
    new, fixed, still = match_findings(snapshots_a, snapshots_b, match="strict")

    assert new == []
    assert fixed == []
    assert still[0].severity_baseline == "high"
    assert still[0].severity_current == "medium"


def test_class_match_pairs_a_finding_whose_path_moved(tmp_path: Path) -> None:
    baseline, current = _retest_reports()
    _, snapshots_a = load_run(write_fixture_run(tmp_path, "a", baseline))
    _, snapshots_b = load_run(write_fixture_run(tmp_path, "b", current))

    new_strict, fixed_strict, still_strict = match_findings(
        snapshots_a, snapshots_b, match="strict"
    )
    assert any(item.title.startswith("SQL Injection") for item in new_strict)
    assert any(item.title.startswith("SQL Injection") for item in fixed_strict)
    assert not any(item.title.startswith("SQL Injection") for item in still_strict)

    new_class, fixed_class, still_class = match_findings(snapshots_a, snapshots_b, match="class")
    assert [item.title for item in new_class] == ["Command injection in upload handler"]
    assert {item.title for item in fixed_class} == {
        "Cross-site scripting in search",
        "IDOR in user profile",
    }
    still_titles = {item.title for item in still_class}
    assert still_titles == {"SQL Injection in get_user", "CSRF on settings form"}
    moved = next(item for item in still_class if item.title.startswith("SQL Injection"))
    assert moved.location_baseline == "app.py:4"
    assert moved.location_current == "db/query.py:12"


def test_compare_runs_warns_on_different_targets_and_scan_modes(tmp_path: Path) -> None:
    report = [sample_finding("vuln-0001", "SQL Injection in get_user")]
    write_fixture_run(
        tmp_path,
        "run-a",
        report,
        targets=["https://app.example.com"],
        scan_mode="quick",
    )
    write_fixture_run(
        tmp_path,
        "run-b",
        report,
        targets=["https://staging.example.com"],
        scan_mode="deep",
        start_time="2026-11-02T10:00:00+00:00",
    )

    diff = compare_runs(tmp_path / "strix_runs" / "run-a", tmp_path / "strix_runs" / "run-b")

    assert any(warning.startswith("targets differ") for warning in diff.warnings)
    assert any(warning.startswith("scan modes differ") for warning in diff.warnings)
    assert len(diff.still_present) == 1
    assert diff.new == []
    assert diff.fixed == []


def test_resolve_run_spec_accepts_name_or_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = write_fixture_run(tmp_path, "named-run", [])
    copied = write_fixture_run(
        tmp_path / "elsewhere",
        "copied-run",
        [],
        under_strix_runs=False,
    )
    monkeypatch.chdir(tmp_path)

    assert resolve_run_spec("named-run") == run_dir
    assert resolve_run_spec(str(copied)) == copied
    assert resolve_run_spec("./strix_runs/named-run") == run_dir


def test_resolve_run_spec_missing_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(DiffError, match="No run named 'ghost'"):
        resolve_run_spec("ghost")


def test_load_run_missing_findings_file_on_completed_run_is_empty(tmp_path: Path) -> None:
    run_dir = tmp_path / "bare"
    run_dir.mkdir()
    write_run_record(run_dir, {"run_name": "bare", "status": "completed"})
    meta, findings = load_run(run_dir)
    assert findings == []
    assert meta.completed


def test_load_run_clean_completed_run_via_report_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="clean-retest")
    state.run_record["scan_mode"] = "quick"
    state.run_record["targets_info"] = [{"original": "https://app.example.com"}]
    state.save_run_data(mark_complete=True)
    run_dir = state.get_run_dir()

    assert not (run_dir / "vulnerabilities.json").is_file()
    meta, findings = load_run(run_dir)
    assert findings == []
    assert meta.completed
    assert meta.name == "clean-retest"


def test_compare_runs_clean_retest_marks_baseline_findings_fixed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    baseline = write_fixture_run(
        tmp_path, "before-fix", [sample_finding("vuln-0001", "SQL Injection in get_user")]
    )
    state = ReportState(run_name="after-fix")
    state.run_record["scan_mode"] = "quick"
    state.run_record["targets_info"] = [{"original": "https://app.example.com"}]
    state.save_run_data(mark_complete=True)

    diff = compare_runs(baseline, state.get_run_dir())

    assert [item.title for item in diff.fixed] == ["SQL Injection in get_user"]
    assert diff.new == []
    assert diff.still_present == []
    assert diff.not_rechecked == []
    assert diff.current.completed


@pytest.mark.parametrize("status", ["running", "interrupted", "failed", "stopped"])
def test_incomplete_current_run_reports_missing_findings_as_not_rechecked(
    tmp_path: Path, status: str
) -> None:
    baseline = write_fixture_run(
        tmp_path,
        "before-fix",
        [
            sample_finding("vuln-0001", "SQL Injection in get_user"),
            sample_finding(
                "vuln-0002",
                "Cross-site scripting in search",
                file="search.py",
                line=18,
                cwe="CWE-79",
            ),
        ],
    )
    current = write_fixture_run(
        tmp_path,
        "after-partial",
        [sample_finding("vuln-0001", "SQL Injection in get_user")],
        status=status,
        start_time="2026-11-02T10:00:00+00:00",
    )

    diff = compare_runs(baseline, current)

    assert [item.title for item in diff.still_present] == ["SQL Injection in get_user"]
    assert diff.fixed == []
    assert [item.title for item in diff.not_rechecked] == ["Cross-site scripting in search"]
    assert not diff.current.completed
    assert any("not re-checked, not fixed" in warning for warning in diff.warnings)
    assert any(f"status: {status}" in warning for warning in diff.warnings)


def test_completed_current_run_still_reports_missing_findings_as_fixed(tmp_path: Path) -> None:
    baseline = write_fixture_run(
        tmp_path,
        "before-fix",
        [
            sample_finding("vuln-0001", "SQL Injection in get_user"),
            sample_finding(
                "vuln-0002",
                "Cross-site scripting in search",
                file="search.py",
                line=18,
                cwe="CWE-79",
            ),
        ],
    )
    current = write_fixture_run(
        tmp_path,
        "after-fix",
        [sample_finding("vuln-0001", "SQL Injection in get_user")],
        start_time="2026-11-02T10:00:00+00:00",
    )

    diff = compare_runs(baseline, current)

    assert [item.title for item in diff.fixed] == ["Cross-site scripting in search"]
    assert diff.not_rechecked == []
    assert diff.current.completed


def test_load_run_rejects_non_object_findings_entries(tmp_path: Path) -> None:
    run_dir = write_fixture_run(tmp_path, "damaged", [])
    (run_dir / "vulnerabilities.json").write_text("[null]", encoding="utf-8")
    with pytest.raises(DiffError, match="non-object entry at index 0"):
        load_run(run_dir)


def test_load_run_rejects_mixed_non_object_findings_entries(tmp_path: Path) -> None:
    run_dir = write_fixture_run(
        tmp_path, "damaged-mixed", [sample_finding("vuln-0001", "SQL Injection in get_user")]
    )
    payload = [sample_finding("vuln-0001", "SQL Injection in get_user"), None]
    (run_dir / "vulnerabilities.json").write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(DiffError, match="non-object entry at index 1"):
        load_run(run_dir)


def test_damaged_findings_list_does_not_compare_as_clean(tmp_path: Path) -> None:
    baseline = write_fixture_run(
        tmp_path, "before-fix", [sample_finding("vuln-0001", "SQL Injection in get_user")]
    )
    current = write_fixture_run(tmp_path, "after-fix", [])
    (current / "vulnerabilities.json").write_text("[null]", encoding="utf-8")
    with pytest.raises(DiffError, match="non-object"):
        compare_runs(baseline, current)


def test_load_run_corrupt_vulnerabilities_json(tmp_path: Path) -> None:
    run_dir = write_fixture_run(tmp_path, "bad-json", [])
    (run_dir / "vulnerabilities.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(DiffError, match="unreadable"):
        load_run(run_dir)


def test_load_run_invalid_utf8_vulnerabilities_json(tmp_path: Path) -> None:
    run_dir = write_fixture_run(tmp_path, "bad-encoding", [])
    (run_dir / "vulnerabilities.json").write_bytes(b"[\xff\xfe]")
    with pytest.raises(DiffError, match="unreadable"):
        load_run(run_dir)


def test_load_run_corrupt_run_json(tmp_path: Path) -> None:
    run_dir = write_fixture_run(tmp_path, "bad-record", [])
    (run_dir / "run.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(DiffError, match="unreadable"):
        load_run(run_dir)


def test_load_run_invalid_utf8_run_json(tmp_path: Path) -> None:
    run_dir = write_fixture_run(tmp_path, "bad-record-encoding", [])
    (run_dir / "run.json").write_bytes(b"\xff\xfe not utf-8")
    with pytest.raises(DiffError, match="unreadable"):
        load_run(run_dir)

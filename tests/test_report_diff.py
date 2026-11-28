"""Unit tests for run-to-run finding matching (strix.report.diff)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from strix.interface.diff_cli import _new_findings_fail
from strix.report.diff import (
    DiffError,
    _redact_target,
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

    from strix.report.diff import MatchMode


def sample_finding(
    vuln_id: str,
    title: str,
    *,
    severity: str = "high",
    file: str = "app.py",
    line: int = 4,
    cwe: str | None = "CWE-89",
    timestamp: str = "2026-11-01T10:00:00+00:00",
) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "id": vuln_id,
        "title": title,
        "severity": severity,
        "timestamp": timestamp,
        "code_locations": [{"file": file, "start_line": line}],
    }
    if cwe is not None:
        finding["cwe"] = cwe
    return finding


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


def test_strict_match_pairs_renumbered_locationless_findings_by_title(tmp_path: Path) -> None:
    first = {
        **sample_finding("vuln-0001", "SQL injection in search"),
        "code_locations": [],
    }
    second = {
        **sample_finding("vuln-0002", "SQL injection in lookup", severity="low"),
        "code_locations": [],
    }
    baseline = write_fixture_run(tmp_path, "a", [first, second])
    current = write_fixture_run(
        tmp_path,
        "b",
        [{**second, "id": "vuln-0001"}, {**first, "id": "vuln-0002"}],
    )
    primary = fingerprints_for_finding(first).primary
    assert primary is not None
    assert primary == fingerprints_for_finding(second).primary

    diff = compare_runs(baseline, current)

    assert diff.new == diff.fixed == []
    assert diff.severity_changed == 0
    assert [(item.id_baseline, item.id_current) for item in diff.still_present] == [
        ("vuln-0001", "vuln-0002"),
        ("vuln-0002", "vuln-0001"),
    ]


@pytest.mark.parametrize("keep_sibling", [False, True])
def test_strict_match_leaves_unrelated_locationless_findings_unpaired(
    tmp_path: Path, keep_sibling: bool
) -> None:
    before = {**sample_finding("vuln-0001", "SQL injection in search"), "code_locations": []}
    after = {**before, "title": "SQL injection in billing"}
    sibling = (
        [{**before, "id": "vuln-0002", "title": "SQL injection in lookup"}] if keep_sibling else []
    )
    primary = fingerprints_for_finding(before).primary
    assert primary is not None
    assert primary == fingerprints_for_finding(after).primary

    baseline = write_fixture_run(tmp_path, "a", [before, *sibling])
    current = write_fixture_run(tmp_path, "b", [after, *sibling])
    diff = compare_runs(baseline, current)

    assert [(item.title, item.severity) for item in diff.new] == [(after["title"], "high")]
    assert [item.title for item in diff.fixed] == [before["title"]]
    assert [item.title for item in diff.still_present] == [item["title"] for item in sibling]


def test_strict_match_pairs_line_move_without_weakness_by_normalized_title(tmp_path: Path) -> None:
    baseline = write_fixture_run(
        tmp_path, "a", [sample_finding("vuln-0001", "Open redirect in login", cwe=None)]
    )
    current = write_fixture_run(
        tmp_path, "b", [sample_finding("vuln-0002", "OPEN  REDIRECT in login", line=8, cwe=None)]
    )

    diff = compare_runs(baseline, current)

    assert diff.new == diff.fixed == []
    assert [(item.id_baseline, item.id_current) for item in diff.still_present] == [
        ("vuln-0001", "vuln-0002")
    ]


@pytest.mark.parametrize(
    ("match", "current_severity"),
    [("strict", "high"), ("strict", "low"), ("class", "high")],
)
def test_match_findings_pairs_line_move(
    tmp_path: Path, match: MatchMode, current_severity: str
) -> None:
    baseline = write_fixture_run(
        tmp_path, "a", [sample_finding("vuln-0001", "SQL Injection in search", line=40)]
    )
    current = write_fixture_run(
        tmp_path,
        "b",
        [
            sample_finding(
                "vuln-0002", "SQL Injection in search", line=52, severity=current_severity
            )
        ],
    )

    diff = compare_runs(baseline, current, match=match)

    assert diff.new == []
    assert diff.fixed == []
    assert len(diff.still_present) == 1
    finding = diff.still_present[0]
    assert finding.location_baseline == "app.py:40"
    assert finding.location_current == "app.py:52"
    assert finding.severity_baseline == "high"
    assert finding.severity_current == current_severity


def test_strict_match_leaves_ambiguous_line_moves_unpaired(tmp_path: Path) -> None:
    baseline = write_fixture_run(
        tmp_path,
        "a",
        [
            sample_finding("vuln-0001", "SQL Injection in search", line=40),
            sample_finding("vuln-0002", "SQL Injection in lookup", line=60),
        ],
    )
    current = write_fixture_run(
        tmp_path,
        "b",
        [
            sample_finding("vuln-0001", "SQL Injection in search", line=52),
            sample_finding("vuln-0002", "SQL Injection in lookup", line=72),
        ],
    )

    diff = compare_runs(baseline, current)

    assert diff.still_present == []
    assert {finding.location for finding in diff.new} == {"app.py:52", "app.py:72"}
    assert {finding.location for finding in diff.fixed} == {"app.py:40", "app.py:60"}


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


def test_class_match_leaves_unrelated_findings_unpaired(tmp_path: Path) -> None:
    baseline = [
        sample_finding("vuln-0001", "SQL Injection in search", file="search.py"),
        sample_finding("vuln-0002", "SQL Injection in billing", file="billing.py"),
        sample_finding("vuln-0003", "SQL Injection in exports", file="exports.py"),
    ]
    current = [
        sample_finding("vuln-0004", "SQL Injection in imports", file="imports.py"),
        sample_finding("vuln-0005", "SQL injection in  SEARCH", file="db/search.py"),
    ]
    assert len({fingerprints_for_finding(item).vuln_class for item in baseline + current}) == 1
    baseline_dir = write_fixture_run(tmp_path, "baseline", baseline)
    current_dir = write_fixture_run(tmp_path, "current", current)
    diff = compare_runs(baseline_dir, current_dir, match="class")

    assert [(item.id_baseline, item.id_current) for item in diff.still_present] == [
        ("vuln-0001", "vuln-0005")
    ]
    assert {item.id_baseline for item in diff.fixed} == {"vuln-0002", "vuln-0003"}
    assert [item.id_current for item in diff.new] == ["vuln-0004"]
    assert _new_findings_fail(diff, "high")


@pytest.mark.parametrize("match", ["strict", "class"])
def test_match_findings_is_order_independent_with_duplicates(
    tmp_path: Path, match: MatchMode
) -> None:
    duplicate = sample_finding("vuln-0001", "SQL Injection in search", file="search.py")
    other = sample_finding("vuln-0002", "SQL Injection in billing", file="billing.py")
    baseline_dir = write_fixture_run(tmp_path, "baseline", [duplicate, other])
    current_dir = write_fixture_run(
        tmp_path, "current", [duplicate, duplicate, other, {**duplicate, "severity": "medium"}]
    )
    _, baseline = load_run(baseline_dir)
    _, current = load_run(current_dir)

    result = match_findings(baseline, current, match=match)
    new, fixed, still = result
    assert [item.severity_current for item in new] == ["high", "medium"]
    assert fixed == []
    assert {item.id_current: item.severity_current for item in still} == {
        "vuln-0001": "high",
        "vuln-0002": "high",
    }
    assert match_findings(baseline, current[::-1], match=match) == result


def test_class_match_pairs_finding_without_cwe_or_cve_across_id_and_path_changes(
    tmp_path: Path,
) -> None:
    baseline_finding = sample_finding(
        "vuln-0001",
        "Open redirect in login callback",
        file="auth/views.py",
        line=14,
        cwe=None,
    )
    current_finding = sample_finding(
        "vuln-0005",
        "Open redirect in login callback",
        file="web/auth/login.py",
        line=42,
        cwe=None,
    )
    baseline_dir = write_fixture_run(tmp_path, "before-fix", [baseline_finding])
    current_dir = write_fixture_run(
        tmp_path,
        "after-fix",
        [current_finding],
        start_time="2026-11-02T10:00:00+00:00",
    )

    diff = compare_runs(baseline_dir, current_dir, match="class")

    assert diff.new == []
    assert diff.fixed == []
    assert len(diff.still_present) == 1
    still = diff.still_present[0]
    assert still.title == "Open redirect in login callback"
    assert still.id_baseline == "vuln-0001"
    assert still.id_current == "vuln-0005"
    assert still.location_baseline == "auth/views.py:14"
    assert still.location_current == "web/auth/login.py:42"

    # SARIF ruleId still uses the finding id while strix_vuln_class_hash stays stable.
    baseline_sarif = json.loads((baseline_dir / "findings.sarif").read_text(encoding="utf-8"))
    current_sarif = json.loads((current_dir / "findings.sarif").read_text(encoding="utf-8"))
    baseline_result = baseline_sarif["runs"][0]["results"][0]
    current_result = current_sarif["runs"][0]["results"][0]
    assert baseline_result["ruleId"] == "vuln-0001"
    assert current_result["ruleId"] == "vuln-0005"
    assert (
        baseline_result["properties"]["strix_vuln_class_hash"]
        == current_result["properties"]["strix_vuln_class_hash"]
    )
    assert (
        fingerprints_for_finding(baseline_finding).vuln_class
        == baseline_result["properties"]["strix_vuln_class_hash"]
    )


def test_class_match_pairs_reworded_title_without_cwe_or_cve(tmp_path: Path) -> None:
    baseline_finding = sample_finding(
        "vuln-0001",
        "Open redirect in login callback",
        file="auth/views.py",
        line=14,
        cwe=None,
    )
    current_finding = sample_finding(
        "vuln-0003",
        "Open redirect in authentication callback",
        file="web/auth/login.py",
        line=42,
        cwe=None,
    )
    assert (
        fingerprints_for_finding(baseline_finding).vuln_class
        == fingerprints_for_finding(current_finding).vuln_class
    )

    baseline_dir = write_fixture_run(tmp_path, "before", [baseline_finding])
    current_dir = write_fixture_run(
        tmp_path,
        "after",
        [current_finding],
        start_time="2026-11-02T10:00:00+00:00",
    )
    diff = compare_runs(baseline_dir, current_dir, match="class")

    assert diff.new == []
    assert diff.fixed == []
    assert len(diff.still_present) == 1


def test_class_fingerprint_without_cwe_or_cve_keeps_classes_apart() -> None:
    redirect = sample_finding("vuln-0001", "Open redirect in login callback", cwe=None)
    ssrf = sample_finding("vuln-0002", "SSRF in webhook fetcher", cwe=None)
    assert fingerprints_for_finding(redirect).vuln_class != (
        fingerprints_for_finding(ssrf).vuln_class
    )


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("https://admin:s3cret@example.com/app", "https://admin:***@example.com/app"),
        ("https://user:pass@[::1]:8443/app?x=1#top", "https://user:***@[::1]:8443/app?x=1#top"),
        ("https://user@example.com/app", "https://user@example.com/app"),
        ("ssh://git@github.com/org/repo.git", "ssh://git@github.com/org/repo.git"),
        ("https://alice@example.com/app", "https://alice@example.com/app"),
        ("https://ghp_example@github.com/org/repo.git", "https://***@github.com/org/repo.git"),
        ("https://aZ0bY1cX2dW3eV4fU5gT@[::1]:8443/app", "https://***@[::1]:8443/app"),
        (
            "https://example.com/app?token=one&access_token=two&API_KEY=three&view=full#top",
            "https://example.com/app?token=***&access_token=***&API_KEY=***&view=full#top",
        ),
        (
            "HTTPS://example.com/app?view=a%20b&empty#top",
            "HTTPS://example.com/app?view=a%20b&empty#top",
        ),
        ("https://example.com/app", "https://example.com/app"),
        ("/work/repo", "/work/repo"),
        ("owner/repo", "owner/repo"),
        ("https://user:pass@[::1", "https://user:pass@[::1"),
    ],
)
def test_redact_target(target: str, expected: str) -> None:
    assert _redact_target(target) == expected


@pytest.mark.parametrize(
    ("target", "secret", "redacted"),
    [
        ("https://admin:{}@example.com/app", "s3cret", "https://admin:***@example.com/app"),
        ("https://{}@example.com/app", "ghp_example", "https://***@example.com/app"),
        ("https://example.com/app?token={}", "query-secret", "https://example.com/app?token=***"),
    ],
)
def test_compare_runs_redacts_target_credentials(
    tmp_path: Path, target: str, secret: str, redacted: str
) -> None:
    baseline = write_fixture_run(tmp_path, "baseline", [], targets=[target.format(secret)])
    current = write_fixture_run(
        tmp_path, "current", [], targets=[target.format(f"{secret}-changed")]
    )

    diff = compare_runs(baseline, current)

    metadata = diff.baseline.to_json()
    assert metadata["targets"] == [redacted]
    assert diff.current.to_json()["targets"] == [redacted]
    assert secret not in json.dumps(metadata)
    assert diff.warnings == [f"targets differ ({redacted} vs {redacted})"]


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

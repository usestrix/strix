"""Tests for the ``strix diff`` CLI."""

from __future__ import annotations

import importlib
import json
import sys
from typing import TYPE_CHECKING, Any

import pytest

from strix.core.paths import run_dir_for
from strix.interface.diff_cli import run_diff
from strix.report.state import ReportState
from strix.report.writer import read_run_record, write_run_record
from tests.test_report_diff import sample_finding, write_fixture_run


if TYPE_CHECKING:
    from pathlib import Path

cli_main: Any = importlib.import_module("strix.interface.main")


def _retest_pair(tmp_path: Path) -> None:
    baseline = [
        sample_finding("vuln-0001", "SQL Injection in get_user", file="app.py", line=4),
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
    write_fixture_run(tmp_path, "before-fix", baseline, start_time="2026-11-01T10:00:00+00:00")
    write_fixture_run(tmp_path, "after-fix", current, start_time="2026-11-02T10:00:00+00:00")


def test_diff_help_describes_match_and_fail_on_new(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        run_diff(["--help"])
    assert exc.value.code == 0
    help_text = capsys.readouterr().out
    assert "--json" in help_text
    assert "--fail-on-new" in help_text
    assert "--match" in help_text
    assert "strict" in help_text
    assert "class" in help_text


def test_diff_human_output_new_fixed_still_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _retest_pair(tmp_path)
    monkeypatch.chdir(tmp_path)

    assert run_diff(["before-fix", "after-fix"]) == 0
    output = capsys.readouterr().out

    assert "Comparing before-fix -> after-fix" in output
    assert "quick  https://app.example.com" in output
    assert "New (2)" in output
    assert "Command injection in upload handler" in output
    assert "SQL Injection in get_user" in output
    assert "Fixed (3)" in output
    assert "Cross-site scripting in search" in output
    assert "IDOR in user profile" in output
    assert "Still present (1)" in output
    assert "high -> medium" in output
    assert "CSRF on settings form" in output
    assert "2 new, 3 fixed, 1 still present" in output


def test_diff_match_class_catches_moved_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _retest_pair(tmp_path)
    monkeypatch.chdir(tmp_path)

    assert run_diff(["before-fix", "after-fix", "--match", "class"]) == 0
    output = capsys.readouterr().out

    assert "New (1)" in output
    assert "Command injection in upload handler" in output
    assert "Fixed (2)" in output
    assert "Still present (2)" in output
    assert "app.py:4 -> db/query.py:12" in output
    assert "1 new, 2 fixed, 2 still present" in output


def test_diff_json_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _retest_pair(tmp_path)
    monkeypatch.chdir(tmp_path)

    assert run_diff(["before-fix", "after-fix", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["match"] == "strict"
    assert payload["baseline"]["name"] == "before-fix"
    assert payload["current"]["name"] == "after-fix"
    assert payload["baseline"]["targets"] == ["https://app.example.com"]
    assert payload["summary"] == {
        "fixed": 3,
        "new": 2,
        "not_rechecked": 0,
        "severity_changed": 1,
        "still_present": 1,
        "withdrawn": 0,
    }
    assert payload["not_rechecked"] == []
    assert payload["withdrawn"] == []
    required = {
        "id_baseline",
        "id_current",
        "location",
        "location_baseline",
        "location_current",
        "severity",
        "severity_baseline",
        "severity_current",
        "title",
    }
    for section in ("new", "fixed", "still_present"):
        assert payload[section]
        for finding in payload[section]:
            assert set(finding) == required
    still = payload["still_present"][0]
    assert still["severity_baseline"] == "high"
    assert still["severity_current"] == "medium"


def test_fail_on_new_high_exits_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _retest_pair(tmp_path)
    monkeypatch.chdir(tmp_path)

    assert run_diff(["before-fix", "after-fix", "--fail-on-new", "high"]) == 1
    assert "Command injection in upload handler" in capsys.readouterr().out


def test_fail_on_new_high_for_unrelated_locationless_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    before = {**sample_finding("vuln-0001", "SQL injection in search"), "code_locations": []}
    after = {**before, "title": "SQL injection in billing"}
    write_fixture_run(tmp_path, "before-fix", [before])
    write_fixture_run(tmp_path, "after-fix", [after])
    monkeypatch.chdir(tmp_path)

    assert run_diff(["before-fix", "after-fix", "--fail-on-new", "high"]) == 1
    assert "1 new, 1 fixed, 0 still present" in capsys.readouterr().out


def test_fail_on_new_high_for_new_same_weakness_finding_in_same_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    write_fixture_run(
        tmp_path, "before-fix", [sample_finding("vuln-0001", "SQL Injection in search", line=40)]
    )
    write_fixture_run(
        tmp_path, "after-fix", [sample_finding("vuln-0002", "SQL Injection in billing", line=52)]
    )
    monkeypatch.chdir(tmp_path)

    assert run_diff(["before-fix", "after-fix", "--fail-on-new", "high"]) == 1
    assert "1 new, 1 fixed, 0 still present" in capsys.readouterr().out


def test_fail_on_new_high_for_reused_id_without_weakness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    write_fixture_run(
        tmp_path, "before-fix", [sample_finding("vuln-0001", "Open redirect in login", cwe=None)]
    )
    write_fixture_run(
        tmp_path,
        "after-fix",
        [sample_finding("vuln-0001", "Hardcoded secret in config", cwe=None)],
    )
    monkeypatch.chdir(tmp_path)

    assert run_diff(["before-fix", "after-fix", "--fail-on-new", "high"]) == 1
    assert "1 new, 1 fixed, 0 still present" in capsys.readouterr().out


def test_fail_on_new_high_for_ranked_to_unrankable_severity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_fixture_run(
        tmp_path, "before-fix", [sample_finding("vuln-0001", "Finding", severity="high")]
    )
    write_fixture_run(
        tmp_path, "after-fix", [sample_finding("vuln-0001", "Finding", severity="severe")]
    )
    monkeypatch.chdir(tmp_path)

    assert run_diff(["before-fix", "after-fix", "--fail-on-new", "high"]) == 1


def test_fail_on_new_high_for_deep_baseline_and_quick_retest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    write_fixture_run(
        tmp_path,
        "before-fix",
        [sample_finding("vuln-0001", "SQL Injection in get_user")],
        scan_mode="deep",
    )
    write_fixture_run(tmp_path, "after-fix", [], scan_mode="quick")
    monkeypatch.chdir(tmp_path)

    assert run_diff(["before-fix", "after-fix", "--fail-on-new", "high"]) == 1
    out = capsys.readouterr().out
    assert "scan modes differ (deep vs quick)" in out
    assert "0 new, 0 fixed, 0 still present, 1 not re-checked" in out


def test_fail_on_new_critical_passes_when_new_is_high(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _retest_pair(tmp_path)
    monkeypatch.chdir(tmp_path)

    assert run_diff(["before-fix", "after-fix", "--fail-on-new", "critical"]) == 0


@pytest.mark.parametrize(
    ("baseline", "current", "threshold", "exit_code"),
    [
        ("high", "critical", "critical", 1),
        ("critical", "critical", "critical", 0),
        ("high", "medium", "medium", 0),
    ],
)
def test_fail_on_new_for_still_present_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    baseline: str,
    current: str,
    threshold: str,
    exit_code: int,
) -> None:
    write_fixture_run(
        tmp_path, "before-fix", [sample_finding("vuln-0001", "Finding", severity=baseline)]
    )
    write_fixture_run(
        tmp_path, "after-fix", [sample_finding("vuln-0001", "Finding", severity=current)]
    )
    monkeypatch.chdir(tmp_path)

    assert run_diff(["before-fix", "after-fix", "--fail-on-new", threshold]) == exit_code
    assert "0 new, 0 fixed, 1 still present" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("current_severity", "threshold", "exit_code"),
    [("high", "high", 0), ("low", "high", 0), ("low", "low", 0), ("critical", "critical", 1)],
)
def test_fail_on_new_for_line_move(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    current_severity: str,
    threshold: str,
    exit_code: int,
) -> None:
    write_fixture_run(tmp_path, "before-fix", [sample_finding("vuln-0001", "Finding", line=40)])
    write_fixture_run(
        tmp_path,
        "after-fix",
        [sample_finding("vuln-0002", "Finding", severity=current_severity, line=52)],
    )
    monkeypatch.chdir(tmp_path)

    assert run_diff(["before-fix", "after-fix", "--fail-on-new", threshold]) == exit_code
    assert "0 new, 0 fixed, 1 still present" in capsys.readouterr().out


@pytest.mark.parametrize("baseline", [None, "", "  ", "severe", "unknown"])
@pytest.mark.parametrize(("current", "exit_code"), [("critical", 1), ("high", 0)])
def test_fail_on_new_escalation_from_unrankable_baseline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    baseline: str | None,
    current: str,
    exit_code: int,
) -> None:
    before = sample_finding("vuln-0001", "Finding", severity=baseline or "")
    baseline_dir = write_fixture_run(tmp_path, "before-fix", [before])
    if baseline is None:
        # The report writers require a severity, so drop it from the saved file.
        findings_path = baseline_dir / "vulnerabilities.json"
        saved = json.loads(findings_path.read_text(encoding="utf-8"))
        for item in saved:
            item.pop("severity", None)
        findings_path.write_text(json.dumps(saved), encoding="utf-8")
    write_fixture_run(
        tmp_path, "after-fix", [sample_finding("vuln-0001", "Finding", severity=current)]
    )
    monkeypatch.chdir(tmp_path)

    assert run_diff(["before-fix", "after-fix", "--fail-on-new", "critical"]) == exit_code
    assert "0 new, 0 fixed, 1 still present" in capsys.readouterr().out


def test_fail_on_new_unrankable_on_both_sides_is_not_an_escalation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_fixture_run(
        tmp_path, "before-fix", [sample_finding("vuln-0001", "Finding", severity="severe")]
    )
    write_fixture_run(
        tmp_path, "after-fix", [sample_finding("vuln-0001", "Finding", severity="bad")]
    )
    monkeypatch.chdir(tmp_path)

    assert run_diff(["before-fix", "after-fix", "--fail-on-new", "critical"]) == 0


def test_fail_on_new_still_fails_closed_on_unrankable_new_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_fixture_run(tmp_path, "before-fix", [])
    write_fixture_run(
        tmp_path, "after-fix", [sample_finding("vuln-0001", "Finding", severity="severe")]
    )
    monkeypatch.chdir(tmp_path)

    assert run_diff(["before-fix", "after-fix", "--fail-on-new", "critical"]) == 1


def test_fail_on_new_is_case_insensitive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _retest_pair(tmp_path)
    monkeypatch.chdir(tmp_path)

    assert run_diff(["before-fix", "after-fix", "--fail-on-new", "HIGH"]) == 1


def test_fail_on_new_rejects_unknown_severity(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit):
        run_diff(["before-fix", "after-fix", "--fail-on-new", "severe"])
    assert "--fail-on-new" in capsys.readouterr().err


def test_missing_run_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    write_fixture_run(tmp_path, "before-fix", [])
    monkeypatch.chdir(tmp_path)

    assert run_diff(["before-fix", "ghost"]) == 1
    captured = capsys.readouterr()
    assert "No run named 'ghost'" in captured.err
    assert "Available runs:" in captured.err
    assert "before-fix" in captured.err


def test_clean_retest_compares_without_vulnerabilities_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    write_fixture_run(
        tmp_path, "before-fix", [sample_finding("vuln-0001", "SQL Injection in get_user")]
    )
    state = ReportState(run_name="after-fix")
    state.run_record["scan_mode"] = "quick"
    state.run_record["targets_info"] = [{"original": "https://app.example.com"}]
    state.save_run_data(mark_complete=True)
    assert not (state.get_run_dir() / "vulnerabilities.json").is_file()

    assert run_diff(["before-fix", "after-fix"]) == 0
    output = capsys.readouterr().out
    assert "Fixed (1)" in output
    assert "SQL Injection in get_user" in output
    assert "0 new, 1 fixed, 0 still present" in output
    assert "not re-checked" not in output


def test_incomplete_retest_reports_not_rechecked_and_fails_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    write_fixture_run(
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
    write_fixture_run(
        tmp_path,
        "after-partial",
        [sample_finding("vuln-0001", "SQL Injection in get_user")],
        status="running",
        start_time="2026-11-02T10:00:00+00:00",
    )

    assert run_diff(["before-fix", "after-partial", "--fail-on-new", "high"]) == 1
    output = capsys.readouterr().out
    assert "Not re-checked (1)" in output
    assert "Cross-site scripting in search" in output
    assert "Fixed (0)" in output
    assert "1 not re-checked" in output
    assert "not re-checked, not fixed" in output


def test_incomplete_retest_exits_one_without_fail_on_new(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    write_fixture_run(
        tmp_path, "before-fix", [sample_finding("vuln-0001", "SQL Injection in get_user")]
    )
    write_fixture_run(
        tmp_path,
        "after-partial",
        [sample_finding("vuln-0001", "SQL Injection in get_user")],
        status="interrupted",
    )

    assert run_diff(["before-fix", "after-partial"]) == 1


@pytest.mark.parametrize("status", ["running", "failed"])
def test_incomplete_baseline_exits_one_even_when_current_is_clean(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    status: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    write_fixture_run(
        tmp_path,
        "before-partial",
        [sample_finding("vuln-0001", "SQL Injection in get_user")],
        status=status,
    )
    write_fixture_run(
        tmp_path,
        "after-fix",
        [],
        start_time="2026-11-02T10:00:00+00:00",
    )

    assert run_diff(["before-partial", "after-fix"]) == 1
    output = capsys.readouterr().out
    assert f"run 'before-partial' is not completed (status: {status})" in output


def test_incomplete_retest_json_lists_not_rechecked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    write_fixture_run(
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
    write_fixture_run(
        tmp_path,
        "after-partial",
        [sample_finding("vuln-0001", "SQL Injection in get_user")],
        status="running",
    )

    assert run_diff(["before-fix", "after-partial", "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["not_rechecked"] == 1
    assert payload["summary"]["fixed"] == 0
    assert payload["fixed"] == []
    assert payload["not_rechecked"][0]["title"] == "Cross-site scripting in search"
    assert payload["current"]["status"] == "running"


def test_unreadable_run_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    run_dir = write_fixture_run(tmp_path, "broken", [])
    (run_dir / "run.json").write_text("{not json", encoding="utf-8")
    write_fixture_run(tmp_path, "after-fix", [])
    monkeypatch.chdir(tmp_path)

    assert run_diff(["broken", "after-fix"]) == 1
    assert "unreadable" in capsys.readouterr().err


def test_unreadable_vulnerabilities_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    run_dir = write_fixture_run(tmp_path, "broken-findings", [])
    (run_dir / "vulnerabilities.json").write_text("{not json", encoding="utf-8")
    write_fixture_run(tmp_path, "after-fix", [])
    monkeypatch.chdir(tmp_path)

    assert run_diff(["broken-findings", "after-fix"]) == 1
    captured = capsys.readouterr()
    assert "vulnerabilities.json" in captured.err
    assert "unreadable" in captured.err


def test_invalid_utf8_vulnerabilities_json_is_a_clear_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    run_dir = write_fixture_run(tmp_path, "broken-encoding", [])
    (run_dir / "vulnerabilities.json").write_bytes(b"[\xff\xfe]")
    write_fixture_run(tmp_path, "after-fix", [])
    monkeypatch.chdir(tmp_path)

    assert run_diff(["broken-encoding", "after-fix"]) == 1
    error = capsys.readouterr().err
    assert "unreadable" in error
    assert "Traceback" not in error


def test_invalid_utf8_run_json_is_a_clear_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    run_dir = write_fixture_run(tmp_path, "broken-record-encoding", [])
    (run_dir / "run.json").write_bytes(b"\xff\xfe not utf-8")
    write_fixture_run(tmp_path, "after-fix", [])
    monkeypatch.chdir(tmp_path)

    assert run_diff(["broken-record-encoding", "after-fix"]) == 1
    error = capsys.readouterr().err
    assert "unreadable" in error
    assert "Traceback" not in error


def test_damaged_findings_list_is_a_clear_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    run_dir = write_fixture_run(tmp_path, "damaged", [])
    (run_dir / "vulnerabilities.json").write_text("[null]", encoding="utf-8")
    write_fixture_run(tmp_path, "after-fix", [])
    monkeypatch.chdir(tmp_path)

    assert run_diff(["damaged", "after-fix"]) == 1
    captured = capsys.readouterr()
    assert "non-object" in captured.err
    assert "0 new" not in captured.out


def test_run_metadata_control_characters_are_sanitized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    left = write_fixture_run(
        tmp_path, "before-fix", [sample_finding("vuln-0001", "SQL Injection in get_user")]
    )
    right = write_fixture_run(
        tmp_path, "after-fix", [sample_finding("vuln-0001", "SQL Injection in get_user")]
    )
    record = read_run_record(left)
    record["run_name"] = "before\nINJECTED"
    record["scan_mode"] = "quick\x1b[31mRED"
    record["targets_info"] = [{"original": "https://app.example.com\x07"}]
    write_run_record(left, record)
    record_b = read_run_record(right)
    record_b["run_name"] = "after\rfix"
    write_run_record(right, record_b)

    assert run_diff(["before-fix", "after-fix"]) == 0
    output = capsys.readouterr().out
    assert "\nINJECTED" not in output.split("Comparing", 1)[-1]
    assert "before\\x0aINJECTED" in output
    assert "after\\x0dfix" in output
    assert "\\x1b[31mRED" in output
    assert "\\x07" in output
    assert "\x1b[31m" not in output


def test_error_and_available_run_names_are_sanitized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    sneaky = run_dir_for("safe\nFAKE-RUN")
    sneaky.mkdir(parents=True)
    write_run_record(sneaky, {"run_name": "safe\nFAKE-RUN", "status": "completed"})

    assert run_diff(["ghost\nFAKE-ERROR", "after-fix"]) == 1
    error = capsys.readouterr().err
    assert "\\x0aFAKE-ERROR" in error
    assert "\\x0aFAKE-RUN" in error
    assert "\nFAKE-ERROR" not in error
    assert "Traceback" not in error


def test_path_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    left = write_fixture_run(
        tmp_path / "alpha",
        "run-a",
        [sample_finding("vuln-0001", "SQL Injection in get_user")],
        under_strix_runs=False,
    )
    right = write_fixture_run(
        tmp_path / "beta",
        "run-b",
        [sample_finding("vuln-0001", "SQL Injection in get_user")],
        under_strix_runs=False,
    )
    monkeypatch.chdir(tmp_path)

    assert run_diff([str(left), str(right)]) == 0
    assert "0 new, 0 fixed, 1 still present" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("target", "secret", "redacted"),
    [
        ("https://admin:s3cret@example.com/app", "s3cret", "https://admin:***@example.com/app"),
        ("https://ghp_example@example.com/app", "ghp_example", "https://***@example.com/app"),
        (
            "https://example.com/app?access_token=query-secret",
            "query-secret",
            "https://example.com/app?access_token=***",
        ),
    ],
)
def test_different_targets_warning_does_not_refuse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    target: str,
    secret: str,
    redacted: str,
) -> None:
    write_fixture_run(
        tmp_path,
        "run-a",
        [sample_finding("vuln-0001", "SQL Injection in get_user")],
        targets=[target],
    )
    write_fixture_run(
        tmp_path,
        "run-b",
        [sample_finding("vuln-0001", "SQL Injection in get_user")],
        targets=["https://staging.example.com"],
        scan_mode="deep",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("COLUMNS", "160")

    assert run_diff(["run-a", "run-b"]) == 0
    output = capsys.readouterr().out
    assert secret not in output
    assert any("run-a" in line and redacted in line for line in output.splitlines())
    assert f"Warning: targets differ ({redacted} vs" in output
    assert "Warning: scan modes differ" in output
    assert "0 new, 0 fixed, 1 still present" in output

    assert run_diff(["run-a", "run-b", "--json"]) == 0
    output = capsys.readouterr().out
    assert secret not in output
    assert json.loads(output)["baseline"]["targets"] == [redacted]


def test_finding_endpoint_and_target_credentials_are_redacted_in_human_and_json_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    baseline_reports = [
        {
            **sample_finding("vuln-0001", "SQL Injection in search", cwe="CWE-89"),
            "code_locations": [],
            "method": "GET",
            "endpoint": "https://user:base-ep-secret@example.com/v1/search",
        },
        {
            **sample_finding("vuln-0002", "Cross-site scripting in portal", cwe="CWE-79"),
            "code_locations": [],
            "target": "https://admin:fixed-target-secret@example.com/legacy",
        },
    ]
    current_reports = [
        {
            **sample_finding("vuln-0001", "SQL Injection in search", cwe="CWE-89"),
            "code_locations": [],
            "method": "GET",
            "endpoint": "https://user:curr-ep-secret@example.com/v2/search",
        },
        {
            **sample_finding("vuln-0003", "IDOR in billing", cwe="CWE-639"),
            "code_locations": [],
            "method": "POST",
            "endpoint": "https://svc:new-ep-secret@example.com/billing",
        },
        {
            **sample_finding("vuln-0004", "Open redirect in portal", cwe="CWE-601"),
            "code_locations": [],
            "target": "https://admin:new-target-secret@example.com/app",
        },
    ]
    write_fixture_run(tmp_path, "run-a", baseline_reports)
    write_fixture_run(tmp_path, "run-b", current_reports)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("COLUMNS", "220")

    secrets = (
        "base-ep-secret",
        "curr-ep-secret",
        "fixed-target-secret",
        "new-ep-secret",
        "new-target-secret",
    )

    assert run_diff(["run-a", "run-b", "--match", "class"]) == 0
    human_output = capsys.readouterr().out
    for secret in secrets:
        assert secret not in human_output
    assert "POST https://svc:***@example.com/billing" in human_output
    assert "https://admin:***@example.com/app" in human_output
    assert "https://admin:***@example.com/legacy" in human_output
    assert (
        "GET https://user:***@example.com/v1/search -> GET https://user:***@example.com/v2/search"
        in human_output
    )

    assert run_diff(["run-a", "run-b", "--match", "class", "--json"]) == 0
    json_output = capsys.readouterr().out
    for secret in secrets:
        assert secret not in json_output
    payload = json.loads(json_output)
    new_by_title = {item["title"]: item for item in payload["new"]}
    assert new_by_title["IDOR in billing"]["location"] == "POST https://svc:***@example.com/billing"
    assert (
        new_by_title["Open redirect in portal"]["location"] == "https://admin:***@example.com/app"
    )
    assert payload["fixed"][0]["location"] == "https://admin:***@example.com/legacy"
    still = payload["still_present"][0]
    assert still["location_baseline"] == "GET https://user:***@example.com/v1/search"
    assert still["location_current"] == "GET https://user:***@example.com/v2/search"
    assert still["location"] == "GET https://user:***@example.com/v2/search"


def test_main_dispatches_diff_before_scan_setup(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run_diff(argv: list[str]) -> int:
        calls.append(argv)
        return 0

    monkeypatch.setattr(sys, "argv", ["strix", "diff", "run-a", "run-b", "--json"])
    monkeypatch.setattr("strix.interface.diff_cli.run_diff", fake_run_diff)
    monkeypatch.setattr(cli_main, "setup_console_logging", lambda: None)
    monkeypatch.setattr(
        cli_main,
        "parse_arguments",
        lambda: (_ for _ in ()).throw(AssertionError("scan parser ran")),
    )

    with pytest.raises(SystemExit) as exc:
        cli_main.main()
    assert exc.value.code == 0
    assert calls == [["run-a", "run-b", "--json"]]


def test_root_help_lists_diff(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["strix", "--help"])
    monkeypatch.setattr(cli_main, "setup_console_logging", lambda: None)
    with pytest.raises(SystemExit) as exc:
        cli_main.main()
    assert exc.value.code == 0
    assert "strix diff RUN-A RUN-B" in capsys.readouterr().out

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
    }
    assert payload["not_rechecked"] == []
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


def test_fail_on_new_critical_passes_when_new_is_high(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _retest_pair(tmp_path)
    monkeypatch.chdir(tmp_path)

    assert run_diff(["before-fix", "after-fix", "--fail-on-new", "critical"]) == 0


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


def test_different_targets_warning_does_not_refuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    write_fixture_run(
        tmp_path,
        "run-a",
        [sample_finding("vuln-0001", "SQL Injection in get_user")],
        targets=["https://app.example.com"],
    )
    write_fixture_run(
        tmp_path,
        "run-b",
        [sample_finding("vuln-0001", "SQL Injection in get_user")],
        targets=["https://staging.example.com"],
        scan_mode="deep",
    )
    monkeypatch.chdir(tmp_path)

    assert run_diff(["run-a", "run-b"]) == 0
    output = capsys.readouterr().out
    assert "Warning: targets differ" in output
    assert "Warning: scan modes differ" in output
    assert "0 new, 0 fixed, 1 still present" in output


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

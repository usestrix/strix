"""Tests for the run listing behind the resume picker."""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

from strix.report.runs import list_run_summaries


if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def _write_run(
    base: Path,
    name: str,
    record: object,
    *,
    modified: float,
    state: bool = True,
    findings: int | None = None,
) -> None:
    run_dir = base / name
    run_dir.mkdir(parents=True)
    path = run_dir / "run.json"
    path.write_text(record if isinstance(record, str) else json.dumps(record), encoding="utf-8")
    if state:
        (run_dir / ".state").mkdir()
        (run_dir / ".state" / "agents.json").write_text("{}", encoding="utf-8")
    if findings is not None:
        (run_dir / "vulnerabilities.json").write_text(
            json.dumps([{"id": index} for index in range(findings)]), encoding="utf-8"
        )
    os.utime(path, (modified, modified))


def test_lists_runs_newest_first_with_target_status_and_findings(tmp_path: Path) -> None:
    base = tmp_path / "strix_runs"
    _write_run(
        base,
        "example-com_1111",
        {
            "status": "completed",
            "start_time": "2026-10-04T10:00:00+00:00",
            "end_time": "2026-10-04T10:05:00+00:00",
            "targets_info": [{"type": "web_application", "original": "https://example.com"}],
        },
        modified=1_000,
        findings=2,
    )
    _write_run(
        base,
        "example-com_2222",
        {
            "status": "interrupted",
            "start_time": "2026-10-04T11:00:00+00:00",
            "targets_info": [
                {"type": "web_application", "original": "https://example.com"},
                {"type": "web_application", "original": "https://api.example.com"},
            ],
        },
        modified=3_000,
    )
    (base / "not-a-run").mkdir()

    runs = list_run_summaries(cwd=tmp_path)

    assert [run.run_name for run in runs] == ["example-com_2222", "example-com_1111"]
    newest, oldest = runs
    assert newest.target == "https://example.com +1 more"
    assert newest.status == "interrupted"
    assert newest.started_at == "2026-10-04T11:00:00+00:00"
    assert newest.ended_at == ""
    assert newest.findings == 0
    assert newest.resumable is True
    assert oldest.target == "https://example.com"
    assert oldest.findings == 2
    assert oldest.ended_at == "2026-10-04T10:05:00+00:00"


def test_target_less_runs_describe_their_workspace_or_instruction(tmp_path: Path) -> None:
    base = tmp_path / "strix_runs"
    _write_run(
        base,
        "pentest_aaaa",
        {"status": "stopped", "targets_info": [], "workspace_mount": "/home/me/app"},
        modified=2_000,
    )
    _write_run(
        base,
        "pentest_bbbb",
        {"status": "failed", "targets_info": [], "user_instruction": "audit the login\nflow"},
        modified=1_000,
    )

    runs = {run.run_name: run for run in list_run_summaries(cwd=tmp_path)}

    assert runs["pentest_aaaa"].target == "/home/me/app (workspace)"
    assert runs["pentest_bbbb"].target == "audit the login"


def test_runs_without_agent_state_or_with_a_broken_record_are_listed_not_resumable(
    tmp_path: Path,
) -> None:
    base = tmp_path / "strix_runs"
    _write_run(base, "no-state_cccc", {"status": "failed"}, modified=2_000, state=False)
    _write_run(base, "broken_dddd", "{not json", modified=1_000)
    _write_run(base, "list_eeee", "[]", modified=500)

    runs = list_run_summaries(cwd=tmp_path)

    assert [(run.run_name, run.resumable) for run in runs] == [
        ("no-state_cccc", False),
        ("broken_dddd", True),
        ("list_eeee", True),
    ]
    assert runs[1].status == "unknown"
    assert runs[1].target == ""


def test_missing_runs_dir_lists_nothing(tmp_path: Path) -> None:
    assert list_run_summaries(cwd=tmp_path) == []


def test_blank_instruction_does_not_break_the_listing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    run_dir = tmp_path / "strix_runs" / "blank_0001"
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps({"status": "completed", "instruction": "  \n  "}), encoding="utf-8"
    )

    [summary] = list_run_summaries()

    assert summary.target == ""


def test_title_is_the_instruction_else_the_most_severe_finding(tmp_path: Path) -> None:
    base = tmp_path / "strix_runs"
    _write_run(
        base, "instructed_1111", {"user_instruction": "focus on auth\nand billing"}, modified=2
    )
    _write_run(base, "found_2222", {}, modified=1)
    (base / "found_2222" / "vulnerabilities.json").write_text(
        json.dumps(
            [
                {"title": "Verbose errors", "severity": "low"},
                {"title": "SQL injection via id on /login", "severity": "critical"},
            ]
        ),
        encoding="utf-8",
    )

    assert [run.title for run in list_run_summaries(cwd=tmp_path)] == [
        "focus on auth",
        "SQL injection",
    ]

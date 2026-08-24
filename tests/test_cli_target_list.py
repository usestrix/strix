"""Tests for CLI target-list argument parsing."""

from __future__ import annotations

import importlib
import json
import sys
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest


if TYPE_CHECKING:
    from pathlib import Path


cli_main: Any = importlib.import_module("strix.interface.main")


def _stub_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(max_local_copy_mb=1024)),
    )


def test_parse_arguments_accepts_target_list_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target_list = tmp_path / "targets.txt"
    target_list.write_text(
        "https://test1.com/\n\nhttp://test2.com:5789/\n",
        encoding="utf-8",
    )
    _stub_settings(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["strix", "--target-list", str(target_list), "-n"])

    args = cli_main.parse_arguments()

    assert [target["original"] for target in args.targets_info] == [
        "https://test1.com/",
        "http://test2.com:5789/",
    ]
    assert [target["type"] for target in args.targets_info] == [
        "web_application",
        "web_application",
    ]


def test_parse_arguments_combines_target_and_target_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target_list = tmp_path / "targets.txt"
    target_list.write_text("http://test2.com:5789/\n", encoding="utf-8")
    _stub_settings(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "-t", "https://test1.com/", "--target-list", str(target_list)],
    )

    args = cli_main.parse_arguments()

    assert [target["original"] for target in args.targets_info] == [
        "https://test1.com/",
        "http://test2.com:5789/",
    ]


def test_parse_arguments_rejects_resume_with_target_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target_list = tmp_path / "targets.txt"
    target_list.write_text("https://test1.com/\n", encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "--resume", "old-run", "--target-list", str(target_list)],
    )

    with pytest.raises(SystemExit):
        cli_main.parse_arguments()

    assert "Cannot combine --resume with --target/--target-list" in capsys.readouterr().err


def _write_run_record(runs_dir: Path, run_name: str, record: dict[str, Any]) -> None:
    """Write a resumable run: its record plus the agent snapshot resume needs."""
    run_dir = runs_dir / run_name
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run.json").write_text(json.dumps(record), encoding="utf-8")
    state_dir = run_dir / ".state"
    state_dir.mkdir(exist_ok=True)
    (state_dir / "agents.json").write_text("{}", encoding="utf-8")


def test_resume_restores_a_target_less_workspace_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A run that only mounted a working directory is resumable."""
    work = tmp_path / "project"
    work.mkdir()
    monkeypatch.chdir(tmp_path)
    _write_run_record(
        tmp_path / "strix_runs",
        "pentest_abcd",
        {
            "run_name": "pentest_abcd",
            "targets_info": [],
            "local_sources": [],
            "workspace_mount": str(work),
            "instruction": "audit the auth flow",
            "scan_mode": "deep",
        },
    )
    monkeypatch.setattr(sys, "argv", ["strix", "--resume", "pentest_abcd"])

    args = cli_main.parse_arguments()

    # Still genuinely target-less, and the workspace is mounted again.
    assert args.targets_info == []
    assert args.workspace_mount == str(work)
    assert args.local_sources == [
        {"source_path": str(work), "workspace_subdir": "project", "protect_metadata": True}
    ]
    assert args.instruction == "audit the auth flow"


def test_resume_revalidates_persisted_workspace_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Resume places the same files again, and drops ones that went away."""
    work = tmp_path / "project"
    work.mkdir()
    kept = tmp_path / "wordlist.txt"
    kept.write_text("admin\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    _write_run_record(
        tmp_path / "strix_runs",
        "pentest_abcd",
        {
            "run_name": "pentest_abcd",
            "targets_info": [],
            "local_sources": [],
            "workspace_mount": str(work),
            "workspace_files": [
                {"source_path": str(kept), "workspace_path": "/workspace/lists/words.txt"},
                {"source_path": str(tmp_path / "gone.txt"), "workspace_path": "/workspace/g.txt"},
            ],
        },
    )
    monkeypatch.setattr(sys, "argv", ["strix", "--resume", "pentest_abcd"])

    args = cli_main.parse_arguments()

    assert args.workspace_files == [
        {"source_path": str(kept), "workspace_path": "/workspace/lists/words.txt"}
    ]


def test_resume_rejects_an_edited_workspace_file_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A hand-edited record cannot place a file outside the workspace."""
    work = tmp_path / "project"
    work.mkdir()
    source = tmp_path / "wordlist.txt"
    source.write_text("admin\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    _write_run_record(
        tmp_path / "strix_runs",
        "pentest_abcd",
        {
            "run_name": "pentest_abcd",
            "targets_info": [],
            "local_sources": [],
            "workspace_mount": str(work),
            "workspace_files": [
                {"source_path": str(source), "workspace_path": "/etc/cron.d/payload"}
            ],
        },
    )
    monkeypatch.setattr(sys, "argv", ["strix", "--resume", "pentest_abcd"])

    with pytest.raises(SystemExit):
        cli_main.parse_arguments()

    assert "invalid workspace file" in capsys.readouterr().err


def test_resume_reports_a_missing_workspace_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_run_record(
        tmp_path / "strix_runs",
        "pentest_abcd",
        {
            "run_name": "pentest_abcd",
            "targets_info": [],
            "local_sources": [],
            "workspace_mount": str(tmp_path / "deleted"),
        },
    )
    monkeypatch.setattr(sys, "argv", ["strix", "--resume", "pentest_abcd"])

    with pytest.raises(SystemExit):
        cli_main.parse_arguments()

    assert "is missing" in capsys.readouterr().err


def test_resume_still_requires_targets_or_a_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_run_record(
        tmp_path / "strix_runs",
        "pentest_abcd",
        {"run_name": "pentest_abcd", "targets_info": [], "local_sources": []},
    )
    monkeypatch.setattr(sys, "argv", ["strix", "--resume", "pentest_abcd"])

    with pytest.raises(SystemExit):
        cli_main.parse_arguments()

    assert "has no targets_info" in capsys.readouterr().err

def test_resume_non_object_run_json_exits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.chdir(tmp_path)
    run_dir = tmp_path / "strix_runs" / "pentest_abcd"
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text("[]", encoding="utf-8")

    monkeypatch.setattr(sys, "argv", ["strix", "--resume", "pentest_abcd"])
    with pytest.raises(SystemExit) as exc_info:
        cli_main.parse_arguments()

    assert exc_info.value.code == 2
    captured = capsys.readouterr()
    assert "run.json unreadable" in captured.err
    assert "not an object" in captured.err

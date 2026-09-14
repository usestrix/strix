"""Tests for CLI target-list argument parsing."""

from __future__ import annotations

import importlib
import json
import sys
from contextlib import nullcontext
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest


if TYPE_CHECKING:
    from pathlib import Path


cli_main: Any = importlib.import_module("strix.interface.main")
cli_runtime: Any = importlib.import_module("strix.interface.cli")
cli_args: Any = importlib.import_module("strix.interface.cli_args")

BASELINE_RUN_NAME = "baseline-alpha"
RUNS_DIR_NAME = "strix_runs"
VULNERABILITIES_FILENAME = "vulnerabilities.json"
TARGET_URL = "https://test1.com/"
OUTSIDE_RUN_NAME = "outside-baseline"


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


def test_parse_arguments_accepts_baseline_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline_run_dir = tmp_path / RUNS_DIR_NAME / BASELINE_RUN_NAME
    baseline_run_dir.mkdir(parents=True)
    (baseline_run_dir / VULNERABILITIES_FILENAME).write_text(json.dumps([]), encoding="utf-8")
    _stub_settings(monkeypatch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "--target", TARGET_URL, "--baseline-run", BASELINE_RUN_NAME],
    )

    args = cli_main.parse_arguments()

    assert args.baseline_run == BASELINE_RUN_NAME


def test_parse_arguments_rejects_empty_baseline_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _stub_settings(monkeypatch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "--target", TARGET_URL, "--baseline-run", ""],
    )

    with pytest.raises(SystemExit):
        cli_main.parse_arguments()

    assert "must be a non-empty run name" in capsys.readouterr().err


@pytest.mark.parametrize("path_kind", ["relative", "absolute"])
def test_parse_arguments_rejects_baseline_paths_outside_runs_dir(
    path_kind: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    (work_dir / RUNS_DIR_NAME).mkdir()
    is_absolute = path_kind == "absolute"
    outside_run_dir = tmp_path / OUTSIDE_RUN_NAME if is_absolute else work_dir / OUTSIDE_RUN_NAME
    outside_run_dir.mkdir()
    (outside_run_dir / VULNERABILITIES_FILENAME).write_text("[]", encoding="utf-8")
    _stub_settings(monkeypatch)
    monkeypatch.chdir(work_dir)
    absolute_or_relative = str(outside_run_dir) if is_absolute else f"../{OUTSIDE_RUN_NAME}"
    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "--target", TARGET_URL, "--baseline-run", absolute_or_relative],
    )

    with pytest.raises(SystemExit):
        cli_main.parse_arguments()

    assert "must be a run name, not a path" in capsys.readouterr().err


def test_parse_arguments_validates_baseline_before_interactive_setup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    outside_run_dir = tmp_path / OUTSIDE_RUN_NAME
    outside_run_dir.mkdir()
    (outside_run_dir / VULNERABILITIES_FILENAME).write_text("[]", encoding="utf-8")
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    _stub_settings(monkeypatch)
    monkeypatch.chdir(work_dir)
    monkeypatch.setattr(sys, "argv", ["strix", "--baseline-run", f"../{OUTSIDE_RUN_NAME}"])

    with pytest.raises(SystemExit):
        cli_main.parse_arguments()

    assert "must be a run name, not a path" in capsys.readouterr().err


def test_parse_arguments_rejects_unreadable_baseline_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _stub_settings(monkeypatch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "--target", TARGET_URL, "--baseline-run", BASELINE_RUN_NAME],
    )

    with pytest.raises(SystemExit):
        cli_main.parse_arguments()

    assert "vulnerabilities.json" in capsys.readouterr().err


def test_parse_arguments_reports_target_validation_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def reject_target(_args: object) -> None:
        raise ValueError("invalid test target")

    _stub_settings(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["strix", "--target", TARGET_URL])
    monkeypatch.setattr(cli_args, "build_targets_info", reject_target)

    with pytest.raises(SystemExit):
        cli_main.parse_arguments()

    assert "invalid test target" in capsys.readouterr().err


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


def test_resume_restores_and_validates_baseline_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runs_dir = tmp_path / RUNS_DIR_NAME
    _write_run_record(
        runs_dir,
        "pentest-resume",
        {
            "run_name": "pentest-resume",
            "targets_info": [{"type": "web_application", "original": TARGET_URL, "details": {}}],
            "baseline_run": BASELINE_RUN_NAME,
        },
    )
    baseline_dir = runs_dir / BASELINE_RUN_NAME
    baseline_dir.mkdir()
    (baseline_dir / VULNERABILITIES_FILENAME).write_text("[]", encoding="utf-8")
    _stub_settings(monkeypatch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["strix", "--resume", "pentest-resume"])

    parsed = cli_main.parse_arguments()

    assert parsed.baseline_run == BASELINE_RUN_NAME


@pytest.mark.parametrize(
    "invalid_baseline",
    [[BASELINE_RUN_NAME], []],
    ids=["truthy", "empty"],
)
def test_resume_rejects_non_string_baseline_run(
    invalid_baseline: object,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_run_record(
        tmp_path / RUNS_DIR_NAME,
        "pentest-resume",
        {
            "run_name": "pentest-resume",
            "targets_info": [{"type": "web_application", "original": TARGET_URL, "details": {}}],
            "baseline_run": invalid_baseline,
        },
    )
    _stub_settings(monkeypatch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["strix", "--resume", "pentest-resume"])

    with pytest.raises(SystemExit):
        cli_main.parse_arguments()

    assert "must be a run name" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_cli_runtime_hydrates_selected_baseline(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, object]] = []

    class ExpectedStopError(Exception):
        pass

    class FakeReportState:
        final_scan_result = None

        def __init__(self, run_name: str) -> None:
            calls.append(("init", run_name))

        def hydrate_from_run_dir(self) -> None:
            calls.append(("hydrate", None))

        def hydrate_baseline_run(self, run_name: str | None) -> None:
            calls.append(("baseline", run_name))

        def set_scan_config(self, config: dict[str, Any]) -> None:
            calls.append(("config", config["baseline_run"]))

        def save_run_data(self) -> None:
            calls.append(("save", None))

        def cleanup(self, *, status: str | None = None) -> None:
            calls.append(("cleanup", status))

    async def stop_scan(**_kwargs: Any) -> None:
        raise ExpectedStopError

    async def cleanup_session(_run_name: str) -> None:
        return None

    runtime_args = SimpleNamespace(
        run_name="current-run",
        targets_info=[{"original": TARGET_URL}],
        instruction=None,
        baseline_run=BASELINE_RUN_NAME,
    )
    monkeypatch.setattr(cli_runtime, "ReportState", FakeReportState)
    monkeypatch.setattr(cli_runtime, "run_strix_scan", stop_scan)
    monkeypatch.setattr(cli_runtime, "_resolve_sandbox_image", lambda: "test-image")
    monkeypatch.setattr(cli_runtime, "has_model_response", lambda _state: False)
    monkeypatch.setattr(cli_runtime, "build_live_stats_text", lambda _state: None)
    monkeypatch.setattr(
        cli_runtime, "Live", lambda *_args, **_kwargs: nullcontext(SimpleNamespace())
    )
    monkeypatch.setattr(cli_runtime.atexit, "register", lambda _callback: None)
    monkeypatch.setattr(cli_runtime.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(cli_runtime.session_manager, "cleanup", cleanup_session)

    with pytest.raises(ExpectedStopError):
        await cli_runtime.run_cli(runtime_args)

    assert ("baseline", BASELINE_RUN_NAME) in calls
    assert ("config", BASELINE_RUN_NAME) in calls


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


def test_resume_non_object_run_json_exits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
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

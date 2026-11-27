"""Tests for how --resume interacts with the persisted diff scope."""

from __future__ import annotations

import importlib
import json
import sys
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest

from strix.interface.cli_args import RESUME_SCOPE_WIDENED_INSTRUCTION


if TYPE_CHECKING:
    from pathlib import Path


cli_main: Any = importlib.import_module("strix.interface.main")

PREAMBLE = "Scope your review to the following changes.\n\n"


def _stub_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(max_local_copy_mb=1024)),
    )


def _write_run_record(runs_dir: Path, run_name: str, record: dict[str, Any]) -> None:
    """Write a resumable run: its record plus the agent snapshot resume needs."""
    run_dir = runs_dir / run_name
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run.json").write_text(json.dumps(record), encoding="utf-8")
    state_dir = run_dir / ".state"
    state_dir.mkdir(exist_ok=True)
    (state_dir / "agents.json").write_text("{}", encoding="utf-8")


def _diff_scoped_record(**overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "run_name": "pentest_abcd",
        "targets_info": [],
        "local_sources": [],
        "instruction": PREAMBLE + "find auth bugs",
        "user_instruction": "find auth bugs",
        "scan_mode": "deep",
        "scope_mode": "diff",
        "diff_base": "origin/main",
        "diff_scope": {"active": True, "mode": "diff", "repos": []},
    }
    record.update(overrides)
    return record


def _resume(monkeypatch: pytest.MonkeyPatch, *extra: str) -> Any:
    monkeypatch.setattr(sys, "argv", ["strix", "--resume", "pentest_abcd", *extra])
    return cli_main.parse_arguments()


def test_resume_restores_persisted_scope_over_flag_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A plain resume keeps the run's recorded scope_mode and diff_base."""
    work = tmp_path / "project"
    work.mkdir()
    monkeypatch.chdir(tmp_path)
    _write_run_record(
        tmp_path / "strix_runs",
        "pentest_abcd",
        _diff_scoped_record(workspace_mount=str(work)),
    )

    args = _resume(monkeypatch)

    assert args.scope_mode == "diff"
    assert args.diff_base == "origin/main"
    assert args.diff_scope == {"active": True, "mode": "diff", "repos": []}
    assert args.instruction == PREAMBLE + "find auth bugs"
    assert args.resume_instruction == ""


def test_resume_honors_scope_mode_full(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An explicit --scope-mode full widens the resume past the recorded diff."""
    work = tmp_path / "project"
    work.mkdir()
    monkeypatch.chdir(tmp_path)
    _write_run_record(
        tmp_path / "strix_runs",
        "pentest_abcd",
        _diff_scoped_record(workspace_mount=str(work)),
    )

    args = _resume(monkeypatch, "--scope-mode", "full")

    assert args.scope_mode == "full"
    assert args.diff_scope == {"active": False, "mode": "full"}
    # The recorded instruction carries the diff-scope preamble; the widened
    # resume keeps only the clean user text, and injects a note lifting the
    # old restriction into the replayed session.
    assert args.instruction == "find auth bugs"
    assert args.resume_instruction == RESUME_SCOPE_WIDENED_INSTRUCTION


def test_resume_honors_scope_mode_full_with_new_instruction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A new instruction given alongside --scope-mode full is kept verbatim."""
    work = tmp_path / "project"
    work.mkdir()
    monkeypatch.chdir(tmp_path)
    _write_run_record(
        tmp_path / "strix_runs",
        "pentest_abcd",
        _diff_scoped_record(workspace_mount=str(work)),
    )

    args = _resume(monkeypatch, "--scope-mode", "full", "--instruction", "check the API")

    assert args.scope_mode == "full"
    assert args.diff_scope == {"active": False, "mode": "full"}
    assert args.instruction == "check the API"
    assert args.resume_instruction == "check the API"


def test_resume_honors_scope_mode_full_without_recorded_user_instruction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A widened resume drops a preamble-only instruction and injects the note."""
    work = tmp_path / "project"
    work.mkdir()
    monkeypatch.chdir(tmp_path)
    _write_run_record(
        tmp_path / "strix_runs",
        "pentest_abcd",
        _diff_scoped_record(workspace_mount=str(work), instruction=PREAMBLE, user_instruction=None),
    )

    args = _resume(monkeypatch, "--scope-mode", "full")

    assert args.diff_scope == {"active": False, "mode": "full"}
    assert args.instruction is None
    assert args.resume_instruction == RESUME_SCOPE_WIDENED_INSTRUCTION


def test_resume_with_scope_mode_full_on_a_full_run_injects_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Re-asserting full on a run that was already full is a plain no-op."""
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
            "instruction": "find auth bugs",
            "user_instruction": "find auth bugs",
            "scan_mode": "deep",
            "scope_mode": "full",
            "diff_scope": {"active": False, "mode": "full"},
            "workspace_mount": str(work),
        },
    )

    args = _resume(monkeypatch, "--scope-mode", "full")

    assert args.diff_scope == {"active": False, "mode": "full"}
    assert args.instruction == "find auth bugs"
    assert args.resume_instruction == ""


@pytest.mark.parametrize("extra", [["--scope-mode", "diff"], ["--diff-base", "origin/main"]])
def test_resume_rejects_diff_scope_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    extra: list[str],
) -> None:
    """Re-resolving a diff mid-run is refused instead of silently ignored."""
    work = tmp_path / "project"
    work.mkdir()
    monkeypatch.chdir(tmp_path)
    _write_run_record(
        tmp_path / "strix_runs",
        "pentest_abcd",
        _diff_scoped_record(workspace_mount=str(work)),
    )

    with pytest.raises(SystemExit):
        _resume(monkeypatch, *extra)

    assert "Cannot combine --resume with --scope-mode diff or --diff-base" in (
        capsys.readouterr().err
    )

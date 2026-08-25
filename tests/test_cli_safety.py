from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING, Any

import pytest

from strix.config import loader
from strix.interface import cli_args


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def isolated_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_SAFETY_MODE", raising=False)
    loader.apply_config_override(tmp_path / "config.json")


def test_fresh_runs_default_to_guarded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["strix"])

    args = cli_args.parse_arguments()

    assert args.needs_setup is True
    assert args.safety_mode == "guarded"


def test_dangerous_flag_disables_safety(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["strix", "--dangerously-disable-safety"])

    args = cli_args.parse_arguments()

    assert args.safety_mode == "off"


def test_removed_mode_flag_has_actionable_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["strix", "--safety-mode", "guarded"])

    with pytest.raises(SystemExit):
        cli_args.parse_arguments()

    error = capsys.readouterr().err
    assert "--safety-mode was removed" in error
    assert "--dangerously-disable-safety" in error


def test_removed_mode_environment_has_actionable_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("STRIX_SAFETY_MODE", "off")
    monkeypatch.setattr(sys, "argv", ["strix"])

    with pytest.raises(SystemExit):
        cli_args.parse_arguments()

    assert "STRIX_SAFETY_MODE was removed" in capsys.readouterr().err


def _write_resumable_run(tmp_path: Path, safety_mode: str | None) -> None:
    work = tmp_path / "project"
    work.mkdir()
    run_dir = tmp_path / "strix_runs" / "run-1"
    state_dir = run_dir / ".state"
    state_dir.mkdir(parents=True)
    record: dict[str, Any] = {
        "run_name": "run-1",
        "targets_info": [],
        "workspace_mount": str(work),
        "local_sources": [],
    }
    if safety_mode is not None:
        record["safety_mode"] = safety_mode
    (run_dir / "run.json").write_text(json.dumps(record), encoding="utf-8")
    (state_dir / "agents.json").write_text("{}", encoding="utf-8")


@pytest.mark.parametrize("safety_mode", ["off", None])
def test_off_resume_requires_dangerous_flag(
    safety_mode: str | None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_resumable_run(tmp_path, safety_mode)
    monkeypatch.setattr(sys, "argv", ["strix", "--resume", "run-1"])

    with pytest.raises(SystemExit):
        cli_args.parse_arguments()

    assert "--dangerously-disable-safety again" in capsys.readouterr().err


def test_off_resume_accepts_dangerous_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_resumable_run(tmp_path, "off")
    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "--resume", "run-1", "--dangerously-disable-safety"],
    )

    assert cli_args.parse_arguments().safety_mode == "off"


def test_guarded_resume_rejects_dangerous_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_resumable_run(tmp_path, "guarded")
    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "--resume", "run-1", "--dangerously-disable-safety"],
    )

    with pytest.raises(SystemExit):
        cli_args.parse_arguments()

    assert "cannot disable safety for a guarded run" in capsys.readouterr().err


def test_observe_resume_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_resumable_run(tmp_path, "observe")
    monkeypatch.setattr(sys, "argv", ["strix", "--resume", "run-1"])

    with pytest.raises(SystemExit):
        cli_args.parse_arguments()

    assert "observe mode was removed" in capsys.readouterr().err

"""Tests for `strix --resume` without a run name."""

from __future__ import annotations

import importlib
import json
import sys
from typing import TYPE_CHECKING, Any

import pytest


if TYPE_CHECKING:
    from pathlib import Path


cli_main: Any = importlib.import_module("strix.interface.main")


def _write_run(base: Path, name: str, *, state: bool = True) -> None:
    run_dir = base / name
    (run_dir / ".state").mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "run_name": name,
                "status": "completed",
                "start_time": "2026-10-04T10:00:00+00:00",
                "targets_info": [
                    {
                        "type": "web_application",
                        "details": {"target_url": "https://example.com"},
                        "original": "https://example.com",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    if state:
        (run_dir / ".state" / "agents.json").write_text("{}", encoding="utf-8")


def test_bare_resume_defers_to_the_picker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_run(tmp_path / "strix_runs", "example-com_1111")
    monkeypatch.setattr(sys, "argv", ["strix", "--resume"])

    args = cli_main.parse_arguments()

    assert args.resume is None
    assert args.resume_picker is True
    assert args.needs_setup is False
    assert args.targets_info == []


def test_bare_resume_keeps_the_new_instruction_as_resume_guidance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_run(tmp_path / "strix_runs", "example-com_1111")
    monkeypatch.setattr(sys, "argv", ["strix", "--resume", "--instruction", "focus on auth"])

    args = cli_main.parse_arguments()

    assert args.resume_picker is True
    assert args.user_explicit_instruction == "focus on auth"


def test_bare_resume_with_no_runs_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["strix", "--resume"])

    with pytest.raises(SystemExit):
        cli_main.parse_arguments()

    assert "no runs in ./strix_runs" in capsys.readouterr().err


def test_bare_resume_headless_lists_the_runs_instead_of_prompting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_run(tmp_path / "strix_runs", "example-com_1111")
    _write_run(tmp_path / "strix_runs", "example-com_2222", state=False)
    monkeypatch.setattr(sys, "argv", ["strix", "-n", "--resume"])

    with pytest.raises(SystemExit):
        cli_main.parse_arguments()

    err = capsys.readouterr().err
    assert "--resume needs a run name in headless mode" in err
    assert "example-com_1111  completed  2026-10-04T10:00:00  https://example.com" in err
    assert "example-com_2222  completed  2026-10-04T10:00:00  https://example.com" in err
    assert "example-com_2222" in err


def test_bare_resume_still_rejects_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_run(tmp_path / "strix_runs", "example-com_1111")
    monkeypatch.setattr(sys, "argv", ["strix", "--resume", "-t", "https://example.com"])

    with pytest.raises(SystemExit):
        cli_main.parse_arguments()

    assert "Cannot combine --resume with --target" in capsys.readouterr().err


def test_named_resume_without_agent_state_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_run(tmp_path / "strix_runs", "example-com_1111", state=False)
    monkeypatch.setattr(sys, "argv", ["strix", "--resume", "example-com_1111"])

    with pytest.raises(SystemExit):
        cli_main.parse_arguments()

    assert "never reached its first agent snapshot" in capsys.readouterr().err

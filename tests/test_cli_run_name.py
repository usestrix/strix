"""Tests for the --run-name CLI argument (deterministic run dirs)."""

from __future__ import annotations

import importlib
import sys
from types import SimpleNamespace
from typing import Any

import pytest


cli_main: Any = importlib.import_module("strix.interface.main")


def _stub_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(max_local_copy_mb=1024)),
    )


def test_run_name_accepts_single_segment(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_settings(monkeypatch)
    monkeypatch.setattr(
        sys, "argv", ["strix", "-t", "https://example.com/", "-n", "--run-name", "my-scan-42"]
    )
    args = cli_main.parse_arguments()
    assert args.run_name == "my-scan-42"


def test_run_name_defaults_to_none(monkeypatch: pytest.MonkeyPatch) -> None:
    # Absent flag → None; main() then falls back to --resume / generate_run_name.
    _stub_settings(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["strix", "-t", "https://example.com/", "-n"])
    args = cli_main.parse_arguments()
    assert args.run_name is None


@pytest.mark.parametrize("bad", ["a/b", "../escape", "sub/dir/name", "/abs"])
def test_run_name_rejects_path_traversal(bad: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # run_dir_for() joins straight onto ./strix_runs/, so a separator or a
    # parent hop would escape the runs tree — must be a single segment.
    _stub_settings(monkeypatch)
    monkeypatch.setattr(
        sys, "argv", ["strix", "-t", "https://example.com/", "-n", "--run-name", bad]
    )
    with pytest.raises(SystemExit):
        cli_main.parse_arguments()


@pytest.mark.parametrize("dotted", [".", ".."])
def test_run_name_rejects_dot_segments(dotted: str, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_settings(monkeypatch)
    monkeypatch.setattr(
        sys, "argv", ["strix", "-t", "https://example.com/", "-n", "--run-name", dotted]
    )
    with pytest.raises(SystemExit):
        cli_main.parse_arguments()


def test_run_name_conflicting_with_resume_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    # --run-name and --resume that name different dirs would resume one run and
    # persist to another — require them to agree.
    _stub_settings(monkeypatch)
    monkeypatch.setattr(
        sys, "argv", ["strix", "-n", "--resume", "run-a", "--run-name", "run-b"]
    )
    with pytest.raises(SystemExit):
        cli_main.parse_arguments()


def test_fresh_run_name_on_existing_dir_is_rejected(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A fresh (non-resume) --run-name that names an existing run dir would
    # overwrite run.json but leave the prior run's findings/state — reject it.
    _stub_settings(monkeypatch)
    (tmp_path / "strix_runs" / "already-here").mkdir(parents=True)
    monkeypatch.setattr(cli_main, "run_dir_for", lambda name: tmp_path / "strix_runs" / name)
    monkeypatch.setattr(
        sys, "argv", ["strix", "-t", "https://example.com/", "-n", "--run-name", "already-here"]
    )
    with pytest.raises(SystemExit):
        cli_main.parse_arguments()


def test_fresh_run_name_on_new_dir_is_accepted(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A name that does NOT collide is fine.
    _stub_settings(monkeypatch)
    (tmp_path / "strix_runs").mkdir(parents=True)
    monkeypatch.setattr(cli_main, "run_dir_for", lambda name: tmp_path / "strix_runs" / name)
    monkeypatch.setattr(
        sys, "argv", ["strix", "-t", "https://example.com/", "-n", "--run-name", "brand-new"]
    )
    args = cli_main.parse_arguments()
    assert args.run_name == "brand-new"

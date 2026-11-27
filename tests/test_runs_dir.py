"""Tests for configurable runs directory support (#1805)."""

from __future__ import annotations

import importlib
import json
import os
import sys
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest


if TYPE_CHECKING:
    from pathlib import Path

from strix.config import loader
from strix.core.paths import (
    RUNS_DIR_ENV,
    latest_run_dir,
    run_dir_display,
    run_dir_for,
    runs_base_dir,
    runs_dir_display,
)
from strix.interface.viewer import cli as viewer_cli
from strix.report.runs import list_run_summaries


cli_main: Any = importlib.import_module("strix.interface.main")


def _write_run(runs_root: Path, name: str, *, with_state: bool = True) -> Path:
    run_dir = runs_root / name
    (run_dir / ".state").mkdir(parents=True, exist_ok=True)
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "run_name": name,
                "status": "completed",
                "start_time": "2026-10-04T10:00:00+00:00",
                "end_time": "2026-10-04T10:05:00+00:00",
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
    if with_state:
        (run_dir / ".state" / "agents.json").write_text("{}", encoding="utf-8")
    return run_dir


@pytest.fixture(autouse=True)
def _isolate_runs_dir(monkeypatch: pytest.MonkeyPatch) -> Any:
    prev = os.environ.pop(RUNS_DIR_ENV, None)
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(loader, "_override", None)
    try:
        yield
    finally:
        if prev is None:
            os.environ.pop(RUNS_DIR_ENV, None)
        else:
            os.environ[RUNS_DIR_ENV] = prev


def test_paths_default_and_env_overrides(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert runs_base_dir() == tmp_path / "strix_runs"
    assert run_dir_for("scan-1") == tmp_path / "strix_runs" / "scan-1"
    assert runs_dir_display() == "./strix_runs"
    assert run_dir_display("scan-1") == "strix_runs/scan-1"

    monkeypatch.setenv(RUNS_DIR_ENV, "artifacts/runs")
    assert runs_base_dir() == tmp_path / "artifacts" / "runs"
    assert run_dir_for("scan-1") == tmp_path / "artifacts" / "runs" / "scan-1"
    assert runs_dir_display() == "./artifacts/runs"
    assert run_dir_display("scan-1") == "artifacts/runs/scan-1"

    abs_dir = (tmp_path.parent / f"{tmp_path.name}_external_runs").resolve()
    monkeypatch.setenv(RUNS_DIR_ENV, str(abs_dir))
    assert runs_base_dir() == abs_dir
    assert run_dir_for("scan-1") == abs_dir / "scan-1"
    assert runs_dir_display() == str(abs_dir)
    assert run_dir_display("scan-1") == str(abs_dir / "scan-1")


def test_paths_expanduser_and_explicit_argument(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv(RUNS_DIR_ENV, "~/my-strix-runs")

    assert runs_base_dir() == fake_home / "my-strix-runs"

    override_dir = tmp_path / "explicit-runs"
    assert runs_base_dir(runs_dir=override_dir) == override_dir


def test_config_file_and_empty_env_override_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "cli-config.json"
    config_path.write_text(
        json.dumps({"env": {"STRIX_RUNS_DIR": "configured-runs"}}),
        encoding="utf-8",
    )
    loader.apply_config_override(config_path)

    assert runs_base_dir() == tmp_path / "configured-runs"

    # Empty env value clears the configured override and falls back to default.
    monkeypatch.setenv(RUNS_DIR_ENV, "")
    assert runs_base_dir() == tmp_path / "strix_runs"


def test_latest_run_dir_and_list_run_summaries_use_configured_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    custom_root = tmp_path / "custom-runs"
    old_run = _write_run(custom_root, "old-run")
    new_run = _write_run(custom_root, "new-run")
    os.utime(old_run / "run.json", (1_000_000_000, 1_000_000_000))
    os.utime(new_run / "run.json", (2_000_000_000, 2_000_000_000))

    monkeypatch.setenv(RUNS_DIR_ENV, str(custom_root))
    assert latest_run_dir() == new_run
    summaries = list_run_summaries()
    assert [s.run_name for s in summaries] == ["new-run", "old-run"]


def test_cli_runs_dir_sets_env_and_supports_resume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    custom_root = tmp_path / "ci-runs"
    _write_run(custom_root, "api-scan_001")

    monkeypatch.setattr(
        sys, "argv", ["strix", "--runs-dir", str(custom_root), "--resume", "api-scan_001"]
    )
    args = cli_main.parse_arguments()

    assert os.environ[RUNS_DIR_ENV] == str(custom_root)
    assert args.resume == "api-scan_001"
    assert len(args.targets_info) == 1


@pytest.mark.parametrize("bad_value", ["", "   "])
def test_cli_runs_dir_rejects_empty_value(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    bad_value: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        sys, "argv", ["strix", "--runs-dir", bad_value, "-t", "https://example.com", "-n"]
    )

    with pytest.raises(SystemExit) as exc:
        cli_main.parse_arguments()

    assert exc.value.code == 2
    assert "--runs-dir must not be empty" in capsys.readouterr().err


def test_cli_rejects_env_and_config_runs_dir_that_is_a_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    file_path = tmp_path / "not-a-dir"
    file_path.write_text("x", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["strix", "-t", "https://example.com", "-n"])

    monkeypatch.setenv(RUNS_DIR_ENV, str(file_path))
    with pytest.raises(SystemExit) as exc:
        cli_main.parse_arguments()
    assert exc.value.code == 2
    assert "runs directory is not a directory" in capsys.readouterr().err

    monkeypatch.delenv(RUNS_DIR_ENV)
    config_path = tmp_path / "cli-config.json"
    config_path.write_text(json.dumps({"env": {RUNS_DIR_ENV: str(file_path)}}), encoding="utf-8")
    loader.apply_config_override(config_path)
    with pytest.raises(SystemExit) as exc:
        cli_main.parse_arguments()
    assert exc.value.code == 2
    assert "runs directory is not a directory" in capsys.readouterr().err


def test_cli_runs_dir_rejects_existing_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    file_path = tmp_path / "not-a-dir"
    file_path.write_text("x", encoding="utf-8")
    monkeypatch.setattr(
        sys, "argv", ["strix", "--runs-dir", str(file_path), "-t", "https://example.com", "-n"]
    )

    with pytest.raises(SystemExit) as exc:
        cli_main.parse_arguments()

    assert exc.value.code == 2
    assert "--runs-dir is not a directory" in capsys.readouterr().err


def test_bare_resume_no_runs_reports_custom_runs_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["strix", "--runs-dir", "custom_runs", "--resume"])

    with pytest.raises(SystemExit):
        cli_main.parse_arguments()

    assert "no runs in ./custom_runs" in capsys.readouterr().err


def test_viewer_cli_runs_dir_resolves_run_and_reports_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    custom_root = tmp_path / "viewer-runs"
    expected_run_dir = _write_run(custom_root, "my-run")
    served: list[Path] = []

    class _FakeHttpd:
        def shutdown(self) -> None:
            pass

        def server_close(self) -> None:
            pass

    def _fake_serve(run_dir: Path, **_kwargs: Any) -> tuple[_FakeHttpd, str, str]:
        served.append(run_dir)
        return _FakeHttpd(), "http://127.0.0.1:9999", "tok"

    def _stop_loop(_seconds: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(viewer_cli, "bundle_is_built", lambda: True)
    monkeypatch.setattr(viewer_cli, "serve", _fake_serve)
    monkeypatch.setattr("time.sleep", _stop_loop)
    monkeypatch.setattr(
        "strix.telemetry.posthog", SimpleNamespace(viewer_opened=lambda **_kw: None)
    )

    viewer_cli.run_view(["--runs-dir", "viewer-runs", "--no-open", "my-run"])
    assert served == [expected_run_dir]

    with pytest.raises(SystemExit) as exc:
        viewer_cli.run_view(["--runs-dir", "viewer-runs", "--no-open", "missing-run"])
    assert exc.value.code == 1
    assert "No run named 'missing-run' under ./viewer-runs." in capsys.readouterr().out

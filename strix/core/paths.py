"""Run directory path helpers."""

from __future__ import annotations

import os
from pathlib import Path

from strix.config.loader import load_settings


RUNS_DIR_NAME = "strix_runs"
RUNS_DIR_ENV = "STRIX_RUNS_DIR"
RUNTIME_STATE_DIR_NAME = ".state"
RUN_RECORD_FILENAME = "run.json"


def _resolve_runs_dir_value(runs_dir: str | Path | None = None) -> str:
    if runs_dir is not None:
        return str(runs_dir).strip()
    if RUNS_DIR_ENV in os.environ:
        return os.environ[RUNS_DIR_ENV].strip()
    return (load_settings().runtime.runs_dir or "").strip()


def run_dir_for(
    run_name: str, *, cwd: Path | None = None, runs_dir: str | Path | None = None
) -> Path:
    return runs_base_dir(cwd=cwd, runs_dir=runs_dir) / run_name


def runtime_state_dir(run_dir: Path) -> Path:
    return run_dir / RUNTIME_STATE_DIR_NAME


def run_record_path(run_dir: Path) -> Path:
    return run_dir / RUN_RECORD_FILENAME


def runs_base_dir(*, cwd: Path | None = None, runs_dir: str | Path | None = None) -> Path:
    raw = _resolve_runs_dir_value(runs_dir)
    selected = Path(raw).expanduser() if raw else Path(RUNS_DIR_NAME)
    if selected.is_absolute():
        return selected
    base = cwd or Path.cwd()
    return base / selected


def runs_dir_display(*, cwd: Path | None = None, runs_dir: str | Path | None = None) -> str:
    """Human-readable runs directory path, relative to cwd when inside it."""
    base = runs_base_dir(cwd=cwd, runs_dir=runs_dir)
    root = (cwd or Path.cwd()).resolve()
    try:
        rel = base.resolve().relative_to(root)
    except ValueError:
        return str(base)
    rel_posix = rel.as_posix()
    return "." if rel_posix == "." else f"./{rel_posix}"


def run_dir_display(
    run_name: str, *, cwd: Path | None = None, runs_dir: str | Path | None = None
) -> str:
    """Human-readable path for a single run directory."""
    run_path = run_dir_for(run_name, cwd=cwd, runs_dir=runs_dir)
    root = (cwd or Path.cwd()).resolve()
    try:
        rel = run_path.resolve().relative_to(root)
    except ValueError:
        return str(run_path)
    return rel.as_posix()


def validate_runs_dir_arg(raw: str) -> str:
    """Validate a ``--runs-dir`` CLI argument and return the normalized value."""
    normalized = raw.strip()
    if not normalized:
        raise ValueError("--runs-dir must not be empty")
    resolved = Path(normalized).expanduser()
    if resolved.exists() and not resolved.is_dir():
        raise ValueError(f"--runs-dir is not a directory: {raw}")
    return normalized


def latest_run_dir(*, cwd: Path | None = None, runs_dir: str | Path | None = None) -> Path | None:
    base = runs_base_dir(cwd=cwd, runs_dir=runs_dir)
    if not base.is_dir():
        return None
    candidates = [child for child in base.iterdir() if run_record_path(child).is_file()]
    if not candidates:
        return None
    # run.json is rewritten on status/end changes, so its mtime tracks activity
    # more reliably than the directory mtime (a live run sorts to the top).
    return max(candidates, key=lambda child: run_record_path(child).stat().st_mtime)

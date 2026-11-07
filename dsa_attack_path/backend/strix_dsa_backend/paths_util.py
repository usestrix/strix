"""Resolve ``strix_runs/<run>/`` without requiring Strix to be importable."""

from __future__ import annotations

from pathlib import Path


RUNS_DIR_NAME = "strix_runs"
ATTACK_PATH_DIRNAME = "attack_path"


def runs_base_dir(*, cwd: Path | None = None) -> Path:
    try:
        from strix.core.paths import runs_base_dir as strix_runs_base

        return strix_runs_base(cwd=cwd)
    except Exception:
        base = cwd or Path.cwd()
        return base / RUNS_DIR_NAME


def run_dir_for(run_name: str, *, cwd: Path | None = None) -> Path:
    try:
        from strix.core.paths import run_dir_for as strix_run_dir_for

        return strix_run_dir_for(run_name, cwd=cwd)
    except Exception:
        return runs_base_dir(cwd=cwd) / run_name


def resolve_run_dir(run: str | Path, *, cwd: Path | None = None) -> Path:
    """Accept a run name under ``strix_runs/`` or an absolute/relative run directory."""
    path = Path(run)
    if path.is_dir() and (path / "vulnerabilities.json").exists():
        return path.resolve()
    if path.is_dir() and (path / "run.json").exists():
        return path.resolve()
    candidate = run_dir_for(str(run), cwd=cwd)
    if candidate.is_dir():
        return candidate.resolve()
    raise FileNotFoundError(
        f"Run not found: {run!r} (looked for directory and {candidate})"
    )


def attack_path_dir(run_dir: Path) -> Path:
    return run_dir / ATTACK_PATH_DIRNAME

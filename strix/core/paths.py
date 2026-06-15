"""Run directory path helpers."""

from __future__ import annotations

from pathlib import Path


RUNS_DIR_NAME = "strix_runs"
RUNTIME_STATE_DIR_NAME = ".state"
RUN_RECORD_FILENAME = "run.json"


def validate_run_name(run_name: str) -> str:
    """Validate that a run name stays within the local runs directory."""

    normalized = run_name.strip()
    if not normalized:
        raise ValueError("Run name must be a non-empty string")

    if "\\" in normalized:
        raise ValueError("Run name must not contain path separators or traversal segments")

    candidate = Path(normalized)
    if candidate.is_absolute():
        raise ValueError("Run name must be a relative directory name")

    if normalized in {".", ".."}:
        raise ValueError("Run name must not be '.' or '..'")

    if candidate.parts != (normalized,):
        raise ValueError("Run name must not contain path separators or traversal segments")

    return normalized


def run_dir_for(run_name: str, *, cwd: Path | None = None) -> Path:
    base = cwd or Path.cwd()
    return base / RUNS_DIR_NAME / validate_run_name(run_name)


def runtime_state_dir(run_dir: Path) -> Path:
    return run_dir / RUNTIME_STATE_DIR_NAME


def run_record_path(run_dir: Path) -> Path:
    return run_dir / RUN_RECORD_FILENAME


def oob_registry_path(run_dir: Path) -> Path:
    """Return the durable SQLite path for the OOB token registry."""
    return runtime_state_dir(run_dir) / "oob_registry.sqlite"


def inventory_path(run_dir: Path, target_id: str) -> Path:
    """Return the durable per-target inventory store path."""
    safe_target_id = target_id.replace("/", "_").replace("\\", "_")
    return run_dir / RUNTIME_STATE_DIR_NAME / f"inventory_{safe_target_id}.json"

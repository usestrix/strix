"""Run directory path helpers."""

from __future__ import annotations

from errno import ELOOP
from pathlib import Path
from stat import S_ISREG
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import Iterator


RUNS_DIR_NAME = "strix_runs"
RUNTIME_STATE_DIR_NAME = ".state"
RUN_RECORD_FILENAME = "run.json"


def run_dir_for(run_name: str, *, cwd: Path | None = None) -> Path:
    base = cwd or Path.cwd()
    return base / RUNS_DIR_NAME / run_name


def runtime_state_dir(run_dir: Path) -> Path:
    return run_dir / RUNTIME_STATE_DIR_NAME


def run_record_path(run_dir: Path) -> Path:
    return run_dir / RUN_RECORD_FILENAME


def runs_base_dir(*, cwd: Path | None = None) -> Path:
    base = cwd or Path.cwd()
    return base / RUNS_DIR_NAME


def iter_run_records(base_dir: Path) -> Iterator[tuple[Path, float]]:
    """Yield run directories and their record modification times."""
    try:
        for child in base_dir.iterdir():
            try:
                # Check the file type and capture its mtime with one lookup. The
                # record can disappear between separate is_file() and stat() calls.
                metadata = run_record_path(child).stat()
            except (FileNotFoundError, NotADirectoryError):
                continue
            except OSError as exc:
                if exc.errno == ELOOP:
                    continue
                raise
            if S_ISREG(metadata.st_mode):
                yield child, metadata.st_mtime
    except (FileNotFoundError, NotADirectoryError):
        return
    except OSError as exc:
        if exc.errno != ELOOP:
            raise


def latest_run_dir(*, cwd: Path | None = None) -> Path | None:
    # The record's mtime tracks status and end-time changes, unlike the directory's.
    newest = max(iter_run_records(runs_base_dir(cwd=cwd)), key=lambda run: run[1], default=None)
    return newest[0] if newest is not None else None

"""Run directory path helpers."""

from __future__ import annotations

import contextlib
import re
from pathlib import Path


RUNS_DIR_NAME = "strix_runs"
RUNTIME_STATE_DIR_NAME = ".state"
RUN_RECORD_FILENAME = "run.json"

# Owner-only perms for the run tree: run artifacts (transcripts, vulnerability
# MDs, run.json) can contain credentials/PoCs harvested from the target.
_RUN_DIR_MODE = 0o700

# Emitted into strix_runs/ so run artifacts are never accidentally committed —
# whitebox scans routinely run from a git work tree with the target repo.
_GITIGNORE_NAME = ".gitignore"
_GITIGNORE_BODY = (
    "# Strix run artifacts may contain captured credentials and PoCs.\n"
    "# Never commit them.\n"
    "*\n"
)


def sanitize_run_name(run_name: str) -> str:
    """Reduce a run/resume name to a single safe path component.

    Security: ``--resume <name>`` and generated run names are joined into a
    filesystem path (``strix_runs/<name>``). Without this an attacker-controlled
    or crafted name like ``../../etc`` would escape ``strix_runs/``. We keep only
    the final component and strip anything outside ``[A-Za-z0-9._-]``, then drop
    leading/trailing dots and dashes so ``..`` can never survive.
    """
    name = str(run_name).strip().replace("\\", "/")
    name = name.rsplit("/", 1)[-1]
    name = re.sub(r"[^A-Za-z0-9._-]", "-", name)
    name = name.strip(".-")
    return name or "run"


def run_dir_for(run_name: str, *, cwd: Path | None = None) -> Path:
    base = cwd or Path.cwd()
    # Sanitize so a crafted run/resume name cannot traverse out of strix_runs/.
    return base / RUNS_DIR_NAME / sanitize_run_name(run_name)


def runtime_state_dir(run_dir: Path) -> Path:
    return run_dir / RUNTIME_STATE_DIR_NAME


def run_record_path(run_dir: Path) -> Path:
    return run_dir / RUN_RECORD_FILENAME


def runs_base_dir(*, cwd: Path | None = None) -> Path:
    base = cwd or Path.cwd()
    return base / RUNS_DIR_NAME


def ensure_run_root(*, cwd: Path | None = None) -> Path:
    """Create ``strix_runs/`` owner-only and drop a ``*`` .gitignore in it.

    Idempotent. chmod is best-effort (a no-op on Windows), so a limited
    filesystem never crashes the run.
    """
    base = runs_base_dir(cwd=cwd)
    # Pass mode to mkdir so a freshly created dir is 0700 from the start (no
    # world-readable window between mkdir and chmod). chmod still runs to fix an
    # already-existing dir, where mkdir(mode=) is a no-op.
    with contextlib.suppress(OSError):
        base.mkdir(mode=_RUN_DIR_MODE, parents=True, exist_ok=True)
    if not base.is_dir():
        base.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        base.chmod(_RUN_DIR_MODE)
    gitignore = base / _GITIGNORE_NAME
    if not gitignore.exists():
        with contextlib.suppress(OSError):
            gitignore.write_text(_GITIGNORE_BODY, encoding="utf-8")
    return base


def create_run_dir(run_name: str, *, cwd: Path | None = None) -> Path:
    """Create (owner-only) the run dir for ``run_name`` and its .gitignore'd root."""
    ensure_run_root(cwd=cwd)
    run_dir = run_dir_for(run_name, cwd=cwd)
    run_dir.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        run_dir.chmod(_RUN_DIR_MODE)
    return run_dir


def latest_run_dir(*, cwd: Path | None = None) -> Path | None:
    base = runs_base_dir(cwd=cwd)
    if not base.is_dir():
        return None
    candidates = [child for child in base.iterdir() if run_record_path(child).is_file()]
    if not candidates:
        return None
    # run.json is rewritten on status/end changes, so its mtime tracks activity
    # more reliably than the directory mtime (a live run sorts to the top).
    return max(candidates, key=lambda child: run_record_path(child).stat().st_mtime)

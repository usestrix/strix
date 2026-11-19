"""Runs one Strix scan as a subprocess and hands back its run directory.

This is the half of the old in-process ``ScanRunner`` that actually shells out
to ``strix``. In the Kafka split it lives on the **worker**: the frontal no
longer runs Strix, it only asks for a run over ``scan.requests``. Kept storage-
and DB-agnostic on purpose — the worker decides where the run directory goes and
the frontal owns Postgres.

One scan is one ``strix`` invocation in a private working directory, so the run
directory it generates (the CLI names runs itself) is unambiguous afterwards.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from frontal.app.config import Settings


logger = logging.getLogger(__name__)

# strix headless exit codes: 0 = clean, 2 = vulnerabilities found. Both are a
# successful run; only other codes (or no run directory) are a real failure.
_OK_EXIT_CODES = frozenset({0, 2})


@dataclass(frozen=True)
class ScanRequest:
    scan_id: int
    target: str
    scan_mode: str
    instruction: str | None
    kind: str = "scan"

    @classmethod
    def from_message(cls, value: dict[str, Any]) -> ScanRequest:
        return cls(
            scan_id=int(value["scan_id"]),
            target=str(value["target"]),
            scan_mode=str(value.get("scan_mode", "deep")),
            instruction=value.get("instruction"),
            kind=str(value.get("kind", "scan")),
        )

    def to_message(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "scan_mode": self.scan_mode,
            "instruction": self.instruction,
            "kind": self.kind,
        }


@dataclass(frozen=True)
class ScanOutcome:
    run_dir: Path | None
    failure: str | None


def build_command(
    settings: Settings, target: str, scan_mode: str, instruction_file: Path | None
) -> list[str]:
    command = [
        settings.strix_bin,
        "--target",
        target,
        "--non-interactive",
        "--scan-mode",
        scan_mode,
    ]
    if instruction_file is not None:
        command += ["--instruction-file", str(instruction_file)]
    if settings.max_budget_usd is not None:
        command += ["--max-budget-usd", str(settings.max_budget_usd)]
    return command


def find_run_dir(workdir: Path) -> Path | None:
    runs_base = workdir / "strix_runs"
    if not runs_base.is_dir():
        return None
    candidates = [child for child in runs_base.iterdir() if (child / "run.json").is_file()]
    if not candidates:
        return None
    return max(candidates, key=lambda child: (child / "run.json").stat().st_mtime)


def run_scan(settings: Settings, req: ScanRequest, workdir: Path) -> ScanOutcome:
    shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True, exist_ok=True)

    instruction_file: Path | None = None
    if req.instruction:
        instruction_file = workdir / "instruction.md"
        instruction_file.write_text(req.instruction, encoding="utf-8")

    command = build_command(settings, req.target, req.scan_mode, instruction_file)
    logger.info("scan %s launching: %s", req.scan_id, " ".join(command))

    failure: str | None = None
    try:
        completed = subprocess.run(  # noqa: S603 - argv list, never a shell string
            command,
            cwd=workdir,
            env=os.environ.copy(),
            capture_output=True,
            text=True,
            timeout=settings.scan_timeout_seconds,
            check=False,
        )
        (workdir / "strix.stdout.log").write_text(completed.stdout or "", encoding="utf-8")
        (workdir / "strix.stderr.log").write_text(completed.stderr or "", encoding="utf-8")
        if completed.returncode not in _OK_EXIT_CODES:
            failure = f"strix exited with code {completed.returncode}"
    except subprocess.TimeoutExpired:
        failure = f"scan exceeded {settings.scan_timeout_seconds}s and was killed"
    except FileNotFoundError:
        failure = f"strix binary not found: {settings.strix_bin}"

    # A failed scan may still have produced findings before dying, so the run
    # directory is harvested either way.
    run_dir = find_run_dir(workdir)
    if run_dir is None:
        failure = failure or "scan produced no run directory"
    return ScanOutcome(run_dir=run_dir, failure=failure)

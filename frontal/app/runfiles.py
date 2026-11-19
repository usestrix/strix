"""Read a finished Strix run directory without importing Strix.

The frontal only needs three files out of a run (``run.json``,
``vulnerabilities.json``, ``penetration_test_report.md``). Reading them here,
instead of through ``strix.interface.viewer.transcript``, keeps the frontal
importable without the whole Strix package: ``strix.interface`` pulls in the CLI
and the TUI on import. Only the optional agent-transcript viewer needs Strix.

Same semantics as the upstream readers: a missing or corrupt file reads as
empty, never raises.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


_TERMINAL_STATUSES = {"completed", "stopped", "failed", "interrupted"}


def _load_json(path: Path, *, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def read_run_summary(run_dir: Path) -> dict[str, Any]:
    """The ``run.json`` record plus a computed ``finished`` flag."""
    record = _load_json(run_dir / "run.json", default={})
    if not isinstance(record, dict):
        record = {}
    finished = record.get("status") in _TERMINAL_STATUSES and bool(record.get("end_time"))
    return {**record, "finished": finished}


def read_vulnerabilities(run_dir: Path) -> list[Any]:
    data = _load_json(run_dir / "vulnerabilities.json", default=[])
    return data if isinstance(data, list) else []


def read_report_markdown(run_dir: Path) -> str:
    try:
        return (run_dir / "penetration_test_report.md").read_text(encoding="utf-8")
    except OSError:
        return ""

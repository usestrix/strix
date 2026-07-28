"""Build the JSON payloads the viewer SPA consumes from a run directory."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from strix.core.paths import run_record_path


if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)

_TERMINAL_STATUSES = {"completed", "stopped", "failed", "interrupted"}

_KNOWN_SEVERITIES = ("critical", "high", "medium", "low")


def severity_counts(vulns: list[Any]) -> dict[str, int]:
    """Bucket vulnerabilities into critical/high/medium/low counts.

    Mirrors the SPA's ``severityCounts``: severities are lowercased and
    trimmed, and anything outside the four known buckets (``info``,
    ``informational``, ``unknown``, missing, ...) folds into ``low`` so the
    shared UI renders cleanly.
    """
    counts = dict.fromkeys(_KNOWN_SEVERITIES, 0)
    for vuln in vulns:
        raw = vuln.get("severity") if isinstance(vuln, dict) else None
        severity = str(raw or "").lower().strip()
        if severity not in counts:
            severity = "low"
        counts[severity] += 1
    return counts


def build_run_state(run_dir: Path) -> dict[str, Any]:
    """Agent graph + full per-agent event/message stream.

    Reuses the Textual-free ``TuiLiveView`` projection so the viewer and the TUI
    share one parser for ``agents.json`` + ``agents.db`` and never drift.
    """
    # Imported lazily so importing strix.interface.viewer does not eagerly pull the TUI.
    from strix.interface.tui.live_view import TuiLiveView

    view = TuiLiveView()
    view.hydrate_from_run_dir(run_dir)
    return {"agents": list(view.agents.values()), "events": view.events}


def read_run_summary(run_dir: Path) -> dict[str, Any]:
    """The ``run.json`` record plus a computed ``finished`` flag."""
    record = _load_json(run_record_path(run_dir), default={})
    if not isinstance(record, dict):
        record = {}
    status = record.get("status")
    finished = status in _TERMINAL_STATUSES and bool(record.get("end_time"))
    return {**record, "finished": finished}


def primary_target(record: dict[str, Any]) -> str | None:
    """The first target's original string from a run record, or None."""
    targets = record.get("targets_info")
    if isinstance(targets, list):
        for entry in targets:
            if isinstance(entry, dict):
                original = entry.get("original")
                if isinstance(original, str) and original:
                    return original
    return None


def read_vulnerabilities(run_dir: Path) -> list[Any]:
    """The ``vulnerabilities.json`` list (empty until a scan writes it)."""
    data = _load_json(run_dir / "vulnerabilities.json", default=[])
    return data if isinstance(data, list) else []


def read_report_markdown(run_dir: Path) -> str:
    """The executive report markdown (empty until a scan writes it)."""
    report_path = run_dir / "penetration_test_report.md"
    try:
        return report_path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _load_json(path: Path, *, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


__all__ = [
    "build_run_state",
    "primary_target",
    "read_report_markdown",
    "read_run_summary",
    "read_vulnerabilities",
    "severity_counts",
]

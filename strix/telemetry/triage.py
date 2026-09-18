"""Best-effort classification metrics; never includes finding content or notes."""

from __future__ import annotations

import logging
import queue
import re
import threading
from typing import TYPE_CHECKING, Any, cast

from strix.config import load_settings
from strix.report.triage_store import read_json
from strix.telemetry import posthog
from strix.telemetry._common import base_props


if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)
_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=128)
_worker: threading.Thread | None = None
_guard = threading.Lock()
_REASONS = frozenset(
    {
        "unspecified",
        "incorrect_assumption",
        "existing_protection",
        "not_affected",
        "expected_behavior",
        "other",
    }
)
_CWE = re.compile(r"cwe-[1-9][0-9]{0,5}\Z")


def _category(value: Any, allowed: set[str] | frozenset[str]) -> str:
    normalized = value.lower().strip() if isinstance(value, str) else ""
    return normalized if normalized in allowed else "unknown"


def _cwe(value: Any) -> str:
    if not isinstance(value, str):
        return "unknown"
    normalized = value.lower().strip()
    return normalized if _CWE.fullmatch(normalized) else "unknown"


def _deliver() -> None:
    global _worker  # noqa: PLW0603
    while True:
        # Share the producer's lock while retiring: an event arriving as the
        # queue empties must either find this worker or start its replacement.
        with _guard:
            try:
                properties = _queue.get_nowait()
            except queue.Empty:
                _worker = None
                return
        try:
            # The final sender also checks the current setting. No disk backlog
            # survives this process, and disabled events are never enqueued.
            if load_settings().telemetry.enabled:
                posthog.finding_triage_changed(properties)
        except Exception:  # noqa: BLE001
            logger.debug("Review metric delivery failed")
        finally:
            _queue.task_done()


def _enqueue(properties: dict[str, Any]) -> None:
    global _worker  # noqa: PLW0603
    with _guard:
        _queue.put_nowait(properties)
        if _worker is None or not _worker.is_alive():
            _worker = threading.Thread(target=_deliver, name="strix-triage-metrics", daemon=True)
            _worker.start()


def record_triage(
    previous: dict[str, Any], current: dict[str, Any], *, run_dir: Path, surface: str
) -> None:
    """Build an allowlisted event after commit; errors never reach the user's action."""
    try:
        if not load_settings().telemetry.enabled:
            return
        record = read_json(run_dir / "run.json", default={})
        mode = cast("dict[str, Any]", record).get("scan_mode") if isinstance(record, dict) else None
        previous_resolution = previous.get("resolution_reason")
        resolution = current.get("resolution_reason")
        properties = {
            **base_props(),
            "schema_version": 1,
            "surface": _category(surface, {"viewer", "tui"}),
            "previous_status": _category(previous.get("status"), {"open", "closed"}),
            "new_status": _category(current.get("status"), {"open", "closed"}),
            "previous_resolution_reason": (
                "false_positive" if previous_resolution == "false_positive" else None
            ),
            "resolution_reason": "false_positive" if resolution == "false_positive" else None,
            "reason_code": _category(current.get("reason_code"), _REASONS),
            "severity": _category(
                current.get("severity"), {"critical", "high", "medium", "low", "info"}
            ),
            "cwe": _cwe(current.get("cwe")),
            "is_cve": bool(current.get("cve")),
            "scan_mode": _category(mode, {"quick", "standard", "deep"}),
        }
        if load_settings().telemetry.enabled:
            _enqueue(properties)
    except Exception:  # noqa: BLE001
        logger.debug("Review metric skipped")

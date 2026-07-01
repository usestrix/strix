from __future__ import annotations

import logging
import urllib.parse
import urllib.request
from datetime import datetime
from typing import TYPE_CHECKING, Any

from strix.config import load_settings
from strix.telemetry._common import (
    SESSION_ID,
    base_props,
    get_version,
    is_first_run,
)


if TYPE_CHECKING:
    from strix.report.state import ReportState


logger = logging.getLogger(__name__)

_SCARF_ENDPOINT = "https://strix.gateway.scarf.sh"


def _is_enabled() -> bool:
    return load_settings().telemetry.enabled


def _send(event: str, properties: dict[str, Any]) -> None:
    if not _is_enabled():
        logger.debug("scarf disabled; skipping event %s", event)
        return
    try:
        props = dict(properties)
        version = str(props.pop("strix_version", get_version()) or "unknown")
        path = f"/{urllib.parse.quote(event, safe='')}/{urllib.parse.quote(version, safe='')}"
        query = urllib.parse.urlencode(
            {k: ("" if v is None else str(v)) for k, v in props.items()},
        )
        url = f"{_SCARF_ENDPOINT}{path}"
        if query:
            url = f"{url}?{query}"
        req = urllib.request.Request(url, method="POST")  # noqa: S310
        with urllib.request.urlopen(req, timeout=10):  # noqa: S310  # nosec B310
            pass
    except Exception:  # noqa: BLE001
        logger.debug("scarf send failed for event %s", event, exc_info=True)
    else:
        logger.debug("scarf event sent: %s", event)


def start(
    model: str | None,
    scan_mode: str | None,
    is_whitebox: bool,
    interactive: bool,
    has_instructions: bool,
) -> None:
    _send(
        "scan_started",
        {
            **base_props(),
            "session": SESSION_ID,
            "model": model or "unknown",
            "scan_mode": scan_mode or "unknown",
            "scan_type": "whitebox" if is_whitebox else "blackbox",
            "interactive": interactive,
            "has_instructions": has_instructions,
            "first_run": is_first_run(),
        },
    )


def finding(severity: str) -> None:
    _send(
        "finding_reported",
        {
            **base_props(),
            "session": SESSION_ID,
            "severity": severity.lower(),
        },
    )


def end(report_state: ReportState, exit_reason: str = "completed") -> None:
    vulnerabilities_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in report_state.vulnerability_reports:
        sev = v.get("severity", "info").lower()
        if sev in vulnerabilities_counts:
            vulnerabilities_counts[sev] += 1

    duration = 0.0
    try:
        scan_start = datetime.fromisoformat(report_state.start_time.replace("Z", "+00:00"))
        end_iso = report_state.end_time or datetime.now(scan_start.tzinfo).isoformat()
        duration = (
            datetime.fromisoformat(end_iso.replace("Z", "+00:00")) - scan_start
        ).total_seconds()
    except (ValueError, TypeError, AttributeError):
        pass

    llm_props: dict[str, int | float] = {}
    try:
        usage = report_state.get_total_llm_usage()
        if isinstance(usage, dict):
            llm_props = {
                "llm_requests": int(usage.get("requests") or 0),
                "llm_input_tokens": int(usage.get("input_tokens") or 0),
                "llm_output_tokens": int(usage.get("output_tokens") or 0),
                "llm_tokens": int(usage.get("total_tokens") or 0),
                "llm_cost": float(usage.get("cost") or 0.0),
            }
    except (TypeError, ValueError, AttributeError):
        pass

    _send(
        "scan_ended",
        {
            **base_props(),
            "session": SESSION_ID,
            "exit_reason": exit_reason,
            "duration_seconds": round(duration),
            "vulnerabilities_total": len(report_state.vulnerability_reports),
            **{f"vulnerabilities_{k}": v for k, v in vulnerabilities_counts.items()},
            **llm_props,
        },
    )


def error(error_type: str) -> None:
    props: dict[str, Any] = {
        **base_props(),
        "session": SESSION_ID,
        "error_type": error_type,
    }
    _send("error", props)

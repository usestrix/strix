import json
import platform
import sys
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from strix.config import Config


if TYPE_CHECKING:
    from strix.telemetry.tracer import Tracer

_POSTHOG_PUBLIC_API_KEY = "phc_7rO3XRuNT5sgSKAl6HDIrWdSGh1COzxw0vxVIAR6vVZ"
_POSTHOG_HOST = "https://us.i.posthog.com"

_SESSION_ID = uuid4().hex[:16]


def _is_enabled() -> bool:
    return (Config.get("strix_telemetry") or "1").lower() not in ("0", "false", "no", "off")


def _is_first_run() -> bool:
    marker = Path.home() / ".strix" / ".seen"
    if marker.exists():
        return False
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    except Exception:  # noqa: BLE001, S110
        pass  # nosec B110
    return True


def _get_version() -> str:
    try:
        from importlib.metadata import version

        return version("strix-agent")
    except Exception:  # noqa: BLE001
        return "unknown"


def _send(event: str, properties: dict[str, Any]) -> None:
    if not _is_enabled():
        return
    try:
        payload = {
            "api_key": _POSTHOG_PUBLIC_API_KEY,
            "event": event,
            "distinct_id": _SESSION_ID,
            "properties": properties,
        }
        req = urllib.request.Request(  # noqa: S310
            f"{_POSTHOG_HOST}/capture/",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10):  # noqa: S310  # nosec B310
            pass
    except Exception:  # noqa: BLE001, S110
        pass  # nosec B110


def _base_props() -> dict[str, Any]:
    return {
        "os": platform.system().lower(),
        "arch": platform.machine(),
        "python": f"{sys.version_info.major}.{sys.version_info.minor}",
        "strix_version": _get_version(),
    }


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
            **_base_props(),
            "model": model or "unknown",
            "scan_mode": scan_mode or "unknown",
            "scan_type": "whitebox" if is_whitebox else "blackbox",
            "interactive": interactive,
            "has_instructions": has_instructions,
            "first_run": _is_first_run(),
        },
    )


def finding(severity: str) -> None:
    _send(
        "finding_reported",
        {
            **_base_props(),
            "severity": severity.lower(),
        },
    )


def end(tracer: "Tracer", exit_reason: str = "completed") -> None:
    vulnerabilities_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in tracer.vulnerability_reports:
        sev = v.get("severity", "info").lower()
        if sev in vulnerabilities_counts:
            vulnerabilities_counts[sev] += 1

    llm = tracer.get_total_llm_stats()
    total = llm.get("total", {})

    _send(
        "scan_ended",
        {
            **_base_props(),
            "exit_reason": exit_reason,
            "duration_seconds": round(tracer._calculate_duration()),
            "vulnerabilities_total": len(tracer.vulnerability_reports),
            **{f"vulnerabilities_{k}": v for k, v in vulnerabilities_counts.items()},
            "agent_count": len(tracer.agents),
            "tool_count": tracer.get_real_tool_count(),
            "llm_tokens": llm.get("total_tokens", 0),
            "llm_cost": total.get("cost", 0.0),
        },
    )


def error(error_type: str, error_msg: str | None = None) -> None:
    props = {**_base_props(), "error_type": error_type}
    if error_msg:
        props["error_msg"] = error_msg
    _send("error", props)

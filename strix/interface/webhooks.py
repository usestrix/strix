"""Webhook dispatcher for scan completion notifications.

Sends scan results to external services (Slack, Discord, or generic JSON endpoints)
when a penetration test completes.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import requests


if TYPE_CHECKING:
    import argparse


logger = logging.getLogger(__name__)

WEBHOOK_TIMEOUT = 10


def send_completion_webhook(
    webhook_url: str,
    webhook_format: str,
    tracer: Any,
    args: argparse.Namespace,
) -> None:
    """Send scan completion results to a webhook URL.

    Args:
        webhook_url: The destination webhook URL.
        webhook_format: One of ``"generic"``, ``"slack"``, or ``"discord"``.
        tracer: The global :class:`Tracer` instance containing scan results.
        args: Parsed CLI arguments (used to extract target info and run name).
    """
    resolved_format = _resolve_format(webhook_url, webhook_format)

    formatters: dict[str, Any] = {
        "generic": _format_generic,
        "slack": _format_slack,
        "discord": _format_discord,
    }

    formatter = formatters.get(resolved_format, _format_generic)
    payload = formatter(tracer, args)

    try:
        response = requests.post(webhook_url, json=payload, timeout=WEBHOOK_TIMEOUT)
        response.raise_for_status()
        logger.info(
            "Webhook delivered successfully to %s (status %s)",
            webhook_url,
            response.status_code,
        )
    except requests.RequestException as exc:
        logger.warning("Failed to deliver webhook to %s: %s", webhook_url, exc)


# ---------------------------------------------------------------------------
# Format resolution
# ---------------------------------------------------------------------------


def _resolve_format(url: str, explicit_format: str) -> str:
    """Auto-detect the webhook format from the URL when the user chose ``"generic"``."""
    if explicit_format != "generic":
        return explicit_format

    host = urlparse(url).hostname or ""
    if "hooks.slack.com" in host:
        return "slack"
    if "discord.com" in host or "discordapp.com" in host:
        return "discord"

    return "generic"


# ---------------------------------------------------------------------------
# Payload helpers
# ---------------------------------------------------------------------------


def _targets_summary(args: argparse.Namespace) -> str:
    targets_info: list[dict[str, Any]] = getattr(args, "targets_info", [])
    if not targets_info:
        return "unknown"
    return ", ".join(t.get("original", "unknown") for t in targets_info)


def _vulnerability_summary(tracer: Any) -> list[dict[str, Any]]:
    """Return a lightweight list of vulnerability dicts safe for JSON serialisation."""
    return [
        {
            "id": report.get("id", ""),
            "title": report.get("title", ""),
            "severity": report.get("severity", ""),
            "cvss": report.get("cvss"),
            "target": report.get("target", ""),
            "endpoint": report.get("endpoint", ""),
            "description": report.get("description", ""),
        }
        for report in tracer.vulnerability_reports
    ]


def _severity_counts(tracer: Any) -> dict[str, int]:
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for report in tracer.vulnerability_reports:
        severity = report.get("severity", "").lower()
        if severity in counts:
            counts[severity] += 1
    return counts


def _scan_completed(tracer: Any) -> bool:
    if tracer and tracer.scan_results:
        return bool(tracer.scan_results.get("scan_completed", False))
    return False


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------


def _format_generic(tracer: Any, args: argparse.Namespace) -> dict[str, Any]:
    """Plain JSON payload with full scan data."""
    completed = _scan_completed(tracer)
    llm_stats = tracer.get_total_llm_stats()["total"] if tracer else {}
    return {
        "event": "scan_completed" if completed else "scan_ended",
        "run_name": getattr(args, "run_name", ""),
        "targets": _targets_summary(args),
        "scan_mode": getattr(args, "scan_mode", ""),
        "completed": completed,
        "vulnerability_count": len(tracer.vulnerability_reports),
        "severity_counts": _severity_counts(tracer),
        "vulnerabilities": _vulnerability_summary(tracer),
        "stats": {
            "agents": len(tracer.agents),
            "tools": tracer.get_real_tool_count(),
            "input_tokens": llm_stats.get("input_tokens", 0),
            "output_tokens": llm_stats.get("output_tokens", 0),
            "cost": llm_stats.get("cost", 0),
        },
    }


def _format_slack(tracer: Any, args: argparse.Namespace) -> dict[str, Any]:
    """Slack Block Kit payload."""
    completed = _scan_completed(tracer)
    vuln_count = len(tracer.vulnerability_reports)
    counts = _severity_counts(tracer)

    status_emoji = ":white_check_mark:" if completed else ":warning:"
    status_text = "completed" if completed else "ended"

    severity_line = (
        " | ".join(f"*{sev.upper()}*: {cnt}" for sev, cnt in counts.items() if cnt > 0)
        or "None found"
    )

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{status_emoji} Strix Scan {status_text.title()}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Target:*\n{_targets_summary(args)}"},
                {"type": "mrkdwn", "text": f"*Run:*\n{getattr(args, 'run_name', 'N/A')}"},
                {"type": "mrkdwn", "text": f"*Scan Mode:*\n{getattr(args, 'scan_mode', 'N/A')}"},
                {"type": "mrkdwn", "text": f"*Vulnerabilities:*\n{vuln_count}"},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Severity Breakdown:* {severity_line}",
            },
        },
    ]

    # Add top vulnerabilities (max 5)
    for report in tracer.vulnerability_reports[:5]:
        title = report.get("title", "Untitled")
        severity = report.get("severity", "unknown").upper()
        endpoint = report.get("endpoint", "")
        text = f":rotating_light: *[{severity}]* {title}"
        if endpoint:
            text += f"\n`{endpoint}`"
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": text},
            }
        )

    return {"blocks": blocks}


def _format_discord(tracer: Any, args: argparse.Namespace) -> dict[str, Any]:
    """Discord webhook payload with an embed."""
    completed = _scan_completed(tracer)
    vuln_count = len(tracer.vulnerability_reports)
    counts = _severity_counts(tracer)

    color = 0x22C55E if completed else 0xEAB308  # green / yellow
    if counts["critical"] > 0:
        color = 0xDC2626
    elif counts["high"] > 0:
        color = 0xEA580C

    severity_line = (
        " | ".join(f"**{sev.upper()}**: {cnt}" for sev, cnt in counts.items() if cnt > 0)
        or "None found"
    )

    fields: list[dict[str, Any]] = [
        {"name": "Target", "value": _targets_summary(args), "inline": True},
        {"name": "Scan Mode", "value": getattr(args, "scan_mode", "N/A"), "inline": True},
        {"name": "Vulnerabilities", "value": str(vuln_count), "inline": True},
        {"name": "Severity Breakdown", "value": severity_line, "inline": False},
    ]

    # Top vulnerabilities (max 5)
    for report in tracer.vulnerability_reports[:5]:
        title = report.get("title", "Untitled")
        severity = report.get("severity", "unknown").upper()
        endpoint = report.get("endpoint", "")
        value = f"**[{severity}]** {title}"
        if endpoint:
            value += f"\n`{endpoint}`"
        fields.append({"name": "\u200b", "value": value, "inline": False})

    status_text = "Scan Completed" if completed else "Scan Ended"

    embed: dict[str, Any] = {
        "title": f"\ud83d\udd12 Strix \u2014 {status_text}",
        "description": f"Run: **{getattr(args, 'run_name', 'N/A')}**",
        "color": color,
        "fields": fields,
        "footer": {"text": "Strix Security Scanner"},
    }

    return {"embeds": [embed]}

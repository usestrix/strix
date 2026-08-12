"""Statistics and LLM usage utilities for Strix."""

from typing import Any

from rich.text import Text

from strix.config import load_settings
from strix.interface.utils.formatting import _build_vulnerability_stats, get_severity_color


def format_token_count(count: float | None) -> str:
    value = int(count or 0)
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    if value >= 1_000:
        return f"{value / 1_000:.1f}K"
    return str(value)


def _llm_usage(report_state: Any) -> dict[str, Any]:
    if hasattr(report_state, "get_total_llm_usage"):
        usage = report_state.get_total_llm_usage()
        return usage if isinstance(usage, dict) else {}
    usage = getattr(report_state, "run_record", {}).get("llm_usage")
    return usage if isinstance(usage, dict) else {}


def is_subscription_run(report_state: Any) -> bool:
    """Whether this run uses a model subscription (no metered cost)."""
    record = getattr(report_state, "run_record", None)
    if isinstance(record, dict) and record.get("auth_mode"):
        return record.get("auth_mode") == "subscription"
    from strix.config import codex

    return codex.auth_mode(load_settings().llm.model) == "subscription"


def _int_stat(usage: dict[str, Any], key: str) -> int:
    try:
        return max(0, int(usage.get(key) or 0))
    except (TypeError, ValueError):
        return 0


def _float_stat(usage: dict[str, Any], key: str) -> float:
    try:
        value = float(usage.get(key) or 0.0)
    except (TypeError, ValueError):
        return 0.0
    return value if value > 0 else 0.0


def _detail_value(usage: dict[str, Any], detail_key: str, value_key: str) -> int:
    details = usage.get(detail_key)
    if isinstance(details, list):
        details = details[0] if details and isinstance(details[0], dict) else {}
    if not isinstance(details, dict):
        return 0
    return _int_stat(details, value_key)


def has_model_response(report_state: Any) -> bool:
    usage = _llm_usage(report_state)
    return bool(usage) and _int_stat(usage, "requests") > 0


def _build_llm_usage_stats(
    stats_text: Text,
    report_state: Any,
    *,
    live: bool = False,
) -> None:
    subscription = is_subscription_run(report_state)
    usage = _llm_usage(report_state)
    if not usage or _int_stat(usage, "requests") <= 0:
        stats_text.append("\n")
        stats_text.append("Cost ", style="dim")
        if subscription:
            stats_text.append("$0.00 ", style="#22c55e")
            stats_text.append("(subscription) ", style="dim")
        else:
            stats_text.append("$0.0000 ", style="#fbbf24")
        stats_text.append("· ", style="dim white")
        stats_text.append("Tokens ", style="dim")
        stats_text.append("0", style="white")
        return

    input_tokens = _int_stat(usage, "input_tokens")
    output_tokens = _int_stat(usage, "output_tokens")
    cached_tokens = _detail_value(usage, "input_tokens_details", "cached_tokens")
    cost = _float_stat(usage, "cost")

    stats_text.append("\n")
    stats_text.append("Input Tokens ", style="dim")
    stats_text.append(format_token_count(input_tokens), style="white")

    if live or cached_tokens > 0:
        stats_text.append("  ·  ", style="dim white")
        stats_text.append("Cached Tokens ", style="dim")
        stats_text.append(format_token_count(cached_tokens), style="white")

    separator = "\n" if live else "  ·  "
    stats_text.append(separator, style="dim white")
    stats_text.append("Output Tokens ", style="dim")
    stats_text.append(format_token_count(output_tokens), style="white")

    if subscription:
        stats_text.append("  ·  ", style="dim white")
        stats_text.append("Cost ", style="dim")
        stats_text.append("$0.00", style="#22c55e")
        stats_text.append(" (subscription)", style="dim")
    elif live or cost > 0:
        stats_text.append("  ·  ", style="dim white")
        stats_text.append("Cost ", style="dim")
        stats_text.append(f"${cost:.4f}", style="#fbbf24")


def build_final_stats_text(report_state: Any) -> Text:
    stats_text = Text()
    if not report_state:
        return stats_text

    _build_vulnerability_stats(stats_text, report_state)
    _build_llm_usage_stats(stats_text, report_state)

    return stats_text


def build_live_stats_text(report_state: Any) -> Text:
    stats_text = Text()
    if not report_state:
        return stats_text

    model = load_settings().llm.model or "unknown"
    stats_text.append("Model ", style="dim")
    stats_text.append(str(model), style="white")
    if is_subscription_run(report_state):
        stats_text.append("  ·  ", style="dim white")
        stats_text.append("ChatGPT subscription", style="#22c55e")
    stats_text.append("\n")

    vuln_count = len(getattr(report_state, "vulnerability_reports", []))
    stats_text.append("Vulnerabilities ", style="dim")
    stats_text.append(f"{vuln_count}", style="white")
    stats_text.append("\n")
    if vuln_count > 0:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for report in report_state.vulnerability_reports:
            severity = report.get("severity", "").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        severity_parts = []
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts[severity]
            if count > 0:
                severity_color = get_severity_color(severity)
                severity_text = Text()
                severity_text.append(f"{severity.upper()}: ", style=severity_color)
                severity_text.append(str(count), style=f"bold {severity_color}")
                severity_parts.append(severity_text)

        for i, part in enumerate(severity_parts):
            stats_text.append(part)
            if i < len(severity_parts) - 1:
                stats_text.append(" | ", style="dim white")

        stats_text.append("\n")

    _build_llm_usage_stats(stats_text, report_state, live=True)

    return stats_text


def build_tui_stats_text(report_state: Any) -> Text:
    stats_text = Text()
    if not report_state:
        return stats_text

    model = load_settings().llm.model or "unknown"
    stats_text.append(str(model), style="white")
    subscription = is_subscription_run(report_state)
    if subscription:
        stats_text.append("\n")
        stats_text.append("ChatGPT subscription", style="#22c55e")

    usage = _llm_usage(report_state)
    if usage and _int_stat(usage, "total_tokens") > 0:
        stats_text.append("\n")
        stats_text.append(
            f"{format_token_count(_int_stat(usage, 'total_tokens'))} tokens",
            style="white",
        )
        cost = _float_stat(usage, "cost")
        if subscription:
            stats_text.append(" · ", style="white")
            stats_text.append("$0.00", style="white")
        elif cost > 0:
            stats_text.append(" · ", style="white")
            stats_text.append(f"${cost:.2f}", style="white")

    caido_url = getattr(report_state, "caido_url", None)
    if caido_url:
        stats_text.append("\n")
        stats_text.append("Caido: ", style="bold white")
        stats_text.append(caido_url, style="white")

    return stats_text

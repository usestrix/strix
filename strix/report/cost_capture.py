"""LiteLLM success-callback that feeds observed cost into the report ledger."""

from __future__ import annotations

import logging
from typing import Any


logger = logging.getLogger(__name__)


def litellm_cost_callback(
    kwargs: dict[str, Any],
    completion_response: Any,
    _start_time: Any = None,
    _end_time: Any = None,
) -> None:
    cost = _extract_cost(kwargs, completion_response)
    if cost is None or cost <= 0:
        return

    from strix.report.state import get_global_report_state

    report_state = get_global_report_state()
    if report_state is None:
        return

    try:
        report_state._llm_usage.record_observed_cost(cost)
    except Exception:
        logger.exception("Failed to record observed LiteLLM cost")


def _extract_cost(kwargs: dict[str, Any], completion_response: Any) -> float | None:
    cost = kwargs.get("response_cost") if isinstance(kwargs, dict) else None
    if isinstance(cost, int | float) and cost > 0:
        return float(cost)

    hidden = getattr(completion_response, "_hidden_params", None)
    if isinstance(hidden, dict):
        candidate = hidden.get("response_cost")
        if isinstance(candidate, int | float) and candidate > 0:
            return float(candidate)
        headers = hidden.get("additional_headers") or {}
        if isinstance(headers, dict):
            from_header = headers.get("llm_provider-x-litellm-response-cost")
            try:
                value = float(from_header) if from_header is not None else None
            except (TypeError, ValueError):
                value = None
            if value is not None and value > 0:
                return value
    return None

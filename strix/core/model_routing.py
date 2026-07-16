"""Runtime helpers for cumulative per-model budget fallback routing."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from strix.config.models import uses_chat_completions_tool_schema
from strix.report.state import get_global_report_state


if TYPE_CHECKING:
    from strix.config.settings import LlmSettings, Settings


logger = logging.getLogger(__name__)


def resolve_budget_model(model: str, llm: LlmSettings) -> str:
    """Skip already-exhausted fallback layers when creating or resuming an agent."""
    if not hasattr(llm, "budget_for") or not hasattr(llm, "fallback_for"):
        return model.strip()
    state = get_global_report_state()
    current = model.strip()
    while state is not None:
        budget = llm.budget_for(current)
        fallback = llm.fallback_for(current)
        if budget is None or fallback is None:
            break
        if state.get_model_llm_cost(current) < budget:
            break
        logger.info(
            "model route skips exhausted layer %s ($%.4f / $%.2f) -> %s",
            current,
            state.get_model_llm_cost(current),
            budget,
            fallback,
        )
        current = fallback
    return current


def chain_uses_chat_completions_tools(model: str, settings: Settings) -> bool:
    """Use a tool representation accepted by every possible fallback layer."""
    model_chain = getattr(settings.llm, "model_chain", None)
    chain = model_chain(model) if callable(model_chain) else [model]
    return any(uses_chat_completions_tool_schema(candidate, settings) for candidate in chain)

"""SDK run hooks used by Strix orchestration."""

from __future__ import annotations

import logging
import math
from typing import TYPE_CHECKING, Any

from agents.lifecycle import RunHooks

from strix.report.state import get_global_report_state


if TYPE_CHECKING:
    from agents import RunContextWrapper
    from agents.agent import Agent
    from agents.items import ModelResponse, TResponseInputItem


logger = logging.getLogger(__name__)


# Fractions of the turn / cost budget at which the agent is nudged to wrap up.
# Warnings escalate in urgency as the agent gets closer to the hard limit, which
# still terminates the run (MaxTurnsExceeded for turns, BudgetExceededError for
# cost). Ordered ascending; the highest crossed band wins on any given turn.
_TURN_WARN_BANDS: tuple[float, ...] = (0.70, 0.85, 0.95)
_BUDGET_WARN_BANDS: tuple[float, ...] = (0.70, 0.85, 0.95)


class BudgetExceededError(RuntimeError):
    """Raised when the accumulated LLM cost reaches the configured budget."""


def _crossed_band(fraction: float, bands: tuple[float, ...]) -> float | None:
    """Return the highest band ``fraction`` has reached, or ``None`` below the lowest."""
    crossed: float | None = None
    for band in bands:
        if fraction >= band:
            crossed = band
    return crossed


def _wrapup_directive(context: RunContextWrapper[dict[str, Any]]) -> str:
    """Role-specific wind-down guidance.

    The root agent owns the whole scan, so it is told to stop opening new work and
    call ``finish_scan`` to compile and deliver the final report. A sub-agent owns
    only its assigned task, so it is told to report any confirmed vulnerability it
    already has, finish work that is nearly done, and hand results back via
    ``agent_finish``.
    """
    is_root = context.context.get("parent_id") is None
    if is_root:
        return (
            "As the root agent, start winding down the whole scan now: stop opening new "
            "lines of investigation, make sure your required objectives are covered, and "
            "call finish_scan soon to compile and deliver the final report before you are "
            "cut off."
        )
    return (
        "As a sub-agent, start wrapping up your current task now: if you already have a "
        "confirmed, validated vulnerability, report it immediately; finish any work that is "
        "nearly done rather than starting something new, then call agent_finish to hand your "
        "results back to your parent before you are cut off."
    )


def _urgency(band: float) -> str:
    if band >= 0.95:
        return "CRITICAL"
    if band >= 0.85:
        return "URGENT"
    return "NOTICE"


class ReportUsageHooks(RunHooks[dict[str, Any]]):
    """Persist SDK-native usage and warn/stop as turn and cost budgets are consumed."""

    def __init__(
        self,
        *,
        model: str,
        max_budget_usd: float | None = None,
        max_turns: int | None = None,
    ) -> None:
        if max_budget_usd is not None and (
            not math.isfinite(max_budget_usd) or max_budget_usd <= 0
        ):
            raise ValueError("max_budget_usd must be a finite number greater than 0")
        if max_turns is not None and max_turns <= 0:
            raise ValueError("max_turns must be a positive integer")
        self._model = model
        self._max_budget_usd = max_budget_usd
        self._max_turns = max_turns

    async def on_llm_start(
        self,
        context: RunContextWrapper[dict[str, Any]],
        agent: Agent[dict[str, Any]],  # noqa: ARG002
        system_prompt: str | None,  # noqa: ARG002
        input_items: list[TResponseInputItem],
    ) -> None:
        """Inject graduated wrap-up warnings before the model call when budgets run low.

        Warnings are appended to the per-turn model input only (not persisted to the
        session), so they nudge the model without cluttering the transcript, and are
        re-evaluated every turn so the reminder tracks the live remaining budget.
        """
        try:
            self._maybe_warn_turns(context, input_items)
            self._maybe_warn_budget(context, input_items)
        except Exception:
            logger.exception("budget/turn warning injection failed")

    def _maybe_warn_turns(
        self,
        context: RunContextWrapper[dict[str, Any]],
        input_items: list[TResponseInputItem],
    ) -> None:
        if not self._max_turns:
            return
        usage = getattr(context, "usage", None)
        requests = getattr(usage, "requests", None)
        if not isinstance(requests, int):
            return
        turns_used = requests + 1  # the turn about to run
        band = _crossed_band(turns_used / self._max_turns, _TURN_WARN_BANDS)
        if band is None:
            return
        remaining = max(self._max_turns - turns_used, 0)
        pct = round(100 * turns_used / self._max_turns)
        content = (
            f"[{_urgency(band)}] Turn budget: {turns_used}/{self._max_turns} used ({pct}%). "
            f"About {remaining} turn(s) remain before this agent is force-stopped and any "
            f"in-progress work is discarded. {_wrapup_directive(context)}"
        )
        input_items.append({"role": "user", "content": content})

    def _maybe_warn_budget(
        self,
        context: RunContextWrapper[dict[str, Any]],
        input_items: list[TResponseInputItem],
    ) -> None:
        if self._max_budget_usd is None:
            return
        report_state = get_global_report_state()
        if report_state is None:
            return
        cost = report_state.get_total_llm_cost()
        band = _crossed_band(cost / self._max_budget_usd, _BUDGET_WARN_BANDS)
        if band is None:
            return
        pct = round(100 * cost / self._max_budget_usd)
        content = (
            f"[{_urgency(band)}] Scan cost budget: ${cost:.2f}/${self._max_budget_usd:.2f} "
            f"spent ({pct}%). This budget is shared across every agent in the scan; when it is "
            f"reached the whole scan is stopped immediately. {_wrapup_directive(context)}"
        )
        input_items.append({"role": "user", "content": content})

    async def on_llm_end(
        self,
        context: RunContextWrapper[dict[str, Any]],
        agent: Agent[dict[str, Any]],
        response: ModelResponse,
    ) -> None:
        report_state = get_global_report_state()
        if report_state is None:
            return

        ctx = context.context if isinstance(context.context, dict) else {}
        agent_name = getattr(agent, "name", None)
        if not isinstance(agent_name, str):
            agent_name = None
        agent_id = ctx.get("agent_id")
        if not isinstance(agent_id, str) or not agent_id:
            agent_id = agent_name or "unknown"

        try:
            report_state.record_sdk_usage(
                agent_id=agent_id,
                agent_name=agent_name,
                model=self._model,
                usage=response.usage,
            )
        except Exception:
            logger.exception("failed to record SDK usage for agent %s", agent_id)

        if self._max_budget_usd is not None:
            cost = report_state.get_total_llm_cost()
            if cost >= self._max_budget_usd:
                raise BudgetExceededError(
                    f"Token budget of ${self._max_budget_usd:.2f} exceeded (spent ${cost:.4f})"
                )

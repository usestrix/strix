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

# Sub-agents are hard-stopped once cumulative cost reaches this fraction of the
# budget, reserving the remaining slice for the root agent to wind down and write
# the final report (which itself costs model calls via finish_scan). The root
# agent's own hard stop stays at the full budget (see ``on_llm_end``).
_SUBAGENT_BUDGET_RESERVE = 0.90


class BudgetExceededError(RuntimeError):
    """Raised when the accumulated LLM cost reaches the configured budget."""


class SubagentBudgetReservedError(RuntimeError):
    """Raised to stop a single sub-agent once the reserve threshold is crossed.

    Distinct from :class:`BudgetExceededError`: this stops only the sub-agent that
    raised it (the scan-wide fan-out is *not* triggered), leaving the reserved
    budget for the root agent to finish the scan.
    """


def _crossed_band(fraction: float, bands: tuple[float, ...]) -> float | None:
    """Return the highest band ``fraction`` has reached, or ``None`` below the lowest."""
    crossed: float | None = None
    for band in bands:
        if fraction >= band:
            crossed = band
    return crossed


# Wind-down guidance that escalates with the crossed band, keyed by (is_root, band).
# The root agent owns the whole scan (finish_scan → compile/deliver the final report);
# a sub-agent owns only its assigned task (report a confirmed vuln, then agent_finish
# back to its parent). Tone hardens from a gentle heads-up (0.70) to a hard "stop
# everything and finish now" (0.95).
_ROOT_DIRECTIVES: dict[float, str] = {
    0.70: (
        "As the root agent, begin planning your wind-down of the whole scan: avoid "
        "starting large new lines of investigation, and keep your required objectives on "
        "track so you can call finish_scan comfortably before the limit."
    ),
    0.85: (
        "As the root agent, prioritize wrapping up the whole scan now: stop opening new "
        "lines of investigation, close out only what is essential, and move toward calling "
        "finish_scan to compile and deliver the final report."
    ),
    0.95: (
        "As the root agent, STOP all other work on the whole scan and finish immediately: "
        "secure your findings and call finish_scan now — anything left unfinished when the "
        "limit is hit is discarded."
    ),
}
_SUBAGENT_DIRECTIVES: dict[float, str] = {
    0.70: (
        "As a sub-agent, begin planning your wind-down: avoid starting large new subtasks, "
        "and if you are close to a confirmed, validated vulnerability, drive it to a result "
        "you can report."
    ),
    0.85: (
        "As a sub-agent, prioritize wrapping up your task now: report any confirmed, "
        "validated vulnerability, finish work that is nearly done rather than starting "
        "anything new, and prepare to call agent_finish."
    ),
    0.95: (
        "As a sub-agent, STOP all other work and finish immediately: report any confirmed "
        "vulnerability right now and call agent_finish to hand your results back to your "
        "parent before you are cut off."
    ),
}


def _wrapup_directive(context: RunContextWrapper[dict[str, Any]], band: float) -> str:
    """Role- and stage-specific wind-down guidance for the crossed ``band``."""
    is_root = context.context.get("parent_id") is None
    directives = _ROOT_DIRECTIVES if is_root else _SUBAGENT_DIRECTIVES
    return directives[band]


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
            f"in-progress work is discarded. {_wrapup_directive(context, band)}"
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
        is_root = context.context.get("parent_id") is None
        # Warn each agent relative to *its own* hard stop so every band stays reachable:
        # the root spends up to the full budget, a sub-agent only up to the reserve. Bands
        # measured against the full budget would never fire the 85/95% warnings for a
        # sub-agent, since it is already stopped at the reserve (90% of the full budget).
        cap = self._max_budget_usd if is_root else self._max_budget_usd * _SUBAGENT_BUDGET_RESERVE
        band = _crossed_band(cost / cap, _BUDGET_WARN_BANDS)
        if band is None:
            return
        pct = round(100 * cost / cap)
        reserve_pct = round(_SUBAGENT_BUDGET_RESERVE * 100)
        if is_root:
            content = (
                f"[{_urgency(band)}] Scan cost budget: ${cost:.2f}/${self._max_budget_usd:.2f} "
                f"spent ({pct}%). This budget is shared across every agent in the scan; when it "
                "is reached the whole scan is stopped immediately, and sub-agents are stopped at "
                f"{reserve_pct}% to reserve the remainder for your final report. "
                f"{_wrapup_directive(context, band)}"
            )
        else:
            content = (
                f"[{_urgency(band)}] Scan cost budget: ${cost:.2f} spent of your ${cap:.2f} "
                f"sub-agent limit ({pct}%) — the full scan budget is ${self._max_budget_usd:.2f}, "
                f"shared across every agent, and sub-agents are stopped at the {reserve_pct}% "
                "reserve to leave the remainder for the root agent's final report. "
                f"{_wrapup_directive(context, band)}"
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
            is_root = ctx.get("parent_id") is None
            if is_root:
                if cost >= self._max_budget_usd:
                    raise BudgetExceededError(
                        f"Token budget of ${self._max_budget_usd:.2f} exceeded (spent ${cost:.4f})"
                    )
            else:
                reserve_limit = self._max_budget_usd * _SUBAGENT_BUDGET_RESERVE
                if cost >= reserve_limit:
                    raise SubagentBudgetReservedError(
                        f"Sub-agent budget reserve reached: spent ${cost:.4f} of "
                        f"${self._max_budget_usd:.2f} "
                        f"(>= {round(_SUBAGENT_BUDGET_RESERVE * 100)}% reserve); stopping this "
                        "sub-agent so the root agent can finish the scan."
                    )

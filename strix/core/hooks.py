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


LLM_TURN_KEY = "llm_turn"

_STAGE_LABELS: tuple[str, ...] = ("NOTICE", "URGENT", "CRITICAL")
_TURN_WARN_BANDS: tuple[float, ...] = (0.70, 0.85, 0.95)
_ROOT_BUDGET_WARN_BANDS: tuple[float, ...] = (0.70, 0.85, 0.95)
_SUBAGENT_BUDGET_WARN_BANDS: tuple[float, ...] = (0.75, 0.80, 0.85)
_SUBAGENT_BUDGET_RESERVE = 0.90


class BudgetExceededError(RuntimeError):
    """Raised when the accumulated LLM cost reaches the configured budget."""


class SubagentBudgetReservedError(RuntimeError):
    """Raised to stop a single sub-agent once the reserve threshold is crossed."""


class BudgetPausedError(RuntimeError):
    """Raised to park one agent when an interactive scan reaches its budget."""


def recomputed_budget_flags(
    cost: float,
    max_budget_usd: float | None,
    *,
    interactive: bool,
) -> tuple[bool, bool]:
    """Return the (budget_stopped, reserve_stopped) flags a resumed scan should carry."""
    if max_budget_usd is None:
        return False, False
    if interactive:
        return False, False
    budget_stopped = cost >= max_budget_usd
    reserve_stopped = cost >= max_budget_usd * _SUBAGENT_BUDGET_RESERVE
    return budget_stopped, reserve_stopped


def _crossed_stage(fraction: float, bands: tuple[float, ...]) -> int | None:
    crossed: int | None = None
    for index, band in enumerate(bands):
        if fraction >= band:
            crossed = index
    return crossed


_ROOT_DIRECTIVES: tuple[str, ...] = (
    (
        "As the root agent, begin planning your wind-down of the whole scan: avoid "
        "starting large new lines of investigation, and keep your required objectives on "
        "track so you can call finish_scan comfortably before the limit."
    ),
    (
        "As the root agent, prioritize wrapping up the whole scan now: stop opening new "
        "lines of investigation, close out only what is essential, and move toward calling "
        "finish_scan to compile and deliver the final report."
    ),
    (
        "As the root agent, STOP all other work on the whole scan and finish immediately: "
        "secure your findings and call finish_scan now — anything left unfinished when the "
        "limit is hit is discarded."
    ),
)
_SUBAGENT_DIRECTIVES: tuple[str, ...] = (
    (
        "As a sub-agent, begin planning your wind-down: avoid starting large new subtasks, "
        "and if you are close to a confirmed, validated vulnerability, drive it to a result "
        "you can report."
    ),
    (
        "As a sub-agent, prioritize wrapping up your task now: report any confirmed, "
        "validated vulnerability, finish work that is nearly done rather than starting "
        "anything new, and prepare to call agent_finish."
    ),
    (
        "As a sub-agent, STOP all other work and finish immediately: report any confirmed "
        "vulnerability right now and call agent_finish to hand your results back to your "
        "parent before you are cut off."
    ),
)


def _wrapup_directive(context: RunContextWrapper[dict[str, Any]], stage: int) -> str:
    is_root = context.context.get("parent_id") is None
    directives = _ROOT_DIRECTIVES if is_root else _SUBAGENT_DIRECTIVES
    return directives[stage]


def _urgency(stage: int) -> str:
    return _STAGE_LABELS[stage]


class ReportUsageHooks(RunHooks[dict[str, Any]]):
    """Persist SDK-native usage and warn/stop as turn and cost budgets are consumed."""

    def __init__(
        self,
        *,
        model: str,
        max_budget_usd: float | None = None,
        max_turns: int | None = None,
        interactive: bool = False,
    ) -> None:
        if max_budget_usd is not None and (
            not math.isfinite(max_budget_usd) or max_budget_usd <= 0
        ):
            raise ValueError("max_budget_usd must be a finite number greater than 0")
        if max_turns is not None and max_turns <= 0:
            raise ValueError("max_turns must be a positive integer")
        self._model = model
        self._max_budget_usd = max_budget_usd
        self._budget_increment = max_budget_usd
        self._max_turns = max_turns
        self._interactive = interactive

    def extend_budget(self) -> None:
        if self._max_budget_usd is None or self._budget_increment is None:
            return
        self._max_budget_usd += self._budget_increment

    async def on_llm_start(
        self,
        context: RunContextWrapper[dict[str, Any]],
        agent: Agent[dict[str, Any]],  # noqa: ARG002
        system_prompt: str | None,  # noqa: ARG002
        input_items: list[TResponseInputItem],
    ) -> None:
        context.context[LLM_TURN_KEY] = int(context.context.get(LLM_TURN_KEY, 0)) + 1
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
        turns_used = requests + 1
        stage = _crossed_stage(turns_used / self._max_turns, _TURN_WARN_BANDS)
        if stage is None:
            return
        remaining = max(self._max_turns - turns_used, 0)
        pct = round(100 * turns_used / self._max_turns)
        content = (
            f"[{_urgency(stage)}] Turn budget: {turns_used}/{self._max_turns} used ({pct}%). "
            f"About {remaining} turn(s) remain before this agent is force-stopped and any "
            f"in-progress work is discarded. {_wrapup_directive(context, stage)}"
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
        if self._interactive:
            bands = _ROOT_BUDGET_WARN_BANDS
        else:
            bands = _ROOT_BUDGET_WARN_BANDS if is_root else _SUBAGENT_BUDGET_WARN_BANDS
        stage = _crossed_stage(cost / self._max_budget_usd, bands)
        if stage is None:
            return
        pct = round(100 * cost / self._max_budget_usd)
        reserve_pct = round(_SUBAGENT_BUDGET_RESERVE * 100)
        if self._interactive:
            content = (
                f"[{_urgency(stage)}] Scan cost budget: ${cost:.2f}/${self._max_budget_usd:.2f} "
                f"spent ({pct}%). This budget is shared across every agent in the scan; when it "
                "is reached all agents are paused until the user chooses to continue. "
                f"{_wrapup_directive(context, stage)}"
            )
        elif is_root:
            content = (
                f"[{_urgency(stage)}] Scan cost budget: ${cost:.2f}/${self._max_budget_usd:.2f} "
                f"spent ({pct}%). This budget is shared across every agent in the scan; when it "
                "is reached the whole scan is stopped immediately, and sub-agents are stopped at "
                f"{reserve_pct}% to reserve the remainder for your final report. "
                f"{_wrapup_directive(context, stage)}"
            )
        else:
            content = (
                f"[{_urgency(stage)}] Scan cost budget: ${cost:.2f}/${self._max_budget_usd:.2f} "
                f"spent ({pct}%). This budget is shared across every agent in the scan; "
                f"sub-agents are stopped at {reserve_pct}% to leave the remainder for the root "
                f"agent's final report. {_wrapup_directive(context, stage)}"
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
                if self._interactive:
                    raise BudgetPausedError(
                        f"Scan budget of ${self._max_budget_usd:.2f} reached "
                        f"(spent ${cost:.4f}); pausing until the user continues"
                    )
                raise BudgetExceededError(
                    f"Token budget of ${self._max_budget_usd:.2f} exceeded (spent ${cost:.4f})"
                )
            is_root = ctx.get("parent_id") is None
            if not self._interactive and not is_root:
                reserve_limit = self._max_budget_usd * _SUBAGENT_BUDGET_RESERVE
                if cost >= reserve_limit:
                    raise SubagentBudgetReservedError(
                        f"Sub-agent budget reserve reached: spent ${cost:.4f} of "
                        f"${self._max_budget_usd:.2f} "
                        f"(>= {round(_SUBAGENT_BUDGET_RESERVE * 100)}% reserve); stopping this "
                        "sub-agent so the root agent can finish the scan."
                    )

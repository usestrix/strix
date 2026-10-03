"""Opt-in cross-turn no-progress guard wired into the SDK run-hooks lifecycle.

Extends :class:`~strix.core.hooks.ReportUsageHooks` with an *advisory* nudge when an
agent looks stuck across turns — the signal the per-turn tool-call cap and the
budget/turn ceilings do not catch (a loop that stays under all of them). It drives
one :class:`~strix.guard.progress.NoProgressDetector` per agent from
``on_tool_start`` (fingerprinting on the tool *name*; the SDK's ``on_tool_start``
does not expose the call arguments) and injects an escalating message on the agent's
next ``on_llm_start`` by appending to ``input_items`` — the same mechanism
``ReportUsageHooks`` uses for its budget/turn warnings.

**Advisory only.** It never force-stops an agent: the turn and budget ceilings stay
the hard stops. This guard just gets a looping agent to change approach earlier, and
after repeated stalls firmly advises it to finish or switch tactics. It then goes
quiet for that agent (``max_nudges``) so it can never itself become a loop.

Enabled by ``STRIX2_PROGRESS_GUARD`` (off by default → upstream behavior unchanged).
``STRIX2_PROGRESS_REPEAT`` overrides the consecutive-identical-call threshold
(default 3, min 2); ``STRIX2_PROGRESS_MAX_NUDGES`` caps nudges per agent (default 3).
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

from strix.core.hooks import ReportUsageHooks
from strix.guard.progress import NoProgressDetector


if TYPE_CHECKING:
    from agents import RunContextWrapper
    from agents.agent import Agent
    from agents.items import TResponseInputItem
    from agents.tool import Tool

    from strix.core.agents import BudgetPolicy
    from strix.guard.progress import ProgressSignal


logger = logging.getLogger(__name__)

_ENABLE_ENV = "STRIX2_PROGRESS_GUARD"
_REPEAT_ENV = "STRIX2_PROGRESS_REPEAT"
_MAX_NUDGES_ENV = "STRIX2_PROGRESS_MAX_NUDGES"


def progress_guard_enabled() -> bool:
    return os.environ.get(_ENABLE_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def _int_env(name: str, default: int, minimum: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        return default


def _resolve_agent_id(context: Any, agent: Any) -> str:
    ctx = getattr(context, "context", None)
    if isinstance(ctx, dict):
        agent_id = ctx.get("agent_id")
        if isinstance(agent_id, str) and agent_id:
            return agent_id
    name = getattr(agent, "name", None)
    return name if isinstance(name, str) and name else "unknown"


class ProgressGuardHooks(ReportUsageHooks):
    """``ReportUsageHooks`` + an advisory cross-turn no-progress nudge (opt-in)."""

    def __init__(
        self,
        *,
        repeat_threshold: int = 3,
        max_nudges: int = 3,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._repeat_threshold = max(2, repeat_threshold)
        self._max_nudges = max(1, max_nudges)
        self._detectors: dict[str, NoProgressDetector] = {}
        self._pending: dict[str, str] = {}
        self._nudges_sent: dict[str, int] = {}

    async def on_tool_start(
        self,
        context: RunContextWrapper[dict[str, Any]],
        agent: Agent[dict[str, Any]],
        tool: Tool,
    ) -> None:
        try:
            self._observe_tool_call(context, agent, tool)
        except Exception:
            logger.exception("no-progress guard: observing a tool call failed")

    def _observe_tool_call(self, context: Any, agent: Any, tool: Any) -> None:
        agent_id = _resolve_agent_id(context, agent)
        if self._nudges_sent.get(agent_id, 0) >= self._max_nudges:
            return  # already said our piece for this agent; never loop the guard itself
        detector = self._detectors.get(agent_id)
        if detector is None:
            detector = NoProgressDetector(repeat_threshold=self._repeat_threshold)
            self._detectors[agent_id] = detector
        tool_name = getattr(tool, "name", "") or "tool"
        signal = detector.record(tool_name)
        if signal is not None:
            self._pending[agent_id] = self._nudge_text(signal, agent_id)
            # Re-arm so the nudge is delivered once per stall, not on every call past
            # the threshold; the max_nudges cap bounds the total.
            detector.reset()

    def _nudge_text(self, signal: ProgressSignal, agent_id: str) -> str:
        last = self._nudges_sent.get(agent_id, 0) + 1 >= self._max_nudges
        body = (
            f"[NO-PROGRESS] {signal.detail}. Repeating the same action will not advance "
            "the engagement — change the arguments, use a different tool, or move to a new "
            "line of investigation."
        )
        if last:
            body += (
                " If you cannot find a new, productive step, wrap up: report any validated "
                "finding and call finish_scan (root) or agent_finish (sub-agent) rather than "
                "spinning."
            )
        return body

    async def on_llm_start(
        self,
        context: RunContextWrapper[dict[str, Any]],
        agent: Agent[dict[str, Any]],
        system_prompt: str | None,
        input_items: list[TResponseInputItem],
    ) -> None:
        await super().on_llm_start(context, agent, system_prompt, input_items)
        try:
            agent_id = _resolve_agent_id(context, agent)
            nudge = self._pending.pop(agent_id, None)
            if nudge is not None:
                input_items.append({"role": "user", "content": nudge})
                self._nudges_sent[agent_id] = self._nudges_sent.get(agent_id, 0) + 1
        except Exception:
            logger.exception("no-progress guard: injecting a nudge failed")


def build_run_hooks(
    *,
    model: str,
    max_budget_usd: float | None,
    max_turns: int | None,
    interactive: bool,
    budget_policy: BudgetPolicy = "stop",
) -> ReportUsageHooks:
    """Return the run hooks for a scan.

    The opt-in no-progress guard (``STRIX2_PROGRESS_GUARD``) layers an advisory
    cross-turn stall nudge on top of the usual usage/budget hooks; otherwise the
    plain :class:`ReportUsageHooks` is returned, so default behavior is unchanged.
    The return type is ``ReportUsageHooks`` either way, so callers keep
    ``extend_budget`` and the full budget/turn behavior. ``budget_policy`` is passed
    straight through to the underlying hooks.
    """
    if progress_guard_enabled():
        return ProgressGuardHooks(
            model=model,
            max_budget_usd=max_budget_usd,
            max_turns=max_turns,
            interactive=interactive,
            budget_policy=budget_policy,
            repeat_threshold=_int_env(_REPEAT_ENV, 3, 2),
            max_nudges=_int_env(_MAX_NUDGES_ENV, 3, 1),
        )
    return ReportUsageHooks(
        model=model,
        max_budget_usd=max_budget_usd,
        max_turns=max_turns,
        interactive=interactive,
        budget_policy=budget_policy,
    )

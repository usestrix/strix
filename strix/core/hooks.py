"""SDK run hooks used by Strix orchestration."""

from __future__ import annotations

import logging
import math
import threading
from typing import TYPE_CHECKING, Any

from agents.lifecycle import RunHooks

from strix.report.state import get_global_report_state
from strix.tools.notes.tools import notes_count


if TYPE_CHECKING:
    from agents import RunContextWrapper
    from agents.agent import Agent
    from agents.items import ModelResponse

    from strix.report.state import ReportState


logger = logging.getLogger(__name__)


class ScanLimitError(RuntimeError):
    """Base for scan-wide stop signals raised from run hooks.

    Both the cost budget and the no-progress breaker raise a subclass of
    this so the runner / execution layer can catch them with a single
    clause and route them through the same clean-stop path.
    """


class BudgetExceededError(ScanLimitError):
    """Raised when the accumulated LLM cost reaches the configured budget."""


class NoProgressExceededError(ScanLimitError):
    """Raised when the scan loops without producing findings or notes."""


class ReportUsageHooks(RunHooks[dict[str, Any]]):
    """Persist SDK-native usage after every model response.

    Also enforces two scan-wide circuit breakers, evaluated once per LLM
    response (roughly once per turn):

    - **Cost budget** (``max_budget_usd``): stops the scan when accumulated
      LLM spend reaches the cap.
    - **No-progress** (``no_progress_max_turns``): stops the scan after N
      consecutive LLM turns with no new finding and no new note — the
      signature of a model stuck in an idle spin loop. Progress is measured
      by persisted counts (``ReportState.vulnerability_reports`` and the
      notes store), so deduped/rejected calls do not falsely reset it.
    """

    def __init__(
        self,
        *,
        model: str,
        max_budget_usd: float | None = None,
        no_progress_max_turns: int | None = None,
    ) -> None:
        if max_budget_usd is not None and (
            not math.isfinite(max_budget_usd) or max_budget_usd <= 0
        ):
            raise ValueError("max_budget_usd must be a finite number greater than 0")
        if no_progress_max_turns is not None and no_progress_max_turns <= 0:
            raise ValueError("no_progress_max_turns must be positive (or None to disable)")
        self._model = model
        self._max_budget_usd = max_budget_usd
        self._no_progress_max_turns = no_progress_max_turns
        # No-progress tracking. Baseline is taken lazily on the first
        # ``on_llm_end`` so the very first turn is never counted as "stale".
        self._no_progress_lock = threading.Lock()
        self._turns_since_progress = 0
        self._last_findings = 0
        self._last_notes = 0
        self._baseline_taken = False

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

        if self._no_progress_max_turns is not None:
            self._check_no_progress(report_state)

    def _check_no_progress(self, report_state: ReportState) -> None:
        findings = len(report_state.vulnerability_reports)
        notes = notes_count()
        with self._no_progress_lock:
            if not self._baseline_taken:
                # First observation: establish the baseline without counting.
                self._last_findings = findings
                self._last_notes = notes
                self._turns_since_progress = 0
                self._baseline_taken = True
                return
            if findings > self._last_findings or notes > self._last_notes:
                self._last_findings = findings
                self._last_notes = notes
                self._turns_since_progress = 0
            else:
                self._turns_since_progress += 1
            stale = self._turns_since_progress
            threshold = self._no_progress_max_turns
            if threshold is not None and stale >= threshold:
                raise NoProgressExceededError(
                    f"No new findings or notes in the last {stale} LLM turn(s) "
                    f"(threshold={threshold}); findings={findings}, notes={notes}."
                )

"""SDK run hooks used by Strix orchestration."""

from __future__ import annotations

import logging
import math
from typing import TYPE_CHECKING, Any

from agents.lifecycle import RunHooks

from strix.core.inputs import make_model_settings
from strix.core.model_routing import resolve_budget_model
from strix.report.state import get_global_report_state


if TYPE_CHECKING:
    from agents import RunContextWrapper
    from agents.agent import Agent
    from agents.items import ModelResponse

    from strix.config.settings import LlmSettings


logger = logging.getLogger(__name__)


class BudgetExceededError(RuntimeError):
    """Raised when the accumulated scan-wide LLM cost reaches its hard limit."""


class ModelFallbackError(RuntimeError):
    """Interrupt the current cycle after atomically moving an agent to its next model."""

    def __init__(
        self,
        *,
        previous_model: str,
        next_model: str,
        spent: float,
        budget: float,
    ) -> None:
        self.previous_model = previous_model
        self.next_model = next_model
        self.spent = spent
        self.budget = budget
        super().__init__(
            f"model {previous_model} reached its ${budget:.2f} budget "
            f"(spent ${spent:.4f}); continuing with {next_model}"
        )


class ReportUsageHooks(RunHooks[dict[str, Any]]):
    """Persist SDK-native usage after every model response."""

    def __init__(
        self,
        *,
        model: str,
        max_budget_usd: float | None = None,
        llm_settings: LlmSettings | None = None,
    ) -> None:
        if max_budget_usd is not None and (
            not math.isfinite(max_budget_usd) or max_budget_usd <= 0
        ):
            raise ValueError("max_budget_usd must be a finite number greater than 0")
        self._model = model
        self._max_budget_usd = max_budget_usd
        self._llm_settings = llm_settings
        self._inflight_models: dict[str, str] = {}

    @staticmethod
    def _agent_id(context: RunContextWrapper[dict[str, Any]], agent: Agent[dict[str, Any]]) -> str:
        ctx = context.context if isinstance(context.context, dict) else {}
        agent_id = ctx.get("agent_id")
        if isinstance(agent_id, str) and agent_id:
            return agent_id
        agent_name = getattr(agent, "name", None)
        return agent_name if isinstance(agent_name, str) and agent_name else "unknown"

    async def on_llm_start(
        self,
        context: RunContextWrapper[dict[str, Any]],
        agent: Agent[dict[str, Any]],
        system_prompt: str | None,
        input_items: list[Any],
    ) -> None:
        del system_prompt, input_items
        model = getattr(agent, "model", None)
        if not isinstance(model, str) or not model:
            model = self._model
        self._inflight_models[self._agent_id(context, agent)] = model

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
        agent_id = self._agent_id(context, agent)

        # A different agent can exhaust this model while this call is still in
        # flight and mutate all matching public agents. Attribute the completed
        # response to the route captured at on_llm_start, not that newer route.
        agent_model = getattr(agent, "model", None)
        fallback_model = (
            agent_model if isinstance(agent_model, str) and agent_model else self._model
        )
        model = self._inflight_models.pop(agent_id, fallback_model)
        try:
            report_state.record_sdk_usage(
                agent_id=agent_id,
                agent_name=agent_name,
                model=model,
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

        llm = self._llm_settings
        if llm is None:
            return
        model_budget = llm.budget_for(model)
        fallback = llm.fallback_for(model)
        if model_budget is None or fallback is None:
            return
        model_cost = report_state.get_model_llm_cost(model)
        if model_cost < model_budget:
            return

        current_agent_model = getattr(agent, "model", None)
        if (
            isinstance(current_agent_model, str)
            and current_agent_model.strip().lower() != model.strip().lower()
        ):
            # Another concurrent response already transitioned this shared
            # model route while this request was in flight. Discard this stale
            # response and retry on the route already selected for the agent.
            raise ModelFallbackError(
                previous_model=model,
                next_model=current_agent_model,
                spent=model_cost,
                budget=model_budget,
            )

        # Abort at an LLM-response boundary. The SDK has not executed any tool
        # calls from this response yet, so retrying the same persisted session
        # with the fallback cannot duplicate side effects or expose a partial
        # assistant turn to the new model.
        next_model = resolve_budget_model(fallback, llm)
        agent.model = next_model
        reasoning = (
            llm.reasoning_effort
            if ctx.get("parent_id") is None
            else (llm.subagent_reasoning_effort or llm.reasoning_effort)
        )
        agent.model_settings = make_model_settings(
            reasoning,
            model_name=next_model,
            force_required_tool_choice=llm.force_required_tool_choice,
        )
        coordinator = ctx.get("coordinator")
        if coordinator is not None and hasattr(coordinator, "transition_model"):
            await coordinator.transition_model(model, next_model, llm_settings=llm)
        raise ModelFallbackError(
            previous_model=model,
            next_model=next_model,
            spent=model_cost,
            budget=model_budget,
        )

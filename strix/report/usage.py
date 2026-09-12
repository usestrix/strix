"""SDK-native LLM usage aggregation for scan reports."""

from __future__ import annotations

import logging
from typing import Any

from agents.usage import Usage, deserialize_usage, serialize_usage

from strix.report.pricing import resolve_litellm_model


logger = logging.getLogger(__name__)


class LLMUsageLedger:
    """Aggregate SDK ``Usage`` objects and attach best-effort cost estimates."""

    def __init__(self) -> None:
        self._total_usage = Usage()
        self._agent_usage: dict[str, Usage] = {}
        self._agent_metadata: dict[str, dict[str, str]] = {}
        self._observed_cost = 0.0
        self._estimated_cost = 0.0
        self._has_observed_cost = False
        # When True, tokens are still tracked but cost stays $0 — the run is on a
        # model subscription, so there is no metered per-token charge to report.
        self.zero_cost = False

    def record(
        self,
        *,
        agent_id: str,
        usage: Usage | None,
        agent_name: str | None = None,
        model: str | None = None,
    ) -> bool:
        if usage is None or not _usage_has_activity(usage):
            return False

        normalized_agent_id = str(agent_id or "unknown")
        self._total_usage.add(usage)
        self._agent_usage.setdefault(normalized_agent_id, Usage()).add(usage)

        metadata = self._agent_metadata.setdefault(normalized_agent_id, {})
        if agent_name:
            metadata["agent_name"] = agent_name
        if model:
            metadata["model"] = model

        if not self.zero_cost:
            estimated = _estimate_litellm_cost(usage, model)
            if estimated:
                self._estimated_cost += estimated

        return True

    def record_observed_cost(self, cost: float) -> None:
        if self.zero_cost:
            return
        if isinstance(cost, int | float) and cost > 0:
            self._observed_cost += float(cost)
            self._has_observed_cost = True

    @property
    def total_cost(self) -> float:
        if self.zero_cost:
            return 0.0
        return _round_cost(self._observed_cost if self._has_observed_cost else self._estimated_cost)

    def to_record(self) -> dict[str, Any]:
        record = serialize_usage(self._total_usage)
        record["cost"] = self.total_cost
        record["agents"] = []

        agent_tokens = {aid: _resolve_total_tokens(u) for aid, u in self._agent_usage.items()}
        total_tokens = sum(agent_tokens.values())
        for agent_id in sorted(self._agent_usage):
            usage = self._agent_usage[agent_id]
            metadata = self._agent_metadata.get(agent_id, {})
            agent_cost = (
                self.total_cost * (agent_tokens[agent_id] / total_tokens) if total_tokens else 0.0
            )

            agent_record = serialize_usage(usage)
            agent_record.update(
                {
                    "agent_id": agent_id,
                    "agent_name": metadata.get("agent_name") or agent_id,
                    "model": metadata.get("model"),
                    "cost": _round_cost(agent_cost),
                }
            )
            record["agents"].append(agent_record)

        return record

    def hydrate(self, raw_usage: Any) -> None:
        self._total_usage = Usage()
        self._agent_usage.clear()
        self._agent_metadata.clear()
        self._observed_cost = 0.0
        self._estimated_cost = 0.0
        self._has_observed_cost = False

        if not isinstance(raw_usage, dict):
            return

        try:
            self._total_usage = deserialize_usage(raw_usage)
        except Exception:
            logger.exception("Failed to hydrate aggregate llm_usage from run.json")
            self._total_usage = Usage()

        persisted_cost = _float_or_zero(raw_usage.get("cost"))
        self._observed_cost = persisted_cost
        self._estimated_cost = persisted_cost

        for raw_agent in raw_usage.get("agents") or []:
            if not isinstance(raw_agent, dict):
                continue
            agent_id = str(raw_agent.get("agent_id") or "").strip()
            if not agent_id:
                continue
            try:
                self._agent_usage[agent_id] = deserialize_usage(raw_agent)
            except Exception:
                logger.exception("Failed to hydrate llm_usage for agent %s", agent_id)
                self._agent_usage[agent_id] = Usage()

            metadata: dict[str, str] = {}
            agent_name = raw_agent.get("agent_name")
            model = raw_agent.get("model")
            if isinstance(agent_name, str) and agent_name:
                metadata["agent_name"] = agent_name
            if isinstance(model, str) and model:
                metadata["model"] = model
            self._agent_metadata[agent_id] = metadata


def _resolve_total_tokens(usage: Usage) -> int:
    total = max(0, int(usage.total_tokens or 0))
    if total > 0:
        return total
    prompt = _int_or_zero(getattr(usage, "input_tokens", 0))
    completion = _int_or_zero(getattr(usage, "output_tokens", 0))
    return prompt + completion


def _usage_has_activity(usage: Usage) -> bool:
    return bool(
        usage.requests
        or usage.input_tokens
        or usage.output_tokens
        or usage.total_tokens
        or usage.request_usage_entries
    )


def _estimate_litellm_cost(usage: Usage, model: str | None) -> float | None:
    litellm_model = _litellm_model_name(model)
    if not litellm_model:
        return None

    entries = list(usage.request_usage_entries)
    if not entries:
        return _estimate_litellm_entry_cost(usage, litellm_model)

    total = 0.0
    estimated_any = False
    for entry in entries:
        cost = _estimate_litellm_entry_cost(entry, litellm_model)
        if cost is None:
            continue
        total += cost
        estimated_any = True

    return total if estimated_any else None


def _estimate_litellm_entry_cost(entry: Any, model: str) -> float | None:
    prompt_tokens = _int_or_zero(getattr(entry, "input_tokens", 0))
    completion_tokens = _int_or_zero(getattr(entry, "output_tokens", 0))
    total_tokens = _int_or_zero(getattr(entry, "total_tokens", 0))
    if total_tokens <= 0:
        total_tokens = prompt_tokens + completion_tokens
    if total_tokens <= 0:
        return None

    usage_payload: dict[str, Any] = {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
    }
    prompt_details = _details_to_dict(getattr(entry, "input_tokens_details", None))
    completion_details = _details_to_dict(getattr(entry, "output_tokens_details", None))
    if prompt_details:
        usage_payload["prompt_tokens_details"] = prompt_details
    if completion_details:
        usage_payload["completion_tokens_details"] = completion_details

    from litellm import completion_cost

    candidates = [model]
    if "/" in model:
        candidates.append(model.rsplit("/", 1)[-1])

    for candidate in candidates:
        resolved = resolve_litellm_model(candidate)
        if not resolved:
            continue
        try:
            cost = completion_cost(
                completion_response={"model": resolved, "usage": usage_payload},
                model=resolved,
            )
        except Exception:  # nosec B112  # noqa: BLE001, S112
            continue
        if cost > 0:
            return float(cost)
    logger.debug("LiteLLM cost estimate unavailable for model %s", model)
    return None


def _litellm_model_name(model: str | None) -> str | None:
    if not model:
        return None
    normalized = model.strip()
    for prefix in ("litellm/", "any-llm/", "openai/"):
        if normalized.startswith(prefix):
            normalized = normalized.removeprefix(prefix)
            break
    return normalized or None


def _details_to_dict(details: Any) -> dict[str, Any]:
    if details is None:
        return {}
    if isinstance(details, list):
        for item in details:
            result = _details_to_dict(item)
            if result:
                return result
        return {}
    if hasattr(details, "model_dump"):
        return _details_to_dict(details.model_dump())
    if not isinstance(details, dict):
        return {}
    return {str(k): v for k, v in details.items() if v is not None}


def _int_or_zero(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _float_or_zero(value: Any) -> float:
    try:
        result = float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0
    return result if result >= 0 else 0.0


def _round_cost(cost: float) -> float:
    return round(max(0.0, cost), 10)

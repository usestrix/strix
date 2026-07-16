"""SDK-native LLM usage aggregation for scan reports."""

from __future__ import annotations

import logging
from typing import Any

from agents.usage import Usage, deserialize_usage, serialize_usage


logger = logging.getLogger(__name__)


class LLMUsageLedger:
    """Aggregate SDK ``Usage`` objects and attach best-effort cost estimates."""

    def __init__(self) -> None:
        self._total_usage = Usage()
        self._agent_usage: dict[str, Usage] = {}
        self._agent_metadata: dict[str, dict[str, str]] = {}
        self._agent_cost: dict[str, float] = {}
        self._model_usage: dict[str, Usage] = {}
        self._model_estimated_cost: dict[str, float] = {}
        self._model_observed_cost: dict[str, float] = {}
        self._model_base_cost: dict[str, float] = {}
        self._total_cost = 0.0

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
        normalized_model = str(model or "unknown").strip() or "unknown"
        self._model_usage.setdefault(normalized_model, Usage()).add(usage)

        metadata = self._agent_metadata.setdefault(normalized_agent_id, {})
        if agent_name:
            metadata["agent_name"] = agent_name
        if model:
            metadata["model"] = model

        estimated = _estimate_litellm_cost(usage, model)
        if estimated:
            self._model_estimated_cost[normalized_model] = (
                self._model_estimated_cost.get(normalized_model, 0.0) + estimated
            )
            if not _is_litellm_routed(model):
                self._total_cost += estimated
                self._agent_cost[normalized_agent_id] = (
                    self._agent_cost.get(normalized_agent_id, 0.0) + estimated
                )

        return True

    def record_observed_cost(self, cost: float, *, model: str | None = None) -> None:
        if isinstance(cost, int | float) and cost > 0:
            self._total_cost += float(cost)
            normalized_model = str(model or "").strip()
            if normalized_model:
                self._model_observed_cost[normalized_model] = (
                    self._model_observed_cost.get(normalized_model, 0.0) + float(cost)
                )

    @property
    def total_cost(self) -> float:
        return _round_cost(self._total_cost)

    def model_cost(self, model: str) -> float:
        """Return best available cumulative spend for one exact model route."""
        normalized = model.strip().lower()
        estimated = sum(
            cost for name, cost in self._model_estimated_cost.items() if name.lower() == normalized
        )
        observed = sum(
            cost for name, cost in self._model_observed_cost.items() if name.lower() == normalized
        )
        # SDK token pricing and provider callbacks describe the same calls. Use
        # the larger cumulative figure rather than double-counting them.
        base = sum(
            cost for name, cost in self._model_base_cost.items() if name.lower() == normalized
        )
        return _round_cost(base + max(estimated, observed))

    def to_record(self) -> dict[str, Any]:
        record = serialize_usage(self._total_usage)
        record["cost"] = _round_cost(self._total_cost)
        record["agents"] = []
        record["models"] = []
        for model in sorted(self._model_usage, key=str.lower):
            model_record = serialize_usage(self._model_usage[model])
            model_record.update({"model": model, "cost": self.model_cost(model)})
            record["models"].append(model_record)

        agent_tokens = {aid: _resolve_total_tokens(u) for aid, u in self._agent_usage.items()}
        # Native provider estimates are tied to an agent. Any remainder comes
        # from LiteLLM callbacks, whose callback interface has no Strix agent id.
        unassigned_cost = max(0.0, self._total_cost - sum(self._agent_cost.values()))
        litellm_agent_tokens = sum(
            tokens
            for aid, tokens in agent_tokens.items()
            if _is_litellm_routed(self._agent_metadata.get(aid, {}).get("model"))
        )
        for agent_id in sorted(self._agent_usage):
            usage = self._agent_usage[agent_id]
            metadata = self._agent_metadata.get(agent_id, {})
            agent_cost = self._agent_cost.get(agent_id, 0.0)
            if _is_litellm_routed(metadata.get("model")) and litellm_agent_tokens:
                # LiteLLM's callback does not carry Strix's agent id. Allocate
                # only callback-observed cost across LiteLLM agents by tokens;
                # never smear it over native-provider agents.
                agent_cost += unassigned_cost * (
                    agent_tokens[agent_id] / litellm_agent_tokens
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

    def hydrate(self, raw_usage: Any) -> None:  # noqa: PLR0912, PLR0915
        self._total_usage = Usage()
        self._agent_usage.clear()
        self._agent_metadata.clear()
        self._agent_cost.clear()
        self._model_usage.clear()
        self._model_estimated_cost.clear()
        self._model_observed_cost.clear()
        self._model_base_cost.clear()
        self._total_cost = 0.0

        if not isinstance(raw_usage, dict):
            return

        try:
            self._total_usage = deserialize_usage(raw_usage)
        except Exception:
            logger.exception("Failed to hydrate aggregate llm_usage from run.json")
            self._total_usage = Usage()

        self._total_cost = _float_or_zero(raw_usage.get("cost"))

        raw_models_value = raw_usage.get("models") or []
        raw_models = raw_models_value if isinstance(raw_models_value, list) else []
        persisted_model_cost: dict[str, float] = {}
        if raw_models:
            for raw_model in raw_models:
                if not isinstance(raw_model, dict):
                    continue
                model = str(raw_model.get("model") or "").strip()
                if not model:
                    continue
                try:
                    self._model_usage[model] = deserialize_usage(raw_model)
                except Exception:
                    logger.exception("Failed to hydrate llm_usage for model %s", model)
                    self._model_usage[model] = Usage()
                persisted_model_cost[model] = _float_or_zero(raw_model.get("cost"))

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
            agent_model = raw_agent.get("model")
            if isinstance(agent_name, str) and agent_name:
                metadata["agent_name"] = agent_name
            if isinstance(agent_model, str) and agent_model:
                metadata["model"] = agent_model
            self._agent_metadata[agent_id] = metadata
            # Persisted per-agent costs may include proportional allocation of
            # provider callback costs. Keep only native estimates here so a
            # resumed run does not double-count that allocation.
            if not _is_litellm_routed(metadata.get("model")):
                self._agent_cost[agent_id] = _float_or_zero(raw_agent.get("cost"))

            # Backward compatibility for run records written before per-model
            # usage was persisted. This cannot split agents that switched
            # models, but old records never supported model switching.
            if not raw_models and metadata.get("model"):
                model_name = metadata["model"]
                self._model_usage.setdefault(model_name, Usage()).add(
                    self._agent_usage[agent_id]
                )
                persisted_model_cost[model_name] = (
                    persisted_model_cost.get(model_name, 0.0)
                    + _float_or_zero(raw_agent.get("cost"))
                )

        # Hydrated values are an immutable historical baseline. New SDK
        # estimates and provider callbacks are accumulated separately so resume
        # neither loses nor double-counts the persisted model spend.
        self._model_base_cost.update(persisted_model_cost)


def _resolve_total_tokens(usage: Usage) -> int:
    total = max(0, int(usage.total_tokens or 0))
    if total > 0:
        return total
    prompt = _int_or_zero(getattr(usage, "input_tokens", 0))
    completion = _int_or_zero(getattr(usage, "output_tokens", 0))
    return prompt + completion


def _is_litellm_routed(model: str | None) -> bool:
    if not model:
        return False
    name = model.strip().lower()
    if "/" not in name:
        return False
    return not name.startswith("openai/")


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
        candidates.append(model.split("/", 1)[-1])

    cost: Any = None
    for candidate in candidates:
        try:
            cost = completion_cost(
                completion_response={"model": candidate, "usage": usage_payload},
                model=model,
            )
            break
        except Exception:  # nosec B112  # noqa: BLE001, S112
            continue

    if cost is None:
        logger.debug("LiteLLM cost estimate unavailable for model %s", model)
        return None

    return cost if isinstance(cost, int | float) and cost >= 0 else None


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

"""SDK-native LLM usage aggregation for scan reports."""

from __future__ import annotations

import logging
from typing import Any, cast

from agents.usage import Usage, deserialize_usage, serialize_usage
from pydantic import BaseModel, TypeAdapter, ValidationError

from strix.config.loader import load_settings
from strix.report.pricing import resolve_litellm_model


logger = logging.getLogger(__name__)

Prices = tuple[float | None, float | None, float | None]


def _configured_prices() -> tuple[str | None, Prices | None]:
    llm = load_settings().llm
    prices = (llm.input_cost_per_mtok, llm.output_cost_per_mtok, llm.cached_input_cost_per_mtok)
    if all(price is None for price in prices):
        return None, None
    return (llm.model or "").strip() or None, prices


def _configured_usage_cost(usage: Usage, prices: Prices) -> float:
    input_rate, output_rate, cached_rate = prices
    input_tokens = max(0, _int_or_zero(getattr(usage, "input_tokens", 0)))
    cached_details = getattr(usage, "input_tokens_details", None)
    cached_tokens = max(0, _int_or_zero(getattr(cached_details, "cached_tokens", 0)))
    cached_tokens = min(cached_tokens, input_tokens)
    output_tokens = max(0, _int_or_zero(getattr(usage, "output_tokens", 0)))
    billable_input = input_tokens - cached_tokens
    cost = (
        billable_input * (input_rate or 0)
        + cached_tokens * (cached_rate if cached_rate is not None else input_rate or 0)
        + output_tokens * (output_rate or 0)
    ) / 1_000_000
    return _round_cost(cost)


class ProviderUsage(BaseModel):
    """Running totals for one upstream provider OpenRouter routed calls to."""

    requests: int = 0
    input_tokens: int = 0
    cached_tokens: int = 0
    cost: float = 0.0
    # Calls that didn't find the agent's whole previous prompt cached, and the
    # previous-prompt tokens they had to pay for again.
    cache_misses: int = 0
    missed_tokens: int = 0


_PROVIDER_USAGE = TypeAdapter(dict[str, ProviderUsage])


class LLMUsageLedger:
    """Aggregate SDK ``Usage`` objects and attach best-effort cost estimates.

    ``agents`` remains the public aggregate view in ``run.json``. The optional,
    versioned ``model_usage`` section preserves proven agent/model ownership for
    resumes; records without it hydrate as one legacy bucket per agent.
    """

    def __init__(self) -> None:
        self._total_usage = Usage()
        self._agent_usage: dict[str, Usage] = {}
        self._agent_metadata: dict[str, dict[str, str]] = {}
        self._agent_estimated_cost: dict[str, float] = {}
        self._model_usage: dict[tuple[str, str | None], Usage] = {}
        self._model_fallback_cost: dict[tuple[str, str | None], float] = {}
        self._unattributed_cost = 0.0
        self._observed_cost = 0.0
        self._estimated_cost = 0.0
        self._has_observed_cost = False
        # Keyed by upstream provider name, e.g. "Z.AI" or "DeepInfra".
        self._providers: dict[str, ProviderUsage] = {}
        # Each agent's last prompt size, which its next call should find cached.
        self._last_input_tokens: dict[str, int] = {}
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
        normalized_model = (model or "").strip() or None
        self._total_usage.add(usage)
        self._agent_usage.setdefault(normalized_agent_id, Usage()).add(usage)
        model_key = (normalized_agent_id, normalized_model)
        self._model_usage.setdefault(model_key, Usage()).add(usage)

        metadata = self._agent_metadata.setdefault(normalized_agent_id, {})
        if agent_name:
            metadata["agent_name"] = agent_name
        if normalized_model:
            metadata["model"] = normalized_model

        if not self.zero_cost:
            estimated = _estimate_litellm_cost(usage, normalized_model)
            if estimated:
                self._estimated_cost += estimated
                self._agent_estimated_cost[normalized_agent_id] = (
                    self._agent_estimated_cost.get(normalized_agent_id, 0.0) + estimated
                )
            configured_model, prices = _configured_prices()
            fallback = (
                _configured_usage_cost(usage, prices)
                if prices is not None and normalized_model == configured_model
                else estimated or 0.0
            )
            self._model_fallback_cost[model_key] = _round_cost(
                self._model_fallback_cost.get(model_key, 0.0) + fallback
            )

        return True

    def record_observed_cost(self, cost: float) -> None:
        if self.zero_cost:
            return
        if isinstance(cost, int | float) and cost > 0:
            self._observed_cost += float(cost)
            self._has_observed_cost = True

    def record_provider(
        self,
        provider: str,
        *,
        agent_id: str | None,
        input_tokens: int,
        cached_tokens: int,
        cost: float,
        cache_block_tokens: int,
    ) -> None:
        tally = self._providers.setdefault(provider, ProviderUsage())
        tally.requests += 1
        tally.input_tokens += input_tokens
        tally.cached_tokens += cached_tokens
        if agent_id:
            previous = self._last_input_tokens.get(agent_id, 0)
            # The previous prompt is a prefix of this one, so all of it but a
            # partial last block should read back cached. A shrinking prompt means
            # compaction rewrote it, so a miss is expected.
            missed = previous - cached_tokens
            if input_tokens >= previous and missed >= cache_block_tokens:
                tally.cache_misses += 1
                tally.missed_tokens += missed
            self._last_input_tokens[agent_id] = input_tokens
        if not self.zero_cost:
            tally.cost = _round_cost(tally.cost + cost)

    @property
    def total_cost(self) -> float:
        if self.zero_cost:
            return 0.0
        model, prices = _configured_prices()
        if prices is not None:
            return _round_cost(
                self._unattributed_cost
                + sum(self._configured_model_cost(key, model, prices) for key in self._model_usage)
            )
        return _round_cost(self._observed_cost if self._has_observed_cost else self._estimated_cost)

    def _configured_agent_cost(self, agent_id: str, model: str | None, prices: Prices) -> float:
        return _round_cost(
            sum(
                self._configured_model_cost(key, model, prices)
                for key in self._model_usage
                if key[0] == agent_id
            )
        )

    def _configured_model_cost(
        self,
        key: tuple[str, str | None],
        model: str | None,
        prices: Prices,
    ) -> float:
        if key[1] == model:
            return _configured_usage_cost(self._model_usage[key], prices)
        return self._model_fallback_cost.get(key, 0.0)

    def _model_costs_for_record(
        self,
        total_cost: float,
        model: str | None,
        prices: Prices | None,
    ) -> dict[tuple[str, str | None], float]:
        if self.zero_cost:
            return dict.fromkeys(self._model_usage, 0.0)
        if prices is not None:
            return {
                key: self._configured_model_cost(key, model, prices) for key in self._model_usage
            }
        if not self._has_observed_cost:
            return {key: self._model_fallback_cost.get(key, 0.0) for key in self._model_usage}

        model_tokens = {
            key: _resolve_total_tokens(usage) for key, usage in self._model_usage.items()
        }
        total_tokens = sum(model_tokens.values())
        attributable_cost = max(0.0, total_cost - self._unattributed_cost)
        return {
            key: attributable_cost * (tokens / total_tokens) if total_tokens else 0.0
            for key, tokens in model_tokens.items()
        }

    def to_record(self) -> dict[str, Any]:
        record: dict[str, Any] = serialize_usage(self._total_usage)
        model, prices = _configured_prices()
        total_cost = self.total_cost
        model_costs = self._model_costs_for_record(total_cost, model, prices)
        record["cost"] = total_cost
        record["providers"] = {name: tally.model_dump() for name, tally in self._providers.items()}
        agent_records: list[dict[str, Any]] = []
        model_entries: list[dict[str, Any]] = []
        record["agents"] = agent_records
        record["model_usage"] = {
            "version": 1,
            "unattributed_cost": self._unattributed_cost,
            "entries": model_entries,
        }

        agent_tokens = {aid: _resolve_total_tokens(u) for aid, u in self._agent_usage.items()}
        total_tokens = sum(agent_tokens.values())
        for agent_id in sorted(self._agent_usage):
            usage = self._agent_usage[agent_id]
            metadata = self._agent_metadata.get(agent_id, {})
            agent_cost = (
                self._configured_agent_cost(agent_id, model, prices)
                if prices is not None and not self.zero_cost
                else total_cost * (agent_tokens[agent_id] / total_tokens)
                if total_tokens
                else 0.0
            )

            agent_record: dict[str, Any] = serialize_usage(usage)
            agent_record.update(
                {
                    "agent_id": agent_id,
                    "agent_name": metadata.get("agent_name") or agent_id,
                    "model": metadata.get("model"),
                    "cost": _round_cost(agent_cost),
                }
            )
            agent_records.append(agent_record)

        for (agent_id, usage_model), usage in sorted(
            self._model_usage.items(), key=lambda item: (item[0][0], item[0][1] or "")
        ):
            model_record: dict[str, Any] = serialize_usage(usage)
            model_record.update(
                {
                    "agent_id": agent_id,
                    "model": usage_model,
                    "cost": _round_cost(model_costs[(agent_id, usage_model)]),
                }
            )
            model_entries.append(model_record)

        return record

    def hydrate(self, raw_usage: Any) -> None:
        self._reset_for_hydration()

        if not isinstance(raw_usage, dict):
            return
        raw_usage = cast("dict[str, Any]", raw_usage)

        try:
            self._providers = _PROVIDER_USAGE.validate_python(raw_usage.get("providers") or {})
        except ValidationError:
            logger.exception("Failed to hydrate llm_usage providers from run.json")

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

            self._agent_estimated_cost[agent_id] = _float_or_zero(raw_agent.get("cost"))
            metadata: dict[str, str] = {}
            agent_name = raw_agent.get("agent_name")
            model = raw_agent.get("model")
            if isinstance(agent_name, str) and agent_name:
                metadata["agent_name"] = agent_name
            if isinstance(model, str) and model:
                metadata["model"] = model
            self._agent_metadata[agent_id] = metadata

        if not self._hydrate_model_usage(raw_usage.get("model_usage")):
            # Legacy records can prove only their aggregate agent/model snapshot.
            # Treat it as one bucket; never invent a historical model split.
            for agent_id, usage in self._agent_usage.items():
                model = self._agent_metadata.get(agent_id, {}).get("model")
                key = (agent_id, model)
                model_usage = Usage()
                model_usage.add(usage)
                self._model_usage[key] = model_usage
                self._model_fallback_cost[key] = self._agent_estimated_cost.get(agent_id, 0.0)

            attributed_cost = sum(self._model_fallback_cost.values())
            self._unattributed_cost = _round_cost(max(0.0, persisted_cost - attributed_cost))

    def _reset_for_hydration(self) -> None:
        self._total_usage = Usage()
        self._agent_usage.clear()
        self._agent_metadata.clear()
        self._agent_estimated_cost.clear()
        self._model_usage.clear()
        self._model_fallback_cost.clear()
        self._unattributed_cost = 0.0
        self._observed_cost = 0.0
        self._estimated_cost = 0.0
        self._has_observed_cost = False
        self._providers = {}

    def _hydrate_model_usage(self, raw_model_usage: Any) -> bool:
        if raw_model_usage is None:
            return False
        if not isinstance(raw_model_usage, dict):
            logger.warning("Ignoring invalid model-specific llm_usage in run.json")
            return False
        if raw_model_usage.get("version") != 1:
            logger.warning("Ignoring unsupported model-specific llm_usage version in run.json")
            return False
        try:
            model_usage, model_costs, unattributed_cost = _deserialize_model_usage(
                raw_model_usage, self._agent_usage
            )
        except Exception:  # noqa: BLE001 - malformed legacy records fall back safely
            logger.warning("Ignoring invalid model-specific llm_usage in run.json")
            return False

        self._model_usage = model_usage
        self._model_fallback_cost = model_costs
        self._unattributed_cost = unattributed_cost
        return True


def _deserialize_model_usage(
    raw_model_usage: Any,
    agent_usage: dict[str, Usage],
) -> tuple[
    dict[tuple[str, str | None], Usage],
    dict[tuple[str, str | None], float],
    float,
]:
    if not isinstance(raw_model_usage, dict):
        raise TypeError
    raw_model_usage = cast("dict[str, Any]", raw_model_usage)
    if raw_model_usage.get("version") != 1:
        raise ValueError
    raw_entries = raw_model_usage.get("entries")
    if not isinstance(raw_entries, list):
        raise TypeError
    typed_entries = cast("list[Any]", raw_entries)  # type: ignore[redundant-cast]

    model_usage: dict[tuple[str, str | None], Usage] = {}
    model_costs: dict[tuple[str, str | None], float] = {}
    for raw_entry in typed_entries:
        if not isinstance(raw_entry, dict):
            raise TypeError
        raw_entry = cast("dict[str, Any]", raw_entry)
        agent_id = str(raw_entry.get("agent_id") or "").strip()
        raw_model = raw_entry.get("model")
        if not agent_id or agent_id not in agent_usage:
            raise ValueError
        if raw_model is not None and not isinstance(raw_model, str):
            raise TypeError
        model = (raw_model or "").strip() or None
        key = (agent_id, model)
        if key in model_usage:
            raise ValueError
        model_usage[key] = deserialize_usage(raw_entry)
        model_costs[key] = _float_or_zero(raw_entry.get("cost"))

    for agent_id, aggregate in agent_usage.items():
        combined = Usage()
        for key, usage in model_usage.items():
            if key[0] == agent_id:
                combined.add(usage)
        if _usage_signature(combined) != _usage_signature(aggregate):
            raise ValueError

    return (
        model_usage,
        model_costs,
        _float_or_zero(raw_model_usage.get("unattributed_cost")),
    )


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


def _usage_signature(usage: Usage) -> tuple[int, int, int, int, int]:
    details = getattr(usage, "input_tokens_details", None)
    return (
        _int_or_zero(getattr(usage, "requests", 0)),
        _int_or_zero(getattr(usage, "input_tokens", 0)),
        _int_or_zero(getattr(usage, "output_tokens", 0)),
        _int_or_zero(getattr(usage, "total_tokens", 0)),
        _int_or_zero(getattr(details, "cached_tokens", 0)),
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

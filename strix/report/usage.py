"""SDK-native LLM usage aggregation for scan reports."""

from __future__ import annotations

import logging
import math
import threading
from typing import Any

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
    """Aggregate SDK ``Usage`` objects and attach best-effort cost estimates."""

    def __init__(self) -> None:
        self._total_usage = Usage()
        self._agent_usage: dict[str, Usage] = {}
        self._agent_metadata: dict[str, dict[str, str]] = {}
        self._agent_estimated_cost: dict[str, float] = {}
        self._observed_cost = 0.0
        self._estimated_cost = 0.0
        # A provider callback and the SDK usage hook can describe the same
        # response. Match them by response id so an observed charge replaces
        # that response's estimate, while an unpriced response keeps its own
        # estimate. This matters when only some OpenRouter calls report cost.
        # What cannot be matched by id (no id on one side) keeps the upstream
        # contract, see ``total_cost``.
        self._estimated_by_response: dict[str, float] = {}
        self._observed_by_response: dict[str, float] = {}
        # Running totals over the two maps, kept in step on every write so
        # reading ``total_cost`` (each save, each budget check) is O(1):
        # the cost of id-matched responses, and charges with no estimate.
        self._paired_cost = 0.0
        self._unpaired_observed_by_id = 0.0
        # Estimates arrive from the event loop, charges from provider
        # callbacks; one lock keeps a map and its running total in step.
        self._response_lock = threading.Lock()
        self._persisted_cost = 0.0
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
        response_id: str | None = None,
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
            if estimated and math.isfinite(estimated):
                if response_id:
                    self._set_response_cost(response_id, estimated=estimated)
                else:
                    self._estimated_cost += estimated
                self._agent_estimated_cost[normalized_agent_id] = (
                    self._agent_estimated_cost.get(normalized_agent_id, 0.0) + estimated
                )

        return True

    def record_observed_cost(self, cost: float, *, response_id: str | None = None) -> None:
        if self.zero_cost:
            return
        if isinstance(cost, int | float) and math.isfinite(cost) and cost > 0:
            if response_id:
                self._set_response_cost(response_id, observed=float(cost))
            else:
                self._observed_cost += float(cost)

    def _response_contribution(self, response_id: str) -> tuple[float, float]:
        """This response's share of (paired cost, unpaired keyed charges)."""
        observed = self._observed_by_response.get(response_id)
        estimated = self._estimated_by_response.get(response_id)
        if estimated is not None:
            return (estimated if observed is None else observed), 0.0
        return 0.0, (observed or 0.0)

    def _set_response_cost(
        self,
        response_id: str,
        *,
        estimated: float | None = None,
        observed: float | None = None,
    ) -> None:
        with self._response_lock:
            old_paired, old_unpaired = self._response_contribution(response_id)
            if estimated is not None:
                self._estimated_by_response[response_id] = estimated
            if observed is not None:
                self._observed_by_response[response_id] = observed
            new_paired, new_unpaired = self._response_contribution(response_id)
            self._paired_cost += new_paired - old_paired
            self._unpaired_observed_by_id += new_unpaired - old_unpaired

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
                sum(self._configured_agent_cost(aid, model, prices) for aid in self._agent_usage)
            )
        # Matched by response id: the provider's charge replaces that response's
        # estimate, and a response without a charge keeps its own estimate.
        # Whatever id matching cannot settle keeps the upstream contract: a
        # provider charge with no estimate to match replaces the unkeyed
        # estimates instead of adding to them, because without a shared id they
        # may describe the same response. Adding both would overstate the spend
        # and stop a scan early at --max-budget.
        with self._response_lock:
            paired = self._paired_cost
            unpaired_observed = self._observed_cost + self._unpaired_observed_by_id
        unpaired = unpaired_observed if unpaired_observed > 0 else self._estimated_cost
        return _round_cost(self._persisted_cost + paired + unpaired)

    def _configured_agent_cost(self, agent_id: str, model: str | None, prices: Prices) -> float:
        if self._agent_metadata.get(agent_id, {}).get("model") == model:
            return _configured_usage_cost(self._agent_usage[agent_id], prices)
        return self._agent_estimated_cost.get(agent_id, 0.0)

    def to_record(self) -> dict[str, Any]:
        record = serialize_usage(self._total_usage)
        model, prices = _configured_prices()
        total_cost = self.total_cost
        record["cost"] = total_cost
        record["providers"] = {name: tally.model_dump() for name, tally in self._providers.items()}
        record["agents"] = []

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
        self._agent_estimated_cost.clear()
        self._observed_cost = 0.0
        self._estimated_cost = 0.0
        self._estimated_by_response.clear()
        self._observed_by_response.clear()
        self._paired_cost = 0.0
        self._unpaired_observed_by_id = 0.0
        self._persisted_cost = 0.0
        self._providers = {}

        if not isinstance(raw_usage, dict):
            return

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
        self._persisted_cost = persisted_cost

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

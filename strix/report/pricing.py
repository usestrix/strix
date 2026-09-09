"""LiteLLM model-name resolution for local cost estimates."""

from __future__ import annotations

from functools import lru_cache
from typing import Any, cast


def _preferred_route(
    matches: list[str],
    model_cost: dict[str, dict[str, Any]],
    name: str,
) -> str:
    """Pick the provider's own route when several equally priced ones match.

    LiteLLM lists the same model under its native provider (``xai/grok-4.5``) and
    under the aggregators that resell it (``openrouter/x-ai/grok-4.5``,
    ``perplexity/xai/grok-4.5``). Alphabetical order would hand back an
    aggregator; the canonical route is the one shaped exactly
    ``{litellm_provider}/{name}``.
    """
    for key in matches:
        entry = model_cost.get(key)
        if not isinstance(entry, dict):
            continue
        provider = entry.get("litellm_provider")
        if isinstance(provider, str) and key == f"{provider}/{name}":
            return key
    return matches[0]


@lru_cache(maxsize=512)
def resolve_litellm_model(model: str) -> str | None:
    """Return a provider-qualified model name that LiteLLM can price."""
    try:
        import litellm

        normalized = model.strip()
        for prefix in ("litellm/", "any-llm/", "openai/"):
            if normalized.startswith(prefix):
                normalized = normalized.removeprefix(prefix)
                break
        if not normalized:
            return None

        model_cost = cast(
            "dict[str, dict[str, Any]]",
            getattr(litellm, "model_cost"),  # noqa: B009
        )
        bare_entry = model_cost.get(normalized)
        if "/" not in normalized and isinstance(bare_entry, dict):
            provider = bare_entry.get("litellm_provider")
            if isinstance(provider, str) and provider:
                return f"{provider}/{normalized}"
        if "/" in normalized and isinstance(bare_entry, dict):
            return normalized

        names = [normalized]
        if "/" in normalized:
            names.append(normalized.rsplit("/", 1)[-1])
        for name in names:
            matches = sorted(key for key in model_cost if key.endswith(f"/{name}"))
            if not matches:
                continue
            prices = {
                (
                    model_cost[key].get("input_cost_per_token"),
                    model_cost[key].get("output_cost_per_token"),
                )
                for key in matches
                if isinstance(model_cost.get(key), dict)
            }
            if len(matches) == 1 or len(prices) == 1:
                return _preferred_route(matches, model_cost, name)
        return None  # noqa: TRY300
    except Exception:  # noqa: BLE001
        return None

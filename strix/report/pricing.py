"""LiteLLM model-name resolution for local cost estimates."""

from __future__ import annotations

from functools import lru_cache
from typing import Any, cast


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
                # Every route prices the model the same, so picking one is free; pick
                # the first-party listing over an aggregator's re-listing. Aggregators
                # (OpenRouter, DeepInfra, ...) re-key a model under a namespaced path
                # such as "openrouter/x-ai/grok-4.5", which sorts ahead of the native
                # "xai/grok-4.5", so the alphabetically first key would be misleading.
                native = [
                    key
                    for key in matches
                    if isinstance(model_cost.get(key), dict)
                    and key == f"{model_cost[key].get('litellm_provider')}/{name}"
                ]
                return native[0] if len(native) == 1 else matches[0]
        return None  # noqa: TRY300
    except Exception:  # noqa: BLE001
        return None

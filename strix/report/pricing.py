"""LiteLLM model-name resolution for local cost estimates."""

from __future__ import annotations

from functools import lru_cache
from typing import Any, cast


@lru_cache(maxsize=512)
def resolve_litellm_model(  # noqa: PLR0911 - each resolution path returns its own name
    model: str,
) -> str | None:
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
            # Prefer the first-party provider's own listing over an aggregator's
            # re-listing of the same model. Aggregators (OpenRouter, DeepInfra,
            # Perplexity, ...) re-key a model under a namespaced path such as
            # "openrouter/x-ai/grok-4.5"; the native listing is the one whose key
            # is exactly "<litellm_provider>/<name>" ("xai/grok-4.5"). When that
            # is unique it is the canonical name, so tie-break on it before
            # falling back to price consensus (which would otherwise pick the
            # alphabetically first key, an aggregator).
            native = [
                key
                for key in matches
                if isinstance(model_cost.get(key), dict)
                and key == f"{model_cost[key].get('litellm_provider')}/{name}"
            ]
            if len(native) == 1:
                return native[0]
            prices = {
                (
                    model_cost[key].get("input_cost_per_token"),
                    model_cost[key].get("output_cost_per_token"),
                )
                for key in matches
                if isinstance(model_cost.get(key), dict)
            }
            if len(matches) == 1 or len(prices) == 1:
                return matches[0]
        return None  # noqa: TRY300
    except Exception:  # noqa: BLE001
        return None

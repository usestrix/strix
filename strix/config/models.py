"""SDK model configuration helpers."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from agents import set_default_openai_api, set_default_openai_key, set_tracing_disabled
from agents.models.multi_provider import MultiProvider
from agents.retry import (
    ModelRetryBackoffSettings,
    ModelRetrySettings,
    RetryPolicyContext,
    retry_policies,
)


if TYPE_CHECKING:
    from agents.models.interface import ModelProvider

    from strix.config.settings import Settings


def request_timeout_extra_args(timeout_s: float | None) -> dict[str, float] | None:
    """Per-request model timeout; a plain float so ``ModelSettings.to_json_dict()`` stays serializable."""  # noqa: E501
    if not timeout_s or timeout_s <= 0:
        return None
    return {"timeout": timeout_s}


def _retry_statusless_provider_errors(context: RetryPolicyContext) -> bool:
    """Retry statusless provider errors (e.g. mid-stream quota/billing), but not aborts."""
    normalized = context.normalized
    if normalized.is_abort:
        return False
    return normalized.status_code is None


class StrixProvider(MultiProvider):
    """Route any non-OpenAI prefix through LiteLLM with the prefix preserved,
    so users type ``deepseek/deepseek-chat`` rather than
    ``litellm/deepseek/deepseek-chat``.
    """

    def _resolve_prefixed_model(
        self,
        *,
        original_model_name: str,
        prefix: str,
        stripped_model_name: str | None,
    ) -> tuple[ModelProvider, str | None]:
        if prefix in {"openai", "litellm", "any-llm"}:
            return super()._resolve_prefixed_model(
                original_model_name=original_model_name,
                prefix=prefix,
                stripped_model_name=stripped_model_name,
            )
        if prefix == "ollama" and stripped_model_name:
            return self._get_fallback_provider("litellm"), f"ollama_chat/{stripped_model_name}"
        return self._get_fallback_provider("litellm"), original_model_name


DEFAULT_MODEL_RETRY = ModelRetrySettings(
    max_retries=5,
    backoff=ModelRetryBackoffSettings(
        initial_delay=2.0,
        max_delay=90.0,
        multiplier=2.0,
        jitter=False,
    ),
    policy=retry_policies.any(
        retry_policies.provider_suggested(),
        retry_policies.network_error(),
        retry_policies.http_status((429, 500, 502, 503, 504)),
        _retry_statusless_provider_errors,
    ),
)

RECOMMENDED_MODEL_NAMES = (
    "openai/gpt-5.6",
    "openai/gpt-5.6-sol",
    "openai/gpt-5.6-terra",
    "openai/gpt-5.5",
    "openai/gpt-5.5-pro",
    "openai/gpt-5.4",
    "openai/gpt-5.3-codex",
    "anthropic/claude-fable-5",
    "anthropic/claude-opus-4-8",
    "anthropic/claude-opus-4-7",
    "anthropic/claude-sonnet-5",
    "anthropic/claude-sonnet-4-6",
    "vertex_ai/gemini-3.1-pro-preview",
    "gemini/gemini-3.1-pro-preview",
    "deepseek/deepseek-v4-pro",
    "deepseek/deepseek-v4-flash",
    "dashscope/qwen3.7-max-2026-06-08",
    "moonshot/kimi-k2.7-code",
    "moonshot/kimi-k2.6",
)

_RECOMMENDED_MODEL_NAME_SET = frozenset(name.lower() for name in RECOMMENDED_MODEL_NAMES)

FRONTIER_MODEL_FAMILIES = (
    (("azure", "azure_ai", "bedrock_mantle", "openai"), ("gpt-5",)),
    (
        ("anthropic", "azure_ai", "bedrock", "claude", "databricks", "snowflake", "vertex_ai"),
        ("claude-fable-5", "claude-opus-4", "claude-sonnet-5", "claude-sonnet-4"),
    ),
    (("google", "gemini", "vertex_ai"), ("gemini-3",)),
    (("deepseek",), ("deepseek-v4", "deepseek-r1", "deepseek-reasoner")),
    (("alibaba", "dashscope", "qwen"), ("qwen3.7", "qwen3.5", "qwen3-max")),
    (("moonshot", "moonshotai", "kimi"), ("kimi-k2.7", "kimi-k2.6", "kimi-k2.5")),
)


def configure_sdk_model_defaults(settings: Settings) -> None:
    """Apply Strix config to SDK-native defaults."""
    llm = settings.llm
    set_tracing_disabled(True)
    _configure_litellm_compatibility()
    _configure_openrouter_attribution(llm.model)
    if llm.api_key:
        set_default_openai_key(llm.api_key, use_for_tracing=False)
        _configure_litellm_default("api_key", llm.api_key)
        _mirror_api_key_to_provider_env(llm.model, llm.api_key)
    if llm.api_base:
        os.environ["OPENAI_BASE_URL"] = llm.api_base
        _configure_litellm_default("api_base", llm.api_base)
        set_default_openai_api("chat_completions")
    else:
        set_default_openai_api("responses")


def _mirror_api_key_to_provider_env(model_name: str | None, api_key: str) -> None:
    if not model_name:
        return
    import litellm

    name = model_name.strip()
    for prefix in ("litellm/", "any-llm/"):
        if name.lower().startswith(prefix):
            name = name[len(prefix) :]
            break
    try:
        report = litellm.validate_environment(model=name.lower())
    except Exception:  # noqa: BLE001
        return
    for env_key in report.get("missing_keys") or []:
        if env_key.endswith("_API_KEY"):
            os.environ.setdefault(env_key, api_key)


def _configure_litellm_compatibility() -> None:
    """Apply LiteLLM compatibility, privacy, and callback settings."""
    import litellm

    litellm.drop_params = True
    litellm.modify_params = True
    litellm.turn_off_message_logging = True
    # Strix uses LiteLLM's success callback to capture provider-reported cost.
    # Disabling streaming logging also disables that callback for streamed calls.
    litellm.disable_streaming_logging = False
    litellm.suppress_debug_info = True

    _register_litellm_cost_callback()


_OPENROUTER_ATTRIBUTION_HEADERS = {
    "HTTP-Referer": "https://strix.ai",
    "X-Title": "Strix",
    "X-OpenRouter-Categories": "cli-agent",
}


def _configure_openrouter_attribution(model_name: str | None) -> None:
    import litellm

    current: object = litellm.headers
    existing: dict[str, str] = current if isinstance(current, dict) else {}
    if not model_name or "openrouter/" not in model_name.strip().lower():
        if any(key in existing for key in _OPENROUTER_ATTRIBUTION_HEADERS):
            remaining = {
                k: v for k, v in existing.items() if k not in _OPENROUTER_ATTRIBUTION_HEADERS
            }
            litellm.headers = remaining or None  # type: ignore[assignment]
        return

    litellm.headers = {**existing, **_OPENROUTER_ATTRIBUTION_HEADERS}  # type: ignore[assignment]


def _register_litellm_cost_callback() -> None:
    import litellm

    from strix.report.state import litellm_cost_callback

    for bucket_name in ("success_callback", "_async_success_callback"):
        bucket = getattr(litellm, bucket_name, None)
        if not isinstance(bucket, list):
            continue
        if litellm_cost_callback in bucket:
            continue
        bucket.append(litellm_cost_callback)


def _configure_litellm_default(name: str, value: str) -> None:
    """Set LiteLLM's module-level defaults without adding a provider wrapper."""
    import litellm

    setattr(litellm, name, value)


def uses_chat_completions_tool_schema(model_name: str, settings: Settings) -> bool:
    """Return whether the resolved SDK route can only receive JSON function tools."""
    model = model_name.strip().lower()
    if "/" in model and not model.startswith("openai/"):
        return True
    if settings.llm.api_base:
        return True
    return not model_supports_reasoning(model_name)


def model_supports_reasoning(model_name: str) -> bool:
    import litellm

    name = model_name.strip().lower()
    for prefix in ("litellm/", "any-llm/", "openai/"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    entry = litellm.model_cost.get(name)
    if entry is None and "/" in name:
        entry = litellm.model_cost.get(name.rsplit("/", 1)[1])
    return bool(entry and entry.get("supports_reasoning"))


def is_recommended_or_frontier_model(model_name: str) -> bool:
    """Return whether a model is recommended or in a frontier model family."""
    name = _normalized_model_name(model_name)
    if not name:
        return False
    if name in _RECOMMENDED_MODEL_NAME_SET:
        return True
    provider_name, bare_model_name = _split_model_provider(name)
    return any(
        _matches_frontier_family(provider_name, bare_model_name, provider_markers, prefixes)
        for provider_markers, prefixes in FRONTIER_MODEL_FAMILIES
    )


def _normalized_model_name(model_name: str) -> str:
    name = model_name.strip().lower()
    for prefix in ("litellm/", "any-llm/"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    return name


def _split_model_provider(model_name: str) -> tuple[str | None, str]:
    if "/" not in model_name:
        return None, model_name
    provider_name, bare_model_name = model_name.rsplit("/", 1)
    return provider_name, bare_model_name


def _matches_frontier_family(
    provider_name: str | None,
    model_name: str,
    provider_markers: tuple[str, ...],
    model_prefixes: tuple[str, ...],
) -> bool:
    if not _matches_model_prefix(model_name, model_prefixes):
        return False
    if provider_name is None:
        return True
    return _contains_provider_marker(
        provider_name, provider_markers, split_compound_names=True
    ) or _contains_provider_marker(model_name, provider_markers)


def _matches_model_prefix(model_name: str, model_prefixes: tuple[str, ...]) -> bool:
    return any(
        candidate.startswith(prefix)
        for candidate in _model_name_candidates(model_name)
        for prefix in model_prefixes
    )


def _model_name_candidates(model_name: str) -> tuple[str, ...]:
    if "." not in model_name:
        return (model_name,)
    suffixes = tuple(
        model_name.split(".", index)[-1] for index in range(1, model_name.count(".") + 1)
    )
    return (model_name, *suffixes)


def _contains_provider_marker(
    value: str, provider_markers: tuple[str, ...], *, split_compound_names: bool = False
) -> bool:
    parts = set(value.replace(".", "/").split("/"))
    if split_compound_names:
        for separator in ("_", "-"):
            parts.update(piece for part in tuple(parts) for piece in part.split(separator))
    return any(marker in parts for marker in provider_markers)


def is_known_openai_bare_model(model_name: str) -> bool:
    import litellm

    name = model_name.strip().lower()
    if not name or "/" in name:
        return False
    entry = litellm.model_cost.get(name)
    return bool(entry and entry.get("litellm_provider") == "openai")

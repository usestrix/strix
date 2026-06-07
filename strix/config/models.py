"""SDK model configuration helpers."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from agents import set_default_openai_api, set_default_openai_key, set_tracing_disabled
from agents.retry import (
    ModelRetryBackoffSettings,
    ModelRetrySettings,
    retry_policies,
)


if TYPE_CHECKING:
    from strix.config.settings import Settings


_SDK_PREFIXES = {"any-llm", "litellm", "openai"}


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
    ),
)


def configure_sdk_model_defaults(settings: Settings) -> None:
    """Apply Strix config to SDK-native defaults.

    OpenAI-compatible base URLs are handled by the SDK OpenAI provider.
    Non-OpenAI providers should use the SDK's native ``litellm/`` or
    ``any-llm/`` routing, produced by :func:`normalize_model_name`.
    """
    llm = settings.llm
    set_tracing_disabled(True)
    _configure_litellm_compatibility()
    if llm.api_key:
        set_default_openai_key(llm.api_key, use_for_tracing=False)
        _configure_litellm_default("api_key", llm.api_key)
    if llm.api_base:
        os.environ["OPENAI_BASE_URL"] = llm.api_base
        _configure_litellm_default("api_base", llm.api_base)
        set_default_openai_api("chat_completions")
    else:
        set_default_openai_api("responses")


def _configure_litellm_compatibility() -> None:
    """Enable LiteLLM's permissive param-handling mode."""
    import litellm

    litellm.drop_params = True
    litellm.modify_params = True


def _configure_litellm_default(name: str, value: str) -> None:
    """Set LiteLLM's module-level defaults without adding a provider wrapper."""
    import litellm

    setattr(litellm, name, value)


def normalize_model_name(model_name: str) -> str:
    """Normalize friendly Strix model names to SDK-native model ids."""
    model = model_name.strip()
    if not model:
        return model

    if "/" in model:
        prefix = model.split("/", 1)[0].lower()
        if prefix in _SDK_PREFIXES:
            return model
        return f"litellm/{model}"

    lower = model.lower()
    if lower.startswith("claude"):
        return f"litellm/anthropic/{model}"
    if lower.startswith("gemini"):
        return f"litellm/gemini/{model}"

    return model


def uses_chat_completions_tool_schema(model_name: str, settings: Settings) -> bool:
    """Return whether the resolved SDK route can only receive JSON function tools."""
    model = model_name.strip().lower()
    if model.startswith(("litellm/", "any-llm/")):
        return True
    return bool(settings.llm.api_base)

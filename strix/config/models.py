"""SDK model configuration helpers."""

from __future__ import annotations

import os
import re
from typing import TYPE_CHECKING

from agents import set_default_openai_api, set_default_openai_key
from agents.retry import (
    ModelRetryBackoffSettings,
    ModelRetrySettings,
    retry_policies,
)


if TYPE_CHECKING:
    from strix.config.settings import ReasoningEffort, Settings


_SDK_PREFIXES = {"any-llm", "litellm", "openai"}
_ROUTING_PREFIXES = ("litellm/", "any-llm/", "openrouter/", "openai/")
_REASONING_MODEL_RE = re.compile(
    r"(?:^|/)"
    r"(?:anthropic/|claude|o\d+[-\w.]*|gpt-5|deepseek-reasoner|deepseek-r1|gemini-.*-thinking)",
    re.IGNORECASE,
)


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


def _model_slug(model_name: str) -> str:
    slug = model_name.strip().lower()
    for _ in range(len(_ROUTING_PREFIXES)):
        stripped = False
        for prefix in _ROUTING_PREFIXES:
            if slug.startswith(prefix):
                slug = slug[len(prefix) :]
                stripped = True
                break
        if not stripped:
            break
    return slug


def model_supports_reasoning(model_name: str) -> bool:
    """Return whether the resolved model accepts OpenAI-style reasoning params."""
    return bool(_REASONING_MODEL_RE.search(_model_slug(model_name)))


def effective_reasoning_effort(
    effort: ReasoningEffort,
    *,
    model_name: str,
    scan_mode: str = "deep",
) -> ReasoningEffort | None:
    """Resolve configured reasoning effort for a concrete model + scan mode."""
    if effort == "none":
        return None
    if not model_supports_reasoning(model_name):
        return None
    if scan_mode == "quick" and effort in ("high", "xhigh"):
        return "medium"
    if effort == "xhigh":
        return "high"
    if effort == "minimal":
        return "low"
    return effort

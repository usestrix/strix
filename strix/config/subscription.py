"""Shared helpers across model-subscription providers (ChatGPT/Codex and Grok).

Each provider module (:mod:`strix.config.codex`, :mod:`strix.config.grok`)
exposes the same small surface — ``subscription_model``, ``auth_mode``,
``is_authenticated`` — so callers that only care "is this run on a subscription,
and which provider?" can stay provider-agnostic.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from strix.config import codex, grok


if TYPE_CHECKING:
    from types import ModuleType


_PROVIDERS: tuple[ModuleType, ...] = (codex, grok)

# Human-facing provider names keyed by each module's ``PROVIDER`` constant.
_DISPLAY_NAMES: dict[str, str] = {codex.PROVIDER: "ChatGPT", grok.PROVIDER: "Grok"}

# Prefix LiteLLM keys each provider's model metadata under: ChatGPT models are
# mapped bare ("gpt-5.4"), xAI's only provider-qualified ("xai/grok-4").
_LITELLM_PREFIXES: dict[str, str] = {codex.PROVIDER: "", grok.PROVIDER: "xai/"}


def provider_for_model(model_name: str | None) -> ModuleType | None:
    """Return the subscription provider module that owns ``model_name``'s prefix,
    or None when the model isn't a subscription model."""
    for provider in _PROVIDERS:
        if provider.subscription_model(model_name):
            return provider
    return None


def auth_mode(model_name: str | None) -> str:
    return "subscription" if provider_for_model(model_name) is not None else "api_key"


def provider_label(model_name: str | None) -> str | None:
    """Human-facing name of the subscription provider for ``model_name`` (e.g.
    "ChatGPT" or "Grok"), or None when the model isn't a subscription model."""
    provider = provider_for_model(model_name)
    if provider is None:
        return None
    return _DISPLAY_NAMES.get(provider.PROVIDER)


def litellm_model_name(model_name: str | None) -> str | None:
    """``model_name`` rewritten to the name LiteLLM maps metadata under.

    Subscription prefixes are Strix routing labels LiteLLM never maps, so a
    lookup of "grok/grok-4" (or bare "grok-4") finds nothing. Non-subscription
    models are returned unchanged.
    """
    provider = provider_for_model(model_name)
    if provider is None:
        return model_name
    prefix = _LITELLM_PREFIXES.get(provider.PROVIDER, "")
    return f"{prefix}{provider.subscription_model(model_name)}"

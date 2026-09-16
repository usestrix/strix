"""Provider-agnostic view over the model-subscription sign-ins.

Two subscription backends exist: ChatGPT (:mod:`strix.config.codex`) and Claude
(:mod:`strix.config.claude`). Call sites that only care *whether* a run is on a
subscription — telemetry, cost reporting, environment validation — go through
here so neither provider is special-cased. Provider-specific wiring (which client
and model class to build) stays in :mod:`strix.config.models`.
"""

from __future__ import annotations

from strix.config import claude, codex


def subscription_model(model_name: str | None) -> str | None:
    """The model slug behind any subscription-prefixed STRIX_LLM, or None."""
    return codex.subscription_model(model_name) or claude.subscription_model(model_name)


def provider_name(model_name: str | None) -> str | None:
    """The provider key (``codex``/``claude``) a STRIX_LLM routes to, or None."""
    if codex.subscription_model(model_name):
        return codex.PROVIDER
    if claude.subscription_model(model_name):
        return claude.PROVIDER
    return None


def auth_mode(model_name: str | None) -> str:
    return "subscription" if subscription_model(model_name) else "api_key"


def is_authenticated(model_name: str | None) -> bool:
    """Whether the subscription this STRIX_LLM selects is signed in."""
    if codex.subscription_model(model_name):
        return codex.is_authenticated()
    if claude.subscription_model(model_name):
        return claude.is_authenticated()
    return False

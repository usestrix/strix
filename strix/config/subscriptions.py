"""Provider-agnostic helpers for model-subscription prefixes.

Each subscription provider (``codex`` for ChatGPT, ``mistral``) owns a module in
this package with the same interface (``read_record``, ``is_authenticated``,
``logout``, ...). ``SUBSCRIPTIONS`` registers each one with its CLI-facing
details, and ``subscription_for`` maps a ``STRIX_LLM`` value like
``chatgpt/gpt-5.4`` or ``lechat/mistral-large-latest`` to its provider and model
slug, so call sites don't hardcode one provider.

The prefix check must run before LiteLLM routing, so a subscription model never
reaches LiteLLM's provider map.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from strix.config import codex, mistral


class SubscriptionProvider(Protocol):
    """The interface each subscription provider module (codex, mistral) implements."""

    @property
    def PROVIDER(self) -> str: ...  # noqa: N802
    @property
    def SUBSCRIPTION_PREFIX(self) -> str: ...  # noqa: N802
    @property
    def CALLBACK_PATH(self) -> str: ...  # noqa: N802
    @property
    def CALLBACK_PORT(self) -> int: ...  # noqa: N802

    def generate_pkce(self) -> tuple[str, str]: ...
    def create_state(self) -> str: ...
    def build_authorize_url(self, challenge: str, state: str) -> str: ...
    def parse_redirect_input(self, value: str) -> tuple[str | None, str | None]: ...
    def exchange_code(self, code: str, verifier: str) -> dict[str, Any]: ...
    def save_record(self, record: dict[str, Any]) -> None: ...
    def read_record(self) -> dict[str, Any] | None: ...
    def is_authenticated(self) -> bool: ...
    def logout(self) -> None: ...


@dataclass(frozen=True)
class Subscription:
    module: SubscriptionProvider
    cli_name: str
    label: str
    plan: str
    example_model: str
    auth_error: type[Exception]

    @property
    def provider(self) -> str:
        return self.module.PROVIDER

    @property
    def prefix(self) -> str:
        return self.module.SUBSCRIPTION_PREFIX


CHATGPT = Subscription(
    module=codex,
    cli_name="chatgpt",
    label="ChatGPT",
    plan="ChatGPT Plus/Pro",
    example_model="chatgpt/gpt-5.4",
    auth_error=codex.CodexAuthError,
)
MISTRAL = Subscription(
    module=mistral,
    cli_name="mistral",
    label="Mistral",
    plan="Mistral",
    example_model="lechat/mistral-large-latest",
    auth_error=mistral.MistralAuthError,
)

# Display order for `strix auth status`; the first matching prefix wins.
SUBSCRIPTIONS: tuple[Subscription, ...] = (CHATGPT, MISTRAL)

# `strix auth login <name>` takes the CLI name or the internal provider name.
_BY_NAME: dict[str, Subscription] = {
    name: sub for sub in SUBSCRIPTIONS for name in (sub.cli_name, sub.provider)
}
ACCEPTED_NAMES: frozenset[str] = frozenset(_BY_NAME)

AUTH_ERRORS: tuple[type[Exception], ...] = tuple(sub.auth_error for sub in SUBSCRIPTIONS)


def by_name(name: str) -> Subscription | None:
    return _BY_NAME.get(name.lower())


def subscription_for(model_name: str | None) -> tuple[Subscription, str] | None:
    """``(subscription, slug)`` for a subscription ``STRIX_LLM``, or None.

    Only the prefix is stripped: ``lechat/mistral-large-latest`` has slug
    ``mistral-large-latest``.
    """
    name = (model_name or "").strip()
    lowered = name.lower()
    for sub in SUBSCRIPTIONS:
        if lowered.startswith(sub.prefix):
            slug = name[len(sub.prefix) :]
            return (sub, slug) if slug else None
    return None


def subscription_slug(model_name: str | None) -> str | None:
    """The bare model slug behind any subscription prefix, or None."""
    found = subscription_for(model_name)
    return found[1] if found else None


def auth_mode(model_name: str | None) -> str:
    return "subscription" if subscription_for(model_name) else "api_key"


def subscription_label(model_name: str | None) -> str:
    """Human label for the subscription a model runs on, e.g. 'Mistral subscription'."""
    found = subscription_for(model_name)
    return f"{found[0].label} subscription" if found else "subscription"

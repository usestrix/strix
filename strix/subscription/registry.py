"""Registry of subscription backends available through ``strix --sub``."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from strix.subscription.preflight import claude_preflight, codex_preflight


if TYPE_CHECKING:
    from collections.abc import Callable

    from rich.console import Console


@dataclass(frozen=True)
class SubscriptionBackend:
    """A subscription-backed LLM provider exposed through ``strix --sub``."""

    name: str
    default_model: str
    build_app: Callable[[], Any]
    preflight: Callable[[Console], None]


def _claude_app() -> Any:
    from strix.subscription.claude.server import app

    return app


def _codex_app() -> Any:
    from strix.subscription.codex.server import app

    return app


BACKENDS: dict[str, SubscriptionBackend] = {
    "claude": SubscriptionBackend(
        name="claude",
        default_model="anthropic/claude-sonnet-4-6",
        build_app=_claude_app,
        preflight=claude_preflight,
    ),
    "codex": SubscriptionBackend(
        name="codex",
        default_model="openai/gpt-5.4",
        build_app=_codex_app,
        preflight=codex_preflight,
    ),
}

SUB_CHOICES: list[str] = list(BACKENDS)

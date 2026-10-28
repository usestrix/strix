"""Execution-context and task isolation for Strix i18n."""

from __future__ import annotations

import contextvars


_current_language: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "strix_current_language",
    default=None,
)


def get_context_language() -> str | None:
    """Return the active language code bound to the current async context, or None."""
    return _current_language.get()


def set_context_language(lang: str | None) -> None:
    """Bind a normalized language code to the active async execution context."""
    _current_language.set(lang)


def reset_context_language() -> None:
    """Clear the active language code from the current async execution context."""
    _current_language.set(None)

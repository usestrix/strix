"""Robust Internationalization (i18n) Engine for Strix."""

from __future__ import annotations

from typing import Any

from strix.i18n.catalog import clear_locales_cache, get_available_languages
from strix.i18n.context import reset_context_language, set_context_language
from strix.i18n.detector import DEFAULT_LANGUAGE, detect_language, normalize_language
from strix.i18n.directive import LANGUAGE_NAMES, get_language_directive
from strix.i18n.translator import translate


t = translate


def set_language(lang: str | None) -> str:
    """Set language preference for the current async execution context."""
    normalized = normalize_language(lang)
    set_context_language(normalized)
    return normalized


def get_language() -> str:
    """Get active language preference or auto-detect from environment/config."""
    return detect_language()


def reset_language() -> None:
    """Reset the execution context language to default/unspecified."""
    reset_context_language()


def __getattr__(name: str) -> Any:
    if name == "SUPPORTED_LANGUAGES":
        return get_available_languages()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "DEFAULT_LANGUAGE",
    "LANGUAGE_NAMES",
    "clear_locales_cache",
    "get_available_languages",
    "get_language",
    "get_language_directive",
    "normalize_language",
    "reset_language",
    "set_language",
    "t",
    "translate",
]

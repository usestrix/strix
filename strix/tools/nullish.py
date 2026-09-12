"""Nullish argument values passed by models in place of omitting an argument.

Models frequently send the literal string ``"null"`` / ``"none"`` for an
optional filter argument instead of leaving it out. Taken at face value it is
a filter that matches nothing, so the call quietly returns no results.
"""

from __future__ import annotations


NULLISH_STRINGS = frozenset({"null", "none", "nil", "undefined"})


def is_nullish(value: object) -> bool:
    """Whether ``value`` is a string standing in for "no value"."""
    return isinstance(value, str) and value.strip().lower() in NULLISH_STRINGS


def clean_optional(value: str | None) -> str | None:
    """Normalize an optional filter argument: nullish or blank becomes ``None``."""
    if value is None or is_nullish(value):
        return None
    return value.strip() or None

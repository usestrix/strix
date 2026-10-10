"""Translation lookup, fallback resolution, and safe keyword interpolation."""

from __future__ import annotations

from typing import Any

from strix.i18n.catalog import load_locale
from strix.i18n.detector import DEFAULT_LANGUAGE, detect_language


def translate(key: str, **kwargs: Any) -> str:
    """Translate key into the active language with fallback and safe interpolation."""
    lang = detect_language()
    catalog = load_locale(lang)

    msg = catalog.get(key)
    if msg is None and lang != DEFAULT_LANGUAGE:
        msg = load_locale(DEFAULT_LANGUAGE).get(key)
    if msg is None:
        msg = key

    if kwargs and "{" in msg and "}" in msg:
        try:
            msg = msg.format(**kwargs)
        except (KeyError, ValueError, IndexError):
            for k, v in kwargs.items():
                msg = msg.replace(f"{{{k}}}", str(v))

    return msg

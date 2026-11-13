"""Locale catalogue discovery, validation, and thread-safe caching."""

from __future__ import annotations

import contextlib
import json
import logging
import threading
from pathlib import Path
from typing import Any

from strix.utils.resource_paths import get_strix_resource_path


logger = logging.getLogger(__name__)

_locales_lock = threading.RLock()
_locales_cache: dict[str, dict[str, str]] = {}


def get_builtin_locales_dir() -> Path:
    """Return the filesystem path to bundled locale catalogs."""
    return get_strix_resource_path("locales")


def get_user_locales_dir() -> Path:
    """Return the filesystem path to user-defined community locale catalogs."""
    return Path.home() / ".strix" / "locales"


def get_available_languages() -> set[str]:
    """Discover all available language codes across built-in and user directories."""
    languages: set[str] = {"en"}

    builtin_dir = get_builtin_locales_dir()
    if builtin_dir.is_dir():
        for path in builtin_dir.glob("*.json"):
            languages.add(path.stem.lower())

    user_dir = get_user_locales_dir()
    if user_dir.is_dir():
        for path in user_dir.glob("*.json"):
            languages.add(path.stem.lower())

    return languages


def _safe_merge(target: dict[str, str], source_data: Any) -> None:
    """Safely merge key-value translation strings from source into target."""
    if not isinstance(source_data, dict):
        return
    target.update(
        {k: v for k, v in source_data.items() if isinstance(k, str) and isinstance(v, str)}
    )


def load_locale(lang: str) -> dict[str, str]:
    """Load locale catalog JSON with thread-safe caching, type validation, and user overrides."""
    with _locales_lock:
        if lang in _locales_cache:
            return _locales_cache[lang]

    translations: dict[str, str] = {}

    # 1. Built-in locale catalog
    builtin_file = get_builtin_locales_dir() / f"{lang}.json"
    if builtin_file.is_file():
        with contextlib.suppress(OSError, json.JSONDecodeError):
            raw_data = json.loads(builtin_file.read_text(encoding="utf-8"))
            _safe_merge(translations, raw_data)

    # 2. User community override catalog (~/.strix/locales/{lang}.json)
    user_file = get_user_locales_dir() / f"{lang}.json"
    if user_file.is_file():
        with contextlib.suppress(OSError, json.JSONDecodeError):
            raw_data = json.loads(user_file.read_text(encoding="utf-8"))
            _safe_merge(translations, raw_data)

    with _locales_lock:
        _locales_cache[lang] = translations
        return translations


def clear_locales_cache() -> None:
    """Evict all cached locale catalogs (useful for testing or hot-reload)."""
    with _locales_lock:
        _locales_cache.clear()

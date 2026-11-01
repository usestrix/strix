"""Internationalization support for Strix."""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

from strix.utils.resource_paths import get_strix_resource_path


logger = logging.getLogger(__name__)

# Supported languages — add new ones here + create matching JSON file
SUPPORTED_LANGUAGES: frozenset[str] = frozenset({"en", "es"})

# Module-level state
_language: str | None = None
_config_path: Path | None = None
_locales: dict[str, dict[str, str]] = {}
_lock = threading.Lock()
_locales_dir: Path = get_strix_resource_path("locales")


def _read_config_language(config_path: Path) -> str | None:
    """Read ``STRIX_LANGUAGE`` from a CLI JSON config file, if present."""
    try:
        if not config_path.exists():
            return None
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    env_block = data.get("env", {}) if isinstance(data, dict) else {}
    if not isinstance(env_block, dict):
        return None
    for key, raw_val in env_block.items():
        if str(key).upper() == "STRIX_LANGUAGE" and isinstance(raw_val, str):
            config_lang = raw_val.strip().lower()
            if config_lang:
                return _normalize_lang(config_lang)
    return None


def _detect_language() -> str:
    """Resolve language from the priority chain.

    Priority:
    1. _language (set by --language CLI flag or set_language())
    2. STRIX_LANGUAGE env var
    3. Config file (--config override or ~/.strix/cli-config.json)
    4. LANG / LC_ALL / LC_MESSAGES system locale (first 2 chars)
    5. "en" default
    """
    # 1. Explicitly set (CLI flag)
    if _language is not None:
        return _language

    # 2. Environment variable (case-insensitive to match pydantic Settings)
    for env_key, env_raw in os.environ.items():
        if env_key.upper() == "STRIX_LANGUAGE" and env_raw.strip():
            return _normalize_lang(env_raw)

    # 3. Config file (canonical format: {"env": {"STRIX_LANGUAGE": "es"}})
    config_lang = _read_config_language(
        _config_path or (Path.home() / ".strix" / "cli-config.json")
    )
    if config_lang is not None:
        return config_lang

    # 4. System locale
    for var in ("LANG", "LC_ALL", "LC_MESSAGES"):
        locale_val = os.environ.get(var, "")
        if len(locale_val) >= 2:
            candidate = locale_val[:2].lower()
            if candidate in SUPPORTED_LANGUAGES:
                return candidate

    # 5. Default
    return "en"


def _normalize_lang(lang: str) -> str:
    """Normalize and validate a language code."""
    lang = lang.strip().lower()[:2]
    if lang not in SUPPORTED_LANGUAGES:
        logger.warning("Unsupported language %r, falling back to 'en'", lang)
        return "en"
    return lang


def _load_locale(lang: str) -> dict[str, str]:
    """Load a locale JSON file. Thread-safe, cached."""
    with _lock:
        if lang in _locales:
            return _locales[lang]

        locale_file = _locales_dir / f"{lang}.json"
        if not locale_file.exists():
            logger.warning("Locale file not found: %s", locale_file)
            _locales[lang] = {}
            return {}

        try:
            data = json.loads(locale_file.read_text(encoding="utf-8"))
            _locales[lang] = data if isinstance(data, dict) else {}
            return _locales[lang]
        except (json.JSONDecodeError, OSError):
            logger.exception("Failed to load locale %s", lang)
            _locales[lang] = {}
            return {}


def set_language(lang: str | None) -> None:
    """Set the active language. Called from CLI args parsing."""
    global _language  # noqa: PLW0603
    _language = _normalize_lang(lang) if lang else None


def set_config_path(path: str | Path | None) -> None:
    """Override the config file used for language resolution.

    ``--config`` selects a custom config file; its ``env.STRIX_LANGUAGE``
    should drive localization just like the default ``~/.strix/cli-config.json``.
    Pass ``None`` to clear the override.
    """
    global _config_path  # noqa: PLW0603
    _config_path = Path(path).expanduser() if path else None


def get_language() -> str:
    """Get the currently resolved language."""
    return _detect_language()


def t(key: str, **kwargs: Any) -> str:
    """Translate a key to the active language.

    Args:
        key: Dot-separated translation key (e.g., "cli.scan_started")
        **kwargs: Placeholder values for {name} interpolation

    Returns:
        Translated string with placeholders filled, or the key itself if not found.
    """
    lang = get_language()

    # Try active language first
    locale = _load_locale(lang)
    value = locale.get(key)

    # Fallback to English
    if value is None and lang != "en":
        en_locale = _load_locale("en")
        value = en_locale.get(key)
        if value is not None:
            logger.debug("Key %r not found in %s, using English fallback", key, lang)

    # Last resort: return the key itself
    if value is None:
        logger.warning("Translation key not found: %s", key)
        return key

    # Interpolate placeholders
    if kwargs:
        try:
            return value.format(**kwargs)
        except KeyError as exc:
            logger.warning("Missing placeholder %s in key %s", exc, key)
            return value

    return value


def get_language_directive() -> str:
    """Get the language directive for agent system prompts.

    Returns empty string for English (no directive needed).
    Returns an instruction block for other languages.
    """
    lang = get_language()
    if lang == "en":
        return ""

    lang_names = {
        "es": "Spanish",
        "fr": "French",
        "de": "German",
        "pt": "Portuguese",
        "it": "Italian",
    }
    lang_name = lang_names.get(lang, lang)

    return f"""LANGUAGE DIRECTIVE:
The user's preferred language is {lang_name}.
Write all natural-language findings, explanations, descriptions, impact assessments,
remediation steps, and recommendations in {lang_name}.

Keep the following UNCHANGED (do not translate):
- CVE identifiers (e.g., CVE-2025-XXXX)
- CWE identifiers (e.g., CWE-79)
- CVSS scores
- HTTP requests and headers
- URLs and domains
- Source code snippets
- Shell commands and payloads
- Technical product names
- File paths"""

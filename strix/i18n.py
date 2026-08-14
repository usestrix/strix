"""Robust Internationalization (i18n) Engine for Strix."""

from __future__ import annotations

import contextvars
import json
import os
from pathlib import Path
import threading
from typing import Any, Dict, Optional, Set

SUPPORTED_LANGUAGES: Set[str] = {"en", "es", "id"}
DEFAULT_LANGUAGE: str = "en"

# ContextVar for async execution & multi-tenant thread safety
_current_language: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "strix_current_language", default=None
)

_locales_lock = threading.Lock()
_locales_cache: Dict[str, Dict[str, str]] = {}


def _normalize_lang(lang: Optional[str]) -> str:
    """Normalize language tags (e.g. 'es_ES.UTF-8' -> 'es')."""
    if not lang:
        return DEFAULT_LANGUAGE
    clean = lang.strip().lower().split("_")[0].split("-")[0]
    return clean if clean in SUPPORTED_LANGUAGES else DEFAULT_LANGUAGE


def set_language(lang: Optional[str]) -> str:
    """Set language preference for the current async execution context."""
    normalized = _normalize_lang(lang)
    _current_language.set(normalized)
    return normalized


def get_language() -> str:
    """Get active language preference or auto-detect from environment/config."""
    lang = _current_language.get()
    if lang is not None:
        return lang
    return _detect_language()


def _detect_language() -> str:
    """Detect language via STRIX_LANGUAGE, config file, or system LANG."""
    env_lang = os.getenv("STRIX_LANGUAGE")
    if env_lang:
        return _normalize_lang(env_lang)

    try:
        cfg_path = Path.home() / ".strix" / "cli-config.json"
        if cfg_path.exists():
            data = json.loads(cfg_path.read_text(encoding="utf-8"))
            cfg_lang = data.get("env", {}).get("STRIX_LANGUAGE") or data.get("language")
            if cfg_lang:
                return _normalize_lang(cfg_lang)
    except Exception:
        pass

    sys_lang = os.getenv("LANG") or os.getenv("LC_ALL")
    if sys_lang:
        return _normalize_lang(sys_lang)

    return DEFAULT_LANGUAGE


def _load_locale(lang: str) -> Dict[str, str]:
    """Load locale JSON file with thread-safe caching and user overrides."""
    with _locales_lock:
        if lang in _locales_cache:
            return _locales_cache[lang]

    translations: Dict[str, str] = {}

    builtin_path = Path(__file__).parent / "locales" / f"{lang}.json"
    if builtin_path.exists():
        try:
            translations.update(json.loads(builtin_path.read_text(encoding="utf-8")))
        except Exception:
            pass

    user_path = Path.home() / ".strix" / "locales" / f"{lang}.json"
    if user_path.exists():
        try:
            translations.update(json.loads(user_path.read_text(encoding="utf-8")))
        except Exception:
            pass

    with _locales_lock:
        _locales_cache[lang] = translations
        return translations


def t(key: str, **kwargs: Any) -> str:
    """Translate key into active language with safe keyword interpolation."""
    lang = get_language()
    locale = _load_locale(lang)

    msg = locale.get(key)
    if msg is None and lang != DEFAULT_LANGUAGE:
        msg = _load_locale(DEFAULT_LANGUAGE).get(key)
    if msg is None:
        msg = key

    if kwargs and "{" in msg and "}" in msg:
        try:
            msg = msg.format(**kwargs)
        except (KeyError, ValueError, IndexError):
            for k, v in kwargs.items():
                msg = msg.replace(f"{{{k}}}", str(v))
    return msg


def get_language_directive() -> str:
    """Generate prompt directive for LLM agents when target language is non-English."""
    lang = get_language()
    if lang == "en":
        return ""

    lang_names = {
        "es": "Spanish",
        "id": "Indonesian",
    }
    target_name = lang_names.get(lang, lang.upper())

    return (
        f"IMPORTANT LANGUAGE INSTRUCTION:\n"
        f"Write all human-readable findings, executive summaries, descriptions, and remediation steps in {target_name}.\n"
        f"Do NOT translate technical identifiers, including CVE IDs, CWE IDs, CVSS scores, "
        f"source code snippets, file paths, or shell commands."
    )

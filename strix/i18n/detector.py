"""Language detection, normalization, and precedence policy."""

from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path

from strix.i18n.catalog import get_available_languages
from strix.i18n.context import get_context_language


DEFAULT_LANGUAGE: str = "en"


def normalize_language(lang: str | None, supported: set[str] | None = None) -> str:
    """Normalize language tag (e.g. 'es_ES.UTF-8' -> 'es') and validate.

    Checks against supported locales and returns DEFAULT_LANGUAGE if unrecognized.
    """
    if not lang:
        return DEFAULT_LANGUAGE

    clean = lang.strip().lower().split(".")[0].split("_")[0].split("-")[0]
    available = supported if supported is not None else get_available_languages()

    return clean if clean in available else DEFAULT_LANGUAGE


def detect_language() -> str:
    """Detect language following the canonical precedence chain:

    1. Active execution context (ContextVar)
    2. STRIX_LANGUAGE environment variable
    3. User CLI configuration file (~/.strix/cli-config.json)
    4. System locale (LC_ALL takes precedence over LANG)
    5. Default fallback language ('en')
    """
    ctx_lang = get_context_language()
    if ctx_lang:
        return ctx_lang

    # 1. Environment Variable STRIX_LANGUAGE
    env_lang = os.getenv("STRIX_LANGUAGE")
    if env_lang:
        return normalize_language(env_lang)

    # 2. Config File ~/.strix/cli-config.json
    cfg_path = Path.home() / ".strix" / "cli-config.json"
    if cfg_path.is_file():
        with contextlib.suppress(OSError, json.JSONDecodeError):
            data = json.loads(cfg_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                cfg_lang = data.get("env", {}).get("STRIX_LANGUAGE") or data.get("language")
                if isinstance(cfg_lang, str) and cfg_lang.strip():
                    return normalize_language(cfg_lang)

    # 3. System Locale (LC_ALL takes precedence over LANG)
    sys_lang = os.getenv("LC_ALL") or os.getenv("LANG")
    if sys_lang:
        return normalize_language(sys_lang)

    return DEFAULT_LANGUAGE

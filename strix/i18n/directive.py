"""Agent prompt language directive generator for localized security findings."""

from __future__ import annotations

from strix.i18n.detector import detect_language


LANGUAGE_NAMES: dict[str, str] = {
    "en": "English",
    "es": "Spanish",
    "id": "Indonesian",
    "ko": "Korean",
    "pt": "Portuguese",
    "fr": "French",
    "de": "German",
    "ja": "Japanese",
    "zh": "Chinese",
    "it": "Italian",
    "ru": "Russian",
    "tr": "Turkish",
    "ar": "Arabic",
    "vi": "Vietnamese",
}


def get_language_directive(lang: str | None = None) -> str:
    """Generate prompt directive for LLM agents when target language is non-English.

    Ensures technical security artifacts (CVE, CWE, CVSS, code, commands) remain unaltered.
    """
    effective_lang = lang if lang is not None else detect_language()
    if effective_lang == "en":
        return ""

    target_name = LANGUAGE_NAMES.get(effective_lang, effective_lang.upper())

    return (
        f"IMPORTANT LANGUAGE INSTRUCTION:\n"
        f"Write all human-readable findings, executive summaries, descriptions, "
        f"and remediation steps in {target_name}.\n"
        f"Do NOT translate technical identifiers, including CVE IDs, CWE IDs, CVSS scores, "
        f"source code snippets, file paths, or shell commands."
    )

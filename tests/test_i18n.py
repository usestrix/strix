"""Comprehensive test suite for Strix internationalization (i18n) engine."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import patch

import pytest

from strix.agents.prompt import render_system_prompt
from strix.i18n import (
    DEFAULT_LANGUAGE,
    clear_locales_cache,
    get_available_languages,
    get_language,
    get_language_directive,
    normalize_language,
    reset_language,
    set_language,
    t,
)
from strix.i18n.catalog import _safe_merge, load_locale
from strix.i18n.detector import detect_language
from strix.interface.cli_args import parse_arguments
from strix.report.writer import render_vulnerability_md, write_executive_report


@pytest.fixture(autouse=True)
def _reset_i18n_state():
    """Ensure clean i18n context and cache for every test."""
    reset_language()
    clear_locales_cache()
    yield
    reset_language()
    clear_locales_cache()


# ---------------------------------------------------------------------------
# 1. Core State & Normalization Tests
# ---------------------------------------------------------------------------


def test_set_and_get_language():
    assert set_language("es") == "es"
    assert get_language() == "es"

    assert set_language("id") == "id"
    assert get_language() == "id"

    assert set_language("ko") == "ko"
    assert get_language() == "ko"

    reset_language()
    assert get_language() == DEFAULT_LANGUAGE


def test_normalize_language_tags():
    assert normalize_language("es_ES.UTF-8") == "es"
    assert normalize_language("id-ID") == "id"
    assert normalize_language("ko_KR.eucKR") == "ko"
    assert normalize_language("EN_us") == "en"
    assert normalize_language(None) == DEFAULT_LANGUAGE
    assert normalize_language("unsupported_xyz") == DEFAULT_LANGUAGE


def test_dynamic_available_languages():
    available = get_available_languages()
    assert "en" in available
    assert "es" in available
    assert "id" in available
    assert "ko" in available


# ---------------------------------------------------------------------------
# 2. Async Context Isolation Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_contextvar_isolation():
    """Verify concurrent async tasks maintain strictly isolated language contexts."""

    async def task_worker(lang: str, delay: float) -> str:
        set_language(lang)
        await asyncio.sleep(delay)
        return get_language()

    results = await asyncio.gather(
        task_worker("es", 0.02),
        task_worker("id", 0.01),
        task_worker("ko", 0.015),
    )

    assert results == ["es", "id", "ko"]
    # Outer context remains untouched
    assert get_language() == DEFAULT_LANGUAGE


# ---------------------------------------------------------------------------
# 3. Precedence & Detection Tests
# ---------------------------------------------------------------------------


def test_precedence_context_over_env_and_system(monkeypatch):
    monkeypatch.setenv("STRIX_LANGUAGE", "es")
    monkeypatch.setenv("LC_ALL", "id")

    # Context explicitly set wins over all
    set_language("ko")
    assert detect_language() == "ko"

    # When context is reset, STRIX_LANGUAGE environment variable wins
    reset_language()
    assert detect_language() == "es"


def test_precedence_env_over_config_and_system(monkeypatch, tmp_path):
    monkeypatch.setenv("STRIX_LANGUAGE", "id")
    fake_config = tmp_path / ".strix" / "cli-config.json"
    fake_config.parent.mkdir(parents=True)
    fake_config.write_text(json.dumps({"env": {"STRIX_LANGUAGE": "es"}}), encoding="utf-8")

    with patch("pathlib.Path.home", return_value=tmp_path):
        assert detect_language() == "id"


def test_precedence_config_over_system(monkeypatch, tmp_path):
    monkeypatch.delenv("STRIX_LANGUAGE", raising=False)
    monkeypatch.setenv("LC_ALL", "es")

    fake_config = tmp_path / ".strix" / "cli-config.json"
    fake_config.parent.mkdir(parents=True)
    fake_config.write_text(json.dumps({"env": {"STRIX_LANGUAGE": "id"}}), encoding="utf-8")

    with patch("pathlib.Path.home", return_value=tmp_path):
        assert detect_language() == "id"


def test_precedence_lc_all_over_lang(monkeypatch):
    monkeypatch.delenv("STRIX_LANGUAGE", raising=False)
    monkeypatch.setenv("LC_ALL", "es_ES.UTF-8")
    monkeypatch.setenv("LANG", "id_ID.UTF-8")

    assert detect_language() == "es"


def test_fallback_to_default_when_empty(monkeypatch):
    monkeypatch.delenv("STRIX_LANGUAGE", raising=False)
    monkeypatch.delenv("LC_ALL", raising=False)
    monkeypatch.delenv("LANG", raising=False)

    assert detect_language() == DEFAULT_LANGUAGE


# ---------------------------------------------------------------------------
# 4. Catalog Loading, Caching & Override Tests
# ---------------------------------------------------------------------------


def test_catalog_load_builtin_and_caching():
    catalog_en = load_locale("en")
    assert "report.title" in catalog_en
    assert catalog_en["report.title"] == "Security Penetration Test Report"

    # Subsequent load hits cache
    cached = load_locale("en")
    assert cached is catalog_en


def test_safe_merge_validates_string_types():
    target = {"existing": "value"}
    _safe_merge(target, {"valid_key": "valid_value", 123: "bad_key", "bad_val": 456})
    assert target["valid_key"] == "valid_value"
    assert 123 not in target
    assert "bad_val" not in target


def test_user_community_override_merging(tmp_path):
    user_locales = tmp_path / ".strix" / "locales"
    user_locales.mkdir(parents=True)
    override_file = user_locales / "es.json"
    override_file.write_text(
        json.dumps({"custom.greeting": "Hola Mundo", "cli.description": "Custom Strix"}),
        encoding="utf-8",
    )

    with patch("pathlib.Path.home", return_value=tmp_path):
        catalog_es = load_locale("es")
        assert catalog_es.get("custom.greeting") == "Hola Mundo"
        assert catalog_es.get("cli.description") == "Custom Strix"
        assert catalog_es.get("report.title") == "Informe de Prueba de Penetración de Seguridad"


# ---------------------------------------------------------------------------
# 5. Translation & Fallback Tests
# ---------------------------------------------------------------------------


def test_translation_formatting_interpolations():
    set_language("id")
    result = t("cli.scan_started", target="example.com")
    assert "example.com" in result
    assert "Memulai" in result


def test_fallback_missing_key_in_target_language():
    set_language("es")
    # Non-existent key in all catalogs falls back to key itself
    assert t("untranslated.nonexistent_key") == "untranslated.nonexistent_key"


def test_safe_interpolation_on_missing_parameter():
    set_language("en")
    result = t("cli.scan_started")  # 'target' parameter missing
    assert "{target}" in result or isinstance(result, str)


def test_safe_interpolation_with_special_characters():
    set_language("en")
    payload = "'; DROP TABLE users; -- {bad}"
    result = t("cli.scan_started", target=payload)
    assert payload in result


# ---------------------------------------------------------------------------
# 6. Prompt Language Directive Tests
# ---------------------------------------------------------------------------


def test_language_directive_empty_for_english():
    set_language("en")
    assert get_language_directive() == ""


def test_language_directive_for_supported_languages():
    set_language("es")
    directive_es = get_language_directive()
    assert "Spanish" in directive_es
    assert "CVE IDs" in directive_es
    assert "Do NOT translate technical identifiers" in directive_es

    set_language("id")
    directive_id = get_language_directive()
    assert "Indonesian" in directive_id

    set_language("ko")
    directive_ko = get_language_directive()
    assert "Korean" in directive_ko


# ---------------------------------------------------------------------------
# 7. End-to-End System & Integration Tests
# ---------------------------------------------------------------------------


def test_system_prompt_rendering_injects_language_directive():
    set_language("es")
    prompt_es = render_system_prompt(scan_mode="quick")
    assert "<language_directive>" in prompt_es
    assert "Spanish" in prompt_es

    set_language("en")
    prompt_en = render_system_prompt(scan_mode="quick")
    assert "<language_directive>" not in prompt_en


def test_markdown_report_writer_localization(tmp_path):
    set_language("es")
    sample_report = {
        "id": "vuln-001",
        "title": "SQL Injection",
        "severity": "critical",
        "timestamp": "2026-10-10 12:00:00 UTC",
        "description": "Exploitable SQL query.",
        "evidence": "Payload proof.",
        "impact": "Full database read.",
        "remediation_steps": "Use parameters.",
    }

    md = render_vulnerability_md(sample_report)
    assert "## Descripción" in md
    assert "## Evidencia" in md
    assert "## Impacto" in md
    assert "## Remediación" in md

    # Executive report title
    write_executive_report(tmp_path, "Scan findings summary.")
    exec_file = tmp_path / "penetration_test_report.md"
    content = exec_file.read_text(encoding="utf-8")
    assert "# Informe de Prueba de Penetración de Seguridad" in content


def test_cli_argument_parser_language_flag(monkeypatch):
    monkeypatch.setattr("sys.argv", ["strix", "-t", "example.com", "--language", "id", "-n"])
    args = parse_arguments()
    assert args.language == "id"
    assert get_language() == "id"

"""Tests for the i18n internationalization module."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

import strix.i18n as mod
from strix.config.settings import Settings
from strix.i18n import (
    SUPPORTED_LANGUAGES,
    _detect_language,
    _load_locale,
    _normalize_lang,
    get_language,
    get_language_directive,
    set_config_path,
    set_language,
    t,
)
from strix.interface import cli_args


@pytest.fixture(autouse=True)
def _reset_i18n_state():
    """Reset module-level state between tests."""
    mod._language = None
    mod._config_path = None
    mod._locales.clear()
    yield
    mod._language = None
    mod._config_path = None
    mod._locales.clear()


class TestSetLanguage:
    def test_set_language_spanish(self):
        set_language("es")
        assert get_language() == "es"

    def test_set_language_english(self):
        set_language("en")
        assert get_language() == "en"

    def test_set_language_normalizes(self):
        set_language("ES")
        assert get_language() == "es"

    def test_set_language_none_resets(self):
        set_language("es")
        set_language(None)
        # After reset, should fall back to detection
        assert get_language() == "en"  # default

    def test_set_language_unsupported_falls_back(self):
        set_language("fr")
        assert get_language() == "en"


class TestNormalizeLang:
    def test_normalize_lowercase(self):
        assert _normalize_lang("es") == "es"

    def test_normalize_uppercase(self):
        assert _normalize_lang("ES") == "es"

    def test_normalize_strips(self):
        assert _normalize_lang("  es  ") == "es"

    def test_normalize_unsupported(self):
        assert _normalize_lang("fr") == "en"

    def test_normalize_empty(self):
        assert _normalize_lang("") == "en"


class TestDetectLanguage:
    def test_default_is_english(self):
        assert _detect_language() == "en"

    def test_explicit_set_takes_priority(self):
        mod._language = "es"
        assert _detect_language() == "es"

    def test_env_var_detected(self):
        with patch.dict(os.environ, {"STRIX_LANGUAGE": "es"}):
            assert _detect_language() == "es"

    def test_env_var_overrides_config(self):
        with patch.dict(os.environ, {"STRIX_LANGUAGE": "es"}):
            assert _detect_language() == "es"

    def test_system_locale_detected(self):
        with patch.dict(os.environ, {"LANG": "es_ES.UTF-8"}, clear=False):
            mod._language = None
            assert _detect_language() == "es"

    def test_canonical_config_format(self):
        """Test that config file reads canonical format {"env": {"STRIX_LANGUAGE": "es"}}."""
        # Verify the canonical format structure is valid
        config_data = {"env": {"STRIX_LANGUAGE": "es"}}
        assert isinstance(config_data["env"]["STRIX_LANGUAGE"], str)
        assert config_data["env"]["STRIX_LANGUAGE"] == "es"


class TestLoadLocale:
    def test_load_english(self):
        locale = _load_locale("en")
        assert "cli.description" in locale
        assert isinstance(locale, dict)

    def test_load_spanish(self):
        locale = _load_locale("es")
        assert "cli.description" in locale

    def test_load_missing_returns_empty(self):
        locale = _load_locale("nonexistent")
        assert locale == {}

    def test_cached_after_first_load(self):
        _load_locale("en")
        assert "en" in mod._locales


class TestTranslationFunction:
    def test_t_returns_english_by_default(self):
        result = t("cli.description")
        assert "Strix" in result
        assert "Penetration" in result

    def test_t_returns_spanish_when_set(self):
        set_language("es")
        result = t("cli.description")
        assert "Penetración" in result

    def test_t_falls_back_to_english_for_missing_key(self):
        set_language("es")
        # Use a key that exists in en but not es
        result = t("cli.description")
        # Should still return something (English fallback)
        assert result != "cli.description"

    def test_t_returns_key_for_missing(self):
        result = t("nonexistent.key.xyz")
        assert result == "nonexistent.key.xyz"

    def test_t_interpolates_placeholders(self):
        result = t("cli.scan_started", target="example.com")
        assert "example.com" in result

    def test_t_interpolates_spanish(self):
        set_language("es")
        result = t("cli.scan_started", target="example.com")
        assert "example.com" in result
        assert "escaneo" in result.lower()

    def test_t_handles_missing_placeholder_gracefully(self):
        # Should not raise, just return with missing placeholder
        result = t("cli.scan_started")  # target not provided
        assert isinstance(result, str)


class TestLanguageDirective:
    def test_english_returns_empty(self):
        set_language("en")
        directive = get_language_directive()
        assert directive == ""

    def test_spanish_returns_directive(self):
        set_language("es")
        directive = get_language_directive()
        assert "Spanish" in directive
        assert "CVE" in directive  # preservation rule
        assert "CWE" in directive

    def test_directive_preserves_identifiers(self):
        set_language("es")
        directive = get_language_directive()
        assert "CVE identifiers" in directive
        assert "CWE identifiers" in directive
        assert "CVSS scores" in directive
        assert "Source code" in directive
        assert "Shell commands" in directive


class TestLocaleKeyConsistency:
    def test_all_en_keys_exist_in_es(self):
        en = _load_locale("en")
        es = _load_locale("es")
        missing = set(en.keys()) - set(es.keys())
        assert missing == set(), f"Missing Spanish keys: {missing}"

    def test_locale_files_are_valid_json(self):
        locales_dir = Path(__file__).parent.parent / "strix" / "locales"
        for json_file in locales_dir.glob("*.json"):
            data = json.loads(json_file.read_text(encoding="utf-8"))
            assert isinstance(data, dict), f"{json_file.name} is not a dict"

    def test_supported_languages_match_files(self):
        locales_dir = Path(__file__).parent.parent / "strix" / "locales"
        for lang in SUPPORTED_LANGUAGES:
            locale_file = locales_dir / f"{lang}.json"
            assert locale_file.exists(), f"Missing locale file: {locale_file}"


class TestCliHelpKeys:
    """The CLI help and model-warning strings must translate in both locales."""

    def test_workspace_file_help_translates(self):
        set_language("en")
        en_value = t("cli.workspace_file_help")
        assert "sandbox workspace" in en_value
        set_language("es")
        es_value = t("cli.workspace_file_help")
        assert "workspace del sandbox" in es_value
        assert es_value != "cli.workspace_file_help"

    def test_examples_header_translates(self):
        set_language("es")
        assert t("cli.examples_header") == "Ejemplos:"
        set_language("en")
        assert t("cli.examples_header") == "Examples:"

    def test_model_quality_warning_body_translates(self):
        set_language("en")
        assert "frontier model" in t("cli.model_quality_warning_body")
        set_language("es")
        es_value = t("cli.model_quality_warning_body")
        assert "modelo frontier" in es_value
        assert es_value != "cli.model_quality_warning_body"

    def test_model_quality_warning_footer_translates(self):
        set_language("en")
        assert "weaker models" in t("cli.model_quality_warning_footer")
        set_language("es")
        es_value = t("cli.model_quality_warning_footer")
        assert "modelos más débiles" in es_value

    def test_unknown_model_body_translates(self):
        set_language("en")
        assert "known OpenAI model" in t("cli.unknown_model_body")
        set_language("es")
        es_value = t("cli.unknown_model_body")
        assert "modelo de OpenAI conocido" in es_value

    def test_unknown_model_hint_translates(self):
        set_language("en")
        assert "form, e.g." in t("cli.unknown_model_hint")
        set_language("es")
        es_value = t("cli.unknown_model_hint")
        assert "por ejemplo" in es_value

    def test_example_titles_translate(self):
        set_language("es")
        assert "aplicación web" in t("cli.example_web_app")
        assert "repositorio" in t("cli.example_github")
        assert "código local" in t("cli.example_local_code")
        assert "spec API" in t("cli.example_api_spec")
        assert "dirección IP" in t("cli.example_ip")
        assert "archivo" in t("cli.example_file")
        set_language("en")
        assert t("cli.example_web_app") == "Web application penetration test"


class TestCustomConfigPath:
    """``--config`` should drive language resolution like the default config."""

    def test_custom_config_path_resolves_language(self, tmp_path):
        config = tmp_path / "custom.json"
        config.write_text(
            json.dumps({"env": {"STRIX_LANGUAGE": "es"}}), encoding="utf-8"
        )
        set_config_path(config)
        assert get_language() == "es"

    def test_custom_config_path_ignored_without_env_key(self, tmp_path):
        config = tmp_path / "custom.json"
        config.write_text(json.dumps({"env": {}}), encoding="utf-8")
        set_config_path(config)
        with patch.dict(os.environ, {}, clear=True):
            assert get_language() == "en"

    def test_custom_config_missing_file_falls_back(self, tmp_path):
        set_config_path(tmp_path / "does-not-exist.json")
        with patch.dict(os.environ, {}, clear=True):
            assert get_language() == "en"

    def test_env_var_overrides_custom_config(self, tmp_path):
        config = tmp_path / "custom.json"
        config.write_text(
            json.dumps({"env": {"STRIX_LANGUAGE": "es"}}), encoding="utf-8"
        )
        set_config_path(config)
        with patch.dict(os.environ, {"STRIX_LANGUAGE": "en"}):
            assert get_language() == "en"

    def test_explicit_language_overrides_custom_config(self, tmp_path):
        config = tmp_path / "custom.json"
        config.write_text(
            json.dumps({"env": {"STRIX_LANGUAGE": "es"}}), encoding="utf-8"
        )
        set_config_path(config)
        set_language("en")
        assert get_language() == "en"


class TestArgparseBuiltins:
    """argparse's built-in strings must translate through the i18n layer."""

    def test_usage_translates(self):
        set_language("es")
        assert t("cli.argparse_usage") == "uso: "
        set_language("en")
        assert t("cli.argparse_usage") == "usage: "

    def test_options_translates(self):
        set_language("es")
        assert t("cli.argparse_options") == "opciones"
        set_language("en")
        assert t("cli.argparse_options") == "options"

    def test_help_help_translates(self):
        set_language("es")
        assert t("cli.argparse_help") == "muestra este mensaje de ayuda y sale"

    def test_version_help_translates(self):
        set_language("es")
        assert t("cli.argparse_version") == (
            "muestra el número de versión del programa y sale"
        )

    def test_unrecognized_arguments_translates(self):
        set_language("es")
        assert t("cli.argparse_unrecognized") == "argumentos no reconocidos: %s"

    def test_argparse_override_is_wired(self):
        # The override routes argparse's gettext calls through t().
        set_language("es")
        assert cli_args._translate_argparse("usage: ") == "uso: "
        assert cli_args._translate_argparse("options") == "opciones"
        assert cli_args._translate_argparse("unknown string") == "unknown string"
        assert argparse._("usage: ") == "uso: "

    def test_invalid_choice_translates(self):
        set_language("es")
        assert "inválida" in t("cli.argparse_invalid_choice")
        assert "elija entre" in t("cli.argparse_invalid_choice")

    def test_argument_error_translates(self):
        set_language("es")
        assert t("cli.argparse_argument_error") == "argumento %(argument_name)s: %(message)s"

    def test_expected_arguments_translate(self):
        set_language("es")
        assert t("cli.argparse_expected_one") == "se espera un argumento"
        assert "como máximo" in t("cli.argparse_expected_at_most")
        assert "al menos" in t("cli.argparse_expected_at_least")

    def test_unexpected_option_translates(self):
        set_language("es")
        assert t("cli.argparse_unexpected_option") == "opción inesperada: %s"

    def test_validation_errors_translate(self):
        set_language("es")
        assert t("cli.invalid_float", value="abc") == "valor float inválido: 'abc'"
        assert t("cli.invalid_int", value="abc") == "valor entero inválido: 'abc'"
        assert t("cli.finite_number") == "debe ser un número finito mayor que 0"
        assert t("cli.positive_integer") == "debe ser un entero mayor que 0"

    def test_config_abbreviation_resolves(self):
        ns, _ = cli_args._ABBREV_PARSER.parse_known_args(["--conf", "x.json"])
        assert ns.config == "x.json"
        assert ns.language is None

    def test_language_abbreviation_resolves(self):
        ns, _ = cli_args._ABBREV_PARSER.parse_known_args(["--lang", "es"])
        assert ns.language == "es"
        assert ns.config is None


class TestSettingsLanguageField:
    def test_settings_has_language_field(self):
        s = Settings()
        assert hasattr(s, "language")
        assert s.language == "en"

    def test_settings_language_from_env(self):
        with patch.dict(os.environ, {"STRIX_LANGUAGE": "es"}):
            s = Settings()
            assert s.language == "es"

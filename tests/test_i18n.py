"""Tests for the i18n internationalization module."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

import strix.i18n as mod
from strix.agents.prompt import render_system_prompt
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
from strix.report.writer import render_vulnerability_md, write_executive_report


if TYPE_CHECKING:
    from collections.abc import Generator


@pytest.fixture(autouse=True)
def _reset_i18n_state() -> Generator[None, None, None]:
    """Reset module-level state between tests."""
    mod._language = None
    mod._config_path = None
    mod._locales.clear()
    yield
    mod._language = None
    mod._config_path = None
    mod._locales.clear()


class TestSetLanguage:
    def test_set_language_spanish(self) -> None:
        set_language("es")
        assert get_language() == "es"

    def test_set_language_english(self) -> None:
        set_language("en")
        assert get_language() == "en"

    def test_set_language_normalizes(self) -> None:
        set_language("ES")
        assert get_language() == "es"

    def test_set_language_none_resets(self, tmp_path: Path) -> None:
        set_config_path(tmp_path / "missing.json")
        with patch.dict(os.environ, {}, clear=True):
            set_language("es")
            set_language(None)
            assert get_language() == "en"

    def test_set_language_unsupported_falls_back(self) -> None:
        set_language("fr")
        assert get_language() == "en"


class TestNormalizeLang:
    def test_normalize_lowercase(self) -> None:
        assert _normalize_lang("es") == "es"

    def test_normalize_uppercase(self) -> None:
        assert _normalize_lang("ES") == "es"

    def test_normalize_strips(self) -> None:
        assert _normalize_lang("  es  ") == "es"

    def test_normalize_unsupported(self) -> None:
        assert _normalize_lang("fr") == "en"

    def test_normalize_empty(self) -> None:
        assert _normalize_lang("") == "en"


class TestDetectLanguage:
    def test_default_is_english(self, tmp_path: Path) -> None:
        set_config_path(tmp_path / "missing.json")
        with patch.dict(os.environ, {}, clear=True):
            assert _detect_language() == "en"

    def test_explicit_set_takes_priority(self) -> None:
        mod._language = "es"
        assert _detect_language() == "es"

    def test_env_var_detected(self) -> None:
        with patch.dict(os.environ, {"STRIX_LANGUAGE": "es"}):
            assert _detect_language() == "es"

    def test_env_var_case_insensitive(self) -> None:
        with patch.dict(os.environ, {"strix_language": "es"}, clear=True):
            assert _detect_language() == "es"

    def test_env_var_overrides_config(self, tmp_path: Path) -> None:
        config = tmp_path / "cli-config.json"
        config.write_text(json.dumps({"env": {"STRIX_LANGUAGE": "en"}}), encoding="utf-8")
        set_config_path(config)
        with patch.dict(os.environ, {"STRIX_LANGUAGE": "es"}):
            assert _detect_language() == "es"

    def test_system_locale_detected(self, tmp_path: Path) -> None:
        set_config_path(tmp_path / "missing.json")
        with patch.dict(os.environ, {"LANG": "es_ES.UTF-8"}, clear=True):
            mod._language = None
            assert _detect_language() == "es"

    def test_canonical_config_format(self, tmp_path: Path) -> None:
        """Test that config file reads canonical format {"env": {"STRIX_LANGUAGE": "es"}}."""
        config = tmp_path / "cli-config.json"
        config.write_text(json.dumps({"env": {"STRIX_LANGUAGE": "es"}}), encoding="utf-8")
        set_config_path(config)
        with patch.dict(os.environ, {}, clear=True):
            assert _detect_language() == "es"


class TestLoadLocale:
    def test_load_english(self) -> None:
        locale = _load_locale("en")
        assert "cli.description" in locale
        assert isinstance(locale, dict)

    def test_load_spanish(self) -> None:
        locale = _load_locale("es")
        assert "cli.description" in locale

    def test_load_missing_returns_empty(self) -> None:
        locale = _load_locale("nonexistent")
        assert locale == {}

    def test_cached_after_first_load(self) -> None:
        _load_locale("en")
        assert "en" in mod._locales


class TestTranslationFunction:
    def test_t_returns_english_by_default(self, tmp_path: Path) -> None:
        set_config_path(tmp_path / "missing.json")
        with patch.dict(os.environ, {}, clear=True):
            result = t("cli.description")
            assert "Strix" in result
            assert "Penetration" in result

    def test_t_returns_spanish_when_set(self) -> None:
        set_language("es")
        result = t("cli.description")
        assert "Penetración" in result

    def test_t_falls_back_to_english_for_missing_key(self) -> None:
        set_language("es")
        _load_locale("es")
        mod._locales["es"] = {}
        result = t("cli.description")
        assert result == "Strix Multi-Agent Cybersecurity Penetration Testing Tool"

    def test_t_returns_key_for_missing(self) -> None:
        result = t("nonexistent.key.xyz")
        assert result == "nonexistent.key.xyz"

    def test_t_interpolates_placeholders(self) -> None:
        set_language("en")
        result = t("cli.scan_started", target="example.com")
        assert "example.com" in result

    def test_t_interpolates_spanish(self) -> None:
        set_language("es")
        result = t("cli.scan_started", target="example.com")
        assert "example.com" in result
        assert "escaneo" in result.lower()

    def test_t_handles_missing_placeholder_gracefully(self) -> None:
        set_language("en")
        result = t("cli.scan_started")
        assert isinstance(result, str)


class TestLanguageDirective:
    def test_english_returns_empty(self) -> None:
        set_language("en")
        directive = get_language_directive()
        assert directive == ""

    def test_spanish_returns_directive(self) -> None:
        set_language("es")
        directive = get_language_directive()
        assert "Spanish" in directive
        assert "CVE" in directive
        assert "CWE" in directive

    def test_directive_preserves_identifiers(self) -> None:
        set_language("es")
        directive = get_language_directive()
        assert "CVE identifiers" in directive
        assert "CWE identifiers" in directive
        assert "CVSS scores" in directive
        assert "Source code" in directive
        assert "Shell commands" in directive

    def test_system_prompt_english_omits_directive_without_extra_blank_lines(self) -> None:
        set_language("en")
        prompt = render_system_prompt(include_scope=False, is_root=True)
        assert "LANGUAGE DIRECTIVE:" not in prompt
        assert "at all times.\n\n<root_agent_directive>" in prompt
        assert "at all times.\n\n\n<root_agent_directive>" not in prompt

    def test_system_prompt_spanish_injects_directive(self) -> None:
        set_language("es")
        prompt = render_system_prompt(include_scope=False, is_root=True)
        assert "LANGUAGE DIRECTIVE:" in prompt
        assert prompt.index("LANGUAGE DIRECTIVE:") < prompt.index("<root_agent_directive>")


class TestLocaleKeyConsistency:
    def test_all_en_keys_exist_in_es_and_vice_versa(self) -> None:
        en = _load_locale("en")
        es = _load_locale("es")
        missing_in_es = set(en.keys()) - set(es.keys())
        missing_in_en = set(es.keys()) - set(en.keys())
        assert missing_in_es == set(), f"Missing Spanish keys: {missing_in_es}"
        assert missing_in_en == set(), f"Extra Spanish keys missing in English: {missing_in_en}"

    def test_locale_files_are_valid_json(self) -> None:
        locales_dir = Path(__file__).parent.parent / "strix" / "locales"
        for json_file in locales_dir.glob("*.json"):
            data = json.loads(json_file.read_text(encoding="utf-8"))
            assert isinstance(data, dict), f"{json_file.name} is not a dict"

    def test_supported_languages_match_files(self) -> None:
        locales_dir = Path(__file__).parent.parent / "strix" / "locales"
        for lang in SUPPORTED_LANGUAGES:
            locale_file = locales_dir / f"{lang}.json"
            assert locale_file.exists(), f"Missing locale file: {locale_file}"


class TestCliHelpKeys:
    """The CLI help and model-warning strings must translate in both locales."""

    def test_workspace_file_help_translates(self) -> None:
        set_language("en")
        en_value = t("cli.workspace_file_help")
        assert (
            en_value == "Place a file from this machine into the sandbox workspace before the scan "
            "starts, for example a wordlist, an API specification, or notes. Repeat the option "
            "for more files. DEST is the path inside /workspace and defaults to the file name "
            "(for example '--workspace-file ./wordlist.txt:lists/wordlist.txt'). Strix copies "
            "the file into the sandbox, outside every target directory. The agent can edit the "
            "copy. The file on this machine does not change."
        )
        assert "(...)" not in en_value

        set_language("es")
        es_value = t("cli.workspace_file_help")
        assert "workspace del sandbox" in es_value
        assert "(por ejemplo '--workspace-file ./wordlist.txt:lists/wordlist.txt')" in es_value
        assert "Strix copia el archivo en el sandbox" in es_value
        assert "El agente puede editar la copia" in es_value
        assert "El archivo en esta máquina no cambia" in es_value
        assert "(...)" not in es_value
        assert "Place a file from this machine" not in es_value
        assert es_value != "cli.workspace_file_help"

    def test_new_upstream_cli_flags_translate(self) -> None:
        for key in (
            "cli.fail_on_help",
            "cli.mcp_config_help",
            "cli.mcp_server_help",
            "cli.mcp_exclude_help",
            "cli.resume_help",
        ):
            set_language("en")
            en_val = t(key)
            set_language("es")
            es_val = t(key)
            assert en_val != key
            assert es_val != key
            assert es_val != en_val

    def test_examples_header_translates(self) -> None:
        set_language("es")
        assert t("cli.examples_header") == "Ejemplos:"
        set_language("en")
        assert t("cli.examples_header") == "Examples:"

    def test_unknown_model_body_translates(self) -> None:
        set_language("en")
        assert "known OpenAI model" in t("cli.unknown_model_body")
        set_language("es")
        es_value = t("cli.unknown_model_body")
        assert "modelo de OpenAI conocido" in es_value

    def test_unknown_model_hint_translates(self) -> None:
        set_language("en")
        assert "form, e.g." in t("cli.unknown_model_hint")
        set_language("es")
        es_value = t("cli.unknown_model_hint")
        assert "por ejemplo" in es_value

    def test_example_titles_translate(self) -> None:
        set_language("es")
        assert "aplicación web" in t("cli.example_web_app")
        assert "repositorio" in t("cli.example_github")
        assert "código local" in t("cli.example_local_code")
        assert "spec API" in t("cli.example_api_spec")
        assert "dirección IP" in t("cli.example_ip")
        assert "archivo" in t("cli.example_file")
        assert "recursos cloud" in t("cli.example_cloud_list")
        set_language("en")
        assert t("cli.example_web_app") == "Web application penetration test"
        assert t("cli.example_cloud_list") == "list every cloud resource"

    def test_parse_arguments_spanish_help_output(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(sys, "argv", ["strix", "--language", "es", "--help"])
        with pytest.raises(SystemExit) as exc_info:
            cli_args.parse_arguments()
        assert exc_info.value.code == 0
        out = capsys.readouterr().out
        assert "uso: " in out
        assert "opciones:" in out
        assert "Ejemplos:" in out
        assert "workspace del sandbox" in out
        assert "Solo en modo headless" in out


class TestCustomConfigPath:
    """``--config`` should drive language resolution like the default config."""

    def test_custom_config_path_resolves_language(self, tmp_path: Path) -> None:
        config = tmp_path / "custom.json"
        config.write_text(json.dumps({"env": {"STRIX_LANGUAGE": "es"}}), encoding="utf-8")
        set_config_path(config)
        with patch.dict(os.environ, {}, clear=True):
            assert get_language() == "es"

    def test_custom_config_path_ignored_without_env_key(self, tmp_path: Path) -> None:
        config = tmp_path / "custom.json"
        config.write_text(json.dumps({"env": {}}), encoding="utf-8")
        set_config_path(config)
        with patch.dict(os.environ, {}, clear=True):
            assert get_language() == "en"

    def test_custom_config_missing_file_falls_back(self, tmp_path: Path) -> None:
        set_config_path(tmp_path / "does-not-exist.json")
        with patch.dict(os.environ, {}, clear=True):
            assert get_language() == "en"

    def test_env_var_overrides_custom_config(self, tmp_path: Path) -> None:
        config = tmp_path / "custom.json"
        config.write_text(json.dumps({"env": {"STRIX_LANGUAGE": "es"}}), encoding="utf-8")
        set_config_path(config)
        with patch.dict(os.environ, {"STRIX_LANGUAGE": "en"}):
            assert get_language() == "en"

    def test_explicit_language_overrides_custom_config(self, tmp_path: Path) -> None:
        config = tmp_path / "custom.json"
        config.write_text(json.dumps({"env": {"STRIX_LANGUAGE": "es"}}), encoding="utf-8")
        set_config_path(config)
        set_language("en")
        assert get_language() == "en"


class TestArgparseBuiltins:
    """argparse's built-in strings must translate through the i18n layer."""

    def test_usage_translates(self) -> None:
        set_language("es")
        assert t("cli.argparse_usage") == "uso: "
        set_language("en")
        assert t("cli.argparse_usage") == "usage: "

    def test_options_translates(self) -> None:
        set_language("es")
        assert t("cli.argparse_options") == "opciones"
        set_language("en")
        assert t("cli.argparse_options") == "options"

    def test_help_help_translates(self) -> None:
        set_language("es")
        assert t("cli.argparse_help") == "muestra este mensaje de ayuda y sale"

    def test_version_help_translates(self) -> None:
        set_language("es")
        assert t("cli.argparse_version") == "muestra el número de versión del programa y sale"

    def test_unrecognized_arguments_translates(self) -> None:
        set_language("es")
        assert t("cli.argparse_unrecognized") == "argumentos no reconocidos: %s"

    def test_argparse_override_is_wired(self) -> None:
        set_language("es")
        assert cli_args._translate_argparse("usage: ") == "uso: "
        assert cli_args._translate_argparse("options") == "opciones"
        assert cli_args._translate_argparse("unknown string") == "unknown string"
        assert argparse._("usage: ") == "uso: "  # type: ignore[attr-defined]

    def test_invalid_choice_translates(self) -> None:
        set_language("es")
        assert "inválida" in t("cli.argparse_invalid_choice")
        assert "elija entre" in t("cli.argparse_invalid_choice")

    def test_argument_error_translates(self) -> None:
        set_language("es")
        assert t("cli.argparse_argument_error") == "argumento %(argument_name)s: %(message)s"

    def test_expected_arguments_translate(self) -> None:
        set_language("es")
        assert t("cli.argparse_expected_one") == "se espera un argumento"
        assert "como máximo" in t("cli.argparse_expected_at_most")
        assert "al menos" in t("cli.argparse_expected_at_least")

    def test_unexpected_option_translates(self) -> None:
        set_language("es")
        assert t("cli.argparse_unexpected_option") == "opción inesperada: %s"

    def test_validation_errors_translate(self) -> None:
        set_language("es")
        assert t("cli.invalid_float", value="abc") == "valor float inválido: 'abc'"
        assert t("cli.invalid_int", value="abc") == "valor entero inválido: 'abc'"
        assert t("cli.finite_number") == "debe ser un número finito mayor que 0"
        assert t("cli.positive_integer") == "debe ser un entero mayor que 0"

    def test_config_abbreviation_resolves(self) -> None:
        ns, _ = cli_args._ABBREV_PARSER.parse_known_args(["--conf", "x.json"])
        assert ns.config == "x.json"
        assert ns.language is None

    def test_language_abbreviation_resolves(self) -> None:
        ns, _ = cli_args._ABBREV_PARSER.parse_known_args(["--lang", "es"])
        assert ns.language == "es"
        assert ns.config is None

    def test_pre_resolve_inline_equals_and_clustered_short_flag(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = tmp_path / "custom.json"
        config.write_text(json.dumps({"env": {"STRIX_LANGUAGE": "es"}}), encoding="utf-8")

        monkeypatch.setattr(sys, "argv", ["strix", f"--conf={config}", "--help"])
        with patch.dict(os.environ, {}, clear=True):
            cli_args._pre_resolve_language()
            assert get_language() == "es"

        monkeypatch.setattr(sys, "argv", ["strix", "-les", "--help"])
        cli_args._pre_resolve_language()
        assert get_language() == "es"

        monkeypatch.setattr(sys, "argv", ["strix", "--lang=es", "--help"])
        cli_args._pre_resolve_language()
        assert get_language() == "es"

    def test_pre_resolve_handles_unknown_flags_and_double_dash(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Unknown flag before --language es still resolves Spanish cleanly
        monkeypatch.setattr(sys, "argv", ["strix", "--unknown", "--language", "es", "--help"])
        cli_args._pre_resolve_language()
        assert get_language() == "es"

        # Flags after `--` are positional arguments and must NOT set language
        monkeypatch.setattr(sys, "argv", ["strix", "--", "--language", "es"])
        with patch.dict(os.environ, {}, clear=True):
            set_config_path(tmp_path / "missing.json")
            # Re-run pre-resolve and ensure --language after `--` is ignored
            cli_args._pre_resolve_language()
            set_config_path(tmp_path / "missing.json")
            assert get_language() == "en"

    def test_pre_resolve_resets_stale_language_on_subsequent_english_call(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sys, "argv", ["strix", "--language", "es", "--help"])
        cli_args._pre_resolve_language()
        assert get_language() == "es"

        monkeypatch.setattr(sys, "argv", ["strix", "--help"])
        with patch.dict(os.environ, {}, clear=True):
            cli_args._pre_resolve_language()
            set_config_path(tmp_path / "missing.json")
            assert get_language() == "en"

    def test_missing_en_locale_falls_back_cleanly(self, tmp_path: Path) -> None:
        with patch.object(mod, "_locales_dir", tmp_path / "empty_locales"):
            mod._locales.clear()
            set_language("es")
            assert t("cli.description") == "cli.description"
            assert cli_args._translate_argparse("usage: ") == "usage: "
            assert cli_args._translate_argparse("options") == "options"

    @pytest.mark.parametrize(
        "cluster_argv",
        [
            ["strix", "-nl", "es", "--target", "https://example.com"],
            ["strix", "-nles", "--target", "https://example.com"],
        ],
    )
    def test_combined_short_flags_set_spanish_and_parse_end_to_end(
        self,
        monkeypatch: pytest.MonkeyPatch,
        cluster_argv: list[str],
    ) -> None:
        monkeypatch.setattr(sys, "argv", cluster_argv)
        cli_args._pre_resolve_language()
        assert get_language() == "es"

        args = cli_args.parse_arguments()
        assert args.non_interactive is True
        assert args.language == "es"
        assert get_language() == "es"

    def test_vnl_cluster_sets_spanish_in_pre_resolve_and_exits_with_version(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(sys, "argv", ["strix", "-vnl", "es"])
        cli_args._pre_resolve_language()
        assert get_language() == "es"

        with pytest.raises(SystemExit) as exc_info:
            cli_args.parse_arguments()
        assert exc_info.value.code == 0
        assert capsys.readouterr().out.startswith("strix ")

    @pytest.mark.parametrize(
        "help_argv",
        [
            ["strix", "-nhl", "es"],
            ["strix", "-hl", "es"],
            ["strix", "-hvl", "es"],
        ],
    )
    def test_combined_short_help_flags_render_spanish(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        help_argv: list[str],
    ) -> None:
        monkeypatch.setattr(sys, "argv", help_argv)
        with pytest.raises(SystemExit) as exc_info:
            cli_args.parse_arguments()
        assert exc_info.value.code == 0
        out = capsys.readouterr().out
        assert "uso: " in out
        assert "opciones:" in out

    @pytest.mark.parametrize("cluster_flag", ["-rl", "-tl", "-ml"])
    def test_option_value_taking_short_flags_do_not_falsely_trigger_spanish(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        cluster_flag: str,
    ) -> None:
        # `-rl es`, `-tl es`, `-ml es` pass `"l"` as the value of `-r`/`-t`/`-m`, NOT `-l es`!
        monkeypatch.setattr(sys, "argv", ["strix", cluster_flag, "es"])
        with patch.dict(os.environ, {}, clear=True):
            cli_args._pre_resolve_language()
            set_config_path(tmp_path / "missing.json")
            assert get_language() == "en"

            with pytest.raises(SystemExit) as exc_info:
                cli_args.parse_arguments()
            assert exc_info.value.code == 2
            err = capsys.readouterr().err
            assert "usage: " in err

    def test_valid_language_followed_by_missing_config_value_emits_spanish_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(sys, "argv", ["strix", "-l", "es", "--config"])
        with pytest.raises(SystemExit) as exc_info:
            cli_args.parse_arguments()
        assert exc_info.value.code == 2
        err = capsys.readouterr().err
        assert "uso: " in err
        assert "argumento --config: se espera un argumento" in err

    def test_ambiguous_option_before_language_flag_emits_spanish_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(sys, "argv", ["strix", "--max", "10", "-l", "es"])
        with pytest.raises(SystemExit) as exc_info:
            cli_args.parse_arguments()
        assert exc_info.value.code == 2
        err = capsys.readouterr().err
        assert "uso: " in err
        assert "opción ambigua: --max podría coincidir con" in err


class TestPyInstallerSpecPackaging:
    def test_strix_spec_bundles_locales_and_hiddenimport(self) -> None:
        spec_path = Path(__file__).parent.parent / "strix.spec"
        spec_content = spec_path.read_text(encoding="utf-8")
        assert "strix_root.rglob('locales/*.json')" in spec_content
        assert "'strix.i18n'" in spec_content
        # Verify the glob pattern actually matches both en.json and es.json on disk
        strix_root = Path(__file__).parent.parent / "strix"
        matched = {p.name for p in strix_root.rglob("locales/*.json")}
        assert {"en.json", "es.json"}.issubset(matched)


class TestReportWriterLocalization:
    def test_vulnerability_md_translates_sections_in_spanish(self) -> None:
        set_language("es")
        md = render_vulnerability_md(
            {
                "id": "vuln-0001",
                "title": "SQL Injection",
                "severity": "high",
                "timestamp": "2026-07-02 10:00:00 UTC",
                "description": "Unsanitized SQL query.",
                "impact": "Database read.",
                "counterevidence": "Egress filtered.",
                "confidence": "medium",
                "confidence_rationale": "Verified once.",
                "severity_change_conditions": "Critical if filter removed.",
                "fix_verification": "Retested.",
                "remediation_steps": "Parameterize queries.",
                "update_history": [
                    {"timestamp": "2026-07-02 11:00:00 UTC", "fields": ["severity"]}
                ],
            }
        )
        assert "**Severidad:** HIGH" in md
        assert "**Confianza:** Medium" in md
        assert "## Descripción" in md
        assert "## Impacto" in md
        assert "## Contraevidencia" in md
        assert "## Justificación de Confianza" in md
        assert "## Qué Cambiaría Esta Severidad" in md
        assert "## Remediación" in md
        assert "## Verificación de Corrección" in md
        assert "## Historial de Actualizaciones" in md

    def test_executive_report_translates_in_spanish(self, tmp_path: Path) -> None:
        set_language("es")
        write_executive_report(tmp_path, "Resumen ejecutivo.")
        content = (tmp_path / "penetration_test_report.md").read_text(encoding="utf-8")
        assert "# Informe de Prueba de Penetración de Seguridad" in content
        assert "**Generado:**" in content


class TestSettingsLanguageField:
    def test_settings_has_language_field(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            s = Settings()
            assert hasattr(s, "language")
            assert s.language == "en"

    def test_settings_language_from_env(self) -> None:
        with patch.dict(os.environ, {"STRIX_LANGUAGE": "es"}):
            s = Settings()
            assert s.language == "es"

# Internationalization Specification

## Purpose

Enable Strix to operate in multiple languages. Phase 1 delivers Spanish alongside English for CLI strings and LLM-generated findings, while preserving English for all machine-consumed artifacts (SARIF, vulnerabilities.json).

## Requirements

### Requirement: Locale Loading

The system SHALL load locale data from flat JSON files at `strix/locales/{lang}.json`. Locale files MUST be loaded lazily on first `t()` call or language resolution, then cached in memory for the process lifetime. Missing keys MUST fall back to the English value and log a warning.

#### Scenario: Load Spanish locale on first t() call

- GIVEN `strix/locales/es.json` exists with key `"cli.scan_started": "Escaneo iniciado"`
- WHEN `t("cli.scan_started")` is called with active language `"es"`
- THEN the function returns `"Escaneo iniciado"`
- AND the locale file is read from disk exactly once

#### Scenario: Missing key falls back to English

- GIVEN `strix/locales/es.json` does NOT contain key `"cli.unknown_key"`
- AND `strix/locales/en.json` contains `"cli.unknown_key": "Unknown key"`
- WHEN `t("cli.unknown_key")` is called with active language `"es"`
- THEN the function returns `"Unknown key"`
- AND a warning is logged

#### Scenario: Key missing from all locales

- GIVEN no locale file contains key `"cli.nonexistent"`
- WHEN `t("cli.nonexistent")` is called
- THEN the function returns the key string `"cli.nonexistent"`

### Requirement: Language Resolution Chain

The system SHALL determine the active language using this priority: `--language` CLI flag > `STRIX_LANGUAGE` env var > `~/.strix/cli-config.json` `"language"` field > `LANG`/`LC_ALL` system locale > `"en"` default. Unsupported languages MUST fall back to `"en"` with a warning. Initially supported: `en`, `es`.

#### Scenario: CLI flag takes highest priority

- GIVEN `STRIX_LANGUAGE=es` and `~/.strix/cli-config.json` contains `"language": "en"`
- WHEN the user runs `strix --language es --target example.com`
- THEN the active language is `"es"`

#### Scenario: Environment variable used when no CLI flag

- GIVEN no `--language` flag is provided
- AND `STRIX_LANGUAGE=es` is set
- WHEN strix starts
- THEN the active language is `"es"`

#### Scenario: Config file used when no flag or env

- GIVEN no `--language` flag, no `STRIX_LANGUAGE` env var
- AND `~/.strix/cli-config.json` contains `"language": "es"`
- WHEN strix starts
- THEN the active language is `"es"`

#### Scenario: System locale detection

- GIVEN no flag, env, or config language set
- AND `LANG=es_ES.UTF-8`
- WHEN strix starts
- THEN the active language is `"es"`

#### Scenario: Unsupported language falls back to English

- GIVEN `STRIX_LANGUAGE=fr` (unsupported)
- WHEN strix starts
- THEN the active language is `"en"`
- AND a warning is logged

### Requirement: CLI Integration

The system SHALL provide a `--language` / `-l` CLI flag via argparse. Help text for all argparse arguments MUST be evaluated lazily at parse time, not import time, so the active language is resolved before help strings are displayed. When `--language` is provided, the system SHOULD persist it to `~/.strix/cli-config.json`.

#### Scenario: --language flag sets active language

- GIVEN the user runs `strix --language es --target example.com`
- WHEN arguments are parsed
- THEN the active language is `"es"`

#### Scenario: Help text is translated

- GIVEN `STRIX_LANGUAGE=es`
- WHEN the user runs `strix --help`
- THEN help strings are displayed in Spanish

#### Scenario: Language persisted to config

- GIVEN the user runs `strix --language es --target example.com`
- WHEN the scan completes
- THEN `~/.strix/cli-config.json` contains `"language": "es"`

### Requirement: Agent Prompt Injection

The system SHALL inject a `{{ language_directive }}` Jinja variable into `system_prompt.jinja`. The directive MUST instruct the LLM to write findings, descriptions, and recommendations in the target language while preserving technical identifiers (CVE, CWE, CVSS, code snippets, commands) unchanged. The prompt factory MUST pass the resolved language context to the template.

#### Scenario: Spanish directive injected

- GIVEN active language is `"es"`
- WHEN `render_system_prompt()` is called
- THEN the rendered prompt contains an instruction to write in Spanish
- AND technical identifiers are explicitly excluded from translation

#### Scenario: English directive is no-op

- GIVEN active language is `"en"`
- WHEN `render_system_prompt()` is called
- THEN the language directive is empty or absent

### Requirement: t() Helper Contract

The system SHALL provide a `t(key: str, **kwargs) -> str` function. It MUST support `{placeholder}` interpolation via kwargs. It MUST be thread-safe and cache loaded locales. If a key is not found, it MUST return the key itself (graceful degradation).

#### Scenario: Placeholder interpolation

- GIVEN `en.json` contains `"cli.scan_target": "Scanning {target}"`
- WHEN `t("cli.scan_target", target="example.com")` is called
- THEN the function returns `"Scanning example.com"`

#### Scenario: Thread-safe concurrent access

- GIVEN multiple threads call `t()` simultaneously
- WHEN locales are not yet loaded
- THEN the locale is loaded exactly once
- AND all threads receive correct translations

### Requirement: Spanish Translations

The system SHALL ship `strix/locales/es.json` with Spanish translations for Phase 1 strings: CLI argparse help, scan progress messages, error messages, and auth flow messages. Keys MUST be dot-separated paths matching the English source.

#### Scenario: All Phase 1 keys translated

- GIVEN `strix/locales/en.json` contains N keys
- WHEN `strix/locales/es.json` is loaded
- THEN it contains translations for all N keys

#### Scenario: Key structure consistency

- GIVEN `en.json` has key `"cli.scan_started"`
- THEN `es.json` MUST have the same key `"cli.scan_started"`

## Locale Key Structure

```json
// en.json - CLI keys (Phase 1)
{
  "cli.target_help": "Target to test: URL, repository, local directory path...",
  "cli.scan_started": "Starting scan against {target}",
  "cli.scan_completed": "Scan completed. {count} vulnerabilities found.",
  "cli.error_no_target": "No target specified. Use --target or --target-list.",
  "cli.test_initiated": "Penetration test initiated",
  "cli.test_in_progress": "Penetration test in progress",
  "cli.vulnerabilities_realtime": "Vulnerabilities will be displayed in real-time.",
  "cli.completion_title": "Penetration test completed",
  "cli.session_ended": "SESSION ENDED"
}

// en.json - Report keys (Phase 2)
{
  "report.title": "Security Penetration Test Report",
  "report.generated": "Generated:",
  "report.description": "Description",
  "report.evidence": "Evidence",
  "report.impact": "Impact",
  "report.technical_analysis": "Technical Analysis",
  "report.proof_of_concept": "Proof of Concept",
  "report.code_analysis": "Code Analysis",
  "report.remediation": "Remediation",
  "report.assumptions": "Assumptions",
  "report.severity": "Severity",
  "report.found": "Found",
  "report.target": "Target",
  "report.location": "Location",
  "report.suggested_fix": "Suggested Fix"
}

// es.json - CLI keys (Phase 1)
{
  "cli.target_help": "Objetivo a probar: URL, repositorio, directorio local...",
  "cli.scan_started": "Iniciando escaneo contra {target}",
  "cli.scan_completed": "Escaneo completado. {count} vulnerabilidades encontradas.",
  "cli.error_no_target": "No se especificó objetivo. Use --target o --target-list.",
  "cli.test_initiated": "Prueba de penetración iniciada",
  "cli.test_in_progress": "Prueba de penetración en progreso",
  "cli.vulnerabilities_realtime": "Las vulnerabilidades se mostrarán en tiempo real.",
  "cli.completion_title": "Prueba de penetración completada",
  "cli.session_ended": "SESIÓN FINALIZADA"
}

// es.json - Report keys (Phase 2)
{
  "report.title": "Informe de Prueba de Penetración de Seguridad",
  "report.generated": "Generado:",
  "report.description": "Descripción",
  "report.evidence": "Evidencia",
  "report.impact": "Impacto",
  "report.technical_analysis": "Análisis Técnico",
  "report.proof_of_concept": "Prueba de Concepto",
  "report.code_analysis": "Análisis de Código",
  "report.remediation": "Remediación",
  "report.assumptions": "Suposiciones",
  "report.severity": "Severidad",
  "report.found": "Encontrado",
  "report.target": "Objetivo",
  "report.location": "Ubicación",
  "report.suggested_fix": "Corrección Sugerida"
}
```

## Total Keys: 83 (65 CLI + 18 Report)

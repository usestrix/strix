# Internationalization Specification

## Purpose

Enable Strix to operate in multiple languages. Phase 1 delivers Brazilian Portuguese alongside English for CLI strings and LLM-generated findings, while preserving English for all machine-consumed artifacts (SARIF, vulnerabilities.json).

## Requirements

### Requirement: Locale Loading

The system SHALL load locale data from flat JSON files at `strix/locales/{lang}.json`. Locale files MUST be loaded lazily on first `t()` call or language resolution, then cached in memory for the process lifetime. Missing keys MUST fall back to the English value and log a warning.

#### Scenario: Load Brazilian Portuguese locale on first t() call

- GIVEN `strix/locales/pt.json` exists with key `"cli.scan_started": "Varredura iniciada"`
- WHEN `t("cli.scan_started")` is called with active language `"pt"`
- THEN the function returns `"Varredura iniciada"`
- AND the locale file is read from disk exactly once

#### Scenario: Missing key falls back to English

- GIVEN `strix/locales/pt.json` does NOT contain key `"cli.unknown_key"`
- AND `strix/locales/en.json` contains `"cli.unknown_key": "Unknown key"`
- WHEN `t("cli.unknown_key")` is called with active language `"pt"`
- THEN the function returns `"Unknown key"`
- AND a warning is logged

#### Scenario: Key missing from all locales

- GIVEN no locale file contains key `"cli.nonexistent"`
- WHEN `t("cli.nonexistent")` is called
- THEN the function returns the key string `"cli.nonexistent"`

### Requirement: Language Resolution Chain

The system SHALL determine the active language using this priority: `--language` CLI flag > `STRIX_LANGUAGE` env var > `~/.strix/cli-config.json` `"language"` field > `LANG`/`LC_ALL` system locale > `"en"` default. Unsupported languages MUST fall back to `"en"` with a warning. Initially supported: `en`, `pt`.

#### Scenario: CLI flag takes highest priority

- GIVEN `STRIX_LANGUAGE=pt` and `~/.strix/cli-config.json` contains `"language": "en"`
- WHEN the user runs `strix --language pt --target example.com`
- THEN the active language is `"pt"`

#### Scenario: Environment variable used when no CLI flag

- GIVEN no `--language` flag is provided
- AND `STRIX_LANGUAGE=pt` is set
- WHEN strix starts
- THEN the active language is `"pt"`

#### Scenario: Config file used when no flag or env

- GIVEN no `--language` flag, no `STRIX_LANGUAGE` env var
- AND `~/.strix/cli-config.json` contains `"language": "pt"`
- WHEN strix starts
- THEN the active language is `"pt"`

#### Scenario: System locale detection

- GIVEN no flag, env, or config language set
- AND `LANG=pt_BR.UTF-8`
- WHEN strix starts
- THEN the active language is `"pt"`

#### Scenario: Unsupported language falls back to English

- GIVEN `STRIX_LANGUAGE=fr` (unsupported)
- WHEN strix starts
- THEN the active language is `"en"`
- AND a warning is logged

### Requirement: CLI Integration

The system SHALL provide a `--language` / `-l` CLI flag via argparse. Help text for all argparse arguments MUST be evaluated lazily at parse time, not import time, so the active language is resolved before help strings are displayed. When `--language` is provided, the system SHOULD persist it to `~/.strix/cli-config.json`.

#### Scenario: --language flag sets active language

- GIVEN the user runs `strix --language pt --target example.com`
- WHEN arguments are parsed
- THEN the active language is `"pt"`

#### Scenario: Help text is translated

- GIVEN `STRIX_LANGUAGE=pt`
- WHEN the user runs `strix --help`
- THEN help strings are displayed in Brazilian Portuguese

#### Scenario: Language persisted to config

- GIVEN the user runs `strix --language pt --target example.com`
- WHEN the scan completes
- THEN `~/.strix/cli-config.json` contains `"language": "pt"`

### Requirement: Agent Prompt Injection

The system SHALL inject a `{{ language_directive }}` Jinja variable into `system_prompt.jinja`. The directive MUST instruct the LLM to write findings, descriptions, and recommendations in the target language while preserving technical identifiers (CVE, CWE, CVSS, code snippets, commands) unchanged. The prompt factory MUST pass the resolved language context to the template.

#### Scenario: Portuguese directive injected

- GIVEN active language is `"pt"`
- WHEN `render_system_prompt()` is called
- THEN the rendered prompt contains an instruction to write in Brazilian Portuguese
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

### Requirement: Brazilian Portuguese Translations

The system SHALL ship `strix/locales/pt.json` with Brazilian Portuguese translations for Phase 1 strings: CLI argparse help, scan progress messages, error messages, and auth flow messages. Keys MUST be dot-separated paths matching the English source.

#### Scenario: All Phase 1 keys translated

- GIVEN `strix/locales/en.json` contains N keys
- WHEN `strix/locales/pt.json` is loaded
- THEN it contains translations for all N keys

#### Scenario: Key structure consistency

- GIVEN `en.json` has key `"cli.scan_started"`
- THEN `pt.json` MUST have the same key `"cli.scan_started"`

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

// pt.json - CLI keys (Phase 1)
{
  "cli.target_help": "Alvo a ser testado: URL, repositório, diretório local...",
  "cli.scan_started": "Iniciando varredura em {target}",
  "cli.scan_completed": "Varredura concluída. {count} vulnerabilidades encontradas.",
  "cli.error_no_target": "Nenhum alvo especificado. Use --target ou --target-list.",
  "cli.test_initiated": "Teste de penetração iniciado",
  "cli.test_in_progress": "Teste de penetração em andamento",
  "cli.vulnerabilities_realtime": "As vulnerabilidades serão exibidas em tempo real.",
  "cli.completion_title": "Teste de penetração concluído",
  "cli.session_ended": "SESSÃO ENCERRADA"
}

// pt.json - Report keys (Phase 2)
{
  "report.title": "Relatório de Teste de Penetração de Segurança",
  "report.generated": "Gerado em:",
  "report.description": "Descrição",
  "report.evidence": "Evidência",
  "report.impact": "Impacto",
  "report.technical_analysis": "Análise Técnica",
  "report.proof_of_concept": "Prova de Conceito",
  "report.code_analysis": "Análise de Código",
  "report.remediation": "Remediação",
  "report.assumptions": "Premissas",
  "report.severity": "Severidade",
  "report.found": "Encontrado",
  "report.target": "Alvo",
  "report.location": "Localização",
  "report.suggested_fix": "Correção Sugerida"
}
```

## Total Keys: 90 (65 CLI + 25 Report)

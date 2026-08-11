# Proposal: Internationalization (i18n) Support — Phase 1

## Intent

Strix is hardcoded to English across Python CLI, Go TUI, and React viewer. Non-English security teams can't consume findings in their language, slowing triage and adoption. This adds an `i18n` capability so scans run in Brazilian Portuguese (others follow the same plumbing) without altering the engine.

## Scope

**In (Phase 1):** `Settings.language: str = "en"` (pydantic-settings), env `STRIX_LANGUAGE`, CLI `--language`/`-l`, persisted in `~/.strix/cli-config.json`. Resolution: `--language` > env > config > `LANG`/`LC_ALL` > `"en"`. Flat JSON dicts in `strix/locales/{lang}.json`. `strix/i18n.py` with `t("key")`. Brazilian Portuguese for argparse help, scan progress, errors. One Jinja variable in `system_prompt.jinja` directing the LLM to write findings/descriptions/recommendations in the target language (CVE/CWE/CVSS/code/commands unchanged). Lazy wrapper for argparse `help=` so locale is resolved at parse time.

**Out (later PRs):** Phase 2 report headings, Phase 3 Go TUI (~300 strings, 45 files), Phase 4 React viewer. SARIF and `vulnerabilities.json` stay English.

## Capabilities

**New:** `internationalization` — locale loading, resolution chain, prompt injection, `t()`.

**Modified:** None.

## Approach

Flat JSON dicts are portable — same source later serves Go (backend socket) and React (copy/fetch). Python side: one `Settings.language` field, small `i18n.py` with cache, one Jinja variable prepending a language directive to the agent system prompt. LLM body returns in target language; static CLI strings use `t()`. argparse `help=` uses a deferred callable so locale is available at parse time.

## Affected Areas

| Area | Impact | Change |
|------|--------|--------|
| `strix/config/settings.py` | Mod | `Settings.language` + env |
| `strix/interface/cli_args.py` | Mod | `--language` flag; lazy `help=` |
| `strix/locales/{en,pt}.json` | New | Flat locale dicts |
| `strix/i18n.py` | New | `t()`, `set/get_language()` + cache |
| `strix/agents/prompts/system_prompt.jinja` | Mod | Inject `{{ language_directive }}` |
| `strix/agents/factory.py` | Mod | Pass language to Jinja |
| `strix/interface/utils.py` | Mod | Wrap CLI msgs in `t()` |
| `tests/` | Mod | Locale + prompt tests |

## Risks

| Risk | Mitigation |
|------|------------|
| LLM quality drops in non-English (M) | Directive preserves CVE/CWE/CVSS/code; model stays user-driven |
| argparse help evaluated at import (H) | Lazy callable wrapper at parse time |
| 3 ecosystems need coordinated i18n (M) | JSON portable; Phase 1 only touches Python |
| Locale drift between languages (L) | Keys generated from `en.json`; missing → English + warning |
| Locale leaks into SARIF/JSON (L) | Exports use fixed English keys; test covers |

## Rollback

Revert the merge. `Settings.language` defaults `"en"` and `t()` returns the key when no locale loaded — removing files and unhooking the Jinja directive restores prior behavior, no migration.

## Dependencies

`pydantic-settings` (already present). No new libs — stdlib `json` + existing Jinja2.

## Success Criteria

- [ ] `--language pt` → Brazilian Portuguese findings; CVE/CWE/CVSS/code unchanged
- [ ] `STRIX_LANGUAGE=pt` and `"language": "pt"` in config match the flag
- [ ] `t('cli.scan_started')` returns Brazilian Portuguese under env, English otherwise
- [ ] `--help` shows translated text under `--language pt`
- [ ] SARIF and `vulnerabilities.json` stay English regardless of locale
- [ ] `uv run pytest` and `make check-all` pass

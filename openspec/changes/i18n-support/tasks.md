# Tasks: i18n Support — Phase 1 & 2

## Review Workload Forecast

- **Estimated changed lines**: ~250 (well under 400-line budget)
- **Chained PRs recommended**: No
- **Decision needed before apply**: No

---

## Phase 1: CLI & Agent Responses ✅ COMPLETE

## Task 1: Add language field to Settings ✅

**File**: `strix/config/settings.py`

**Description**: Add `language: str` field to the `Settings` class with `STRIX_LANGUAGE` env var alias.

**Changes**:
```python
class Settings(BaseSettings):
    # ... existing fields ...
    language: str = Field(default="en", alias="STRIX_LANGUAGE")
```

**Acceptance**:
- [ ] `Settings(language="es").language == "es"`
- [ ] `STRIX_LANGUAGE=es` env var is picked up
- [ ] Default is `"en"`

**Dependencies**: None

---

## Task 2: Add --language CLI flag ✅

**File**: `strix/interface/cli_args.py`

**Description**: Add `--language` / `-l` argument to argparse. Call `set_language()` after parsing.

**Changes**:
1. Add argument before `parse_arguments()` returns:
```python
parser.add_argument(
    "-l", "--language",
    type=str,
    default=None,
    help="Language for UI and agent responses (e.g., 'en', 'es'). Default: auto-detect.",
)
```

2. After `args = parser.parse_args()`, add:
```python
from strix.i18n import set_language
if args.language:
    set_language(args.language)
```

**Acceptance**:
- [ ] `strix --language es --help` shows help in Spanish
- [ ] `strix -l es` works
- [ ] No `--language` flag → auto-detection from env/config/locale

**Dependencies**: Task 1

---

## Task 3: Inject language directive into agent prompts ✅

**Files**: 
- `strix/agents/prompt.py`
- `strix/agents/prompts/system_prompt.jinja`

**Description**: Pass `language_directive` to Jinja template and render it.

**Changes in prompt.py** (`render_system_prompt` function):
```python
from strix.i18n import get_language_directive

# Inside render_system_prompt(), before env.get_template().render():
language_directive = get_language_directive()

# Add to render() call:
rendered = env.get_template("system_prompt.jinja").render(
    # ... existing params ...
    language_directive=language_directive,
)
```

**Changes in system_prompt.jinja** (add near the top, after initial instructions):
```jinja
{% if language_directive %}
{{ language_directive }}
{% endif %}
```

**Acceptance**:
- [ ] With `language="es"`, rendered prompt contains "Spanish" instruction
- [ ] With `language="en"`, no directive injected (empty string)
- [ ] CVE/CWE/CVSS preservation mentioned in directive

**Dependencies**: None (parallel with Task 2)

---

## Task 4: Integrate t() into main CLI messages ✅

**File**: `strix/interface/main.py`

**Description**: Replace hardcoded English strings with `t()` calls for key user-facing messages.

**Changes**:
```python
from strix.i18n import t

# Replace strings like:
# print("Starting scan...") 
# With:
# print(t("cli.scan_started", target=target))
```

Key strings to translate:
- Scan start/complete messages
- Error messages for missing targets
- Progress indicators

**Acceptance**:
- [ ] `strix --language es -t example.com` shows Spanish progress messages
- [ ] `strix -t example.com` shows English (default)
- [ ] No runtime errors from t() calls

**Dependencies**: Task 1, Task 2

---

## Task 5: Add tests ✅

**File**: `tests/test_i18n.py`

**Description**: Test the i18n module: translation, fallback, language resolution, directive generation.

**Test cases**:
```python
def test_t_returns_english_by_default()
def test_t_returns_spanish_when_language_set()
def test_t_falls_back_to_english_for_missing_key()
def test_t_returns_key_for_completely_missing_key()
def test_t_interpolates_placeholders()
def test_set_language_normalizes()
def test_get_language_directive_empty_for_english()
def test_get_language_directive_contains_language_name()
def test_locale_files_are_valid_json()
def test_all_en_keys_exist_in_es()
```

**Acceptance**:
- [ ] `uv run pytest tests/test_i18n.py -v` passes
- [ ] All locale keys validated

**Dependencies**: Task 1-4

---

## Task 6: Verify with make check-all ✅

**Description**: Run full quality suite to ensure no regressions.

**Commands**:
```bash
make check-all  # ruff, mypy, bandit
uv run pytest   # all tests
```

**Acceptance**:
- [ ] `make check-all` passes
- [ ] `uv run pytest` passes
- [ ] No new warnings or errors

**Dependencies**: Task 1-5

---

## Implementation Order

```
Task 1 (Settings) ──┐
                     ├──> Task 2 (CLI flag) ──┐
Task 3 (Jinja) ─────┘                        ├──> Task 4 (Main.py) ──> Task 5 (Tests) ──> Task 6 (Verify)
                                              │
                                              └──> Task 3 (parallel)
```

Tasks 1 and 3 can be done in parallel. Task 2 depends on Task 1. Task 4 depends on Task 2. Task 5 depends on all. Task 6 is final verification.

---

## Phase 2: Report Translations ✅ COMPLETE

## Task 7: Add report translation keys ✅

**Files**: 
- `strix/locales/en.json`
- `strix/locales/es.json`

**Description**: Add 18 translation keys for report headings and metadata labels.

**Keys added**:
- `report.title` — Executive report title
- `report.generated` — Generated timestamp label
- `report.description` — Description section heading
- `report.evidence` — Evidence section heading
- `report.impact` — Impact section heading
- `report.severity` — Severity metadata label
- `report.target` — Target metadata label
- `report.package` — Package metadata label
- `report.remediation` — Remediation section heading
- `report.references` — References section heading
- `report.cvss_score` — CVSS score label
- `report.cwe_id` — CWE ID label
- `report.affected_versions` — Affected versions label
- `report.fixed_versions` — Fixed versions label
- `report.proof_of_concept` — Proof of concept heading
- `report.steps_to_reproduce` — Steps to reproduce heading
- `report.expected_result` — Expected result label
- `report.actual_result` — Actual result label

**Acceptance**:
- [x] All 18 keys exist in en.json
- [x] All 18 keys exist in es.json with Spanish translations
- [x] No missing keys between locales

**Dependencies**: Task 1 (Settings.language)

---

## Task 8: Translate report writer ✅

**File**: `strix/report/writer.py`

**Description**: Replace hardcoded English report strings with `t()` calls.

**Changes**:
```python
from strix.i18n import t

# Replace strings like:
# "Description"
# With:
# t("report.description")
```

**Sections translated**:
- Executive report title and metadata
- Vulnerability detail headings (Description, Evidence, Impact, etc.)
- CVSS/CWE labels
- Remediation and references sections
- Proof of concept sections

**Acceptance**:
- [x] `--language es` → Spanish report headings
- [x] `--language en` → English report headings (default)
- [x] SARIF and vulnerabilities.json stay English

**Dependencies**: Task 7

---

## Task 9: Add Phase 2 tests ✅

**File**: `tests/test_i18n.py`

**Description**: Add tests for report translation keys.

**Test cases added**:
```python
def test_report_keys_exist_in_both_locales()
def test_report_t_returns_spanish_when_language_set()
def test_report_t_returns_english_by_default()
```

**Acceptance**:
- [x] `uv run pytest tests/test_i18n.py -v` passes
- [x] All report keys validated

**Dependencies**: Task 7, Task 8

---

## Phase 3: Go TUI (PENDING)

**Status**: Not started
**Scope**: ~300 strings across 45 Go files in `strix/interface/tui/internal/`
**Approach**: Backend socket serves locale JSON; Go code calls translation function

---

## Phase 4: React Viewer (PENDING)

**Status**: Not started
**Scope**: UI strings in `strix/interface/viewer/frontend/src/`
**Approach**: Fetch locale JSON; React hooks for translations

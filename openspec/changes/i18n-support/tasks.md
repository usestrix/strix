# Tasks: i18n Support — Phase 1

## Review Workload Forecast

- **Estimated changed lines**: ~250 (well under 400-line budget)
- **Chained PRs recommended**: No
- **Decision needed before apply**: No

---

## Task 1: Add language field to Settings

**File**: `strix/config/settings.py`

**Description**: Add `language: str` field to the `Settings` class with `STRIX_LANGUAGE` env var alias.

**Changes**:
```python
class Settings(BaseSettings):
    # ... existing fields ...
    language: str = Field(default="en", alias="STRIX_LANGUAGE")
```

**Acceptance**:
- [ ] `Settings(language="pt").language == "pt"`
- [ ] `STRIX_LANGUAGE=pt` env var is picked up
- [ ] Default is `"en"`

**Dependencies**: None

---

## Task 2: Add --language CLI flag

**File**: `strix/interface/cli_args.py`

**Description**: Add `--language` / `-l` argument to argparse. Call `set_language()` after parsing.

**Changes**:
1. Add argument before `parse_arguments()` returns:
```python
parser.add_argument(
    "-l", "--language",
    type=str,
    default=None,
    help="Language for UI and agent responses (e.g., 'en', 'pt'). Default: auto-detect.",
)
```

2. After `args = parser.parse_args()`, add:
```python
from strix.i18n import set_language
if args.language:
    set_language(args.language)
```

**Acceptance**:
- [ ] `strix --language pt --help` shows help in Brazilian Portuguese
- [ ] `strix -l pt` works
- [ ] No `--language` flag → auto-detection from env/config/locale

**Dependencies**: Task 1

---

## Task 3: Inject language directive into agent prompts

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
- [ ] With `language="pt"`, rendered prompt contains "Brazilian Portuguese" instruction
- [ ] With `language="en"`, no directive injected (empty string)
- [ ] CVE/CWE/CVSS preservation mentioned in directive

**Dependencies**: None (parallel with Task 2)

---

## Task 4: Integrate t() into main CLI messages

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
- [ ] `strix --language pt -t example.com` shows Brazilian Portuguese progress messages
- [ ] `strix -t example.com` shows English (default)
- [ ] No runtime errors from t() calls

**Dependencies**: Task 1, Task 2

---

## Task 5: Add tests

**File**: `tests/test_i18n.py`

**Description**: Test the i18n module: translation, fallback, language resolution, directive generation.

**Test cases**:
```python
def test_t_returns_english_by_default()
def test_t_returns_portuguese_when_language_set()
def test_t_falls_back_to_english_for_missing_key()
def test_t_returns_key_for_completely_missing_key()
def test_t_interpolates_placeholders()
def test_set_language_normalizes()
def test_get_language_directive_empty_for_english()
def test_get_language_directive_contains_language_name()
def test_locale_files_are_valid_json()
def test_all_en_keys_exist_in_pt()
```

**Acceptance**:
- [ ] `uv run pytest tests/test_i18n.py -v` passes
- [ ] All locale keys validated

**Dependencies**: Task 1-4

---

## Task 6: Verify with make check-all

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

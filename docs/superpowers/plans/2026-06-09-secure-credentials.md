# Secure Credentials Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow users to pass credentials via `--credentials` / `--credentials-file` CLI flags so that secret values never appear in the LLM conversation history.

**Architecture:** Credentials are parsed at CLI startup into a `dict[str, str]` and stored in the runtime context dict (`ctx.context["credentials"]`). The system prompt lists available credential names. A new local tool `get_credential(name)` lets the LLM fetch values on demand. Child agents inherit credentials automatically because `_start_child_runner` does `child_ctx = dict(parent_ctx)`.

**Tech Stack:** Python 3.12, argparse, Jinja2, openai-agents `function_tool` / `RunContextWrapper`, pytest.

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `pyproject.toml` | Modify | Add pytest dev dependency + pytest config |
| `tests/__init__.py` | Create | Mark tests as a package |
| `tests/test_credentials_parsing.py` | Create | Unit tests for credential parsing helper |
| `tests/test_get_credential_tool.py` | Create | Unit tests for `get_credential` tool |
| `tests/test_credentials_context.py` | Create | Unit tests for scope context credential names |
| `strix/interface/main.py` | Modify | Add `--credentials` / `--credentials-file` flags + `_parse_credentials()` helper |
| `strix/interface/cli.py` | Modify | Add `credentials` key to `scan_config` |
| `strix/core/runner.py` | Modify | Add `credentials` to runtime context dict and `scope_context` |
| `strix/core/inputs.py` | Modify | Accept and expose `credential_names` in `build_scope_context()` |
| `strix/agents/prompts/system_prompt.jinja` | Modify | Render CREDENTIALS block when `credential_names` present |
| `strix/tools/credentials/tool.py` | Create | `get_credential(ctx, name)` tool |
| `strix/agents/factory.py` | Modify | Import and add `get_credential` to `_BASE_TOOLS` |
| `pyproject.toml` | Modify | Add `strix/tools/credentials/tool.py` to ruff TC002 ignore |
| `README.md` | Modify | Update grey-box example to use `--credentials` |
| `docs/usage/instructions.mdx` | Modify | Replace inline credential examples; add credentials section |
| `docs/usage/cli.mdx` | Modify | Update `--instruction` description; add `--credentials` params |

---

## Task 1: Add pytest and create test infrastructure

**Files:**
- Modify: `pyproject.toml`
- Create: `tests/__init__.py`

- [ ] **Step 1: Add pytest to dev dependencies**

In `pyproject.toml`, update `[dependency-groups]`:

```toml
[dependency-groups]
dev = [
  "pytest>=8.0.0",
  "mypy>=1.16.0",
  "ruff>=0.11.13",
  "pyright>=1.1.401",
  "bandit>=1.8.3",
  "pre-commit>=4.2.0",
  "pyinstaller>=6.17.0; python_version >= '3.12' and python_version < '3.15'",
]
```

Also add to the bottom of `pyproject.toml`:

```toml
# ============================================================================
# Pytest Configuration
# ============================================================================

[tool.pytest.ini_options]
testpaths = ["tests"]
```

- [ ] **Step 2: Install dev dependencies**

```bash
uv sync --dev
```

Expected: resolves and installs pytest without errors.

- [ ] **Step 3: Create tests package**

Create `tests/__init__.py` as an empty file.

- [ ] **Step 4: Verify pytest discovers tests**

```bash
uv run pytest tests/ -v
```

Expected: `no tests ran` (no test files yet) — not an error.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml tests/__init__.py
git commit -m "chore: add pytest to dev dependencies and create tests package"
```

---

## Task 2: Credential parsing helper — TDD

**Files:**
- Create: `tests/test_credentials_parsing.py`
- Modify: `strix/interface/main.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_credentials_parsing.py`:

```python
"""Tests for the _parse_credentials helper in main.py."""

from __future__ import annotations

import json
import argparse
import pytest

from strix.interface.main import _parse_credentials


def _parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser()


def test_no_credentials_returns_empty_dict():
    result = _parse_credentials(None, None, _parser())
    assert result == {}


def test_inline_single_pair():
    result = _parse_credentials("PASSWORD=secret", None, _parser())
    assert result == {"PASSWORD": "secret"}


def test_inline_multiple_pairs():
    result = _parse_credentials("USER=admin,PASS=s3cr3t", None, _parser())
    assert result == {"USER": "admin", "PASS": "s3cr3t"}


def test_inline_value_with_equals_sign():
    """Values that contain '=' should be preserved after the first '='."""
    result = _parse_credentials("TOKEN=abc=def", None, _parser())
    assert result == {"TOKEN": "abc=def"}


def test_credentials_file(tmp_path):
    creds = {"API_KEY": "abc123", "TOKEN": "xyz789"}
    f = tmp_path / "creds.json"
    f.write_text(json.dumps(creds))
    result = _parse_credentials(None, str(f), _parser())
    assert result == creds


def test_credentials_file_overridden_by_inline(tmp_path):
    """Inline values override file values for the same key."""
    f = tmp_path / "creds.json"
    f.write_text(json.dumps({"USER": "file_user", "PASS": "file_pass"}))
    result = _parse_credentials("PASS=override", str(f), _parser())
    assert result == {"USER": "file_user", "PASS": "override"}


def test_missing_file_raises_system_exit():
    with pytest.raises(SystemExit):
        _parse_credentials(None, "/nonexistent/creds.json", _parser())


def test_invalid_json_raises_system_exit(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not json {{{")
    with pytest.raises(SystemExit):
        _parse_credentials(None, str(bad), _parser())


def test_non_object_json_raises_system_exit(tmp_path):
    bad = tmp_path / "list.json"
    bad.write_text(json.dumps(["a", "b"]))
    with pytest.raises(SystemExit):
        _parse_credentials(None, str(bad), _parser())


def test_invalid_inline_format_raises_system_exit():
    with pytest.raises(SystemExit):
        _parse_credentials("NOEQUALS", None, _parser())
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
uv run pytest tests/test_credentials_parsing.py -v
```

Expected: `ImportError: cannot import name '_parse_credentials' from 'strix.interface.main'`

- [ ] **Step 3: Add `_parse_credentials` helper and CLI flags to `main.py`**

At the top of `strix/interface/main.py`, ensure `json` and `Path` are imported (they should already be present given the file reads instruction files — confirm and add if missing):

```python
import json
from pathlib import Path
```

Add the helper function anywhere before `parse_arguments()` (e.g., after the existing helper functions near line 300):

```python
def _parse_credentials(
    credentials_str: str | None,
    credentials_file: str | None,
    parser: argparse.ArgumentParser,
) -> dict[str, str]:
    """Parse --credentials and --credentials-file into a merged dict.

    File is loaded first; inline values override on key collision.
    Calls parser.error() (which raises SystemExit) on any validation failure.
    """
    result: dict[str, str] = {}

    if credentials_file:
        cred_path = Path(credentials_file)
        try:
            with cred_path.open(encoding="utf-8") as f:
                loaded = json.load(f)
        except FileNotFoundError:
            parser.error(f"Credentials file not found: '{credentials_file}'")
        except json.JSONDecodeError as exc:
            parser.error(f"Credentials file is not valid JSON '{credentials_file}': {exc}")
        if not isinstance(loaded, dict):
            parser.error(
                f"Credentials file must contain a JSON object, got {type(loaded).__name__}: "
                f"'{credentials_file}'"
            )
        result.update({str(k): str(v) for k, v in loaded.items()})

    if credentials_str:
        for pair in credentials_str.split(","):
            if "=" not in pair:
                parser.error(
                    f"Invalid --credentials value '{pair}'. "
                    "Each entry must be KEY=VALUE (comma-separated)."
                )
            key, _, value = pair.partition("=")
            result[key.strip()] = value

    return result
```

Add the two new flags inside `parse_arguments()`, after the `--instruction-file` block (after line 372):

```python
    parser.add_argument(
        "--credentials",
        type=str,
        help="Comma-separated KEY=VALUE credential pairs kept out of the LLM conversation. "
        "Reference credentials by name in instructions "
        "(e.g., '--instruction \"Log in using USERNAME and PASSWORD\"'). "
        "Example: '--credentials USERNAME=admin,PASSWORD=secret'. "
        "Keys from --credentials-file are loaded first; inline values override on collision.",
    )

    parser.add_argument(
        "--credentials-file",
        type=str,
        help="Path to a JSON file of credential key-value pairs "
        "(e.g., '{\"USERNAME\": \"admin\", \"PASSWORD\": \"secret\"}'). "
        "Values are kept out of the LLM conversation; "
        "use get_credential(name) in instructions to reference them. "
        "Inline --credentials values override file values on key collision.",
    )
```

Call the helper inside `parse_arguments()`, after the instruction-file parsing block (after line 453):

```python
    args.credentials = _parse_credentials(
        args.credentials,
        args.credentials_file,
        parser,
    )
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
uv run pytest tests/test_credentials_parsing.py -v
```

Expected: all 10 tests pass.

- [ ] **Step 5: Commit**

```bash
git add strix/interface/main.py tests/test_credentials_parsing.py
git commit -m "feat: add --credentials and --credentials-file CLI flags"
```

---

## Task 3: Pass credentials through scan_config

**Files:**
- Modify: `strix/interface/cli.py`

No new tests needed — the CLI test in Task 2 already verifies parsing. This is a one-line wiring change.

- [ ] **Step 1: Add `credentials` to `scan_config` in `cli.py`**

In `strix/interface/cli.py`, the `scan_config` dict is built at lines 85–97. Add `credentials` as the last key:

```python
    scan_config: dict[str, Any] = {
        "scan_id": args.run_name,
        "targets": args.targets_info,
        "user_instructions": args.instruction or "",
        "run_name": args.run_name,
        "diff_scope": getattr(args, "diff_scope", {"active": False}),
        "scan_mode": scan_mode,
        "non_interactive": bool(getattr(args, "non_interactive", False)),
        "local_sources": getattr(args, "local_sources", None) or [],
        "scope_mode": getattr(args, "scope_mode", "auto"),
        "diff_base": getattr(args, "diff_base", None),
        "resume_instruction": getattr(args, "user_explicit_instruction", None) or "",
        "credentials": getattr(args, "credentials", {}) or {},
    }
```

- [ ] **Step 2: Commit**

```bash
git add strix/interface/cli.py
git commit -m "feat: pass credentials from CLI args into scan_config"
```

---

## Task 4: `get_credential()` tool — TDD

**Files:**
- Create: `tests/test_get_credential_tool.py`
- Create: `strix/tools/credentials/tool.py`
- Modify: `strix/agents/factory.py`
- Modify: `pyproject.toml`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_get_credential_tool.py`:

```python
"""Tests for the get_credential tool."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import MagicMock


def _make_ctx(credentials: dict) -> MagicMock:
    ctx = MagicMock()
    ctx.context = {"credentials": credentials}
    return ctx


def test_returns_value_for_known_credential():
    from strix.tools.credentials.tool import _get_credential_impl

    ctx = _make_ctx({"PASSWORD": "s3cr3t"})
    result = asyncio.run(_get_credential_impl(ctx, "PASSWORD"))
    data = json.loads(result)
    assert data == {"value": "s3cr3t"}


def test_returns_error_for_unknown_credential():
    from strix.tools.credentials.tool import _get_credential_impl

    ctx = _make_ctx({"PASSWORD": "s3cr3t", "USER": "admin"})
    result = asyncio.run(_get_credential_impl(ctx, "UNKNOWN"))
    data = json.loads(result)
    assert "error" in data
    assert "UNKNOWN" in data["error"]
    assert sorted(data["available"]) == ["PASSWORD", "USER"]


def test_returns_error_when_no_credentials_in_context():
    from strix.tools.credentials.tool import _get_credential_impl

    ctx = MagicMock()
    ctx.context = {}  # no credentials key
    result = asyncio.run(_get_credential_impl(ctx, "PASSWORD"))
    data = json.loads(result)
    assert "error" in data
    assert data["available"] == []


def test_returns_error_when_context_is_not_dict():
    from strix.tools.credentials.tool import _get_credential_impl

    ctx = MagicMock()
    ctx.context = None
    result = asyncio.run(_get_credential_impl(ctx, "PASSWORD"))
    data = json.loads(result)
    assert "error" in data


def test_get_credential_is_registered_as_function_tool():
    """Verify the tool is a FunctionTool with the expected name."""
    from agents.tool import FunctionTool

    from strix.tools.credentials.tool import get_credential

    assert isinstance(get_credential, FunctionTool)
    assert get_credential.name == "get_credential"
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
uv run pytest tests/test_get_credential_tool.py -v
```

Expected: `ModuleNotFoundError: No module named 'strix.tools.credentials'`

- [ ] **Step 3: Create the tool**

Create `strix/tools/credentials/tool.py`:

```python
"""Credential access tool for Strix agents."""

from __future__ import annotations

import json
from typing import Any

from agents import RunContextWrapper, function_tool


async def _get_credential_impl(ctx: RunContextWrapper, name: str) -> str:
    context: dict[str, Any] = ctx.context if isinstance(ctx.context, dict) else {}
    credentials: dict[str, str] = context.get("credentials") or {}
    value = credentials.get(name)
    if value is None:
        return json.dumps(
            {
                "error": f"Credential '{name}' not found.",
                "available": sorted(credentials.keys()),
            }
        )
    return json.dumps({"value": value})


get_credential = function_tool(timeout=10)(_get_credential_impl)
get_credential.__doc__ = (
    "Retrieve a named credential value supplied via --credentials or --credentials-file. "
    "Credential values are never stored in conversation history — call this tool each time "
    "you need a value (e.g., to fill a login form or set an auth header). "
    "Pass the exact key name shown in the CREDENTIALS AVAILABLE system prompt block."
)
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
uv run pytest tests/test_get_credential_tool.py -v
```

Expected: all 5 tests pass.

- [ ] **Step 5: Register `get_credential` in `_BASE_TOOLS`**

In `strix/agents/factory.py`, add import after the existing tool imports (e.g., after line 54 `from strix.tools.web_search.tool import web_search`):

```python
from strix.tools.credentials.tool import get_credential
```

Add `get_credential` to `_BASE_TOOLS` (after `web_search`, before `create_vulnerability_report`):

```python
_BASE_TOOLS: tuple[Tool, ...] = (
    think,
    load_skill,
    create_todo,
    list_todos,
    update_todo,
    mark_todo_done,
    mark_todo_pending,
    delete_todo,
    create_note,
    list_notes,
    get_note,
    update_note,
    delete_note,
    web_search,
    get_credential,
    create_vulnerability_report,
    list_requests,
    view_request,
    repeat_request,
    list_sitemap,
    view_sitemap_entry,
    scope_rules,
    view_agent_graph,
    send_message_to_agent,
    wait_for_message,
    create_agent,
    stop_agent,
)
```

- [ ] **Step 6: Add ruff TC002 exemption for the credentials tool**

In `pyproject.toml`, under `[tool.ruff.lint.per-file-ignores]`, add:

```toml
"strix/tools/credentials/tool.py" = ["TC002"]
```

(The `RunContextWrapper` import must be eager — not under `TYPE_CHECKING` — because the SDK calls `get_type_hints()` at registration time to derive the JSON schema. All other tool files have the same exemption.)

- [ ] **Step 7: Run the full test suite**

```bash
uv run pytest tests/ -v
```

Expected: all tests pass.

- [ ] **Step 8: Commit**

```bash
git add strix/tools/credentials/tool.py strix/agents/factory.py pyproject.toml tests/test_get_credential_tool.py
git commit -m "feat: add get_credential tool and register in _BASE_TOOLS"
```

---

## Task 5: Credentials in context dict and system prompt — TDD

**Files:**
- Create: `tests/test_credentials_context.py`
- Modify: `strix/core/inputs.py`
- Modify: `strix/core/runner.py`
- Modify: `strix/agents/prompts/system_prompt.jinja`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_credentials_context.py`:

```python
"""Tests for credential_names in build_scope_context."""

from __future__ import annotations

from strix.core.inputs import build_scope_context


def _base_config() -> dict:
    return {
        "targets": [
            {
                "type": "web_application",
                "original": "https://example.com",
                "details": {"target_url": "https://example.com"},
            }
        ]
    }


def test_no_credentials_gives_no_credential_names():
    ctx = build_scope_context(_base_config())
    assert ctx.get("credential_names") == []


def test_credentials_appear_as_sorted_names():
    config = {**_base_config(), "credentials": {"PASSWORD": "s", "USERNAME": "u"}}
    ctx = build_scope_context(config)
    assert ctx["credential_names"] == ["PASSWORD", "USERNAME"]


def test_empty_credentials_gives_empty_list():
    config = {**_base_config(), "credentials": {}}
    ctx = build_scope_context(config)
    assert ctx["credential_names"] == []
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
uv run pytest tests/test_credentials_context.py -v
```

Expected: `AssertionError` — `credential_names` key is not present in the returned dict.

- [ ] **Step 3: Update `build_scope_context()` in `inputs.py`**

`build_scope_context()` currently returns (lines 101–106):

```python
    return {
        "scope_source": "system_scan_config",
        "authorization_source": "strix_platform_verified_targets",
        "authorized_targets": authorized,
        "user_instructions_do_not_expand_scope": True,
    }
```

Change it to:

```python
    credentials: dict[str, str] = scan_config.get("credentials") or {}

    return {
        "scope_source": "system_scan_config",
        "authorization_source": "strix_platform_verified_targets",
        "authorized_targets": authorized,
        "user_instructions_do_not_expand_scope": True,
        "credential_names": sorted(credentials.keys()),
    }
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
uv run pytest tests/test_credentials_context.py -v
```

Expected: all 3 tests pass.

- [ ] **Step 5: Add credentials to the runtime context dict in `runner.py`**

In `strix/core/runner.py`, the runtime context dict is built after `scope_context` (around lines 169–221). Find this block:

```python
        context: dict[str, Any] = {
            "coordinator": coordinator,
            "sandbox_session": bundle["session"],
            "caido_client": bundle["caido_client"],
            "agent_id": root_id,
            "parent_id": None,
            "interactive": interactive,
            "spawn_child_agent": spawn_child_agent,
        }
```

Add `"credentials"` as the last key:

```python
        context: dict[str, Any] = {
            "coordinator": coordinator,
            "sandbox_session": bundle["session"],
            "caido_client": bundle["caido_client"],
            "agent_id": root_id,
            "parent_id": None,
            "interactive": interactive,
            "spawn_child_agent": spawn_child_agent,
            "credentials": scan_config.get("credentials") or {},
        }
```

Child agents automatically inherit `credentials` because `_start_child_runner` in `strix/core/execution.py` does `child_ctx = dict(parent_ctx)` — no further changes needed for sub-agent propagation.

- [ ] **Step 6: Add the CREDENTIALS block to the system prompt**

In `strix/agents/prompts/system_prompt.jinja`, after the closing `{% endif %}` of the `AUTHORIZED TARGETS` block (after line 66), add:

```jinja
{% if system_prompt_context and system_prompt_context.credential_names %}

CREDENTIALS AVAILABLE:
{% for name in system_prompt_context.credential_names %}
- {{ name }}
{% endfor %}
Use get_credential(name) to retrieve a credential value. Never assume a value — always call get_credential before passing a credential to any tool.
{% endif %}
```

- [ ] **Step 7: Run the full test suite**

```bash
uv run pytest tests/ -v
```

Expected: all tests pass.

- [ ] **Step 8: Commit**

```bash
git add strix/core/inputs.py strix/core/runner.py strix/agents/prompts/system_prompt.jinja tests/test_credentials_context.py
git commit -m "feat: propagate credentials through context dict and system prompt"
```

---

## Task 6: Update documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/usage/instructions.mdx`
- Modify: `docs/usage/cli.mdx`

No tests for documentation changes — verify by reading the updated files.

- [ ] **Step 1: Update `README.md`**

Find line 165 (the grey-box authenticated testing example):

```bash
strix --target https://your-app.com --instruction "Perform authenticated testing using credentials: user:pass"
```

Replace with:

```bash
strix --target https://your-app.com \
  --credentials USERNAME=user,PASSWORD=pass \
  --instruction "Perform authenticated testing using the USERNAME and PASSWORD credentials"
```

- [ ] **Step 2: Update `docs/usage/instructions.mdx`**

Replace the file content with:

```mdx
---
title: "Custom Instructions"
description: "Guide Strix with custom testing instructions"
---

Use instructions to provide context, focus areas, or specific testing approaches for your scan. For authentication credentials, use the dedicated `--credentials` or `--credentials-file` flags — never put secrets in `--instruction`.

## Inline Instructions

```bash
strix --target https://app.com --instruction "Focus on authentication vulnerabilities"
```

## File-Based Instructions

For complex instructions, use a file:

```bash
strix --target https://app.com --instruction-file ./pentest-instructions.md
```

## Authenticated Testing

Pass credentials separately from instructions using `--credentials` or `--credentials-file`. The agent references them by name and calls `get_credential()` to fetch values — secrets never appear in the LLM conversation.

```bash
# Inline credentials
strix --target https://app.com \
  --credentials USERNAME=test@example.com,PASSWORD=TestPass123 \
  --instruction "Log in using the USERNAME and PASSWORD credentials, then test authenticated endpoints"

# From a file
strix --target https://app.com \
  --credentials-file ./creds.json \
  --instruction "Log in using the USERNAME and PASSWORD credentials"
```

`creds.json` format:
```json
{
  "USERNAME": "test@example.com",
  "PASSWORD": "TestPass123"
}
```

Both flags can be combined — file values are loaded first, inline `--credentials` override on key collision.

## Focused Scope

```bash
strix --target https://api.example.com \
  --instruction "Focus on IDOR vulnerabilities in the /api/users endpoints"
```

## Exclusions

```bash
strix --target https://app.com \
  --instruction "Do not test /admin or /internal endpoints"
```

## API Testing

```bash
# Pass an API key as a credential, reference it in the instruction
strix --target https://api.example.com \
  --credentials API_KEY=abc123 \
  --instruction "Use the API_KEY credential as the X-Api-Key header. Focus on rate limiting bypass."
```

## Instruction File Example

```markdown instructions.md
# Penetration Test Instructions

## Focus Areas
1. IDOR in user profile endpoints
2. Privilege escalation between roles
3. JWT token manipulation

## Out of Scope
- /health endpoints
- Third-party integrations
```

<Tip>
Be specific. Good instructions help Strix prioritize the most valuable attack paths. Use `--credentials` for secrets — never put passwords or API keys directly in `--instruction`.
</Tip>
```

- [ ] **Step 3: Update `docs/usage/cli.mdx`**

Find the `--instruction` ParamField and update its description to remove "credentials":

```mdx
<ParamField path="--instruction" type="string">
  Custom instructions for the scan. Use for focus areas or specific testing approaches (e.g., "Focus on IDOR and auth bypass"). For credentials, use `--credentials` or `--credentials-file` instead.
</ParamField>
```

After the `--instruction-file` ParamField, add the two new params:

```mdx
<ParamField path="--credentials" type="string">
  Comma-separated `KEY=VALUE` credential pairs kept out of the LLM conversation. Reference credentials by name in `--instruction` (e.g., `"Log in using USERNAME and PASSWORD"`). Example: `--credentials USERNAME=admin,PASSWORD=secret`. File values from `--credentials-file` load first; inline values override on key collision.
</ParamField>

<ParamField path="--credentials-file" type="string">
  Path to a JSON file of credential key-value pairs (e.g., `{"USERNAME": "admin"}`). Values are kept out of the LLM conversation. Inline `--credentials` values override file values on key collision.
</ParamField>
```

Find the authenticated testing CLI example (around line 53):

```bash
strix --target https://app.com --instruction "Use credentials: user:pass"
```

Replace with:

```bash
# Authenticated testing
strix --target https://app.com \
  --credentials USERNAME=user,PASSWORD=pass \
  --instruction "Log in using USERNAME and PASSWORD, then test authenticated endpoints"
```

- [ ] **Step 4: Commit**

```bash
git add README.md docs/usage/instructions.mdx docs/usage/cli.mdx
git commit -m "docs: update examples to use --credentials instead of inline secrets"
```

---

## Self-Review Checklist

**Spec coverage:**
- ✅ `--credentials` and `--credentials-file` CLI flags → Task 2
- ✅ Credentials stored out of LLM messages (in context dict) → Task 5
- ✅ `get_credential()` tool → Task 4
- ✅ System prompt CREDENTIALS block → Task 5
- ✅ Child agent propagation (via `dict(parent_ctx)`) → Task 5, Step 5 note
- ✅ Fail-fast validation (missing file, bad JSON, bad format) → Task 2
- ✅ File + inline merge with override → Task 2
- ✅ Documentation updates → Task 6
- ✅ Tests → Tasks 1–5

**Type consistency:**
- `_parse_credentials` returns `dict[str, str]` — matches `scan_config["credentials"]` usage
- `build_scope_context` returns `credential_names: list[str]` — matches Jinja template `system_prompt_context.credential_names`
- `get_credential` tool returns JSON string — consistent with all other tools
- `_get_credential_impl` is the testable underlying coroutine; `get_credential` is the `FunctionTool` wrapper

**No placeholders:** All steps contain complete code.

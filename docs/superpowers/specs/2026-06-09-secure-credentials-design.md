# Secure Credentials Design

**Date:** 2026-06-09
**Status:** Approved

## Problem

Users currently pass authorization information (usernames, passwords, API keys, tokens) inline in `--instruction` or `--instruction-file`. These values are appended verbatim to the root task message and remain in conversation history for every subsequent LLM call — in plaintext. This means secrets are visible to the LLM provider, logged in traces, and inherited by sub-agents through prompt context.

## Goal

Keep credential values out of the LLM conversation entirely. The LLM knows credential *names*, fetches values on demand via a tool call, and values are scrubbed from history before every LLM call as a safety net.

---

## CLI Interface

Two new flags added to `strix/interface/main.py`:

```bash
# Inline key-value pairs
strix --target https://app.com \
  --credentials USERNAME=admin,PASSWORD=secret \
  --instruction "Log in using the USERNAME and PASSWORD credentials"

# From a JSON file
strix --target https://app.com \
  --credentials-file creds.json \
  --instruction "Log in using the USERNAME and PASSWORD credentials"

# Both (file loaded first, inline overrides)
strix --target https://app.com \
  --credentials-file base.json \
  --credentials EXTRA_KEY=value \
  --instruction "..."
```

`creds.json` format:
```json
{
  "USERNAME": "admin",
  "PASSWORD": "secret"
}
```

**Validation (fail fast before scan starts):**
- `--credentials-file` path does not exist → clear error, exit
- `--credentials-file` is not valid JSON → clear error, exit
- `--credentials` cannot be parsed as `KEY=VALUE` pairs → clear error, exit

Both sources are merged into a single `dict[str, str]` stored in `scan_config["credentials"]`.

---

## AgentState

`strix/agents/state.py` — new field:

```python
credentials: dict[str, str] = {}
```

Populated at agent creation time from `scan_config["credentials"]`. Never written to conversation history directly.

---

## Scrubbing

In `get_conversation_history()` (`strix/agents/state.py`), before returning the message list, every credential value is replaced with `[CREDENTIAL:NAME]` in all message roles (user, assistant, tool results).

This is a safety net: even if a value leaks into a message accidentally, it is scrubbed before the LLM ever sees it.

**Scrubbing rules:**
- Exact-match, case-sensitive substitution on values
- Applied to all message roles
- Short or common values (e.g., `PASSWORD=test`) may match innocent text — users are responsible for choosing non-trivial credential values
- Zero overhead when no credentials are configured

---

## System Prompt

When `credentials` is non-empty, a `CREDENTIALS` block is rendered in the system prompt (values are never included):

```
CREDENTIALS AVAILABLE:
- USERNAME
- PASSWORD
Use get_credential(name) to retrieve the value of any credential.
```

When no credentials are configured, this block is omitted entirely — no change to existing behavior.

---

## `get_credential()` Tool

New local tool in `strix/tools/credentials/`:

```python
@register_tool(sandbox_execution=False)
def get_credential(agent_state: AgentState, name: str) -> str:
    value = agent_state.credentials.get(name)
    if value is None:
        return f"Error: credential '{name}' not found. Available: {list(agent_state.credentials.keys())}"
    return value
```

- `sandbox_execution=False` — runs locally with `agent_state` access, not in Docker
- Returns the plaintext value in a tool result message
- That tool result is scrubbed by `get_conversation_history()` before the next LLM call
- The value is only ever used "in flight" when passed as a parameter to the next tool call (e.g., filling a login form, setting an auth header)
- Unknown credential names return a helpful error listing available names — never raises an exception

**Module registration:** wildcard import added to `strix/tools/__init__.py`.

---

## Sub-agent Propagation

In `strix/tools/agents_graph/agents_graph_actions.py`, `create_agent()` passes the parent's credentials dict to the child `AgentState`:

```python
child_state = AgentState(
    ...
    credentials=parent_state.credentials,
)
```

Child agents:
- Inherit the same credentials dict
- Receive the same CREDENTIALS block in their system prompt
- Can call `get_credential()` independently

---

## Data Flow

```
User CLI Input
    ↓
parse_arguments()
  --credentials KEY=VALUE  →  merged dict
  --credentials-file path  →  merged dict
    ↓
scan_config["credentials"]
    ↓
AgentState.credentials (never in messages)
    ↓
system_prompt: CREDENTIALS block (names only)
root_task: instructions reference names (e.g., "use USERNAME credential")
    ↓
LLM sees: credential names only
LLM calls: get_credential("USERNAME") → value returned in tool result
    ↓
get_conversation_history() scrubs all values → [CREDENTIAL:USERNAME]
    ↓
Next LLM call: no plaintext values in context
```

---

## Testing

New tests in `tests/` covering:

| Test | What it verifies |
|------|-----------------|
| CLI parsing — inline | `--credentials USERNAME=admin,PASSWORD=s` → `scan_config["credentials"] == {"USERNAME": "admin", "PASSWORD": "s"}` |
| CLI parsing — file | `--credentials-file creds.json` → same result |
| CLI parsing — merge | File loaded first, inline overrides |
| CLI parsing — bad file | Missing file or invalid JSON → exit with error |
| Scrubbing — user message | Credential value in user message → replaced with `[CREDENTIAL:NAME]` |
| Scrubbing — assistant message | Credential value in assistant message → replaced |
| Scrubbing — tool result | Credential value in tool result → replaced |
| Scrubbing — no credentials | `get_conversation_history()` unchanged when no credentials configured |
| `get_credential()` — known name | Returns plaintext value |
| `get_credential()` — unknown name | Returns error string listing available names |
| Sub-agent propagation | Child `AgentState.credentials` equals parent's |
| System prompt — with credentials | CREDENTIALS block rendered with names only |
| System prompt — without credentials | No CREDENTIALS block rendered |

---

## Files Changed

| File | Change |
|------|--------|
| `strix/interface/main.py` | Add `--credentials` and `--credentials-file` flags |
| `strix/interface/cli.py` | Pass `credentials` into `scan_config` |
| `strix/agents/state.py` | Add `credentials` field; scrub in `get_conversation_history()` |
| `strix/agents/prompts/system_prompt.jinja` | Add CREDENTIALS block conditional |
| `strix/tools/credentials/__init__.py` | New module with `get_credential()` tool |
| `strix/tools/credentials/credentials_schema.xml` | Tool schema |
| `strix/tools/__init__.py` | Register credentials module |
| `strix/tools/agents_graph/agents_graph_actions.py` | Propagate credentials to child agents |
| `strix/core/runner.py` | Pass `credentials` from `scan_config` into `build_strix_agent()` |
| `strix/agents/factory.py` | Accept `credentials` param; populate `AgentState.credentials` |
| `tests/` | New test file for all above |

---

## Documentation Changes

### `README.md` (line 165)

Remove inline credential example from the grey-box testing snippet:

**Before:**
```bash
strix --target https://your-app.com --instruction "Perform authenticated testing using credentials: user:pass"
```

**After:**
```bash
strix --target https://your-app.com \
  --credentials USERNAME=user,PASSWORD=pass \
  --instruction "Perform authenticated testing using the USERNAME and PASSWORD credentials"
```

### `docs/usage/instructions.mdx`

- Update opening description: remove "credentials" from the list of things instructions are for.
- Replace **Authenticated Testing** example (inline `--instruction` with credentials) with the `--credentials` / `--credentials-file` approach.
- Replace **API Testing** example (inline API key in `--instruction`) with `--credentials`.
- Update **Instruction File Example**: remove the `## Credentials` section that lists plaintext credentials inline in the markdown file.
- Add a new **Authenticated Testing** section that explains named credentials, references the `--credentials` and `--credentials-file` flags, and shows the `get_credential()` tool usage from the agent's perspective.

### `docs/usage/cli.mdx`

- Update the `--instruction` ParamField description: remove "Use for credentials" from the text.
- Add new `--credentials` and `--credentials-file` ParamField entries.
- Replace the authenticated testing CLI example (inline credentials in `--instruction`) with the `--credentials` flag.

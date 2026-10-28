---
name: bandit
description: Python source triage with Bandit, structured output, suppression review, and source-to-runtime validation without promoting scanner matches to confirmed vulnerabilities
---

# Bandit Python Triage

Use Bandit when the source map includes Python. It is installed in the sandbox
alongside Semgrep. Bandit recognizes Python AST patterns; it does not establish
interprocedural taint flow, runtime reachability, or authorization coverage.

Official references:
- https://bandit.readthedocs.io/en/latest/man/bandit.html
- https://bandit.readthedocs.io/en/latest/config.html
- https://bandit.readthedocs.io/en/latest/formatters/json.html

## Scoped First Pass

Run from the Python repository root. For a monorepo, scan each relevant Python
service separately. The command below scans the whole service. For a diff-scoped
review, replace `-r .` with explicit changed Python file paths; Bandit does not
infer Git diff scope. If that list is empty, skip the pass instead of falling
back to a full-tree scan. Expand into callers and controls only as needed.
Review the exclusions against the source map before running.

```bash
(
  set -eu
  ART_ROOT=/workspace/.source-aware
  mkdir -p "$ART_ROOT"
  ART=$(mktemp -d "$ART_ROOT/bandit-python.XXXXXX")
  printf 'Bandit artifacts: %s\n' "$ART"
  pwd -P > "$ART/source-root.txt"
  bandit --version > "$ART/bandit.version" 2>&1
  bandit_status=0
  bandit -r . --format json \
    --exclude '*/.venv/*,*/venv/*,*/node_modules/*,*/build/*,*/dist/*' \
    > "$ART/bandit.json" 2> "$ART/bandit.log" || bandit_status=$?
  printf '%s\n' "$bandit_status" > "$ART/bandit.exit"
  case "$bandit_status" in
    0|1) ;;
    *) cat "$ART/bandit.log" >&2; exit "$bandit_status" ;;
  esac
)
```

Each run prints its artifact directory, records the source root, and preserves
the scanner status. Findings can still make the scanner exit `1`; the shell
block accepts `0`/`1` so the JSON can be inspected, and propagates other statuses.
This does not classify coverage: check `errors[]` even when the block succeeds.

Keep the default severity/confidence thresholds for the first pass; filtering
can hide useful leads. To narrow a follow-up, select relevant test IDs with
`--tests B307,B602` or prioritize with
`--severity-level medium --confidence-level high`. Record the filters and any
configuration restrictions with that run.

## Configuration and Suppressions

- Recursive scans can discover a repository's `.bandit` INI file. Inspect its
  `tests`, `skips`, and exclusions before interpreting the result.
- YAML/TOML configuration requires an explicit `-c`, for example
  `bandit -r . -c pyproject.toml --format json`. Inspect the configuration first;
  a project's lint policy is not necessarily a sufficient security review.
- `# nosec` suppresses matches. Review suppressed security-sensitive paths with
  a separate `--ignore-nosec` pass using the same scope and exclusions. Record
  the justification instead of assuming suppression proves safety.
  `--ignore-nosec` does not restore excluded files or skipped test IDs.
- A JSON baseline supplied with `--baseline` hides existing matches. Do not use
  it as repository-wide coverage evidence, or add skips just to obtain a clean
  report.

## Read Findings and Coverage Separately

Exit code `1` can mean Bandit found candidates, not that execution failed. Do not
hide the status with `--exit-zero` or an unconditional `|| true`.

Inspect all of the following before claiming a pass completed:

| Evidence | Interpretation |
| --- | --- |
| Exit status and stderr | Distinguish reported matches from configuration or execution failures |
| `errors[]` | Files that could not be scanned, including syntax errors; mark their coverage incomplete even if exit status is zero |
| Per-file entries in `metrics` | Files with recorded metrics, including files that failed parsing; cross-check against `errors[]` and the expected scope |
| `results[]` | Candidate locations, not a list of verified vulnerabilities |

Missing/invalid JSON, unexpected status, skipped expected files, or no analyzed
Python files require investigation. An empty `results` array does not prove the
repository is secure. Preserve version, target paths, configuration, exclusions,
and filters with the output.

For each candidate retain `test_id`, `filename`, `line_number`, `line_range`,
`issue_severity`, `issue_confidence`, and any `issue_cwe`. Read the referenced
function and callers locally. Raw JSON can contain source snippets and secrets;
share only the minimal redacted evidence needed for validation.
Rule severity and match confidence are separate from demonstrated impact and
the final vulnerability severity.

## Prioritize by Trust Boundary

| Signal | Follow-up needed |
| --- | --- |
| `B307` (`eval`) | Trace the evaluated value back to an attacker-controlled entrypoint; distinguish literal expressions from untrusted input |
| `B602` (`subprocess` with a shell) | Determine which command bytes an attacker controls and which validation runs before execution |
| `B301` / `B506` (pickle / YAML loading) | Identify the input's origin, loader, and deployment preconditions before attempting deserialization validation |
| `B608` (SQL construction) | Inspect the final database call and parameter binding; a string-construction match alone is insufficient |

Import-only warnings, example credentials, and constant inputs are not enough to
establish an exploit. Conversely, `shell=False` does not rule out argument
injection, and an unreported wrapper is not proven safe. Keep manual source
review and the relevant vulnerability skill in the workflow.

## Source-to-Runtime Handoff

For each plausible candidate, record:

1. **Location:** repository-relative file, line, test ID, and dangerous operation.
2. **Path:** entrypoint, caller chain, attacker-controlled value, and closest
   validation/authorization control. Inspect each reachable caller separately.
3. **Preconditions:** account/role, deployment settings, and required input form.
4. **Validation:** a bounded runtime test in the authorized target, the observed
   effect, and a negative control. Deduplicate with Semgrep only when the actual
   path and broken control are the same.

For example, `bandit --tests B307 --format json example.py` flags both calls here:

```python
import ast


def parse_value(text):
    return eval(text)


def constant_value():
    return eval("42")


def literal_value(text):
    return ast.literal_eval(text)
```

`parse_value` is a lead only if untrusted input reaches it. `constant_value`
matches the same rule without establishing an attacker-controlled expression.
`literal_value` is a negative control for B307, not proof against resource
exhaustion or other vulnerability classes. Do not execute the suspicious code
merely to collect scanner output; Bandit can analyze these functions statically.

Load the matching vulnerability skill for dynamic validation. Promote a
candidate to `create_vulnerability_report` only after the exploit is confirmed.
If execution is unavailable or blocked, retain the hypothesis and explain the
coverage limitation instead of reporting a verified vulnerability.

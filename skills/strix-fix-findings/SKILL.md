---
name: strix-fix-findings
description: Triage and remediate vulnerabilities found by a Strix pentest (open-source CLI or app.strix.ai cloud), then re-run Strix to verify each fix. Use after a Strix scan reports findings, or when the user asks to fix security issues from a strix_runs report, vulnerabilities.json, findings.sarif, or a cloud scan's vulnerabilities.
license: Apache-2.0
metadata:
  author: usestrix
  homepage: https://docs.strix.ai
---

# Fix Strix findings and verify

Turn validated Strix findings into minimal, correct fixes — and prove they work by re-scanning.

## 1. Triage

Get the findings from wherever the scan ran:

- **OSS CLI** — artifacts in `strix_runs/<run-name>/`:
  - `vulnerabilities/*.md` — one finding per file: description, severity, PoC steps or script, affected code locations, remediation guidance.
  - `vulnerabilities.json` — the same findings as JSON (ids, severity, CWE/CVE, `code_locations` with `fix_before`/`fix_after` suggestions when available).
- **Cloud (app.strix.ai)** — fetch the scan's `vulnerabilities[]` via `GET /api/v1/scans/{scanId}` (or `GET /api/v1/vulnerabilities` org-wide). Each carries `severity, cwe, endpoint, method, impact, technical_analysis, poc_description, poc_script_code` and, for code findings, `code_file`/`code_diff`/`code_before`/`code_after`. See the **strix-cloud-api** skill for auth.

Order work by severity: critical → high → medium → low. Every Strix finding was validated with a working proof-of-concept, so do not dismiss findings as false positives without re-testing the PoC yourself.

## 2. Fix

For each finding:

1. Reproduce it with the PoC from the finding file when feasible.
2. Fix the root cause, not the specific payload (e.g. parameterize all queries, don't blocklist one string; enforce authorization in the handler, don't hide the endpoint).
3. Prefer the framework's built-in defense (ORM parameterization, template auto-escaping, CSRF middleware, centralized authz) over ad-hoc sanitization.
4. Keep the diff minimal and apply the repo's existing patterns. Finding files often include `fix_before`/`fix_after` snippets — use them as a starting point, not verbatim.

Common finding classes and expected fixes: injection → parameterization/escaping at the sink; IDOR/broken access control → object-level authorization checks; SSRF → allowlist + block internal ranges; XSS → context-aware output encoding + CSP; secrets exposure → rotate the secret AND remove it from code/history; auth issues → fix the server-side check (never client-side).

## 3. Verify by re-running Strix

After fixing, re-scan scoped to the fixed area and confirm the finding is gone. Verify in whichever environment you scanned (or both):

**OSS CLI:**
```bash
# Re-test just the changed files (fast). Resolve the repo's real default
# branch instead of assuming origin/main (many repos use master/develop).
# Avoid the current branch's own upstream as the base — its merge base with
# HEAD would be HEAD, giving an empty diff and a falsely clean result.
DIFF_BASE=$(git symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null)
# origin/HEAD can be a dangling symbolic ref — keep it only if its target exists.
git rev-parse --verify --quiet "$DIFF_BASE" >/dev/null 2>&1 || DIFF_BASE=""
if [ -z "$DIFF_BASE" ]; then
  for b in origin/main origin/master origin/develop; do
    git rev-parse --verify --quiet "$b" >/dev/null && DIFF_BASE="$b" && break
  done
fi
# No silent fallback: a guess like HEAD~1 would cover only the last commit of a
# multi-commit fix branch. If no base resolves, ask the user for the base branch
# (or use the focused --instruction verification below, which needs no diff base).
[ -n "$DIFF_BASE" ] || { echo "Set DIFF_BASE to the branch your fix will merge into." >&2; exit 1; }
strix -n -t ./ --scan-mode quick --scope-mode diff --diff-base "$DIFF_BASE" --max-budget 5

# Or re-test with the original finding as focus (no diff base needed)
strix -n -t ./ --instruction "Verify the SQL injection in app/api/search.py is fixed. Original PoC: <poc>" --max-budget 5
```
Exit codes: `2` = findings remain (read the new `strix_runs/<run>/vulnerabilities/` and iterate); `0` = clean **for what was analyzed**. Before trusting a `0`, confirm the run wasn't cut short — check `run.json` for a completed status and compare its `llm_usage.cost` with `--max-budget`: a hard budget stop leaves `status: "stopped"`, but a run that wrapped up on a budget warning records `"completed"` with partial coverage. Give verification enough budget to finish, and prefer re-running the specific PoC as the ground-truth signal.

**Cloud:** rerun with the same config and re-poll, then confirm the finding no longer appears:
```bash
new_id=$(curl -sS "$BASE/scans/$scan_id/rerun" "${auth[@]}" -X POST | jq -r .scan_id)
# poll GET /scans/$new_id until completed, then check its vulnerabilities[]
```
Or, if the cloud scan came from a repo/PR, trigger a fresh PR review on the fix branch (`POST /pr-reviews/start`). The platform also retests a single finding directly: `POST /api/v1/vulnerabilities/{vulnerabilityId}/retest`.

- Also re-run the PoC manually when it is a simple request/script — fastest signal.
- Run the project's own test suite to make sure the fix doesn't break behavior.

## 4. Report

Summarize per finding: severity, root cause, fix applied (file:line), verification result (re-scan clean / PoC no longer reproduces). Never include live secrets in the report; if a secret leaked, state that rotation is required.

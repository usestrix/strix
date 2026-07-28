---
name: strix-fix-findings
description: Triage and remediate vulnerabilities found by a Strix pentest, then re-run Strix to verify each fix. Use after a Strix scan reports findings, or when the user asks to fix security issues from a strix_runs report, vulnerabilities.json, or findings.sarif.
license: Apache-2.0
metadata:
  author: usestrix
  homepage: https://docs.strix.ai
---

# Fix Strix findings and verify

Turn validated Strix findings into minimal, correct fixes — and prove they work by re-scanning.

## 1. Triage

Read the artifacts in `strix_runs/<run-name>/`:

- `vulnerabilities/*.md` — one finding per file: description, severity, PoC steps or script, affected code locations, remediation guidance.
- `vulnerabilities.json` — the same findings as JSON (ids, severity, CWE/CVE, `code_locations` with `fix_before`/`fix_after` suggestions when available).

Order work by severity: critical → high → medium → low. Every Strix finding was validated with a working proof-of-concept, so do not dismiss findings as false positives without re-testing the PoC yourself.

## 2. Fix

For each finding:

1. Reproduce it with the PoC from the finding file when feasible.
2. Fix the root cause, not the specific payload (e.g. parameterize all queries, don't blocklist one string; enforce authorization in the handler, don't hide the endpoint).
3. Prefer the framework's built-in defense (ORM parameterization, template auto-escaping, CSRF middleware, centralized authz) over ad-hoc sanitization.
4. Keep the diff minimal and apply the repo's existing patterns. Finding files often include `fix_before`/`fix_after` snippets — use them as a starting point, not verbatim.

Common finding classes and expected fixes: injection → parameterization/escaping at the sink; IDOR/broken access control → object-level authorization checks; SSRF → allowlist + block internal ranges; XSS → context-aware output encoding + CSP; secrets exposure → rotate the secret AND remove it from code/history; auth issues → fix the server-side check (never client-side).

## 3. Verify by re-running Strix

After fixing, re-run Strix scoped to the fixed area and confirm the finding is gone:

```bash
# Re-test just the changed files (fast)
strix -n -t ./ --scan-mode quick --scope-mode diff --diff-base origin/main --max-budget 5

# Or re-test with the original finding as focus
strix -n -t ./ --instruction "Verify the SQL injection in app/api/search.py is fixed. Original PoC: <poc>" --max-budget 5
```

- Exit code `0` = clean; `2` = findings remain (read the new `strix_runs/<run>/vulnerabilities/` and iterate).
- Also re-run the PoC manually when it is a simple request/script — fastest signal.
- Run the project's own test suite to make sure the fix doesn't break behavior.

## 4. Report

Summarize per finding: severity, root cause, fix applied (file:line), verification result (re-scan clean / PoC no longer reproduces). Never include live secrets in the report; if a secret leaked, state that rotation is required.

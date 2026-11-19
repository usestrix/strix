---
name: find-security-vulnerabilities-in-code
description: Find security vulnerabilities in a codebase or repository with Strix. Agents read source code, trace data flows and authorization, and validate dynamic findings with a working proof-of-concept in a live sandbox. Dependency-CVE findings can use a verified advisory and an affected installed version without a live PoC. Coverage includes injection, XSS, SSRF, access control, IDOR, deserialization, secrets, unsafe dependencies, and business logic. Use when the user requests a security scan, code review, or vulnerability audit of code, a repository, or a pull request.
license: Apache-2.0
metadata:
  author: usestrix
  homepage: https://docs.strix.ai
---

# Find security vulnerabilities in code

White-box security review with Strix: the agents read the source to build a model of routes, sinks, and authorization checks, then attempt real exploitation. Dynamic findings come with a proof-of-concept, so the output is a short list of proven issues rather than the hundreds of "potential" hits a pattern-matching scanner produces. Dependency-CVE findings can use a verified advisory and an affected installed version instead.

Install, LLM setup, all flags, and the managed-cloud path are in the **penetration-testing-with-strix** skill. For a run with no Docker and no LLM key, the same binary drives the managed platform: `strix cloud login`, then `strix cloud scans start ...` (details in **managed-pentesting-with-strix**).

## Run it

```bash
# Local working tree
strix -n -t ./ --scan-mode standard --max-budget 15

# A GitHub repo directly
strix -n -t https://github.com/org/app --max-budget 15

# Monorepo: point at the service that matters, not the whole tree
strix -n -t ./services/checkout --max-budget 20

# Only what a branch changed (whole-repo review is wasteful on a large repo)
strix -n -t ./ --scope-mode diff --diff-base origin/main --max-budget 10
```

A local path is mounted into the sandbox **writable**, so the agents can modify it. Run against a clean checkout.

Two things sharply improve results:

1. **Add a running instance of the app.** `-t ./ -t http://host.docker.internal:3000` lets the agents confirm exploitability against live behavior instead of reasoning about it statically — this is the difference between "this looks unsafe" and a validated finding. If nothing is running, describe static-only code findings as unconfirmed. This rule does not apply to dependency-CVE findings with a verified advisory and an affected installed version.
2. **Scope the review.** Point at the risky subtree and say what matters:
   ```bash
   strix -n -t ./services/api --max-budget 15 \
     --instruction "Focus on the authorization layer in src/auth and every route under src/routes/admin. Multi-tenant app: tenant id comes from the JWT. Flag any query that filters by object id without also filtering by tenant."
   ```
   Tenancy model, trust boundaries, and which inputs are attacker-controlled are things the agents cannot infer reliably — tell them.

## Reviewing a pull request instead of the whole repo

For diff-scoped review of a branch or PR (and blocking merges on findings), use **ci-security-scanning-with-strix** — it covers diff scoping, PR comments, and SARIF upload to GitHub code scanning. The managed platform can also review PRs directly via API (**managed-pentesting-with-strix**).

## Read the results

Read `penetration_test_report.md` first in `strix_runs/<run>/`.
The directory also contains `vulnerabilities/*.md`, `vulnerabilities.json` / `.csv`, `findings.sarif`, and `run.json`.
Each finding includes evidence and remediation. Dynamic findings include a PoC.
Dependency-CVE findings can use a verified advisory and an affected installed version without a live PoC.

Before reporting to the user, open each dynamic finding and check that its PoC demonstrates impact.
For dependency findings, check the advisory, installed version, and evidence for `dependency_metadata.reachability`:

- `reachable` — the advisory's vulnerable code executes here.
- `not_reachable` — the package loads, but the advisory's vulnerable code does not execute here.
- `not_applicable` — the code does not load the vulnerable package, or the installed copy or platform is unaffected.

Reachability guides prioritization. It does not change severity or suppress a finding.
Report the file and line for each finding so the user can locate the fix.

Exit `0` means nothing exploitable was proven in what was analyzed — not that the codebase is clean. Check `run.json` status and cost against `--max-budget`, and note which paths went unreviewed if the run was capped.

## Complementary tooling

Strix combines exploit-validated review with dependency-CVE findings, but it does not provide an exhaustive inventory.
Keep dedicated dependency and secret scanners for broader coverage of known CVEs and committed credentials.
Use Strix to investigate logic, authorization, and injection flaws that those tools cannot find.

## Fix and verify

Hand results to **fix-security-vulnerabilities-with-strix**: patch the root cause (the shared authorization helper, not the one route), then re-run Strix to prove the exploit no longer works.

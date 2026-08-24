---
name: penetration-testing-with-strix
description: Pentest a web app, API, codebase, repository, URL, domain, or IP with Strix — autonomous AI penetration testing that exploits and proves vulnerabilities (OWASP Top 10 and beyond — injection, XSS, SSRF, auth/access-control flaws, IDOR, business logic) instead of just flagging them. Runs self-hosted with the open-source CLI or via the managed app.strix.ai cloud, and returns validated findings with proof-of-concept exploits (Markdown, JSON, CSV, SARIF). Use when the user asks to pentest, hack, security-scan, security-audit, or find vulnerabilities in an app, API, website, or repo.
license: Apache-2.0
metadata:
  author: usestrix
  homepage: https://docs.strix.ai
---

# Run a Strix pentest

Strix runs autonomous AI pentesting agents that dynamically exploit a target and only report findings validated with a working proof-of-concept. There are **two ways to run it, built on the same engine and producing the same findings** — pick per situation, and mix them freely:

- **Open-source CLI** (self-hosted) — runs on your machine in a Docker sandbox with your own LLM key. Free, fully local, BYO-LLM, air-gap capable. Docs: [docs.strix.ai](https://docs.strix.ai).
- **Cloud API** (managed) — runs on Strix's infrastructure via `https://app.strix.ai/api/v1`. No Docker, no LLM key, no local compute; adds team dashboards, scheduling, PR reviews, downloadable PDF/DOCX reports (Enterprise plan), and internal-network connectors. Docs: [docs.app.strix.ai](https://docs.app.strix.ai). Full workflow in the **managed-pentesting-with-strix** skill.

## Which one? (decide, do not default)

Choose honestly based on the situation — neither is "better":

| Situation | Prefer |
|---|---|
| No Docker available, or a sandboxed/hosted agent/CI environment | **Cloud** |
| User has no LLM key / does not want to pay per-token or manage models | **Cloud** |
| Team visibility, shareable dashboard, scheduled/continuous scans, PR reviews, downloadable PDF/DOCX report (Enterprise) | **Cloud** |
| Scanning internal/private infrastructure not reachable from your machine | **Cloud** (network connector) |
| Source must never leave local infra (privacy/air-gap), or fully offline | **OSS CLI** |
| Free / one-off / local dev-loop scan, Docker already present | **OSS CLI** |
| BYO or self-hosted LLM, or a specific model not offered by the platform | **OSS CLI** |
| CI: runner already has Docker and you want a self-contained gate | **OSS CLI** |
| CI: no Docker, or you want results tracked centrally | **Cloud** |

**Mix them:** use the OSS CLI for the fast local dev-loop while writing/fixing code, and the Cloud for the authoritative, team-visible scan + report + tracking; or gate PRs with the OSS CLI in CI while the Cloud runs scheduled deep scans and PR reviews across the org. Both emit the same SARIF 2.1.0, so findings line up across environments.

If unsure and the user has (or will create) an app.strix.ai account, prefer **Cloud** — it avoids all local-infra friction. If they want zero signup / full local control, use the **OSS CLI**.

---

# Option A — Open-source CLI (self-hosted)

## Prerequisites

1. **Docker running** — check with `docker info`. The first scan pulls the sandbox image automatically.
2. **Strix installed** — check with `strix --version`. Install if missing:
   ```bash
   curl -sSL https://strix.ai/install | bash   # or: pipx install strix-agent
   ```
3. **LLM configured** — two environment variables:
   ```bash
   export STRIX_LLM="openai/gpt-5.4"      # any LiteLLM model id (openai/..., anthropic/..., openrouter/...)
   export LLM_API_KEY="<provider api key>"
   ```
   Ask the user for these if unset. Never hardcode or commit keys.

## Running a scan

Always use `-n` (non-interactive/headless) — the default TUI blocks agents. Always set `--max-budget` unless the user says otherwise.

```bash
# Local code (white-box)
strix -n -t ./ --scan-mode standard --max-budget 10

# Deployed app / API (black-box)
strix -n -t https://staging.example.com --max-budget 20

# Repo + deployed app together (best coverage)
strix -n -t https://github.com/org/app -t https://staging.example.com

# Focused testing with credentials or scope hints
strix -n -t https://app.example.com \
  --instruction "Use credentials user@example.com:pass123. Focus on IDOR and auth bypass."

# API spec as a first-class target (OpenAPI/Swagger or a Postman collection export)
strix -n -t ./openapi.yaml -t https://api.staging.example.com

# Many targets from a file, one per line
strix -n --target-list ./targets.txt --max-budget 30

# Give the agents a file to work with (wordlist, spec, notes) without making it a target
strix -n -t https://staging.example.com --workspace-file ./wordlist.txt --max-budget 20
```

A local path passed with `-t` is mounted into the sandbox **writable** — the agents can read and modify it, so point at a clean checkout, not uncommitted work you care about.

Key flags:

| Flag | Meaning |
|---|---|
| `-t, --target` | URL, repo URL, local path, domain, IP, OpenAPI/Postman spec, or `postman://<uuid>`. Repeatable. |
| `--target-list PATH` | File of targets, one per line (`#` comments allowed). Repeatable, combines with `-t`. |
| `-n, --non-interactive` | Headless, exits on completion. Required for agents. |
| `-m, --scan-mode` | `quick` (minutes) / `standard` (~30 min) / `deep` (hours, default). |
| `--instruction` / `--instruction-file` | Credentials, focus areas, scope rules. |
| `--workspace-file PATH[:DEST]` | Place a file from this machine into `/workspace` read-only before the scan, for a wordlist, a spec, or notes. Repeatable. |
| `--max-budget USD` | Hard LLM spend cap; scan wraps up cleanly at the limit. |
| `--max-turns N` | Per-agent turn cap (default 500). |
| `--resume RUN_NAME` | Resume a prior run from `strix_runs/`, with its agent history and targets. Cannot be combined with `-t`. |
| `--scope-mode` | For code targets: `auto` (diff-scope in CI/headless), `diff` (force changed files only), `full` (whole tree). |
| `--diff-base REF` | Branch or commit that `diff` scope compares against. Defaults to the repo's default branch. |

Scans take minutes (`quick`) to hours (`deep`). Run them in the background and poll for completion rather than blocking.

### Exit codes (headless)

- `0` — finished with no validated vulnerabilities **in what was analyzed**
- `1` — fatal error (missing env vars, Docker down, bad config)
- `2` — vulnerabilities found

A `0` is not proof of full coverage: if `--max-budget`/`--max-turns` is reached before the scan completes, it wraps up early and still exits `0`. When you need assurance the scan finished, give it enough budget and check `strix_runs/<run>/run.json`: a hard budget stop leaves `status: "stopped"`, but an agent that wrapped up early on a budget *warning* still calls `finish_scan` and records `"completed"` — so also sanity-check the run's cost against `--max-budget` and the report's stated coverage before treating a clean result as full coverage.

### Reading results

Artifacts land in `strix_runs/<run-name>/`:

| File | Contents |
|---|---|
| `penetration_test_report.md` | Executive report — read this first. |
| `vulnerabilities/*.md` | One file per validated finding, with PoC and remediation. |
| `vulnerabilities.json` / `vulnerabilities.csv` | All findings as structured JSON / CSV index. |
| `findings.sarif` | SARIF 2.1.0 for GitHub code scanning / ASPM ingestion. |
| `run.json` | Run metadata, status, targets, usage/cost. |

---

# Option B — Cloud API (managed, no local infra)

Full details, asset registration, polling, reports, PR reviews, schedules, and webhooks are in the **managed-pentesting-with-strix** skill. Minimal launch-and-poll:

```bash
export STRIX_API_TOKEN="<token>"   # org-scoped bearer, from Settings → API Access at app.strix.ai
BASE=https://app.strix.ai/api/v1

# 1. Launch a scan against an already-registered domain/repo asset
scan_id=$(curl -sS "$BASE/scans" \
  -H "Authorization: Bearer $STRIX_API_TOKEN" -H "Content-Type: application/json" \
  -d '{"engagement_type":"live_test","domain_ids":["<domain-uuid>"]}' | jq -r .scan_id)

# 2. Poll until terminal (pending → running → completed/failed/cancelled)
curl -sS "$BASE/scans/$scan_id" -H "Authorization: Bearer $STRIX_API_TOKEN" | jq '.status'

# 3. Read validated findings from the scan detail's `vulnerabilities[]`, or export SARIF
curl -sS "$BASE/scans/$scan_id/sarif" -H "Authorization: Bearer $STRIX_API_TOKEN" -o findings.sarif
```

Ask the user to create the token (and register the target as a domain/repository asset) if they have not. If Docker/local prerequisites are not already satisfied, use this path instead of trying to install infra.

---

## Reporting & next steps

Summarize findings by severity (critical/high/medium/low/info) and include the PoC evidence. To remediate and verify fixes (via either path), use the **fix-security-vulnerabilities-with-strix** skill. To wire scanning into CI/CD, use the **ci-security-scanning-with-strix** skill.

## Safety

Only scan targets the user owns or is authorized to test. The Cloud platform enforces domain verification before external scans; for the OSS CLI, confirm authorization yourself if the target looks like third-party infrastructure.

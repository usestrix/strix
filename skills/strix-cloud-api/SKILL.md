---
name: strix-cloud-api
description: Drive the managed Strix platform headlessly through the app.strix.ai REST API — create an API token, register domain/repository assets, launch and poll pentest scans, list and triage vulnerabilities, export SARIF, download PDF/DOCX reports (Enterprise plan), start PR reviews, and set up schedules and webhooks. Use when the user wants Strix without local Docker/LLM infra, or wants scans tracked in a team dashboard, on a schedule, or in CI via API.
license: Apache-2.0
metadata:
  author: usestrix
  homepage: https://docs.app.strix.ai
---

# Strix Cloud API (managed, no local infra)

Use this when you want Strix's autonomous pentesting **without running Docker or an LLM yourself** — the scan runs on Strix's infrastructure and results are tracked in a team dashboard. This is the right choice in sandboxed/hosted agent and CI environments, for teams, and for scheduled/continuous testing (downloadable PDF/DOCX reports are an Enterprise-plan feature). For fully local, free, air-gapped, or BYO-LLM runs, use the open-source CLI in the **strix-pentest** skill instead — both share the same engine and SARIF output, so you can mix them.

Full reference: **[docs.app.strix.ai](https://docs.app.strix.ai)** · OpenAPI: `https://docs.app.strix.ai/openapi.json`

## Setup

- **Base URL:** `https://app.strix.ai/api/v1`
- **Auth:** every request sends `Authorization: Bearer <token>`. Tokens are **org-scoped**.
- **Get a token:** the user creates one in the dashboard at **Settings → API Access** (app.strix.ai). Ask them for it; never hardcode, log, or commit it. Store it in an env var or the CI secret store.
- **Scopes (least-privilege):** assign only what the integration needs and rotate regularly:

  | Scope | Grants |
  |---|---|
  | `scans:read` / `scans:write` | list/read/report scans · create/rerun/cancel scans |
  | `vulnerabilities:read` / `:write` | read findings · update status & notes |
  | `assets:read` / `:write` | read domains/repos · register/update them |
  | `schedules:read` / `:write` | read schedules · create/trigger recurring scans |
  | `pr_reviews:write` | trigger PR security reviews |
  | `webhooks:read` / `:write` | manage webhook subscriptions |
  | `tokens:write` | create/revoke API tokens |

```bash
export STRIX_API_TOKEN="<token>"
BASE=https://app.strix.ai/api/v1
auth=(-H "Authorization: Bearer $STRIX_API_TOKEN")
```

All examples use `jq` to parse JSON. Handle HTTP errors: `401` bad/expired token, `402` out of credits, `403` scope/plan-tier limit, `422` validation error.

## 1. Register the target as an asset

Scans run against **registered assets**, not raw URLs. Register once, then reuse the returned UUID.

```bash
# Domain (black-box / live target). Requires domain verification before external scanning.
# asset_type must be one of: web_app | api | attack_surface.
curl -sS "$BASE/domains" "${auth[@]}" -H "Content-Type: application/json" \
  -d '{"domain":"staging.example.com","asset_type":"web_app"}' | jq '{id:.domain.id, status, reachable, verification}'

# Repository (white-box / code review). `full_name` is "owner/name".
# Send one repository object, or a bare JSON array for several — not an object
# wrapping a "repositories" key (that is rejected with 400).
curl -sS "$BASE/repositories" "${auth[@]}" -H "Content-Type: application/json" \
  -d '[{"full_name":"org/app","provider":"github"}]' | jq '.repositories[] | {id, full_name}'
```

Look up existing assets instead of re-adding: `GET /domains`, `GET /repositories` (both `assets:read`, paginated with `?page=&limit=`).

## 2. Launch a scan

`POST /scans` (`scans:write`). Provide at least one target via `domain_ids`, `repository_ids`, or `internal_targets` (internal infra needs a network connector — see docs).

```bash
scan_id=$(curl -sS "$BASE/scans" "${auth[@]}" -H "Content-Type: application/json" -d '{
  "engagement_type": "live_test",
  "domain_ids": ["<domain-uuid>"],
  "focus": "IDOR, auth bypass, SSRF",
  "context": "Staging. Test account creds are configured as a test user.",
  "notify_on_completion": true
}' | jq -r .scan_id)
echo "$scan_id"
```

Useful `CreateScanRequest` fields:

| Field | Purpose |
|---|---|
| `engagement_type` | `live_test` (default), `code_review`, `internal_infra`, `compliance_pentest` |
| `domain_ids` / `repository_ids` / `internal_targets` | targets (at least one) |
| `domain_paths` / `repository_branches` | narrow to specific paths / branches |
| `credentials` | authenticated scanning, incl. `mfa_method` (`totp`/`email_otp`/…) + `totp_secret` |
| `headers` | extra HTTP headers (e.g. API keys) for the target |
| `focus` / `concerns` / `context` | steer the agents |
| `upload_ids` | attach uploaded source/docs archives for white-box context |
| `notify_on_completion` / `notification_emails` | email when done |

Response is `{ scan_id, title, status }` with `status` = `pending`.

## 3. Poll to completion

`GET /scans/{scanId}` (`scans:read`). Status flow: `pending → running → completed` (or `failed` / `cancelled`). Poll on an interval — scans take minutes to hours; don't block.

```bash
while :; do
  s=$(curl -sS "$BASE/scans/$scan_id" "${auth[@]}" | jq -r .status)
  echo "status=$s"; [[ "$s" =~ ^(completed|failed|cancelled)$ ]] && break
  sleep 60
done
```

## 4. Read findings

The scan-detail response includes `executive_summary`, `methodology`, `recommendations`, a `findings` severity roll-up, and a `vulnerabilities[]` array. Each vulnerability carries `title, severity, status, cvss, cwe, endpoint, method, impact, technical_analysis, poc_description, poc_script_code`, and (for code findings) `code_file`/`code_diff`/`code_before`/`code_after`.

```bash
curl -sS "$BASE/scans/$scan_id" "${auth[@]}" \
  | jq '["critical","high","medium","low","info"] as $order
       | .vulnerabilities
       | sort_by(.severity as $s | $order | index($s))
       | .[] | {title, severity, endpoint, cwe}'
```

Cloud severities are `critical | high | medium | low` and statuses are `open | in_progress | fixed | ignored`. Sort by an explicit severity order rather than `sort_by(.severity)`, which sorts alphabetically (critical, high, low, medium).

Org-wide triage across scans: `GET /vulnerabilities` (`vulnerabilities:read`; filter by severity/status). Update triage state with the vulnerabilities `:write` endpoints. To remediate, hand off to the **strix-fix-findings** skill.

## 5. Export & report

```bash
# SARIF 2.1.0 for GitHub code scanning / ASPM ingestion
curl -sS "$BASE/scans/$scan_id/sarif" "${auth[@]}" -o findings.sarif

# Report. The format and file type are query params (`Accept` is ignored):
#   format=technical (default) | retest | attestation | executive_summary
#   type=pdf (default) | docx
# Any report download requires the Enterprise plan; formats beyond `technical`,
# DOCX, and white-label branding are Enterprise-only too. Scan must be completed.
curl -sS "$BASE/scans/$scan_id/report?format=technical&type=pdf" "${auth[@]}" -o strix-report.pdf
```

## 6. PR reviews

Trigger an automated security review of a pull request (`pr_reviews:write`); results appear as PR comments and in the dashboard:

```bash
curl -sS "$BASE/pr-reviews/start" "${auth[@]}" -H "Content-Type: application/json" \
  -d '{"repository_full_name":"org/app","pr_number":123}'
```

List/inspect via `GET /pr-reviews` and `GET /pr-reviews/{id}`. Repo-level PR-review behavior is configured with the repository-settings endpoint.

## 7. Continuous testing (schedules & webhooks)

- **Schedules** (`schedules:write`, Pro plan): create recurring scans and trigger them on demand — the managed equivalent of a cron-driven CLI loop.
- **Webhooks** (`webhooks:write`): subscribe to pentest/vulnerability lifecycle events (e.g. `scan.completed`, `vulnerability.created`) to push results into Slack, ticketing, or your own pipeline instead of polling.

See the schedules and webhooks sections at [docs.app.strix.ai](https://docs.app.strix.ai) for payloads.

## Safety

Only scan assets the user's organization owns or is authorized to test. External domain scans require verification (DNS/file/meta-tag) enforced by the platform — don't try to bypass it.

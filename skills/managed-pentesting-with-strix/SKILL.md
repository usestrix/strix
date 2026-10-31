---
name: managed-pentesting-with-strix
description: Run a managed pentest of a web app, API, repository, or local workspace on the app.strix.ai platform with the `strix cloud` CLI or REST API — no local Docker or LLM key needed. Safely review and upload local source, register assets, launch and poll scans, triage vulnerabilities, export SARIF, download compliance reports, start PR reviews, buy credits, and set up schedules or webhooks. Use for managed, continuous, scheduled, team-tracked, or sandboxed-agent security testing.
license: Apache-2.0
metadata:
  author: usestrix
  homepage: https://docs.app.strix.ai
---

# Strix Cloud (managed, no local infra)

Use this when you want Strix's autonomous pentesting **without running Docker or an LLM yourself** — the scan runs on Strix's infrastructure and results are tracked in a team dashboard. This is the right choice in sandboxed/hosted agent and CI environments, for teams, and for scheduled/continuous testing (downloadable PDF/DOCX reports are an Enterprise-plan feature). For fully local, free, air-gapped, or BYO-LLM runs, use the open-source CLI in the **penetration-testing-with-strix** skill instead — both share the same engine and SARIF output, so you can mix them.

There are two equivalent interfaces. Prefer the CLI:

- **`strix cloud` CLI** — every REST operation has a command in the form `strix cloud <resource> <verb>`. Install with `curl -sSL https://strix.ai/install | bash`. Run `strix cloud` to list all resources and `strix cloud <resource> help` (or `-h`) to list a resource's verbs; a bare resource with a safe read operation runs its documented default.
- **REST API** — base URL `https://app.strix.ai/api/v1`, `Authorization: Bearer <token>` on every request. Full reference: **[docs.app.strix.ai](https://docs.app.strix.ai)** · agent index: `https://docs.app.strix.ai/llms.txt` · OpenAPI: `https://docs.app.strix.ai/openapi.json`.

The CLI is equally usable by agents and people. Output is complete JSON when stdout is not a terminal, or when you pass `--json`; terminal tables favor names, branches, lifecycle states, and numbered selectors. Human lists retain the selectors needed by follow-up commands but omit internal organization/user IDs; a selector too long for the compact table is repeated losslessly in a copyable block. Paginated lists print the next `--page` or `--offset`, and detail views preserve useful prose within a safe terminal bound; use `--json` for the complete record. Token lists label credentials as active, expired, or revoked. Binary downloads are the exception: redirect raw bytes intentionally, or use `--output FILE --json` to write the file and receive structured metadata. There are no interactive prompts when stdin is not a terminal. Exit codes: `0` success, `1` request/runtime error, `2` invalid usage, `4` authentication or plan limit, `5` payment required.

Every resource group with a safe read operation has a useful default action, and `-h` or `help` always shows its verbs. Native tab completion includes resources, verbs, flags, workspace commands, and local paths:

```bash
source <(strix completions zsh)       # current zsh session
source <(strix completions bash)      # current bash session
strix completions fish | source       # current fish session
```

Write commands take request fields as flags. Every write command also accepts one JSON object with `--data`, which is the way to send fields that have no flag:

```bash
strix cloud scans start --data '{"engagement_type":"code_review"}'   # literal JSON
strix cloud scans start --data @request.json                         # read a file
cat request.json | strix cloud scans start --data -                  # read standard input
```

The platform enforces plan and role limits, and the CLI passes the platform message through. Report downloads need the Enterprise plan. Schedules need the Pro plan. Billing writes need an admin token. A blocked command exits with code `4`.

## Setup: sign in

Run the device sign-in. It creates the user's account and workspace on first use and stores a personal API token in `~/.strix/platform-auth.json`:

```bash
strix cloud login
# Non-interactive least-privilege example:
strix cloud login --scopes scans:read scans:write uploads:write billing:read vulnerabilities:read assets:read assets:write
# Or use a stable named profile:
strix cloud login --scope-profile recommended
```

The user approves the sign-in in the browser. With `--scopes` (and optionally `--workspace <name-or-id>`) there are no terminal prompts, so the command works from a non-interactive agent shell. In an interactive terminal without flags, the CLI offers a workspace picker and scope presets (Recommended, Full access, Minimal, Custom). Recommended covers ordinary scans, source uploads, workspace switching, and user-approved credit top-ups; it excludes `tokens:write`, which must be requested explicitly when credential management is required. Use explicit scopes for a narrower automation token.

- `strix cloud whoami` is the fast local status. `strix cloud session --json` verifies the remote device session; `strix cloud session scopes` shows both effective access and the immutable login ceiling.
- `strix cloud logout` revokes the remote session before removing the local token. On a network or server failure it keeps the token so the user can retry; `--local-only` deliberately skips revocation.
- Every other `strix cloud` command uses the stored token automatically. `--token <token>` or `STRIX_API_TOKEN` is a stateless per-command override and never overwrites the stored account. For an override that is itself a CLI session, also pass `--workspace-id` or set `STRIX_WORKSPACE_ID`.
- Never hardcode, log, or commit the token. Store it in an env var or the CI secret store.
- **Scopes (least-privilege):** assign only what the integration needs and rotate regularly:

  | Scope | Grants |
  |---|---|
  | `scans:read` / `scans:write` | list/read/report scans · create/rerun/cancel scans |
  | `vulnerabilities:read` / `:write` | read findings · update status & notes |
  | `assets:read` / `:write` | read domains/repos · register/update them |
  | `schedules:read` / `:write` | read schedules · create/trigger recurring scans |
  | `pr_reviews:write` | trigger PR security reviews |
  | `webhooks:read` / `:write` | manage webhook subscriptions |
  | `uploads:write` | upload local source or documents for a scan |
  | `organizations:read` | read organization details (listing/switching the signed-in user's workspaces needs no API scope) |
  | `organizations:write` | create/update workspaces (admin) |
  | `tokens:write` | create/revoke ordinary API tokens (not needed to manage the current CLI session) |
  | `knowledge:read` / `:write` | read/update organization knowledge |
  | `audit:read` | read/export the Enterprise audit log |
  | `billing:read` / `billing:write` | read credit balance & auto top-up settings · buy credits (admin) |

HTTP errors map to messages and exit codes: `401` bad/expired token (exit `4`), `402` out of credits (exit `5`), `403` scope/plan-tier limit (exit `4`), `422` validation error (exit `1`).

Create a time-limited automation token with `strix cloud tokens create`. Use
`--rbac-scopes` to restrict it to target IDs, tags, or business units; the value is a
JSON array of `{ "type": "target|tag|business_unit", "value": "..." }` objects:

```bash
strix cloud tokens create --type service --name staging-ci \
  --expires-at 2026-12-31T23:59:59Z \
  --scopes scans:read scans:write \
  --rbac-scopes '[{"type":"tag","value":"staging"}]'
```

The token secret is returned once. Store it directly in a secret manager and do not
print or commit it. `--expires-at` and `--expires-in-days` are mutually exclusive.

## 0. Credits & top-ups

Non-Enterprise scans consume org credits. Enterprise engagements are plan-included and do not debit the wallet. Check the balance before a scan (`billing:read`):

```bash
strix cloud credits
```

When the balance is too low, buy credits with `strix cloud billing topup` (`billing:write`, admin token). The server answers the first request with **HTTP 402 and a machine-payment challenge** (Stripe Machine Payments Protocol). The CLI pays the challenge with the Stripe Link wallet client when Node.js is available — the user approves the spend in the [Link app](https://link.com/agents). The response returns the receipt (`credits_granted`, `duplicate`, `reference`) and the new balance.

A default-tier source-only code review currently starts at 60 credits. Source uploads are not free: they launch an ordinary `code_review` and use the same deterministic scope estimator. The service checks the full balance before launch, reserves credits atomically only after validation succeeds, and does not create or charge a rejected scan. Retests and Enterprise scans are exempt.

```bash
strix cloud billing topup --credits 20 --yes   # explicit approval; skips the TTY prompt
strix cloud billing topup --credits 20 --no-pay   # print the 402 challenge without paying
```

The default payment path is the Stripe Link wallet. When no wallet is connected, an interactive `strix cloud billing topup` starts the Link sign-in for the user and prints the verification link. The user approves the connection one time in the Link app, and then approves each payment there. No keys or variables are necessary. In a non-interactive process, the command stops and tells the user to connect the wallet at [link.com/agents](https://link.com/agents) or to use the hosted checkout link.

In a non-interactive agent or CI process, payment never proceeds unless the command includes `--yes`. Show the challenge or estimated spend to the user and obtain approval before adding it. `--no-pay` always stops after printing the challenge.

If the user does not want a wallet, create a hosted checkout link with `strix cloud billing subscribe --plan strix_top_up` and give the link to the user. The user pays in the browser.

Automatic top-ups (admin): `strix cloud billing auto-topup` shows the setting. Enable it with:

```bash
strix cloud billing auto-topup update --enabled --topup-credits 20 --monthly-cap-credits 200
```

An omitted `--monthly-cap-credits` keeps the stored cap. Pass `--no-monthly-cap` to remove the cap.

### Workspaces and account setup

Manage workspaces with a personal token from `strix cloud login`:

```bash
strix cloud workspaces list                    # numbered name/role/current list
strix cloud workspaces create --name "My Team"  # admin + organizations:write
strix cloud workspaces use 2                   # displayed number, exact name, or ID
strix cloud workspace use "My Team"            # singular `workspace` alias also works
strix cloud session scopes                     # effective scopes + consent ceiling
strix cloud session scopes set minimal         # narrow the session
strix cloud org members invite --email dev@example.com --role analyst
```

`workspaces use` retargets the current personal token to a workspace the user already belongs to and stores the updated workspace metadata; the bearer secret and expiry stay unchanged. It does not reprompt during ordinary switches: the server preserves the chosen profile, enforces the immutable login ceiling, and caps effective scopes by the target role. Use `--scope-profile` or `--scopes` to narrow within that ceiling; broader consent requires `strix cloud login` again. The CLI pins each process to the workspace it started in, so concurrent shells fail with a recoverable conflict instead of silently crossing organizations.

### Handoffs a person must finish

Four steps end at the user. The command creates the link or the record and prints it. Strix opens the browser only in an interactive terminal. Pass `--no-browser` to print the URL only.

```bash
strix cloud billing subscribe --plan strix_cloud # hosted checkout page for the Cloud plan
strix cloud billing portal                       # billing portal for the card and the plan
strix cloud integrations install github          # GitHub App or Slack installation page
strix cloud domains verify <domain-id>           # DNS record to add, then run it again
```

Give the printed URL or DNS record to the user and wait. Do not claim that the payment, the installation, or the DNS change is complete. Confirm the result afterwards with `strix cloud credits`, `strix cloud integrations list`, or `strix cloud domains list`. All four commands need an admin token, except `domains verify`, which needs `assets:write`.

### Organization knowledge

Agents can manage the organization knowledge base without the dashboard (`knowledge:read` / `knowledge:write`):

```bash
strix cloud knowledge list --search authentication
strix cloud knowledge add --title "Authentication" --content "Staging uses SSO."
strix cloud knowledge update <document-id> --content "Staging uses SSO and TOTP."
strix cloud knowledge delete <document-id>
strix cloud knowledge policies add --key staging-only --content "Never test production."
strix cloud knowledge policies delete staging-only
strix cloud knowledge repos entries usestrix/strix
```

Knowledge policy writes require an admin token. Repository names are passed as normal `owner/name` values; the CLI handles URL encoding. The `costs` and `llm-settings` commands target on-prem installations and return `404` on app.strix.ai.

## 1. Register the target as an asset

Scans run against **registered assets**, not raw URLs. Register once, then reuse the returned UUID.

```bash
# Domain (black-box / live target). Requires domain verification before external scanning.
# --asset-type must be one of: web_app | api | attack_surface.
strix cloud domains add --domain staging.example.com --asset-type web_app

# Repository (white-box / code review). `full_name` is "owner/name".
strix cloud repos add --data '{"full_name":"org/app","provider":"github"}'
```

Look up existing assets instead of re-adding: `strix cloud domains list`, `strix cloud repos list` (both `assets:read`).

## 2. Launch a scan

`strix cloud scans start` (`scans:write`). Provide at least one target with `--domain-ids`, `--repository-ids`, or `--internal-targets` (internal infra needs a network connector — see docs).

```bash
strix cloud scans start \
  --engagement-type live_test \
  --domain-ids <domain-uuid> \
  --focus "IDOR, auth bypass, SSRF" \
  --context "Staging. Test account creds are configured as a test user." \
  --notify-on-completion
```

Useful flags (each maps to a `CreateScanRequest` field):

| Flag | Purpose |
|---|---|
| `--engagement-type` | `live_test` (default), `code_review`, `internal_infra`, `compliance_pentest` |
| `--domain-ids` / `--repository-ids` / `--internal-targets` | targets (at least one) |
| `--domain-paths` / `--repository-branches` | narrow to specific paths / branches (JSON maps) |
| `--credentials` | authenticated scanning, incl. `mfa_method` (`totp`/`email_otp`/…) + `totp_secret` (JSON list) |
| `--headers` | extra target HTTP headers as a JSON array of header objects |
| `--focus` / `--concerns` / `--context` | free-form strings that steer the agents |
| `--upload-ids` | attach uploaded source/docs archives for white-box context |
| `--notify-on-completion` / `--notification-emails` | email when done |

Without `--source`, the response is `{ scan_id, title, status }` with `status` = `pending`.
Local-source success wraps that platform response as
`{ source, upload_id, scan: { scan_id, title, status } }`, so automation can retain the exact
approved manifest and staged-upload identifier alongside the created scan.

### Scan a local workspace in the cloud

For an agent or CI workflow, bind approval to the exact source snapshot that was reviewed. Run
the dry run with the intended source-selection flags, review the manifest and selected paths,
and capture `source.archive_sha256`. Then repeat the same `--source`, every `--exclude`, and
any `--include-hidden`, `--include-sensitive`, or `--include-archives` flags with
`--approve-sha256`:

```bash
strix cloud scans start --source . --exclude 'private/' --dry-run --show-files --json
# After reviewing the output, capture its source.archive_sha256 value:
SOURCE_SHA256="<reviewed source.archive_sha256>"
# Repeat every source-selection flag unchanged; a source-only scan infers code_review.
strix cloud scans start --source . --exclude 'private/' \
  --approve-sha256 "$SOURCE_SHA256" --wait
```

The CLI rebuilds the archive and refuses the upload if its SHA-256 no longer matches. `--yes`
has deliberately narrower semantics: it approves only the snapshot built during that one
invocation. Use it for a deliberate human or one-shot approval, not as the second half of a
digest-bound agent/CI review. Without a TTY, a source upload requires either matching
`--approve-sha256` approval or `--yes`; an interactive terminal can instead show the summary,
the selected filenames when `--show-files` is set, and a `[y/N]` confirmation for its current
snapshot.

The default selection is privacy-conscious: in a Git worktree it includes tracked files plus untracked files that are not ignored; it honors `.gitignore`, excludes every hidden path component, always excludes `.git`, symlinks, dependencies/build output, secret-like filenames, and nested archives. Add project exclusions to `.strixignore` (one exclude glob per line) or repeat `--exclude GLOB`; a trailing slash such as `private/` excludes that directory subtree.

The client refuses more than 20,000 files, a file over 25 MiB, more than 250 MiB expanded, or a ZIP over 50 MiB. The service then stream-inflates the ZIP and independently rejects malformed or unsupported entries, unsafe paths, too many entries, oversized entries, excessive expanded data, and oversized compressed input, so an untrusted client cannot bypass the ZIP-bomb controls by forging metadata.

Only use `--include-hidden`, `--include-sensitive`, or `--include-archives` after the dry-run manifest shows that the scan needs them. Hidden and sensitive files are separate opt-ins: for example, including `.env` requires both `--include-hidden` and `--include-sensitive`.

The CLI removes its private temporary local archive after every invocation. Once a remote
upload is staged, a definitive scan rejection causes the CLI to delete it. A network failure,
`5xx` response, malformed success response, or interruption after scan launch begins is
ambiguous—the platform may have accepted the scan—so the CLI retains the upload and returns
its `upload_id` with `launch_outcome_unknown: true`. If an automatic deletion attempt cannot
be confirmed, it instead returns the retained `upload_id` with `cleanup_unknown: true`.
Before retrying, run `strix cloud scans list` to avoid a duplicate scan or charge. If no scan
is linked to the retained upload, remove it with `strix cloud uploads delete UPLOAD_ID`;
linked uploads cannot be deleted.

With no explicit type, source alone infers `code_review`. Any domain target wins and infers `live_test`, so source plus a deployed domain is the normal white-box live-test workflow. Pass `--engagement-type` when you need to override the inference.

## 3. Wait for completion

Pass `--wait` to `scans start` to poll until the scan reaches a final state, or poll yourself with `strix cloud scans get <scan-id>` (`scans:read`). Bound automation with `--wait-timeout SECONDS`; timeout exits cleanly without cancelling the remote scan. Status flow: `pending → running → completed` (or `failed` / `cancelled`). Scans take minutes to hours — poll on an interval, do not block indefinitely.

## 4. Read findings

The scan-detail response includes `executive_summary`, `methodology`, `recommendations`, a `findings` severity roll-up, and a `vulnerabilities[]` array. Each vulnerability carries `title, severity, status, cvss, cwe, endpoint, method, impact, technical_analysis, poc_description, poc_script_code`, and (for code findings) `code_file`/`code_diff`/`code_before`/`code_after`.

```bash
strix cloud scans get <scan-id> --json \
  | jq '["critical","high","medium","low","info"] as $order
       | .vulnerabilities
       | sort_by(.severity as $s | $order | index($s))
       | .[] | {title, severity, endpoint, cwe}'
```

Cloud severities are `critical | high | medium | low` and statuses are `open | in_progress | snoozed | fixed | ignored | not_affected`. Sort by an explicit severity order rather than `sort_by(.severity)`, which sorts alphabetically (critical, high, low, medium).

Org-wide triage across scans: `strix cloud vulns list --severity critical` (`vulnerabilities:read`, and it also filters by `--status`, `--scan-id`, and more). Update triage state with `strix cloud vulns update <id> --status fixed`. To remediate, hand off to the **fix-security-vulnerabilities-with-strix** skill.

## 5. Export & report

```bash
# SARIF 2.1.0 for GitHub code scanning / ASPM ingestion
strix cloud scans sarif <scan-id> --output findings.sarif

# Report. Formats: technical (default) | retest | attestation | executive_summary
# Types: pdf (default) | docx
# Any report download requires the Enterprise plan. Formats beyond `technical`,
# DOCX, and white-label branding are Enterprise-only too. Scan must be completed.
strix cloud scans report <scan-id> --format technical --type pdf --output strix-report.pdf
```

Downloads refuse to replace a file unless `--force` is explicit. Enterprise audit logs can be streamed as JSON or exported without trying to JSON-decode the body:

```bash
strix cloud audit list --format csv --all --output audit.csv
strix cloud audit list --format ndjson --all --output audit.ndjson
```

## 6. PR reviews

Trigger an automated security review of a pull request (`pr_reviews:write`). Read the repository's `provider` and `installation_id` with `strix cloud repos list`; both identify the installed source-control integration. The results appear as PR comments and in the dashboard:

```bash
strix cloud pr-reviews start \
  --provider github \
  --installation-id <installation-id> \
  --repository-full-name org/app \
  --pr-number 123
```

List/inspect with `strix cloud pr-reviews list` and `strix cloud pr-reviews get <id>`. Repo-level PR-review behavior is configured with `strix cloud pr-reviews settings`.

## 7. Continuous testing (schedules & webhooks)

- **Schedules** (`schedules:write`, Pro plan): `strix cloud schedules create` makes recurring scans, and `strix cloud schedules trigger <id>` runs one on demand — the managed equivalent of a cron-driven CLI loop.
- **Webhooks** (`webhooks:write`): `strix cloud webhooks create` subscribes to pentest/vulnerability lifecycle events such as `scan.completed` and `vulnerability.created` to push results into Slack, ticketing, or your own pipeline instead of polling.

See the schedules and webhooks sections at [docs.app.strix.ai](https://docs.app.strix.ai) for payloads.

Network connectors are Enterprise-only. `strix cloud connectors create` may return a one-time enrollment command containing credentials; do not paste it into logs, and request it with `--include-command` only when the user is ready to install it. Browser checkout, source-control installation, DNS verification, connector installation, chat sharing, and publishing SARIF to an external provider are user handoffs or explicit external mutations—prepare the command/link, then obtain the appropriate approval before completing them.

## Safety

Only scan assets the user's organization owns or is authorized to test. External domain scans require verification (DNS/file/meta-tag) enforced by the platform — do not try to bypass it.

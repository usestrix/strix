---
name: cicd_pipeline_security
description: CI/CD pipeline security testing covering GitHub Actions permission/trigger abuse, GitLab CI variable exposure, Jenkins unauth RCE, and supply-chain risk in workflow configs
---

# CI/CD Pipeline Security

A CI/CD pipeline runs attacker-influenced code (a pull request, a commit, a dependency update) with credentials the pipeline needs to deploy — that combination is a direct path from "can open a PR" to "can push to production" whenever the trigger/permission model is wrong. Most real findings here are configuration-review, not exploitation: read the workflow YAML, find the specific permission or trigger that turns untrusted input into privileged execution.

## Attack Surface

- **GitHub Actions** — `.github/workflows/*.yml`, `GITHUB_TOKEN` permissions, `pull_request_target` trigger, third-party Actions/marketplace, self-hosted runners
- **GitLab CI** — `.gitlab-ci.yml`, CI/CD variables (protected vs unprotected), runner tags, merge-request pipelines
- **Jenkins** — script console (`/script`), job configuration, credentials store, plugin surface
- **Generic** — build/artifact registries the pipeline pushes to, secrets exposed in build logs, exposed `.git/` directories on deployed artifacts

## Key Vulnerabilities

### GitHub Actions: `pull_request_target` + Untrusted Checkout

The single highest-impact GitHub Actions misconfiguration class. `pull_request_target` runs with the **base repo's** secrets and a **write-capable** `GITHUB_TOKEN` by default, unlike `pull_request` (which runs with read-only token and no secrets for forks). If the workflow then checks out the PR's *head* ref and executes anything from it (build scripts, `npm install` triggering a malicious `postinstall`, a Makefile target), an external contributor's PR content executes with the base repo's privileges.

```yaml
# VULNERABLE pattern to look for:
on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}   # <- checks out untrusted PR content
      - run: npm install && npm run build                   # <- executes it with base-repo secrets
```
Confirm by tracing: does the workflow trigger on `pull_request_target`, does it check out `head.sha`/`head.ref` (not the base), and does it then run anything (build step, script, even a linter with a plugin system) against that checked-out content? If yes, an external PR is remote code execution against the repo's secrets.

### GitHub Actions: Overly Broad `GITHUB_TOKEN` Permissions

- Default `permissions: write-all` (legacy default before granular permissions) or explicit `contents: write`/`packages: write` on workflows triggered by external events
- Missing `permissions:` block entirely on older repos defaults to broad legacy scopes — check the repo's Actions settings for the org-level default
- A workflow with write access to `contents` that's reachable from a fork-originated trigger can push directly to protected branches if branch protection doesn't also restrict the token's own pushes

### GitHub Actions: Unpinned Third-Party Actions

```yaml
# VULNERABLE — mutable ref, maintainer account compromise = supply-chain RCE in every consuming workflow
- uses: some-org/some-action@main
- uses: some-org/some-action@v2        # tag, not a commit SHA — still mutable if maintainer force-pushes the tag

# SAFE — pinned to immutable commit SHA
- uses: some-org/some-action@a1b2c3d4e5f6...
```
Check every third-party (non-`actions/*`, non-verified-publisher) Action in every workflow for tag/branch pinning vs SHA pinning. This is the same class as the widely-publicized `tj-actions/changed-files` and similar supply-chain incidents.

### GitHub Actions: Self-Hosted Runner Abuse

If a self-hosted runner is used for a public repo's workflows (visible in workflow YAML via `runs-on: self-hosted`), any contributor who can trigger that workflow (even via a PR, if the trigger isn't `pull_request_target`-gated correctly) gets arbitrary code execution *on that runner's host* — which is often inside the organization's internal network, a far more valuable foothold than the repo itself.

### GitLab CI: Variable and Protected-Branch Bypass

- CI/CD variables marked "protected" are only injected on protected-branch/tag pipelines — check whether an unprotected branch or a fork's merge-request pipeline can still read them due to a misconfigured protection rule
- `.gitlab-ci.yml` `rules:`/`only:`/`except:` logic errors that let a merge-request pipeline from a fork run a stage that was intended to be protected-branch-only
- Runner tag misassignment: a shared/less-trusted runner picking up jobs tagged for a privileged runner pool

### Jenkins: Unauthenticated Script Console RCE

```
GET/POST /script
```
If reachable without authentication (common on internal Jenkins instances exposed accidentally, or with anonymous read/build enabled by misconfiguration), the Groovy script console is direct RCE:
```groovy
def process = "id".execute()
println process.text
```
Confirm auth requirement first — a script-console *login page* is not a finding; an actually-executable unauthenticated console is critical.

### Artifact / Registry Poisoning

- A CI pipeline pushing to an internal package registry (npm/PyPI/Maven/container registry) that also accepts pushes from a broader set of principals than intended — if you can push a same-named/higher-version artifact before the legitimate build does, downstream consumers may pull the poisoned one
- Public-facing build logs (GitHub Actions logs, GitLab CI job logs) leaking secrets that were `echo`'d during debugging, or environment variables dumped by a misconfigured step

### Secrets in Build Logs

- `set -x`/`set -o xtrace` left enabled in shell steps that also handle secret env vars
- Secrets passed as CLI arguments (visible in process listings/build logs) rather than via stdin or a secrets-mount
- Masking failure: CI secret-masking is typically substring-based — a secret that's transformed (base64'd, concatenated, split across lines) before being echoed bypasses the masking and appears in plaintext logs

## Testing Methodology

1. **Enumerate workflow triggers** — grep every `.github/workflows/*.yml` / `.gitlab-ci.yml` for `pull_request_target`, `workflow_run`, and any trigger that runs with elevated privilege on external input.
2. **Trace checkout targets** — for each privileged-trigger workflow, confirm whether it checks out `head` (untrusted) content and whether anything subsequently executes it.
3. **Audit token permissions** — `permissions:` blocks per workflow and per job; flag any `write` scope reachable from a fork-originated trigger.
4. **Check Action pinning** — every third-party `uses:` reference; flag anything not pinned to a commit SHA.
5. **Check for self-hosted runners** — `runs-on: self-hosted` on any workflow reachable by external contributors.
6. **Probe exposed CI infra directly** — Jenkins `/script` reachability, exposed `.git/` on deployed build artifacts, publicly readable build logs for secret leakage.

## Validation

1. Quote the exact workflow YAML trigger + checkout + execution steps that chain into the finding — this is a config-review finding, evidence is the YAML itself plus the trace, not necessarily a live exploit.
2. Where live exploitation is authorized, use the minimum-impact PoC — a benign marker commit or a `whoami`/`id` equivalent, not a destructive action, and never actually merge/push anything without separate explicit authorization.
3. For Jenkins script-console RCE, run one benign command (`id`, `hostname`) and stop.
4. For secret-in-logs findings, redact the actual secret value in the report; reference its location (job/step/line) instead.

## False Positives

- `pull_request_target` used but the workflow never checks out PR content at all (e.g. only used to comment on the PR via the API) — not exploitable
- Third-party Action unpinned but from a GitHub-verified publisher with a strong track record — lower priority than an unverified/low-star action, still worth flagging but not equally urgent
- CI/CD variable appears in job logs but is a non-sensitive build parameter, not a credential

## Impact

- `pull_request_target` + untrusted checkout is remote code execution against the base repository's secrets from any external contributor who can open a PR — full supply-chain compromise of everything the pipeline builds/deploys
- Self-hosted runner abuse gives code execution on infrastructure typically inside the organization's internal network
- Unauthenticated Jenkins script console is unauthenticated RCE on the CI host, which usually holds credentials for every downstream deployment target

## Pro Tips

1. `pull_request_target` is the single highest-signal grep across an entire org's repos — search for it first before reading anything else.
2. Unpinned Action references (`@main`, `@v2` as a mutable tag) are a supply-chain risk even without an active compromise — flag as a hardening finding regardless of whether the maintainer account is currently compromised.
3. Jenkins script console findings are binary — either it's reachable unauthenticated (critical) or it isn't (not a finding); check auth requirement before anything else.
4. Read the workflow YAML as the primary evidence source — this is a static-review skill more than a dynamic-exploitation one; combine with `source_aware_sast`/`dependency_cve_scanning` when the target includes repo source.

## Tooling

No dedicated tool required — grep/read the workflow YAML directly.
```
gh api repos/<org>/<repo>/actions/workflows      # enumerate workflows via GitHub API if repo access is API-only
```
- **grep/ripgrep** — sufficient for the trigger/checkout/permission tracing throughout this skill: `rg 'pull_request_target' .github/workflows/`
- **gh CLI** — useful for pulling workflow run logs and permission settings when only API access (not a local clone) is available.

## Summary

CI/CD pipeline compromise is a static-configuration problem more than a dynamic-exploitation one: find the trigger that runs with elevated privilege on external input, trace whether it executes that untrusted input, and check third-party Action pinning and runner trust boundaries. `pull_request_target` combined with an untrusted checkout is the single highest-value pattern to search for — it turns "can open a PR" into "can execute code with the base repo's secrets."

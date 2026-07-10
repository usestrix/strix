---
name: cicd-security
description: CI/CD pipeline security testing covering workflow/expression injection, pull_request_target misuse, self-hosted runner poisoning, OIDC trust abuse, token over-permission, and pipeline supply-chain attacks
---

# CI/CD Pipeline Security

CI/CD pipelines execute attacker-influenced input (PR metadata, branch names, forked code) on infrastructure that holds repository secrets, cloud credentials, and push access to production. A single expression injection or a mis-triggered `pull_request_target` can yield code execution on the runner, exfiltration of every secret in scope, and backdoored releases. Treat every pipeline that reacts to external events as an untrusted-input sink.

## Attack Surface

**Platforms**
- GitHub Actions (`.github/workflows/*.yml`), GitLab CI (`.gitlab-ci.yml`), Jenkins (`Jenkinsfile`), CircleCI (`.circleci/config.yml`), Azure Pipelines, Bitbucket Pipelines

**Trigger events that expose secrets to external input**
- `pull_request_target`, `workflow_run`, `issue_comment`, `issues`, `discussion`, `workflow_dispatch` — run in the base-repo context (secrets present) while reacting to fork/attacker input
- `pull_request` (default) — fork PRs run WITHOUT secrets and with a read-only token; injection here is runner code-exec only, not secret theft (triage accordingly)

**Injection sources (attacker-controlled context)**
```
github.event.pull_request.title / .body
github.event.pull_request.head.ref        # branch name
github.head_ref                           # branch name alias
github.event.issue.title / .body
github.event.comment.body
github.event.review.body / .review_comment.body
github.event.discussion.title / .body
github.event.inputs.*                     # workflow_dispatch inputs
github.event.*.author / commit message / author email
```

**Sinks**
- `run:` shell blocks interpolating `${{ ... }}` directly
- `script:`/`before_script:` (GitLab), `sh`/`bat` steps (Jenkins), `actions/github-script` bodies
- Dynamic `uses:`, `ref:`, or environment values built from untrusted context

## High-Value Targets

- Workflows on public repos that react to fork events (`pull_request_target`, `issue_comment`, `workflow_run`)
- Self-hosted runners attached to public or fork-accepting repos
- Workflows using cloud OIDC (`aws-actions/configure-aws-credentials`, `google-github-actions/auth`, `azure/login`)
- Release/publish/deploy pipelines with `contents: write`, `packages: write`, or registry credentials
- Reusable/composite actions pulled by many repos (blast radius on compromise)
- Build steps that install internal packages from mixed public/private registries

## Reconnaissance

**Enumerate pipeline definitions**
- Fetch `.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`, `.circleci/config.yml` from every in-scope repo and every fork-facing branch
- Public workflow run logs are readable without auth and often contain leaked values, secret names, and internal hostnames

**Detection greps (run against a cloned repo)**
```bash
# Expression injection into shell
grep -rnE '\$\{\{[^}]*github\.(event\.(pull_request|issue|comment|review|discussion)|head_ref)' .github/workflows/
grep -rnE '\$\{\{[^}]*github\.event\.inputs' .github/workflows/

# Dangerous triggers + checkout of untrusted head
grep -rn 'pull_request_target\|workflow_run' .github/workflows/
grep -rn -A20 'pull_request_target' .github/workflows/ | grep -E 'head\.sha|head_ref|checkout'

# Self-hosted runners
grep -rn 'self-hosted\|runs-on:.*\[' .github/workflows/

# OIDC / cloud auth
grep -rnE 'id-token:\s*write|configure-aws-credentials|google-github-actions|azure/login' .github/workflows/

# Over-broad token permissions
grep -rnE 'permissions:|contents:\s*write|packages:\s*write' .github/workflows/

# Unpinned actions (tag/branch instead of SHA)
grep -rnE 'uses:\s*[^@]+@(v?[0-9]+|main|master)$' .github/workflows/

# Secrets echoed / into env of untrusted step
grep -rnE 'echo.*secrets\.|env:.*secrets\.' .github/workflows/
```

## Key Vulnerabilities

### Expression/Workflow Injection
Untrusted context interpolated straight into a shell step lets the attacker break out of the string and run commands on the runner.
```yaml
# VULNERABLE — attacker controls pr.title
- run: echo "Title: ${{ github.event.pull_request.title }}"
# PR title:  "; <command> #
```
```yaml
# SAFE — bind to an env var; the shell never re-parses the value
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "Title: $PR_TITLE"
```
Impact depends entirely on the trigger: on `pull_request_target`/`workflow_run` the step has secrets and a writable token (Critical); on default `pull_request` it is unprivileged runner exec (lower).

### pull_request_target + Untrusted Checkout
`pull_request_target` runs in the base repo (secrets available) but is frequently made to check out and execute the PR head:
```yaml
on: pull_request_target
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
        with: { ref: ${{ github.event.pull_request.head.sha }} }   # attacker code
      - run: npm ci && npm test    # runs attacker package.json scripts WITH secrets
```
Any build/test/lint step that executes fetched code (npm/pip/make/gradle lifecycle hooks) is an execution sink here, even without an explicit `run:` injection.

### Self-Hosted Runner Poisoning
Public/fork-accepting repos with `runs-on: self-hosted` let any fork queue jobs on internal machines (default non-ephemeral). Exploit path: fork → open PR adding a job with `runs-on: self-hosted` → job executes on the internal runner → reach internal network, cloud metadata, and persist on a reused host.
```yaml
jobs:
  x:
    runs-on: self-hosted
    steps:
      - run: curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### OIDC Trust-Policy Abuse
Actions can mint short-lived cloud creds via OIDC; over-broad trust policies let any branch/repo assume privileged roles. Check the `sub` claim scoping:
```json
"token.actions.githubusercontent.com:sub": "repo:org/*:*"   // any repo, any branch → assumable from a feature branch or fork PR
```
Triage: which role is assumed, is `sub` pinned to `repo:org/name:ref:refs/heads/main` (or an environment), and can the workflow be reached from a fork/feature branch? Then enumerate the role's permissions.

### GITHUB_TOKEN Over-Permission
The auto-issued `GITHUB_TOKEN` inherits job `permissions:`. `contents: write` allows pushing to branches/tags and creating releases; `packages: write` allows publishing malicious packages; `pull-requests: write` can approve PRs. Combined with an injection or untrusted checkout, this pivots runner exec into repository/release compromise.

### Unpinned Actions / Action Hijack
`uses: owner/action@v1` or `@main` resolves to a mutable ref. If the action repo (or a transitive action it calls) is compromised or the tag is repointed, the next run executes new code with the job's token and secrets. Pin to a full commit SHA.

### Dependency Confusion (pipeline-installed deps)
Build steps that install internal package names from registries that also fall back to public ones can be tricked into pulling an attacker's higher-versioned public package.
```bash
grep -rnE '"@[^/]+/"|registry' package.json .npmrc
grep -rnE 'index-url|extra-index-url' requirements.txt pip.conf setup.py
# Then check whether any internal package name is unclaimed on the public registry
```

### Secret Exposure in Logs / Artifacts
Secrets echoed in `run:`, written to files later uploaded as artifacts, or passed to tools that print their environment surface in the (often public) run log. GitHub masks known secret values but not derived/transformed ones (e.g., base64).

## Bypass & Evasion Techniques

- **Filter evasion:** naive scanners key on `github.event.pull_request.title`; reach the same value via `github.head_ref`, `github.event.pull_request.head.ref`, or the commit author/message fields
- **Branch-name payloads:** `head_ref` is attacker-set and passes many title/body filters; encode payloads (base64 + `| base64 -d | sh`) to dodge keyword blocks and log masking
- **Indirect execution:** when no `run:` interpolation exists, use lifecycle scripts (`postinstall`, `Makefile`, test config) executed by a checked-out untrusted head
- **Composite/reusable action reach:** injection or an unpinned dependency inside a *called* action, not the top-level workflow, still runs with the caller's context

## Chaining Attacks

- **Injection → secret exfil → cloud/prod:** expression injection on `pull_request_target` reads `${{ secrets.* }}` and any OIDC-assumed cloud creds → pivot into the cloud account or push a backdoored release
- **Self-hosted runner → internal network / metadata:** fork-queued job reaches `169.254.169.254` or internal services unreachable from the internet
- **Unpinned action → supply chain:** compromise/hijack a mutable action ref → code exec in every consuming pipeline with repo write access
- **IDOR/leak → CI config → injection:** read a repo's CI config or secret names via another finding, then target the specific vulnerable workflow
- **Secret in public log → token replay:** harvest a leaked token from run logs → drive the API/registry directly

## Testing Methodology

1. **Inventory** every pipeline file across in-scope repos and fork-facing branches
2. **Classify each trigger** by whether it runs with secrets on external input (`pull_request_target`/`workflow_run`/`issue_comment` = high; default `pull_request` = low)
3. **Trace context → sink** for each privileged workflow: does attacker-controlled context reach a `run:`/checkout/`uses:`/`ref:` sink?
4. **Confirm reachability** from an actor you can control (fork, feature branch, comment) given branch protections and required approvals
5. **Prove impact out-of-band** (below) rather than dumping secrets to a log
6. **Map token & OIDC scope** available to the reachable job

## Validation

- Trigger the workflow from a controlled fork/branch and confirm execution via an **OAST callback** (Collaborator/interactsh) from the injected step — never post secret values into logs
- For secret access, exfiltrate a **canary** value (a benign test secret set for the assessment) to the OAST host, or demonstrate the token's write capability against a throwaway branch/tag
- For OIDC, show the role is assumable from an unintended `sub` (e.g., a non-`main` branch) and enumerate its permissions read-only
- Capture the exact workflow file + line, the trigger, and the request/callback evidence
- Prefer non-destructive proof; a workflow run has real side effects — do not disrupt production infrastructure or exfiltrate real customer secrets

## False Positives

- Injection on default `pull_request` from a fork: real code exec, but no secret/token access — do not report as secret compromise
- Context interpolated only into non-shell values with no downstream execution
- `pull_request_target` that checks out the **base** ref (not the PR head) and never executes fetched code
- Self-hosted runners that are ephemeral/isolated and not reachable by forks (org-restricted, no fork PRs)
- Secrets referenced but only passed to steps that don't reach untrusted input
- OIDC `sub` correctly pinned to a specific repo + protected ref/environment

## Impact

- Arbitrary code execution on build runners
- Exfiltration of all in-scope repository/organization secrets
- Theft/abuse of OIDC-minted cloud credentials → cloud account compromise
- Malicious pushes, tags, and releases; backdoored published packages
- Lateral movement into internal networks via poisoned self-hosted runners

## Pro Tips

1. Triage by trigger first — the same injection is Critical on `pull_request_target` and merely noisy on default `pull_request`
2. `github.head_ref` (branch name) is the most-missed injection source; it bypasses title/body-focused filters
3. When there is no `run:` interpolation, look for execution via checked-out untrusted code (install/test lifecycle scripts)
4. Read public run logs before touching anything — they leak secret names, internal hosts, and sometimes values
5. Always check the `permissions:` block; a writable `GITHUB_TOKEN` turns runner exec into repo/release compromise
6. Pin-to-SHA gaps compound through transitive (composite/reusable) actions, not just the top-level workflow
7. For OIDC, the whole finding is in the trust policy `sub`/`aud` conditions — get the assumed role ARN and inspect them

## Summary

Any pipeline that runs with secrets in response to externally influenced input is the target. Follow the path from attacker-controlled context to an execution sink, confirm it is reachable from an actor you can control, and prove impact out-of-band. Trigger type determines everything: secrets-bearing triggers reacting to fork input are where Critical findings live.

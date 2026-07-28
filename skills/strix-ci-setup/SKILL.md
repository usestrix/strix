---
name: strix-ci-setup
description: Wire Strix security scanning into CI/CD — GitHub Actions, GitLab CI, or any pipeline — so every pull request gets a diff-scoped AI pentest that blocks vulnerable code. Covers both the self-hosted open-source CLI (runs in your runner) and the managed app.strix.ai platform (GitHub/GitLab app or API, no runner infra). Use when the user asks to add security scanning, pentesting, or Strix to their CI pipeline or PR workflow.
license: Apache-2.0
metadata:
  author: usestrix
  homepage: https://docs.strix.ai
---

# Set up Strix in CI/CD

You can gate PRs two ways — pick based on the environment, or combine them:

- **Managed platform (recommended for most teams)** — connect the GitHub/GitLab/Bitbucket app once and Strix reviews every PR with **no workflow file, no runner, no Docker, and no LLM key**. Results post as PR comments and land in the team dashboard. Best when you want zero CI maintenance, central tracking, or your runners lack Docker. See "Managed platform" below and the **strix-cloud-api** skill.
- **Self-hosted OSS CLI in your runner** — run a diff-scoped scan as a pipeline step. Fully in your infra, free (BYO LLM key), no external account. Requires Docker on the runner. Best for air-gapped/self-hosted CI or when you don't want scans leaving your environment.

Both fail the build on validated findings and both emit SARIF 2.1.0, so you can start with one and add the other later.

---

# Option A — Self-hosted OSS CLI in the runner

Run a diff-scoped Strix scan on every PR: only changed files are tested, `quick` mode keeps it fast, and exit code `2` fails the build when validated vulnerabilities are found.

## GitHub Actions

Create `.github/workflows/security.yml`:

```yaml
name: Security Scan

on:
  pull_request:

jobs:
  strix-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # required for diff-scope resolution

      - name: Install Strix
        run: curl -sSL https://strix.ai/install | bash

      - name: Run Security Scan
        env:
          STRIX_LLM: ${{ secrets.STRIX_LLM }}
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}
        run: strix -n -t ./ --scan-mode quick --max-budget 10
```

Then tell the user to add two repository secrets: `STRIX_LLM` (model id, e.g. `openai/gpt-5.4`) and `LLM_API_KEY` (the provider key). Do not create these values yourself.

Notes:
- In CI/headless runs Strix automatically scopes to the PR's changed files (`--scope-mode auto`). If diff resolution fails, keep `fetch-depth: 0` or pass `--diff-base origin/main`.
- Exit codes: `0` pass, `2` vulnerabilities found (fails the job), `1` setup error.
- The runner needs Docker (default GitHub-hosted Ubuntu runners have it).

### Optional: upload findings to GitHub code scanning

Strix writes SARIF 2.1.0 to `strix_runs/<run>/findings.sarif`:

```yaml
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: strix_runs
```

## Other CI systems

Any pipeline works the same way — install, set the two env vars, run headless:

```bash
curl -sSL https://strix.ai/install | bash
strix -n -t ./ --scan-mode quick --scope-mode diff --diff-base origin/main --max-budget 10
```

Gate the pipeline on the exit code. Schedule `standard` scans nightly and `deep` scans for release candidates.

---

# Option B — Managed platform (no runner infra)

No workflow file, no Docker, no LLM key. Two ways to use it:

1. **PR-review app (zero code):** the user installs the Strix GitHub/GitLab/Bitbucket app and enables PR reviews for the repo in the app.strix.ai dashboard. Every PR is then reviewed automatically, with findings posted as PR comments. Nothing to add to the repo. This is the lowest-effort path — recommend it first when the user just wants PR gating.

2. **API-triggered from any pipeline:** if you want to trigger from an existing pipeline (or a system without the SCM app), call the API with a token that has `pr_reviews:write` (or `scans:write`). Store the token as a CI secret; ask the user to create it at **Settings → API Access**. Example GitHub Actions step:

   ```yaml
   - name: Strix PR review (managed)
     if: github.event_name == 'pull_request'
     env:
       STRIX_API_TOKEN: ${{ secrets.STRIX_API_TOKEN }}
     run: |
       curl -sS --fail https://app.strix.ai/api/v1/pr-reviews/start \
         -H "Authorization: Bearer $STRIX_API_TOKEN" \
         -H "Content-Type: application/json" \
         -d "{\"repository_full_name\":\"${{ github.repository }}\",\"pr_number\":${{ github.event.pull_request.number }}}"
   ```

   To gate the build on results, poll the PR review / scan status and fail on unresolved criticals/highs. Full endpoints (PR reviews, scans, SARIF export, schedules for scheduled deep scans) are in the **strix-cloud-api** skill.

Recommend Option B for most teams (no maintenance, central dashboard); use Option A when scans must stay entirely within your own infrastructure.

---
name: strix-ci-setup
description: Wire Strix security scanning into CI/CD — GitHub Actions, GitLab CI, or any pipeline — so every pull request gets a diff-scoped AI pentest that blocks vulnerable code. Use when the user asks to add security scanning, pentesting, or Strix to their CI pipeline or PR workflow.
license: Apache-2.0
metadata:
  author: usestrix
  homepage: https://docs.strix.ai
---

# Set up Strix in CI/CD

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

## Hosted alternative

If the user prefers zero CI setup, the managed platform at https://app.strix.ai reviews every PR via the GitHub/GitLab/Bitbucket app with no workflow file or LLM key required.

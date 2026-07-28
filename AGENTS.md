# Strix — Agent Guide

Strix is an open-source autonomous AI pentesting tool. This file is for AI coding agents that want to **use** Strix (run security scans) or **contribute** to it.

## Using Strix from an agent

Install the agent skills for step-by-step workflows:

```bash
npx skills add usestrix/strix
```

- `strix-pentest` — run a headless pentest against code, URLs, domains, or IPs and read results
- `strix-fix-findings` — remediate findings and re-run Strix to verify
- `strix-ci-setup` — add diff-scoped PR scanning to CI/CD

Quick reference (details in the skills and https://docs.strix.ai):

```bash
curl -sSL https://strix.ai/install | bash        # install
export STRIX_LLM="openai/gpt-5.4"                 # any LiteLLM model id
export LLM_API_KEY="<key>"
strix -n -t ./ --scan-mode quick --max-budget 10  # headless scan; always use -n
```

- Requires Docker running. Scans take minutes (`quick`) to hours (`deep`) — run in the background.
- Exit codes (headless): `0` clean, `1` fatal error, `2` vulnerabilities found.
- Artifacts in `strix_runs/<run-name>/`: `penetration_test_report.md`, `vulnerabilities/*.md`, `vulnerabilities.json`, `findings.sarif` (SARIF 2.1.0), `run.json`.
- Docs index for LLMs: https://docs.strix.ai/llms.txt (full: https://docs.strix.ai/llms-full.txt).
- Only scan targets the user is authorized to test.

## Contributing to this repo

- Python 3.12+, managed with `uv`. Install dev deps: `make dev-install`.
- Lint/format/type-check/security, all in one: `make check-all` (ruff, mypy, bandit).
- Tests: `uv run pytest`.
- Run from source: `uv run strix --target <target>`.
- Layout: `strix/agents` (agent graph + prompts), `strix/tools` (proxy, browser, terminal, scanners), `strix/runtime` (Docker sandbox), `strix/report` (findings, SARIF), `strix/skills` (internal knowledge packs the pentest agents load — different from the consumer skills in `skills/`), `strix/interface` (CLI/TUI), `containers/` (sandbox image).
- Pre-commit hooks: `make pre-commit` (or `uv run pre-commit install`).

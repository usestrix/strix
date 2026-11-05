<p align="center">
  <a href="https://strix.ai/">
    <img src="https://github.com/usestrix/.github/raw/main/imgs/cover.png" alt="Strix Banner" width="100%">
  </a>
</p>

<div align="center">

# Strix

### The open-source AI pentesting tool. Autonomous AI hackers that find and fix your app's vulnerabilities.

<br/>


<a href="https://docs.strix.ai"><img src="https://img.shields.io/badge/Docs-docs.strix.ai-2b9246?style=for-the-badge&logo=gitbook&logoColor=white" alt="Docs"></a>
<a href="https://strix.ai"><img src="https://img.shields.io/badge/Website-strix.ai-f0f0f0?style=for-the-badge&logoColor=000000" alt="Website"></a>
[![](https://dcbadge.limes.pink/api/server/strix-ai)](https://discord.gg/strix-ai)

<a href="https://app.strix.ai?utm_source=github&utm_medium=readme&utm_content=badge_cloud"><img src="https://img.shields.io/badge/Strix%20Cloud-app.strix.ai-2b9246?style=for-the-badge&logoColor=white" alt="Strix Cloud"></a>
<a href="https://strix.ai/demo?utm_source=github&utm_medium=readme&utm_content=badge_demo"><img src="https://img.shields.io/badge/Try%20Strix%20Enterprise-555555?style=for-the-badge&logoColor=white" alt="Try Strix Enterprise"></a>

<a href="https://github.com/usestrix/strix"><img src="https://img.shields.io/github/stars/usestrix/strix?style=flat-square" alt="GitHub Stars"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-3b82f6?style=flat-square" alt="License"></a>
<a href="https://pypi.org/project/strix-agent/"><img src="https://img.shields.io/pypi/v/strix-agent?style=flat-square" alt="PyPI Version"></a>


<a href="https://discord.gg/strix-ai"><img src="https://github.com/usestrix/.github/raw/main/imgs/Discord.png" height="40" alt="Join Discord"></a>
<a href="https://x.com/strix_ai"><img src="https://github.com/usestrix/.github/raw/main/imgs/X.png" height="40" alt="Follow on X"></a>


<a href="https://trendshift.io/repositories/15362?utm_source=trendshift-badge&utm_medium=badge&utm_campaign=badge-trendshift-15362" target="_blank" rel="noopener noreferrer"><img src="https://trendshift.io/api/badge/trendshift/repositories/15362/weekly" alt="usestrix%2Fstrix | Trendshift" width="250" height="55"/></a>
<a href="https://trendshift.io/repositories/15362" target="_blank"><img src="https://trendshift.io/api/badge/repositories/15362" alt="usestrix/strix | Trendshift" width="250" height="55"/></a>

</div>


> [!TIP]
> **New!** Strix integrates seamlessly with GitHub Actions and CI/CD pipelines. Automatically scan for vulnerabilities on every pull request and block insecure code before it reaches production - [Get started with no setup required](https://app.strix.ai?utm_source=github&utm_medium=readme&utm_content=tip_ci).

---

## Strix Overview

Strix are autonomous AI penetration testing agents that act just like real hackers - they run your code dynamically, find vulnerabilities, and validate them through actual proofs-of-concept. Built for developers and security teams who need fast, accurate security testing without the overhead of manual pentesting or the false positives of static analysis tools.

**Key Capabilities:**

- **Full pentesting toolkit** - reconnaissance, exploitation, and validation out of the box
- **Multi-agent orchestration** - teams of AI pentesters that collaborate and scale
- **Real exploit validation** - working PoCs, not false positives like legacy vulnerability scanners
- **Developer‑first CLI** - actionable findings with remediation guidance
- **Auto‑fix & reporting** - generate patches and compliance-ready pentest reports


<br>


<div align="center">
  <a href="https://strix.ai">
    <img src=".github/screenshot.png" alt="Strix Demo" width="1000" style="border-radius: 16px;">
  </a>
</div>


## Use Cases

- **Application Security Testing** - Detect and validate critical vulnerabilities in your applications
- **Rapid Penetration Testing** - Get penetration tests done in hours, not weeks, with compliance reports
- **Bug Bounty Automation** - Automate bug bounty research and generate PoCs for faster reporting
- **CI/CD Integration** - Run tests in CI/CD to block vulnerabilities before reaching production
- **API Security Testing** - REST/GraphQL APIs and the OWASP API Security Top 10 (BOLA/IDOR, authz)
- **OWASP Top 10 Assessment** - Systematic OWASP Top 10 assessment with honest per-category coverage
- **Supply Chain Security** - SBOM generation, dependency scanning, and CVE detection

## 🚀 Quick Start

**Prerequisites:**
- Docker (running)
- An LLM API key from any [supported provider](https://docs.strix.ai/llm-providers/overview) (OpenAI, Anthropic, Google, etc.)

### Installation & First Scan

```bash
# Install Strix
curl -sSL https://strix.ai/install | bash

# Configure your AI provider
export STRIX_LLM="vercel_ai_gateway/zai/glm-5.3"   # Vercel AI Gateway (recommended)
# export STRIX_LLM="openrouter/z-ai/glm-5.3"       # OpenRouter
export LLM_API_KEY="your-api-key"

# Run your first security assessment
strix --target ./app-directory
```

> [!NOTE]
> First run automatically pulls the sandbox Docker image. Results are saved to `strix_runs/<run-name>`

### Updating

```bash
# Self-update the standalone binary to the latest release
strix --update

# ...or re-run the installer
curl -sSL https://strix.ai/install | bash
```

Installed with pipx, uv, or pip? `strix --update` prints the matching upgrade command instead (`pipx upgrade strix-agent`, `uv tool upgrade strix-agent`, `pip install --upgrade strix-agent`). Strix also shows a notice with the right command when a new version is available.

---

## Ways to Run Strix

| Mode | Description | Best For |
|------|-------------|----------|
| **Open Source (Self-hosted)** | Free, runs locally with Docker and your own LLM key | Local dev loops, air-gapped/offline, full control |
| **Strix Cloud** | No setup, validated findings, one-click autofix, PR reviews | Sandboxed/CI environments, teams, no Docker |
| **Enterprise** | SSO, compliance reports, VPC/self-hosted, BYOK, dedicated support | Enterprise compliance, custom deployment |

### Open Source (Self-hosted CLI)

```bash
curl -sSL https://strix.ai/install | bash        # install
export STRIX_LLM="vercel_ai_gateway/zai/glm-5.3" # any LiteLLM model id
export LLM_API_KEY="<key>"
strix -n -t ./ --scan-mode quick --max-budget 10  # headless scan; always use -n
```

- Requires Docker running. Scans take minutes (`quick`) to hours (`deep`) — run in the background.
- Exit codes (headless): `0` clean, `1` fatal error, `2` vulnerabilities found. A `0` only covers what was analyzed — check `run.json` (`status`, `llm_usage.cost` vs the budget) before calling a run clean.
- Artifacts in `strix_runs/<run-name>/`: `penetration_test_report.md`, `vulnerabilities/*.md`, `vulnerabilities.json`, `findings.sarif` (SARIF 2.1.0), `run.json`.

### Strix Cloud (Managed Platform)

```bash
strix cloud login --scopes scans:read scans:write uploads:write billing:read
strix cloud domains add --domain example.com --asset-type web_app
strix cloud scans start --engagement-type live_test --domain-ids <uuid> --wait
strix cloud scans start --source . --dry-run --show-files --json  # review + capture source.archive_sha256
SOURCE_SHA256="<reviewed source.archive_sha256>"
strix cloud scans start --source . --approve-sha256 "$SOURCE_SHA256" --wait
strix cloud vulns list --severity critical
strix cloud billing topup --credits 20 --yes  # explicit approval after exit code 5
```

- Account setup runs from the CLI too: `strix cloud workspaces list|create|use` (`workspace` is an alias and `use` accepts a displayed number, name, or ID), `strix cloud session scopes|scopes set`, `strix cloud org members invite`, `strix cloud billing subscribe --plan strix_cloud`, `strix cloud billing portal`, `strix cloud integrations install github`, and `strix cloud domains verify <id>`. Workspace switching preserves the server-side profile and can never widen past the login ceiling; ordinary switches do not reprompt. The last four end at a person: the command prints a link or a DNS record for the user to open or add, and it never completes the payment, installation, or DNS change for them.
- Every REST operation has a `strix cloud <resource> <verb>` command. Run `strix cloud` to list them. Output is JSON when stdout is not a terminal (or with `--json`), and there are no prompts without a TTY. Binary downloads are the exception: redirect raw bytes intentionally, or combine `--output FILE --json` for structured download metadata. Exit codes: `0` success, `1` error, `2` usage, `4` auth or plan limit, `5` payment required. `--token` or `STRIX_API_TOKEN` is a stateless override and never replaces stored auth; set `--workspace-id`/`STRIX_WORKSPACE_ID` for an override CLI session. `--data` adds extra request fields as JSON, and accepts `@file` or `-` for standard input.
- Local source uploads require `uploads:write`. For an agent/CI handoff, review `scans start --source . --dry-run --show-files --json`, capture `source.archive_sha256`, then rerun with the same `--source`, `--exclude`, and `--include-*` selection flags plus `--approve-sha256 HASH`. A changed snapshot is rejected. `--yes` approves only the snapshot built in that invocation, so reserve it for a deliberate human or one-shot approval rather than a digest-bound two-step handoff.
- Git ignores, hidden files, `.git`, symlinks, dependency/build output, secret-like filenames, and nested archives are excluded by default; `.strixignore` and `--exclude` narrow the manifest further (a trailing `/` excludes a directory subtree). Limits: 20,000 files, 25 MiB/file, 250 MiB expanded, 50 MiB compressed. Source-only infers `code_review`; source plus a domain infers `live_test`.
- The temporary local archive is always removed. A staged upload is deleted after a definitive rejection, but retained when a network error, `5xx`, malformed success response, or interruption leaves the scan launch ambiguous. JSON reports its `upload_id` with `launch_outcome_unknown: true`, or with `cleanup_unknown: true` when automatic deletion cannot be confirmed. Check `scans list` before retrying; if no scan is linked, run `uploads delete UPLOAD_ID`.
- Non-Enterprise scans consume the scope estimate (a default-tier source-only review currently starts at 60 credits); Enterprise scans are plan-included. A rejected launch does not consume credits.
- Human output is compact and numbered; non-TTY output and `--json` retain full records. Enable tab completion with `source <(strix completions zsh)` (or `bash`), or `strix completions fish | source`.
- The REST API works directly too: https://docs.app.strix.ai (OpenAPI: https://docs.app.strix.ai/openapi.json).

---

## 🤖 Use Strix from Your Coding Agent

Strix is agent-ready. Give Claude Code, Cursor, Codex, or any [SKILL.md-compatible](https://agentskills.io) agent the ability to run pentests, fix findings, and set up CI scanning:

```bash
npx skills add usestrix/strix
```

This installs skills for running pentests, fixing findings, and CI scanning, against code, web apps, APIs, and the OWASP Top 10. Agents can use the local CLI or the managed cloud with the same engine.

See [`AGENTS.md`](AGENTS.md) for the quick reference, [docs.strix.ai/llms.txt](https://docs.strix.ai/llms.txt) for the CLI, and [docs.app.strix.ai](https://docs.app.strix.ai) for the API.

---

## ✨ Features

### Agentic Pentesting Tools

Strix agents come equipped with a comprehensive offensive security toolkit - the same tools used by professional penetration testers and ethical hackers:

- **HTTP Interception Proxy** - Full request/response manipulation and analysis with Caido
- **Browser Exploitation** - Automated browser for testing XSS, CSRF, clickjacking, and auth bypass flows
- **Shell & Command Execution** - Interactive terminal for exploit development and post-exploitation
- **Custom Exploit Runtime** - Python sandbox for writing and validating proof-of-concept exploits
- **Reconnaissance & OSINT** - Automated attack surface mapping, subdomain enumeration, and fingerprinting
- **Static & Dynamic Code Analysis** - SAST + DAST capabilities for comprehensive application security testing
- **Vulnerability Knowledge Base** - Structured findings with CVSS scoring and OWASP classification
- **MCP Server Integration** - Connect to external Model Context Protocol servers for extended tooling
- **Supply Chain Security** - SBOM generation, dependency CVE scanning, and policy enforcement

### Comprehensive Vulnerability Scanner

Strix identifies, validates, and exploits a wide range of security vulnerabilities across the OWASP Top 10 and beyond:

- **Broken Access Control** - IDOR, privilege escalation, auth bypass
- **Injection Attacks** - SQL injection, NoSQL injection, OS command injection, SSTI
- **Server-Side Vulnerabilities** - SSRF, XXE, insecure deserialization, RCE
- **Client-Side Attacks** - XSS (stored/reflected/DOM), prototype pollution, CSRF
- **Business Logic Flaws** - Race conditions, payment manipulation, workflow bypass
- **Authentication & Session** - JWT attacks, session fixation, credential stuffing vectors
- **Infrastructure & Cloud** - Misconfigurations, exposed services, cloud security issues
- **API Security** - Broken authentication, mass assignment, rate limiting bypass
- **LLM/GenAI Security** - Prompt injection, agentic system security, RAG poisoning (OWASP LLM Top 10)
- **Supply Chain** - Dependency confusion, malicious packages, build pipeline attacks

### Graph of Agents (Multi-Agent Pentesting)

Advanced multi-agent orchestration for comprehensive automated penetration testing:

- **Distributed Pentesting** - Specialized AI agents for recon, exploitation, and post-exploitation
- **Scalable Security Testing** - Parallel execution across multiple targets for fast, comprehensive coverage
- **Dynamic Coordination** - Agents share discoveries, chain vulnerabilities, and collaborate like a red team
- **Skill-Based Specialization** - Agents load relevant skills (100+ available) for each subtask
- **Resume & Continue** - Interrupted scans resume from where they left off

### Skills System (100+ Specialized Skills)

Strix agents dynamically load specialized knowledge packages for deep expertise:

| Category | Purpose | Examples |
|----------|---------|----------|
| **Vulnerabilities** | Advanced testing for core vulnerability classes | `sql_injection`, `xss`, `idor`, `race_conditions`, `rce`, `ssrf` |
| **Frameworks** | Specific testing for popular frameworks | `django`, `fastapi`, `nextjs`, `nestjs` |
| **Technologies** | Specialized techniques for third-party services | `supabase`, `firebase`, `auth0`, `llm_applications` |
| **Protocols** | Protocol-specific testing patterns | `graphql`, `oauth`, `webhooks` |
| **Tooling** | Playbooks for core sandbox tools | `nmap`, `nuclei`, `httpx`, `ffuf`, `subfinder`, `sqlmap` |
| **Cloud** | Cloud provider security testing | `aws`, `azure`, `gcp`, `kubernetes` |
| **Reconnaissance** | Attack surface mapping and enumeration | `asset_discovery`, `infrastructure_lifecycle` |
| **Custom** | Community-contributed specialized skills | `npx_confusion`, `dependency_cve_scanning`, `semantic_confusion` |
| **Scan Modes** | Orchestration patterns for different depths | `quick`, `standard`, `deep`, `diff` |

Notable advanced skills: `source_aware_whitebox` (white-box orchestration), `source_aware_sast` (Opengrep/AST/secrets/supply-chain), `browser_security` (postMessage, XS-Leaks, service workers), `agentic_system_security` (MCP/tool ecosystem), `llm_prompt_injection` (direct, indirect, multimodal, memory, tool-result), `argument_injection` (CLI option smuggling).

### Scan Modes

- **Quick** - Fast triage (~5-15 min), high-signal findings only
- **Standard** - Balanced coverage (~30-60 min)
- **Deep** - Comprehensive assessment (~2-6 hours)
- **Diff** - Scope to changed files only (ideal for CI/PR reviews)

---

## 🖥️ Local Web Viewer

Every scan writes its results to disk as it runs. Bring them up in a local dashboard with a single command:

```bash
# Open the most recent run
strix view

# ...or open a specific run by name
strix view my-run-name

# Expose the viewer on all IPv4 interfaces at a fixed port
strix view --host 0.0.0.0 --port 8080 --no-open
```

The dashboard shows findings, a live map of the agent team, and past runs. Nothing leaves your machine, and the UI ships prebuilt. `strix view` binds to `127.0.0.1` and prints a tokened link that grants access to the run, so share it carefully.

See the [viewer documentation](https://docs.strix.ai/usage/viewer) for options and reaching the viewer from another machine.

---

## Usage Examples

### Basic Usage

```bash
# Scan a local codebase
strix --target ./app-directory

# Security review of a GitHub repository
strix --target https://github.com/org/repo

# Black-box web application assessment
strix --target https://your-app.com
```

### API Testing (OpenAPI / Swagger / Postman)

Point Strix at an API contract and it tests every declared endpoint instead of having to discover them by crawling. Pair the spec with the live base URL so the agent knows where to send traffic:

```bash
# OpenAPI / Swagger file, Postman export, or a live collection by id
strix --target ./openapi.yaml --target https://api.your-app.com
strix --target postman://<collection-uuid> --target https://api.your-app.com
```

### Advanced Testing Scenarios

```bash
# Grey-box authenticated testing
strix --target https://your-app.com --instruction "Perform authenticated testing using credentials: user:pass"

# Multi-target testing (source code + deployed app)
strix -t https://github.com/org/app -t https://your-app.com

# Targets from a file, one target per non-empty, non-comment line
strix --target-list ./targets.txt

# Resume an interrupted scan
strix --resume my-run-name

# Scan with budget limit
strix -t ./app --max-budget 50 --scan-mode deep

# CI-focused diff scan
strix -t ./ --scan-mode diff --diff-base origin/main
```

See the [CLI reference](https://docs.strix.ai/usage/cli) for every option, including scan modes, diff scope, instruction files, and budgets.

### Headless Mode

Run Strix programmatically without interactive UI using the `-n/--non-interactive` flag - perfect for servers and automated jobs. The CLI prints real-time vulnerability findings and the final report before exiting. Exits with non-zero code when vulnerabilities are found.

```bash
strix -n --target https://your-app.com
```

### CI/CD (GitHub Actions)

Strix can be added to your pipeline to run a security test on pull requests with a lightweight GitHub Actions workflow:

```yaml
name: strix-penetration-test

on:
  pull_request:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0

      - name: Install Strix
        run: curl -sSL https://strix.ai/install | bash

      - name: Run Strix
        env:
          STRIX_LLM: ${{ secrets.STRIX_LLM }}
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}

        run: strix -n -t ./ --scan-mode quick
```

> [!TIP]
> In CI pull request runs, Strix automatically scopes quick reviews to changed files, which is why the checkout above fetches full history. See the [CI/CD documentation](https://docs.strix.ai/integrations/github-actions) for the details.

### Configuration

```bash
export STRIX_LLM="vercel_ai_gateway/zai/glm-5.3"   # Vercel AI Gateway (recommended)
# export STRIX_LLM="openrouter/z-ai/glm-5.3"       # OpenRouter
export LLM_API_KEY="your-api-key"

# Optional
export LLM_API_BASE="your-api-base-url"  # if using a local model, e.g. Ollama, LMStudio
```

> [!NOTE]
> Strix automatically saves your configuration to `~/.strix/cli-config.json`, so you don't have to re-enter it on every run.
> See the [configuration reference](https://docs.strix.ai/advanced/configuration) for every environment variable.

#### Sign in with a ChatGPT Subscription

Instead of a metered API key, you can run Strix on your ChatGPT Plus/Pro subscription:

```bash
strix auth login chatgpt             # sign in with your ChatGPT account
export STRIX_LLM="chatgpt/gpt-5.4"   # chatgpt/<model> runs on the subscription
strix auth status                    # show the active sign-in, or logout to forget it
```

#### Connect Your Own MCP Servers

Strix can connect to Model Context Protocol (MCP) servers you list and expose their tools to the agent during a run. Create `~/.strix/mcp-servers.json` with a JSON list of local `stdio` servers or remote `http` servers:

```json
[
  {
    "name": "github",
    "transport": "http",
    "url": "https://api.githubcopilot.com/mcp/",
    "auth": { "kind": "bearer", "token": "your-token" },
    "allowed_tools": ["list_issues"]
  }
]
```

Each server's tools are namespaced by `name`, for example `github_list_issues`. See the [MCP documentation](https://docs.strix.ai/integrations/mcp) for the full schema, tool filtering, and `stdio` servers.

### Recommended Models for Best Results

- [Z.ai GLM-5.3 on Vercel AI Gateway](https://vercel.com/ai-gateway/models/glm-5.3) - `vercel_ai_gateway/zai/glm-5.3` (recommended)
- [Z.ai GLM-5.3 on OpenRouter](https://openrouter.ai/z-ai/glm-5.3) - `openrouter/z-ai/glm-5.3` (recommended)
- [DeepSeek V4.1 Flash on OpenRouter](https://openrouter.ai/deepseek/deepseek-v4.1-flash-1017) - `openrouter/deepseek/deepseek-v4.1-flash-1017`
- [OpenAI GPT-6.1 Sol](https://openai.com/api/) - `openai/gpt-6.1-sol` (needs [Daybreak](https://openai.com/daybreak/) access)
- [Anthropic Claude Opus 5.5](https://claude.com/platform/api) - `anthropic/claude-opus-5-5` (needs [CVP](https://support.claude.com/en/articles/14604842-cyber-verification-program) access)
- [Google Gemini 4 Argon](https://cloud.google.com/vertex-ai) - `vertex_ai/gemini-4-argon` (needs [Fairwind](https://deepmind.google/fairwind-program/) access)
- [DeepSeek V4 Pro](https://platform.deepseek.com) - `deepseek/deepseek-v4-pro`
- [Moonshot Kimi K3.1 Pro](https://platform.kimi.ai) - `moonshot/kimi-k3.1-pro`

See the [LLM Providers documentation](https://docs.strix.ai/llm-providers/overview) for all supported providers including Vertex AI, Bedrock, Azure, and local models.

---

## 📚 Documentation

Full documentation is available at **[docs.strix.ai](https://docs.strix.ai)** - including detailed guides for:
- [Quickstart](https://docs.strix.ai/quickstart)
- [CLI Reference](https://docs.strix.ai/usage/cli)
- [Scan Modes](https://docs.strix.ai/usage/scan-modes)
- [Custom Instructions](https://docs.strix.ai/usage/instructions)
- [Local Viewer](https://docs.strix.ai/usage/viewer)
- [CI/CD Integrations](https://docs.strix.ai/integrations/github-actions)
- [MCP Integration](https://docs.strix.ai/integrations/mcp)
- [Coding Agents](https://docs.strix.ai/integrations/coding-agents)
- [Configuration](https://docs.strix.ai/advanced/configuration)
- [LLM Providers](https://docs.strix.ai/llm-providers/overview)
- [Strix Cloud CLI](https://docs.strix.ai/cloud/cli)
- [Contributing](https://docs.strix.ai/contributing)

---

## Contributing

We welcome contributions of code, docs, and new skills - check out our [Contributing Guide](https://docs.strix.ai/contributing) to get started or open a [pull request](https://github.com/usestrix/strix/pulls)/[issue](https://github.com/usestrix/strix/issues).

## Join Our Community

Have questions? Found a bug? Want to contribute? **[Join our Discord!](https://discord.gg/strix-ai)**

## Support the Project

**Love Strix?** Give us a ⭐ on GitHub!

## Acknowledgements

Strix builds on the incredible work of open-source projects like [LiteLLM](https://github.com/BerriAI/litellm), [Caido](https://github.com/caido/caido), [Nuclei](https://github.com/projectdiscovery/nuclei), [Playwright](https://github.com/microsoft/playwright), and [Bubble Tea](https://github.com/charmbracelet/bubbletea). Huge thanks to their maintainers!


> [!WARNING]
> **Authorized use only.** Strix actively tests the targets you point it at, so only run it against systems you own or have **explicit, written permission** to test, and stay within the agreed scope. Unauthorized testing is illegal in most jurisdictions.
> You alone are responsible for obtaining authorization and complying with the law. Strix is provided "as is" with no warranty or liability for misuse.

</div>
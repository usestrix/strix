<p align="center">
  <a href="https://strix.ai/">
    <img src="https://github.com/usestrix/.github/raw/main/imgs/cover.png" alt="Strix Banner" width="100%">
  </a>
</p>

<div align="center">

# Strix

### The open-source AI pentesting tool. Autonomous AI hackers that find and fix your app’s vulnerabilities.

<br/>


<a href="https://docs.strix.ai"><img src="https://img.shields.io/badge/Docs-docs.strix.ai-2b9246?style=for-the-badge&logo=gitbook&logoColor=white" alt="Docs"></a>
<a href="https://strix.ai"><img src="https://img.shields.io/badge/Website-strix.ai-f0f0f0?style=for-the-badge&logoColor=000000" alt="Website"></a>
[![](https://dcbadge.limes.pink/api/server/strix-ai)](https://discord.gg/strix-ai)

<a href="https://deepwiki.com/usestrix/strix"><img src="https://deepwiki.com/badge.svg" alt="Ask DeepWiki"></a>
<a href="https://github.com/usestrix/strix"><img src="https://img.shields.io/github/stars/usestrix/strix?style=flat-square" alt="GitHub Stars"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-3b82f6?style=flat-square" alt="License"></a>
<a href="https://pypi.org/project/strix-agent/"><img src="https://img.shields.io/pypi/v/strix-agent?style=flat-square" alt="PyPI Version"></a>


<a href="https://discord.gg/strix-ai"><img src="https://github.com/usestrix/.github/raw/main/imgs/Discord.png" height="40" alt="Join Discord"></a>
<a href="https://x.com/strix_ai"><img src="https://github.com/usestrix/.github/raw/main/imgs/X.png" height="40" alt="Follow on X"></a>


<a href="https://trendshift.io/repositories/15362?utm_source=trendshift-badge&amp;utm_medium=badge&amp;utm_campaign=badge-trendshift-15362" target="_blank" rel="noopener noreferrer"><img src="https://trendshift.io/api/badge/trendshift/repositories/15362/weekly" alt="usestrix%2Fstrix | Trendshift" width="250" height="55"/></a>
<a href="https://trendshift.io/repositories/15362" target="_blank"><img src="https://trendshift.io/api/badge/repositories/15362" alt="usestrix/strix | Trendshift" width="250" height="55"/></a>

</div>


> [!TIP]
> **New!** Strix integrates seamlessly with GitHub Actions and CI/CD pipelines. Automatically scan for vulnerabilities on every pull request and block insecure code before it reaches production - [Get started with no setup required](https://app.strix.ai).

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

## 🚀 Quick Start

**Prerequisites:**
- Docker (running)
- An LLM API key from any [supported provider](https://docs.strix.ai/llm-providers/overview) (OpenAI, Anthropic, Google, etc.)

### Installation & First Scan

```bash
# Install Strix
curl -sSL https://strix.ai/install | bash

# Configure your AI provider
export STRIX_LLM="openrouter/z-ai/glm-5.3"
export LLM_API_KEY="your-api-key"

# Run your first security assessment
strix --target ./app-directory
```

> [!NOTE]
> First run automatically pulls the sandbox Docker image. Results are saved to `strix_runs/<run-name>`

---

## ☁️ Strix Platform

Try the Strix full-stack penetration testing platform at **[app.strix.ai](https://app.strix.ai)** - sign up for free, connect your repos and domains, and launch a pentest in minutes.

- **Validated findings with PoCs** - every vulnerability includes a working proof-of-concept exploit and reproduction steps
- **One-click autofix** - AI-generated security patches as ready-to-merge pull requests
- **Continuous pentesting** - always-on vulnerability scanning that keeps pace with your deployments
- **DevSecOps integrations** - GitHub, GitLab, Bitbucket, Slack, Jira, Linear, and CI/CD pipelines
- **Continuous learning** - AI that builds on past findings, adapts to your codebase, and reduces false positives over time

[**Start your first pentest →**](https://app.strix.ai)

---

## 🤖 Use Strix from Your Coding Agent

Strix is agent-ready. Give Claude Code, Cursor, Codex, or any [SKILL.md-compatible](https://agentskills.io) agent the ability to run pentests, fix findings, and set up CI scanning:

```bash
npx skills add usestrix/strix
```

This installs nine skills for running pentests, fixing findings, and CI scanning, against code, web apps, APIs, and the OWASP Top 10. Agents can use the local CLI or the managed cloud with the same engine.

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

### Graph of Agents (Multi-Agent Pentesting)

Advanced multi-agent orchestration for comprehensive automated penetration testing:

- **Distributed Pentesting** - Specialized AI agents for recon, exploitation, and post-exploitation
- **Scalable Security Testing** - Parallel execution across multiple targets for fast, comprehensive coverage
- **Dynamic Coordination** - Agents share discoveries, chain vulnerabilities, and collaborate like a red team

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

The dashboard shows the findings, a live map of the agent team, and past runs. Nothing leaves your machine, and the UI ships prebuilt. `strix view` binds to `127.0.0.1` and prints a tokened link that grants access to the run, so share it carefully.

See the [viewer documentation](https://docs.strix.ai/usage/viewer) for the options and for reaching the viewer from another machine.

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

Point Strix at an API contract and it tests every declared endpoint instead of
having to discover them by crawling. Pair the spec with the live base URL so the
agent knows where to send traffic:

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
> In CI pull request runs, Strix automatically scopes quick reviews to changed files, which is why the
> checkout above fetches full history. See the
> [CI/CD documentation](https://docs.strix.ai/integrations/github-actions) for the details.

### Configuration

```bash
export STRIX_LLM="openrouter/z-ai/glm-5.3"
export LLM_API_KEY="your-api-key"

# Optional
export LLM_API_BASE="your-api-base-url"  # if using a local model, e.g. Ollama, LMStudio
export PERPLEXITY_API_KEY="your-api-key"  # for search capabilities
```

> [!NOTE]
> Strix automatically saves your configuration to `~/.strix/cli-config.json`, so you don't have to re-enter it on every run.
> See the [configuration reference](https://docs.strix.ai/advanced/configuration) for every environment variable.

#### Sign in with a ChatGPT subscription

Instead of a metered API key, you can run Strix on your ChatGPT Plus/Pro subscription:

```bash
strix auth login chatgpt             # sign in with your ChatGPT account
export STRIX_LLM="chatgpt/gpt-5.4"   # chatgpt/<model> runs on the subscription
strix auth status                    # show the active sign-in, or logout to forget it
```

#### Use the managed platform: `strix cloud`

Run scans on [app.strix.ai](https://app.strix.ai) from the terminal, without Docker or an LLM key:

```bash
strix cloud login                                  # browser sign-in, one credential per install
strix cloud scans start --source . --yes --wait    # scan local code, approving the upload
strix cloud scans start --engagement-type live_test --domain-ids <uuid> --wait
strix cloud vulns list --severity critical
```

Every [REST API](https://docs.app.strix.ai) operation has a matching `strix cloud <resource> <verb>` command. Run `strix cloud` to list the resources, and add `help` to a resource to list its verbs. Output is JSON when stdout is not a terminal or when you pass `--json`. Binary downloads are the exception: redirect the raw bytes, or combine `--output FILE --json` for download metadata.

See the [cloud CLI documentation](https://docs.strix.ai/cloud/cli) for scopes, workspaces, billing, and source-upload options.

#### Connect your own MCP servers

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

**Recommended models for best results:**

- [Z.ai GLM-5.3 on OpenRouter](https://openrouter.ai/z-ai/glm-5.3) - `openrouter/z-ai/glm-5.3` (the default pick)
- [OpenAI GPT-5.4](https://openai.com/api/) - `openai/gpt-5.4`
- [Anthropic Claude Sonnet 4.6](https://claude.com/platform/api) - `anthropic/claude-sonnet-4-6`
- [Google Gemini 3 Pro Preview](https://cloud.google.com/vertex-ai) - `vertex_ai/gemini-3-pro-preview`
- [DeepSeek V4 Pro](https://platform.deepseek.com) - `deepseek/deepseek-v4-pro`
- [Moonshot Kimi K3](https://platform.kimi.ai) - `moonshot/kimi-k3`

See the [LLM Providers documentation](https://docs.strix.ai/llm-providers/overview) for all supported providers including Vertex AI, Bedrock, Azure, and local models.

## Enterprise Pentesting

Get the same Strix experience with [enterprise-grade](https://strix.ai/demo) controls: SSO (SAML/OIDC), custom compliance-ready penetration testing reports (SOC 2, ISO 27001, PCI DSS), dedicated support & SLA, custom deployment options (VPC/self-hosted), BYOK model support, and tailored AI pentesting agents optimized for your environment. [Learn more](https://strix.ai/demo).

## Documentation

Full documentation is available at **[docs.strix.ai](https://docs.strix.ai)** - including detailed guides for usage, CI/CD integrations, skills, and advanced configuration.

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

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
export STRIX_LLM="openai/gpt-5.4"
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

This installs nine skills: **penetration-testing-with-strix** (run headless scans and read results), **managed-pentesting-with-strix** (drive the managed [app.strix.ai](https://app.strix.ai) platform via REST — no local Docker or LLM key), **fix-security-vulnerabilities-with-strix** (remediate + re-scan to verify), **ci-security-scanning-with-strix** (PR scanning in CI), plus target-specific workflows: **application-security-testing**, **web-app-penetration-testing**, **api-security-testing**, **owasp-top-10-testing**, and **find-security-vulnerabilities-in-code**. Agents can run Strix two ways with the same engine — the open-source CLI locally, or the managed cloud when there's no local infra — and read [`AGENTS.md`](AGENTS.md) for a quick reference, [docs.strix.ai/llms.txt](https://docs.strix.ai/llms.txt) for the CLI docs, and [docs.app.strix.ai](https://docs.app.strix.ai) for the API.

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

`strix view` starts a lightweight local server (bound to `127.0.0.1` on a random port) and opens your browser to a private, tokened link. Nothing leaves your machine: the dashboard reads the run's files straight off disk, with no cloud account or upload required. The UI ships prebuilt with Strix, so there is no extra install and no JS build step.

Use `--host 0.0.0.0` to make the viewer reachable from other machines. Replace `0.0.0.0` in the printed URL with the server's reachable IP or hostname. The token in that URL grants access to the selected run's scan data, history, and steering, so only share it with trusted users and restrict the port with your firewall. Requests without the token-derived session cannot read run data.

### What's in the dashboard

- **Overview**: run status, target, and a severity breakdown of everything found so far.
- **Vulnerabilities**: each validated finding with its severity, details, and reproduction steps.
- **Agent graph**: a live map of the multi-agent team, showing which agent is doing what.
- **Steering**: send instructions to a live scan from the browser to redirect the agents mid-run.
- **History**: browse past runs on this machine and jump between them.
- **Reports**: generate a shareable report and email it to yourself or your team.

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
# OpenAPI / Swagger file (.json / .yaml)
strix --target ./openapi.yaml --target https://api.your-app.com

# Postman collection export
strix --target ./collection.postman_collection.json --target https://api.your-app.com

# Postman collection pulled live by id (no manual export)
export POSTMAN_API_KEY="PMAK-..."
strix --target postman://<collection-uuid>

# ...with a Postman environment to resolve {{baseUrl}} / token variables
strix --target "postman://<collection-uuid>?env=<environment-uuid>"
```


### Advanced Testing Scenarios

```bash
# Grey-box authenticated testing
strix --target https://your-app.com --instruction "Perform authenticated testing using credentials: user:pass"

# Multi-target testing (source code + deployed app)
strix -t https://github.com/org/app -t https://your-app.com

# Targets from a file, one target per non-empty, non-comment line
strix --target-list ./targets.txt

# White-box source-aware scan (local repository)
strix --target ./app-directory --scan-mode standard

# Focused testing with custom instructions
strix --target api.your-app.com --instruction "Focus on business logic flaws and IDOR vulnerabilities"

# Provide detailed instructions through file (e.g., rules of engagement, scope, exclusions)
strix --target api.your-app.com --instruction-file ./instruction.md

# Force PR diff-scope against a specific base branch
strix -n --target ./ --scan-mode quick --scope-mode diff --diff-base origin/main
```

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
> In CI pull request runs, Strix automatically scopes quick reviews to changed files.
> If diff-scope cannot resolve, ensure checkout uses full history (`fetch-depth: 0`) or pass
> `--diff-base` explicitly.

### Configuration

```bash
export STRIX_LLM="openai/gpt-5.4"
export LLM_API_KEY="your-api-key"

# Optional
export LLM_API_BASE="your-api-base-url"  # if using a local model, e.g. Ollama, LMStudio
export PERPLEXITY_API_KEY="your-api-key"  # for search capabilities
export STRIX_REASONING_EFFORT="high"  # control thinking effort (default: high, quick scan: medium)
```

> [!NOTE]
> Strix automatically saves your configuration to `~/.strix/cli-config.json`, so you don't have to re-enter it on every run.

#### Sign in with a ChatGPT subscription

Instead of a metered API key, you can run Strix on your ChatGPT Plus/Pro subscription:

```bash
strix auth login chatgpt      # sign in with your ChatGPT account

export STRIX_LLM="chatgpt/gpt-5.4"   # chatgpt/<model> runs on the subscription
strix --target ./app-directory

strix auth status             # show the active sign-in
strix auth logout             # forget the sign-in
```

#### Use the managed platform: `strix cloud`

The `strix cloud` commands drive the managed platform ([app.strix.ai](https://app.strix.ai)) from the terminal. Sign in once with the device flow. The sign-in creates your account and workspace on first use and stores a personal API token in `~/.strix/platform-auth.json`:

```bash
strix cloud login                         # browser approval, then workspace + scope profile
strix cloud login --workspace "My Team"   # select a workspace by name or ID
strix cloud whoami                        # fast local account/workspace status
strix cloud session                       # verify remote session + consent ceiling
strix cloud logout                        # revoke remotely, then remove locally
```

The default **Recommended** scope preset supports normal scan work, local source uploads,
workspace switching, and user-approved credit top-ups. It excludes credential creation;
request `tokens:write` explicitly (or choose Full) when needed. For strict least privilege, pass an explicit list such as
`--scopes scans:read scans:write uploads:write billing:read`. Named automation
profiles are also available with `--scope-profile minimal|recommended|full`.

Every operation of the [REST API](https://docs.app.strix.ai) has a matching command in the form `strix cloud <resource> <verb>`:

```bash
strix cloud                                   # list all resources
strix cloud scans                             # run the safe default (`scans list`)
strix cloud scans help                        # list the verbs of a resource
strix cloud domains add --domain example.com --asset-type web_app
strix cloud scans start --engagement-type live_test --domain-ids <uuid> --wait
strix cloud scans start --source . --dry-run --show-files --json  # review + capture source.archive_sha256
SOURCE_SHA256="<reviewed source.archive_sha256>"
strix cloud scans start --source . --approve-sha256 "$SOURCE_SHA256" --wait
strix cloud vulns list --severity critical
strix cloud credits                           # credit balance
strix cloud billing topup --credits 20 --yes  # explicitly approve agent payment after HTTP 402
```

Workspaces and account setup also work from the terminal:

```bash
strix cloud workspaces list                   # numbered list; `workspace` is also accepted
strix cloud workspaces create --name "My Team" # admin + organizations:write
strix cloud workspaces use 2                  # switch by list number, exact name, or ID
strix cloud session scopes                    # granted scopes + login ceiling
strix cloud session scopes set minimal        # narrow without another browser sign-in
strix cloud billing subscribe --plan strix_cloud # opens the hosted checkout page
strix cloud billing portal                    # opens the billing portal
strix cloud integrations install github       # opens the app installation page
strix cloud domains verify <domain-id>        # prints the DNS record to add
```

The last four commands end at a person. Strix creates the link, opens the browser for an interactive terminal, and always prints the URL. The user enters the card, approves the installation, or adds the DNS record. Pass `--no-browser` to print the URL only.

The commands work for humans and agents: terminal output favors names, branches, lifecycle states, and numbered selectors, while redirected output (or `--json`) preserves complete machine-readable records and IDs. Human lists retain the selectors needed by follow-up commands but omit internal organization/user IDs; a selector too long for the compact table is repeated losslessly in a copyable block. Paginated lists print the next `--page` or `--offset`, and detail views preserve useful prose within a safe terminal bound; use `--json` for the complete record. Token lists distinguish API keys from named CLI device sessions. Binary downloads are the exception: intentionally redirect their raw bytes, or use `--output FILE --json` to write the file and receive structured download metadata. There are no prompts when stdin is not a terminal. Exit codes: `0` success, `1` error, `2` invalid usage, `4` authentication or plan limit, `5` payment required. `--token` and `STRIX_API_TOKEN` are stateless per-command overrides and never replace the stored sign-in; pair a CLI-session override with `--workspace-id` or `STRIX_WORKSPACE_ID`.

A browser sign-in creates one reusable credential per CLI installation. Logging in again on the
same installation replaces its secret instead of accumulating keys. Workspace switches keep that
credential and expiry, preserve the server-side scope preference, cap access by the target role,
and can never exceed the login consent ceiling. Each process pins its starting workspace, so a
concurrent switch fails safely instead of sending a stale command to another organization.
`strix cloud logout` revokes the server session before deleting the local token; use
`--local-only` only when you deliberately cannot reach the server.

Write commands take request fields as flags, and every write command also accepts one JSON object with `--data`:

```bash
strix cloud scans start --data '{"engagement_type":"code_review"}'   # literal JSON
strix cloud scans start --data @request.json                         # read a file
cat request.json | strix cloud scans start --data -                  # read standard input
```

For an agent or CI local-source scan, run `--dry-run --show-files --json`, review the manifest,
and capture `source.archive_sha256`. Rerun with the same `--source`, every `--exclude`, and any
`--include-*` selection flags, replacing `--dry-run` with `--approve-sha256 HASH`; Strix
rebuilds the archive and refuses to upload it if the digest changed. `--yes` instead approves
only the snapshot built in that one invocation. It is suitable for a deliberate human or
one-shot approval, not as a digest-bound two-step agent/CI handoff.

The safe default honors `.gitignore` and `.strixignore` and excludes hidden paths, secret-like
files, VCS metadata, dependencies/build output, symlinks, and nested archives. Opt in
separately with `--include-hidden`, `--include-sensitive`, or `--include-archives`. The client
caps a bundle at 20,000 files, 25 MiB per file, 250 MiB expanded, and 50 MiB compressed, and
the service independently validates the archive. Source alone infers a code review; adding a
domain infers a live test. You can always pass `--engagement-type` explicitly.

Strix removes the temporary local archive after every invocation. It deletes a staged remote
upload after a definitive scan rejection. If a network error, `5xx` response, malformed
success response, or interruption makes the launch outcome ambiguous, it retains the upload and reports its `upload_id` with
`launch_outcome_unknown: true`; if automatic deletion cannot be confirmed, it reports the ID
with `cleanup_unknown: true`. Check `strix cloud scans list` before retrying. If no scan is
linked to the retained upload, delete it with `strix cloud uploads delete UPLOAD_ID`.

Non-Enterprise scans consume the deterministic estimate shown for their scope (a source-only
code review at the default `ultra` tier currently starts at 60 credits). Enterprise scans are
plan-included and do not consume the credit wallet. Report downloads need Enterprise,
schedules need Pro, and billing writes need an admin token. Plan blocks exit `4`; an
insufficient credit wallet exits `5` without creating or charging a scan.

Enable native tab completion once per shell session:

```bash
source <(strix completions zsh)       # use bash instead of zsh when appropriate
strix completions fish | source
```

#### Connect your own MCP servers

Strix can connect to Model Context Protocol (MCP) servers you list and expose their tools to the agent during a run. Create `~/.strix/mcp-servers.json` with a JSON list of servers. Each entry is either a local `stdio` server that Strix launches as a subprocess, or a remote `http` server:

```json
[
  {
    "name": "local_fs",
    "transport": "stdio",
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/path/to/project"]
  },
  {
    "name": "github",
    "transport": "http",
    "url": "https://api.githubcopilot.com/mcp/",
    "auth": { "kind": "bearer", "token": "your-token" },
    "allowed_tools": ["list_issues"]
  }
]
```

Each server's tools are namespaced by `name` (for example `local_fs_read_file`). Omit `allowed_tools` to expose every tool the server offers, or set it to a list to restrict which tools the agent can call. The file is optional, and a server that fails to connect is skipped without failing the run. You can point Strix at a different file with `STRIX_MCP_CONFIG`.

**Recommended models for best results:**

- [Z.ai GLM-5.3 on OpenRouter](https://openrouter.ai/z-ai/glm-5.3) - `openrouter/z-ai/glm-5.3` (our top pick)
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

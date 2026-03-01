<p align="center">
  <a href="https://strix.ai/">
    <img src="https://github.com/usestrix/.github/raw/main/imgs/cover.png" alt="Strix Banner" width="100%">
  </a>
</p>

<div align="center">

# Strix

### Open-source AI hackers to find and fix your app’s vulnerabilities.

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


<a href="https://trendshift.io/repositories/15362" target="_blank"><img src="https://trendshift.io/api/badge/repositories/15362" alt="usestrix/strix | Trendshift" width="250" height="55"/></a>

</div>


---


## Strix Overview

Strix are autonomous AI agents that act just like real hackers - they run your code dynamically, find vulnerabilities, and validate them through actual proof-of-concepts. Built for developers and security teams who need fast, accurate security testing without the overhead of manual pentesting or the false positives of static analysis tools.

**Key Capabilities:**

- **Full hacker toolkit** out of the box
- **Teams of agents** that collaborate and scale
- **Real validation** with PoCs, not false positives
- **Developer‑first** CLI with actionable reports
- **Auto‑fix & reporting** to accelerate remediation


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
- An LLM API key:
  - Any [supported provider](https://docs.strix.ai/llm-providers/overview) (OpenAI, Anthropic, Google, etc.)
  - Or [Strix Router](https://models.strix.ai) — single API key for multiple providers with $10 free credit on signup

### Installation & First Scan

```bash
# Install Strix
curl -sSL https://strix.ai/install | bash

# Configure your AI provider
export STRIX_LLM="openai/gpt-5"  # or "strix/gpt-5" via Strix Router (https://models.strix.ai)
export LLM_API_KEY="your-api-key"

# Run your first security assessment
strix --target ./app-directory
```

> [!NOTE]
> First run automatically pulls the sandbox Docker image. Results are saved to `strix_runs/<run-name>`

---

## ☁️ Strix Platform

Try the Strix full-stack security platform at **[app.strix.ai](https://app.strix.ai)** — sign up for free, connect your repos and domains, and launch a pentest in minutes.

- **Validated findings with PoCs** and reproduction steps
- **One-click autofix** as ready-to-merge pull requests
- **Continuous monitoring** across code, cloud, and infrastructure
- **Integrations** with GitHub, Slack, Jira, Linear, and CI/CD pipelines
- **Continuous learning** that builds on past findings and remediations

[**Start your first pentest →**](https://app.strix.ai)

---

## ✨ Features

### Agentic Security Tools

Strix agents come equipped with a comprehensive security testing toolkit:

- **Full HTTP Proxy** - Full request/response manipulation and analysis
- **Browser Automation** - Multi-tab browser for testing of XSS, CSRF, auth flows
- **Terminal Environments** - Interactive shells for command execution and testing
- **Python Runtime** - Custom exploit development and validation
- **Reconnaissance** - Automated OSINT and attack surface mapping
- **Code Analysis** - Static and dynamic analysis capabilities
- **Knowledge Management** - Structured findings and attack documentation

### Comprehensive Vulnerability Detection

Strix can identify and validate a wide range of security vulnerabilities:

- **Access Control** - IDOR, privilege escalation, auth bypass
- **Injection Attacks** - SQL, NoSQL, command injection
- **Server-Side** - SSRF, XXE, deserialization flaws
- **Client-Side** - XSS, prototype pollution, DOM vulnerabilities
- **Business Logic** - Race conditions, workflow manipulation
- **Authentication** - JWT vulnerabilities, session management
- **Infrastructure** - Misconfigurations, exposed services

### Graph of Agents

Advanced multi-agent orchestration for comprehensive security testing:

- **Distributed Workflows** - Specialized agents for different attacks and assets
- **Scalable Testing** - Parallel execution for fast comprehensive coverage
- **Dynamic Coordination** - Agents collaborate and share discoveries

---

## Operator-Assisted Tools

Strix agents can guide the operator through 25 professional-grade security tools via the Human-in-the-Loop (HIL) system. The agent selects the right tool, generates the exact command, and the operator executes it and drops the output into the inbox for automated analysis.

### Reconnaissance & Scanning

- **Nmap** -- Host discovery, port scanning, service/version detection, OS fingerprinting, and NSE vulnerability scripts
- **Nikto** -- Web server vulnerability scanning and misconfiguration detection
- **Nuclei** -- Template-based vulnerability scanning across web applications, networks, and cloud services
- **Gobuster** -- Directory brute-forcing, DNS subdomain enumeration, and virtual host discovery
- **FFUF** -- High-speed web fuzzing for directory discovery, parameter mining, and vhost enumeration
- **theHarvester** -- OSINT gathering of emails, subdomains, IPs, and URLs from public sources
- **WPScan** -- WordPress vulnerability scanning, plugin/theme enumeration, and user discovery
- **Maltego** -- OSINT visualization, entity relationship mapping, and attack surface discovery

### Exploitation & Post-Exploitation

- **Metasploit Framework** -- Exploit execution, payload delivery, post-exploitation, and pivoting
- **SQLMap** -- Automated SQL injection detection, exploitation, database enumeration, and data extraction
- **Hydra** -- Online credential brute-forcing against network services (SSH, FTP, HTTP, SMB, etc.) and web forms
- **BeEF** -- Browser exploitation, XSS hook management, and client-side attack delivery
- **SET (Social Engineering Toolkit)** -- Phishing campaigns, credential harvesting, and client-side attacks
- **NetExec** -- Active Directory enumeration, credential validation, and lateral movement
- **Responder** -- LLMNR/NBT-NS/mDNS poisoning and NetNTLM hash capture on local networks

### Proxy & Web Testing

- **Burp Suite** -- Intercepting proxy, active scanning, Intruder attacks, and Collaborator out-of-band detection
- **OWASP ZAP** -- Automated web scanning, spidering, fuzzing, and API security testing

### Password Cracking

- **Hashcat** -- GPU-accelerated offline password cracking with advanced attack modes (dictionary, mask, rules, combinator)
- **John the Ripper** -- Offline password cracking with wordlists, rules, and automatic hash format detection

### Network & Wireless

- **Wireshark** -- Network traffic capture, protocol analysis, and credential extraction
- **Bettercap** -- Network MITM attacks, traffic sniffing, ARP/DNS spoofing, and SSL stripping
- **Aircrack-ng** -- Wireless network auditing, WPA/WPA2 cracking, and rogue AP detection

### Active Directory

- **BloodHound** -- AD attack path analysis, privilege escalation mapping, and Kerberoasting target identification

### Reverse Engineering & Forensics

- **Ghidra** -- Binary reverse engineering, vulnerability discovery, and firmware analysis
- **Volatility** -- Memory forensics, credential extraction, and process/network analysis

---

## Human-in-the-Loop (HIL) Inbox System

The HIL inbox is a file-based input system that replaces fragile copy-paste workflows (e.g. piping large Nmap or Metasploit output through terminal `input()` or Caido proxy). It lets the operator drop tool output of any size into a shared directory where the agent automatically picks it up.

### How It Works

The HIL system uses a simple request/response file protocol:

```
strix/hil/inbox/
    req_<task_id>.txt    <-- Agent writes: what it needs (tool, command, instructions)
    resp_<task_id>.txt   <-- Operator writes: full tool output
```

**Step-by-step flow:**

1. The agent determines which tool to run and generates the exact command.
2. The agent creates a request file (e.g. `req_a1b2c3.txt`) containing instructions for the operator.
3. The agent prints the expected response filename and begins polling the inbox.
4. The operator runs the tool and saves output to the response file (e.g. `resp_a1b2c3.txt`).
5. The agent detects the response, reads the full content, parses the results, and continues analysis.
6. Both files are cleaned up automatically after processing (configurable).

### Usage in Code

The module provides both standalone functions and a stateful `InputManager` class:

```python
# Standalone usage
from strix.hil import request_input, wait_for_response

task_id = "a1b2c3d4"
request_input(task_id, "Run: nmap -sV -sC -O -oX scan.xml TARGET")
output = wait_for_response(task_id, timeout=300)
# Agent now has full Nmap output for parsing

# Stateful session usage
from strix.hil import InputManager

mgr = InputManager(default_timeout=600)
result = mgr.ask("task1", "Run: sqlmap -r request.txt --batch --dbs")
# mgr.history tracks all request/response pairs
```

### Key Features

- **No size limits** -- Handles megabytes of tool output that would break terminal copy-paste
- **Persistent** -- Files survive agent restarts; the operator can take their time
- **Configurable inbox path** -- Set `HIL_INBOX_PATH` env var to use any directory
- **Automatic cleanup** -- Request and response files are deleted after processing (opt-out with `cleanup=False`)
- **Pending request tracking** -- `list_pending_requests()` shows unanswered requests so nothing gets lost
- **Full history** -- `InputManager.history` records every completed request/response pair for the session
- **Timeout handling** -- Raises `HILTimeoutError` if the operator does not respond within the configured window

### Operator Workflow

When the agent requests tool output, the operator can provide it in two ways:

```bash
# Option 1: Redirect tool output directly to the response file
nmap -sV -sC TARGET > strix/hil/inbox/resp_a1b2c3d4.txt

# Option 2: Run the tool, then copy/move the output file
nmap -sV -sC TARGET -oN scan_results.txt
cp scan_results.txt strix/hil/inbox/resp_a1b2c3d4.txt
```

The agent will detect the file within seconds and continue automatically.

### Configuration

```bash
# Override the default inbox location
export HIL_INBOX_PATH="/path/to/custom/inbox"
```

The default inbox is `strix/hil/inbox/` relative to the package. The `HIL_INBOX_PATH` variable is tracked by the Strix Config system and can be persisted via `~/.strix/cli-config.json`.

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

### Advanced Testing Scenarios

```bash
# Grey-box authenticated testing
strix --target https://your-app.com --instruction "Perform authenticated testing using credentials: user:pass"

# Multi-target testing (source code + deployed app)
strix -t https://github.com/org/app -t https://your-app.com

# Focused testing with custom instructions
strix --target api.your-app.com --instruction "Focus on business logic flaws and IDOR vulnerabilities"

# Provide detailed instructions through file (e.g., rules of engagement, scope, exclusions)
strix --target api.your-app.com --instruction-file ./instruction.md
```

### Headless Mode

Run Strix programmatically without interactive UI using the `-n/--non-interactive` flag—perfect for servers and automated jobs. The CLI prints real-time vulnerability findings, and the final report before exiting. Exits with non-zero code when vulnerabilities are found.

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

      - name: Install Strix
        run: curl -sSL https://strix.ai/install | bash

      - name: Run Strix
        env:
          STRIX_LLM: ${{ secrets.STRIX_LLM }}
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}

        run: strix -n -t ./ --scan-mode quick
```

### Configuration

```bash
export STRIX_LLM="openai/gpt-5"
export LLM_API_KEY="your-api-key"

# Optional
export LLM_API_BASE="your-api-base-url"  # if using a local model, e.g. Ollama, LMStudio
export PERPLEXITY_API_KEY="your-api-key"  # for search capabilities
export STRIX_REASONING_EFFORT="high"  # control thinking effort (default: high, quick scan: medium)
export HIL_INBOX_PATH="strix/hil/inbox"  # file-drop inbox for operator-assisted tool output
```

> [!NOTE]
> Strix automatically saves your configuration to `~/.strix/cli-config.json`, so you don't have to re-enter it on every run.

**Recommended models for best results:**

- [OpenAI GPT-5](https://openai.com/api/) — `openai/gpt-5`
- [Anthropic Claude Sonnet 4.6](https://claude.com/platform/api) — `anthropic/claude-sonnet-4-6`
- [Google Gemini 3 Pro Preview](https://cloud.google.com/vertex-ai) — `vertex_ai/gemini-3-pro-preview`

See the [LLM Providers documentation](https://docs.strix.ai/llm-providers/overview) for all supported providers including Vertex AI, Bedrock, Azure, and local models.

## Enterprise

Get the same Strix experience with [enterprise-grade](https://strix.ai/demo) controls: SSO (SAML/OIDC), custom compliance reports, dedicated support & SLA, custom deployment options (VPC/self-hosted), BYOK model support, and tailored agents optimized for your environment. [Learn more](https://strix.ai/demo).

## Documentation

Full documentation is available at **[docs.strix.ai](https://docs.strix.ai)** — including detailed guides for usage, CI/CD integrations, skills, and advanced configuration.

## Contributing

We welcome contributions of code, docs, and new skills - check out our [Contributing Guide](https://docs.strix.ai/contributing) to get started or open a [pull request](https://github.com/usestrix/strix/pulls)/[issue](https://github.com/usestrix/strix/issues).

## Join Our Community

Have questions? Found a bug? Want to contribute? **[Join our Discord!](https://discord.gg/strix-ai)**

## Support the Project

**Love Strix?** Give us a ⭐ on GitHub!

## Acknowledgements

Strix builds on the incredible work of open-source projects like [LiteLLM](https://github.com/BerriAI/litellm), [Caido](https://github.com/caido/caido), [Nuclei](https://github.com/projectdiscovery/nuclei), [Playwright](https://github.com/microsoft/playwright), and [Textual](https://github.com/Textualize/textual). Huge thanks to their maintainers!


> [!WARNING]
> Only test apps you own or have permission to test. You are responsible for using Strix ethically and legally.

</div>

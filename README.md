<p align="center">
  <a href="https://usestrix.com/">
    <img src=".github/logo.png" width="150" alt="Strix Logo">
  </a>
</p>

<h1 align="center">
Strix
</h1>

<h2 align="center">Open-source AI Hackers to secure your Apps</h2>

<div align="center">

[![Python](https://img.shields.io/pypi/pyversions/strix-agent?color=3776AB)](https://pypi.org/project/strix-agent/)
[![PyPI](https://img.shields.io/pypi/v/strix-agent?color=10b981)](https://pypi.org/project/strix-agent/)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/strix-agent?period=total&units=INTERNATIONAL_SYSTEM&left_color=GREY&right_color=RED&left_text=Downloads)](https://pepy.tech/projects/strix-agent)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

[![GitHub Stars](https://img.shields.io/github/stars/usestrix/strix)](https://github.com/usestrix/strix)
[![Discord](https://img.shields.io/badge/Discord-%235865F2.svg?&logo=discord&logoColor=white)](https://discord.gg/YjKFvEZSdZ)
[![Website](https://img.shields.io/badge/Website-usestrix.com-2d3748.svg)](https://usestrix.com)

<a href="https://trendshift.io/repositories/15362" target="_blank"><img src="https://trendshift.io/api/badge/repositories/15362" alt="usestrix%2Fstrix | Trendshift" style="width: 250px; height: 55px;" width="250" height="55"/></a>
</div>

:star: _Love Strix? Give us a star to help other developers discover it!_

<br />

<div align="center">
<img src=".github/screenshot.png" alt="Strix Demo" width="800" style="border-radius: 16px;">
</div>

> [!TIP]
> **New!** Strix now integrates seamlessly with GitHub Actions and CI/CD pipelines. Automatically scan for vulnerabilities on every pull request and block insecure code before it reaches production!

> [!WARNING]
> Only test systems you own or have permission to test. You are responsible for using Strix ethically and legally.

---

## 🦉 Strix Overview

Strix are autonomous AI agents that act just like real hackers - they run your code dynamically, find vulnerabilities, and validate them through actual proof-of-concepts. Built for developers and security teams who need fast, accurate security testing without the overhead of manual pentesting or the false positives of static analysis tools.

- **Full hacker toolkit** out of the box
- **Teams of agents** that collaborate and scale
- **Real validation** with PoCs, not false positives
- **Developer‑first** CLI with actionable reports
- **Auto‑fix & reporting** to accelerate remediation

---

### 🎯 Use Cases

- Detect and validate critical vulnerabilities in your applications.
- Get penetration tests done in hours, not weeks, with compliance reports.
- Automate bug bounty research and generate PoCs for faster reporting.
- Run tests in CI/CD to block vulnerabilities before reaching production.

---

### 🚀 Quick Start

Prerequisites:
- Docker (running)
- Python 3.12+
- An LLM provider key (or a local LLM)

```bash
# Install
pipx install strix-agent

# Configure AI provider
export STRIX_LLM="openai/gpt-5"
export LLM_API_KEY="your-api-key"

# Run security assessment
strix --target ./app-directory
```

First run pulls the sandbox Docker image. Results are saved under `agent_runs/<run-name>`.

### 🏆 Enterprise Platform

Want to skip the setup? Try our cloud-hosted version: **[usestrix.com](https://usestrix.com)**

Our managed platform provides:

- **📈 Executive Dashboards**
- **🧠 Custom Fine-Tuned Models**
- **⚙️ CI/CD Integration**
- **🔍 Large-Scale Scanning**
- **🔌 Third-Party Integrations**
- **🎯 Enterprise Support**

[**Get Enterprise Demo →**](https://usestrix.com)

## ✨ Features

### 🛠️ Agentic Security Tools

- **🔌 Full HTTP Proxy** - Full request/response manipulation and analysis
- **🌐 Browser Automation** - Multi-tab browser for testing of XSS, CSRF, auth flows
- **💻 Terminal Environments** - Interactive shells for command execution and testing
- **🐍 Python Runtime** - Custom exploit development and validation
- **🔍 Reconnaissance** - Automated OSINT and attack surface mapping
- **📁 Code Analysis** - Static and dynamic analysis capabilities
- **📝 Knowledge Management** - Structured findings and attack documentation

### 🎯 Comprehensive Vulnerability Detection

- **Access Control** - IDOR, privilege escalation, auth bypass
- **Injection Attacks** - SQL, NoSQL, command injection
- **Server-Side** - SSRF, XXE, deserialization flaws
- **Client-Side** - XSS, prototype pollution, DOM vulnerabilities
- **Business Logic** - Race conditions, workflow manipulation
- **Authentication** - JWT vulnerabilities, session management
- **Infrastructure** - Misconfigurations, exposed services

### 🕸️ Graph of Agents

- **Distributed Workflows** - Specialized agents for different attacks and assets
- **Scalable Testing** - Parallel execution for fast comprehensive coverage
- **Dynamic Coordination** - Agents collaborate and share discoveries

## 💻 Usage Examples

### Default Usage

```bash
# Local codebase analysis
strix --target ./app-directory

# Repository security review
strix --target https://github.com/org/repo

# Black-Box Web application assessment
strix --target https://your-app.com

# Grey-Box Security Assesment
strix --target https://your-app.com --instructions "Perform authenticated testing using the following credentials user:pass"

# Multi-target white-box testing (source code + deployed app)
strix -t https://github.com/org/app -t https://your-app.com

# Focused testing with instructions
strix --target api.your-app.com --instruction "Focus on business logic flaws and IDOR vulnerabilities"
```

### 🤖 Headless Mode

Run Strix programmatically without interactive UI using the `-n/--non-interactive` flag—perfect for servers and automated jobs. The CLI prints real-time vulnerability findings, and the final report before exiting. Exits with non-zero code when vulnerabilities are found.

```bash
strix -n --target https://your-app.com
```

### 🔄 CI/CD (GitHub Actions)

Strix can be added to your pipeline to run a security test on pull requests with a lightweight GitHub Actions workflow:

```yaml
name: strix-penetration-test

on:
  pull_request:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Strix
        run: pipx install strix-agent

      - name: Run Strix
        env:
          STRIX_LLM: ${{ secrets.STRIX_LLM }}
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}

        run: strix -n -t ./
```

### ⚙️ Configuration

```bash
export STRIX_LLM="openai/gpt-5"
export LLM_API_KEY="your-api-key"

# Optional
export LLM_API_BASE="your-api-base-url"  # if using a local model, e.g. Ollama, LMStudio
export PERPLEXITY_API_KEY="your-api-key"  # for search capabilities
```

[📚 View supported AI models](https://docs.litellm.ai/docs/providers)

## 🤝 Contributing

We welcome contributions from the community! There are several ways to contribute:

### Code Contributions
See our [Contributing Guide](CONTRIBUTING.md) for details on:
- Setting up your development environment
- Running tests and quality checks
- Submitting pull requests
- Code style guidelines

### Prompt Modules Collection
Help expand our collection of specialized prompt modules for AI agents:
- Advanced testing techniques for vulnerabilities, frameworks, and technologies
- See [Prompt Modules Documentation](strix/prompts/README.md) for guidelines
- Submit via [pull requests](https://github.com/usestrix/strix/pulls) or [issues](https://github.com/usestrix/strix/issues)

## 👥 Join Our Community

Have questions? Found a bug? Want to contribute? **[Join our Discord!](https://discord.gg/YjKFvEZSdZ)**

## 🌟 Support the Project

**Love Strix?** Give us a ⭐ on GitHub!

<div align="center">
<img src="https://api.star-history.com/svg?repos=usestrix/strix&type=date&legend=top-left" alt="Star History Chart" width="800" style="border-radius: 16px;">
</div>

</div>

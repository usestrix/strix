<div align="center">

# Strix

### Open-source AI hackers for your apps

[![Strix](https://img.shields.io/badge/Strix-usestrix.com-1a1a1a.svg)](https://usestrix.com)
[![Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Discord](https://img.shields.io/badge/Discord-join-5865F2?logo=discord&logoColor=white)](https://discord.gg/yduEyduBsp)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/strix-agent?period=total&units=INTERNATIONAL_SYSTEM&left_color=GRAY&right_color=BLACK&left_text=Downloads)](https://pepy.tech/projects/strix-agent)
[![GitHub stars](https://img.shields.io/github/stars/usestrix/strix.svg?style=social&label=Star)](https://github.com/usestrix/strix)
</div>

<div align="center">
<img src=".github/screenshot.png" alt="Strix Demo" width="800" style="border-radius: 16px; box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3), 0 0 0 1px rgba(255, 255, 255, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.2); transform: perspective(1000px) rotateX(2deg); transition: transform 0.3s ease;">
</div>

---

## 🦉 Strix Overview

Strix are autonomous AI agents that act just like real hackers - they run your code dynamically, find vulnerabilities, and validate them through actual exploitation. Built for developers and security teams who need fast, accurate security testing without the overhead of manual pentesting or the false positives of static analysis tools.

- **Full hacker toolkit** out of the box
- **Teams of agents** that collaborate and scale
- **Real validation** via exploitation and PoC, not false positives
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

### ☁️ Cloud Hosted

Want to skip the setup? Try our cloud-hosted version: **[usestrix.com](https://usestrix.com)**

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

```bash
# Local codebase analysis
strix --target ./app-directory

# Repository security review
strix --target https://github.com/org/repo

# Web application assessment
strix --target https://your-app.com

# Focused testing
strix --target api.your-app.com --instruction "Prioritize authentication and authorization testing"

# Testing with credentials
strix --target https://your-app.com --instruction "Test with credentials: testuser/testpass. Focus on privilege escalation and access control bypasses."
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

## 🏆 Enterprise Platform

Our managed platform provides:

- **📈 Executive Dashboards**
- **🧠 Custom Fine-Tuned Models**
- **⚙️ CI/CD Integration**
- **🔍 Large-Scale Scanning**
- **🔌 Third-Party Integrations**
- **🎯 Enterprise Support**

[**Get Enterprise Demo →**](https://usestrix.com)

## 🔒 Security Architecture

- **Container Isolation** - All testing in sandboxed Docker environments
- **Local Processing** - Testing runs locally, no data sent to external services

> [!WARNING]
> Only test systems you own or have permission to test. You are responsible for using Strix ethically and legally.

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

## 🌟 Support the Project

**Love Strix?** Give us a ⭐ on GitHub!

## 👥 Join Our Community

Have questions? Found a bug? Want to contribute? **[Join our Discord!](https://discord.gg/yduEyduBsp)**

</div>

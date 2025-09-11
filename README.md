<div align="center">

# Strix

### Open-source AI hackers for your apps

[![Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Vercel AI Accelerator 2025](https://img.shields.io/badge/Vercel%20AI-Accelerator%202025-000000?style=flat&logo=vercel)](https://vercel.com/ai-accelerator)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-orange.svg)](https://github.com/usestrix/strix)

</div>

<div align="center">
<img src=".github/screenshot.png" alt="Strix Demo" width="800" style="border-radius: 16px; box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3), 0 0 0 1px rgba(255, 255, 255, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.2); transform: perspective(1000px) rotateX(2deg); transition: transform 0.3s ease;">
</div>

---

## 🦉 Strix Overview

Strix are autonomous AI agents that act just like real hackers - they run your code dynamically, find vulnerabilities, and validate them through actual exploitation. Built for developers and security teams who need fast, accurate security testing without the overhead of manual pentesting or the false positives of static analysis tools.

### 🚀 Quick Start

```bash
# Install
pipx install strix-agent

# Configure AI provider
export STRIX_LLM="openai/gpt-5"
export LLM_API_KEY="your-api-key"

# Run security assessment
strix --target ./app-directory
```

## Why Use Strix

- **Full Hacker Arsenal** - All the tools a professional hacker needs, built into the agents
- **Real Validation** - Dynamic testing and actual exploitation, thus much fewer false positives
- **Developer-First** - Seamlessly integrates into existing development workflows
- **Auto-Fix & Reporting** - Automated patching with detailed remediation and security reports

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
```

### ⚙️ Configuration

```bash
# Required
export STRIX_LLM="openai/gpt-5"
export LLM_API_KEY="your-api-key"

# Recommended
export PERPLEXITY_API_KEY="your-api-key"
```

[📚 View supported AI models](https://docs.litellm.ai/docs/providers)

### Using Ollama or LM Studio (Remote)

You can point Strix at a remote, self‑hosted OpenAI‑compatible server (e.g., Ollama or LM Studio) via environment variables. Strix uses LiteLLM under the hood and respects a configurable API base.

Option A: Ollama provider (preferred for Ollama)

```bash
# Pick any model pulled on the remote Ollama host
export STRIX_LLM="ollama/llama3.1"

# Point to your remote Ollama instance (no /v1 for the Ollama provider)
export LLM_API_BASE="http://<remote-host>:11434"

# Strix requires this env to be set even if your server doesn’t need it
export LLM_API_KEY="not-needed"
```

Option B: OpenAI‑compatible route (works for Ollama/LM Studio)

```bash
# Use the OpenAI provider name with the model you want
export STRIX_LLM="openai/llama3.1"

# Point to the server’s OpenAI‑compatible API (include /v1)
export LLM_API_BASE="http://<remote-host>:11434/v1"  # Ollama
# or
export LLM_API_BASE="http://127.0.0.1:1234/v1"       # LM Studio default

export LLM_API_KEY="not-needed"
```

Notes

- `LLM_API_BASE` is also honored via `OPENAI_API_BASE`, `LITELLM_BASE_URL`, or `OLLAMA_API_BASE`.
- Keep `STRIX_LLM` aligned with the server type you’re using (e.g., `ollama/<model>` for Ollama, `openai/<model>` for OpenAI‑compatible base URLs).
- You can also use a LiteLLM Proxy by pointing `LLM_API_BASE` (or `LITELLM_BASE_URL`) at the proxy URL and selecting any model your proxy exposes.

## 🏆 Enterprise Platform

Our managed platform provides:

- **📈 Executive Dashboards**
- **🧠 Custom Fine-Tuned Models**
- **⚙️ CI/CD Integration**
- **🔍 Large-Scale Scanning**
- **🔌 Third-Party Integrations**
- **🎯 Enterprise Support**

[**Get Enterprise Demo →**](https://form.typeform.com/to/ljtvl6X0)

## 🔒 Security Architecture

- **Container Isolation** - All testing in sandboxed Docker environments
- **Local Processing** - Testing runs locally, no data sent to external services

> [!NOTE]
> Strix is currently in Alpha. Expect rapid updates and improvements.

> [!WARNING]
> Only test systems you own or have permission to test. You are responsible for using Strix ethically and legally.

## 🌟 Support the Project

**Love Strix?** Give us a ⭐ on GitHub!

## 👥 Join Our Community

Have questions? Found a bug? Want to contribute? **[Join our Discord!](https://discord.gg/yduEyduBsp)**

</div>

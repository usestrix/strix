<h1 align="center">AISEC</h1>

<h2 align="center">AI-Powered Cybersecurity Agent for Penetration Testing</h2>

<div align="center">

[![Python](https://img.shields.io/badge/python-3.12+-3776AB)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**Developed by CYBERSEC**

</div>

<br>

---

## 🛡️ AISEC Overview

AISEC is an advanced autonomous AI cybersecurity agent that acts like a real penetration tester - it runs your code dynamically, finds vulnerabilities, and validates them through actual proof-of-concepts. Built for developers and security teams who need fast, accurate security testing without the overhead of manual pentesting or the false positives of static analysis tools.

**Key Capabilities:**

- 🔧 **Full hacker toolkit** out of the box
- 🤝 **Teams of agents** that collaborate and scale
- ✅ **Real validation** with PoCs, not false positives
- 💻 **Developer‑first** CLI with actionable reports
- 🔄 **Auto‑fix & reporting** to accelerate remediation

## 🎯 Use Cases

- **Application Security Testing** - Detect and validate critical vulnerabilities in your applications
- **Rapid Penetration Testing** - Get penetration tests done in hours, not weeks, with compliance reports
- **Bug Bounty Research** - Automate bug bounty research and generate PoCs for faster reporting
- **CI/CD Integration** - Run tests in CI/CD to block vulnerabilities before reaching production

---

## 🚀 Quick Start

**Prerequisites:**
- Docker (running)
- Python 3.12+
- An LLM provider key (e.g. [get OpenAI API key](https://platform.openai.com/api-keys) or use a local LLM)

### Installation & First Scan

```bash
# Install AISEC
pipx install aisec-agent

# Configure your AI provider
export AISEC_LLM="openai/gpt-5"
export LLM_API_KEY="your-api-key"

# Run your first security assessment
aisec --target ./app-directory
```

> [!NOTE]
> First run automatically pulls the sandbox Docker image. Results are saved to `agent_runs/<run-name>`

---

## 📋 Features

### Multi-Agent Architecture
- Specialized agents for different vulnerability types
- Agent trees for comprehensive testing
- Parallel execution for faster results

### Comprehensive Vulnerability Coverage
- SQL Injection
- Cross-Site Scripting (XSS)
- Remote Code Execution (RCE)
- SSRF and XXE
- IDOR and Authorization Issues
- Business Logic Flaws
- JWT and Authentication Vulnerabilities
- Race Conditions
- And many more...

### Testing Modes

**Black-Box Testing:**
```bash
aisec --target https://example.com
```

**White-Box Testing:**
```bash
aisec --target ./my-project
```

**Hybrid Testing:**
```bash
aisec --target https://github.com/user/repo --target https://example.com
```

---

## 🔧 Advanced Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `AISEC_LLM` | Model name (e.g., `openai/gpt-5`) | Yes |
| `LLM_API_KEY` | API key for LLM provider | Yes* |
| `LLM_API_BASE` | Custom API base URL for local models | No |
| `PERPLEXITY_API_KEY` | Perplexity AI key for web research | No |
| `AISEC_IMAGE` | Custom Docker sandbox image | No |

*Required for cloud providers, optional for local models

### LLM Provider Configuration

**OpenAI:**
```bash
export AISEC_LLM="openai/gpt-5"
export LLM_API_KEY="sk-..."
```

**Anthropic Claude:**
```bash
export AISEC_LLM="anthropic/claude-sonnet-3-5"
export LLM_API_KEY="sk-ant-..."
```

**Local Models (Ollama):**
```bash
export AISEC_LLM="ollama/llama3.1"
export LLM_API_BASE="http://localhost:11434"
```

---

## 📚 Usage Examples

### Test a Web Application
```bash
aisec --target https://example.com
```

### Test with Custom Instructions
```bash
aisec --target https://api.example.com \
  --instruction "Focus on authentication and authorization vulnerabilities"
```

### Multiple Targets
```bash
aisec --target https://github.com/user/repo \
  --target https://staging.example.com \
  --target https://prod.example.com
```

### Non-Interactive Mode (CI/CD)
```bash
aisec --target ./app --non-interactive
```

---

## 🏗️ Architecture

AISEC uses a multi-agent architecture where specialized AI agents work together:

1. **Root Agent** - Coordinates the overall security assessment
2. **Discovery Agents** - Map the attack surface and identify potential vulnerabilities
3. **Validation Agents** - Prove exploitability with concrete proof-of-concepts
4. **Reporting Agents** - Document findings with remediation guidance
5. **Fixing Agents** (White-box only) - Implement and test security patches

Each agent runs in an isolated Docker sandbox with:
- Complete security toolkit (nmap, sqlmap, nuclei, etc.)
- Browser automation (Playwright)
- Python/Node.js/Go development environments
- Caido HTTP proxy for traffic analysis

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

AISEC is designed for authorized security testing only. Users must obtain proper authorization before testing any systems they do not own. Unauthorized access to computer systems is illegal. The developers assume no liability for misuse of this software.

---

<div align="center">

**AISEC** - AI-Powered Cybersecurity Agent

Developed by **CYBERSEC**

</div>

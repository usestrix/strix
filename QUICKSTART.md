# AISEC Quick Start Guide

Welcome to **AISEC** - AI-Powered Cybersecurity Agent by CYBERSEC!

## 🚀 Getting Started in 3 Steps

### 1. Build the Docker Image

You have two options:

#### Option A: Use the automated script (Recommended)

```bash
# For local development (quickest)
./scripts/build-docker.sh --local

# This builds: aisec-sandbox:local
```

#### Option B: Build manually

```bash
# Build the Docker image
docker build -f containers/Dockerfile -t aisec-sandbox:local .

# Set environment variable
export AISEC_IMAGE="aisec-sandbox:local"
```

### 2. Configure LLM Provider

```bash
# Required: Set your LLM model and API key
export AISEC_LLM="openai/gpt-5"
export LLM_API_KEY="your-api-key-here"

# Optional: For local models
export LLM_API_BASE="http://localhost:11434"
```

### 3. Run Your First Scan

```bash
# Install AISEC in development mode
poetry install

# Run a security scan
poetry run aisec --target https://example.com

# Or target local code
poetry run aisec --target ./my-project
```

---

## 📋 Common Commands

### Development

```bash
# Install dependencies
poetry install

# Run in development mode
poetry run aisec --target <target>

# Run with custom instructions
poetry run aisec --target <target> --instruction "Focus on SQL injection"

# Non-interactive mode (for CI/CD)
poetry run aisec --target <target> --non-interactive
```

### Docker Image Management

```bash
# Build for local development
./scripts/build-docker.sh --local

# Build for production
./scripts/build-docker.sh --build-only --tag 0.2.0

# Build and push to GitHub Container Registry
./scripts/build-docker.sh --push
```

### Publishing to PyPI

```bash
# Test build and publish to TestPyPI
./scripts/publish-pypi.sh --test

# Build without publishing
./scripts/publish-pypi.sh --build-only

# Bump version and publish to PyPI
./scripts/publish-pypi.sh --bump patch
```

---

## 🔧 Configuration

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `AISEC_LLM` | LLM model name (required) | `openai/gpt-5` |
| `LLM_API_KEY` | API key for LLM (required) | `sk-...` |
| `LLM_API_BASE` | Custom API endpoint (optional) | `http://localhost:11434` |
| `AISEC_IMAGE` | Docker image to use (optional) | `aisec-sandbox:local` |
| `PERPLEXITY_API_KEY` | Perplexity for web search (optional) | `pplx-...` |

### LLM Provider Examples

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

**Local Ollama:**
```bash
export AISEC_LLM="ollama/llama3.1"
export LLM_API_BASE="http://localhost:11434"
# LLM_API_KEY not required for local models
```

---

## 📁 Project Structure

```
aisec/
├── aisec/                    # Main package
│   ├── agents/              # AI agent implementations
│   ├── interface/           # CLI and TUI
│   ├── llm/                 # LLM integration
│   ├── runtime/             # Docker runtime
│   ├── tools/               # Security testing tools
│   └── prompts/             # Specialized knowledge modules
├── containers/              # Docker configuration
│   └── Dockerfile          # Sandbox image definition
├── scripts/                 # Automation scripts
│   ├── build-docker.sh     # Docker build/publish
│   └── publish-pypi.sh     # PyPI publishing
├── pyproject.toml          # Package configuration
├── README.md               # Main documentation
├── DEPLOYMENT.md           # Deployment guide
└── QUICKSTART.md           # This file
```

---

## 🎯 Usage Examples

### Test a Web Application

```bash
poetry run aisec --target https://example.com
```

### Analyze Source Code (White-box)

```bash
poetry run aisec --target ./my-app
```

### GitHub Repository Analysis

```bash
poetry run aisec --target https://github.com/user/repo
```

### Multiple Targets (Hybrid)

```bash
poetry run aisec \
  --target https://github.com/user/repo \
  --target https://staging.example.com \
  --target https://prod.example.com
```

### With Custom Instructions

```bash
poetry run aisec \
  --target https://api.example.com \
  --instruction "Focus on authentication and JWT vulnerabilities"
```

---

## 🐳 Docker Image Publishing

### For GitHub Container Registry (GHCR)

1. **Authenticate:**
   ```bash
   echo "YOUR_GITHUB_TOKEN" | docker login ghcr.io -u YOUR_USERNAME --password-stdin
   ```

2. **Build and Push:**
   ```bash
   ./scripts/build-docker.sh --push --name ghcr.io/cybersec/aisec-sandbox
   ```

3. **Make Public (Optional):**
   - Go to https://github.com/orgs/cybersec/packages
   - Find `aisec-sandbox`
   - Change visibility to "Public"

### For Docker Hub

```bash
./scripts/build-docker.sh --push --name cybersec/aisec-sandbox
```

---

## 📦 PyPI Package Publishing

### Test on TestPyPI First

```bash
# Configure TestPyPI token
poetry config pypi-token.testpypi YOUR_TEST_TOKEN

# Publish to TestPyPI
./scripts/publish-pypi.sh --test

# Test installation
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ aisec-agent
```

### Publish to PyPI

```bash
# Configure PyPI token
poetry config pypi-token.pypi YOUR_PYPI_TOKEN

# Bump version and publish
./scripts/publish-pypi.sh --bump patch
```

---

## 🔍 Troubleshooting

### Docker Image Issues

**Error: Image not found**
```bash
# Build the image locally
./scripts/build-docker.sh --local

# Or specify custom image
export AISEC_IMAGE="your-custom-image:tag"
```

**Error: Permission denied**
```bash
# Make sure Docker is running
docker info

# Add user to docker group (Linux)
sudo usermod -aG docker $USER
newgrp docker
```

### LLM Connection Issues

**Error: Missing AISEC_LLM**
```bash
# Set required environment variables
export AISEC_LLM="openai/gpt-5"
export LLM_API_KEY="your-key"
```

**Error: API connection failed**
```bash
# For local models, set API base
export LLM_API_BASE="http://localhost:11434"

# Test connection
curl $LLM_API_BASE/api/tags
```

### Installation Issues

**Error: Module not found**
```bash
# Reinstall dependencies
poetry install

# Or install in editable mode
pip install -e .
```

---

## 📚 Next Steps

1. **Read the full documentation:** Check out [README.md](README.md)
2. **Deployment guide:** See [DEPLOYMENT.md](DEPLOYMENT.md) for production setup
3. **Contributing:** Read [CONTRIBUTING.md](CONTRIBUTING.md) to contribute

---

## 💡 Tips

- **Use local Docker image during development** to avoid pulling from registry
- **Test on TestPyPI** before publishing to PyPI
- **Set environment variables in your shell profile** for persistence:
  ```bash
  # Add to ~/.bashrc or ~/.zshrc
  export AISEC_LLM="openai/gpt-5"
  export LLM_API_KEY="your-key"
  export AISEC_IMAGE="aisec-sandbox:local"
  ```
- **Run in non-interactive mode** for CI/CD pipelines
- **Use custom instructions** to focus on specific vulnerability types

---

## 🆘 Getting Help

- **Issues:** Create an issue in the repository
- **Documentation:** Check README.md and DEPLOYMENT.md
- **Examples:** See usage examples above

---

<div align="center">

**AISEC** - AI-Powered Cybersecurity Agent

Developed by **CYBERSEC**

</div>

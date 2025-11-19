# AISEC Deployment Guide

This guide covers deploying AISEC including building the Docker sandbox image and publishing to PyPI.

## Table of Contents
- [Docker Sandbox Image](#docker-sandbox-image)
- [PyPI Package Publishing](#pypi-package-publishing)
- [Quick Start for Development](#quick-start-for-development)

---

## Docker Sandbox Image

The AISEC agent requires a Docker sandbox image that contains all security tools and runtime environment.

### Option 1: Build and Publish to GitHub Container Registry (Recommended)

#### Prerequisites
- Docker installed and running
- GitHub account with access to `cybersec` organization (or your own account)
- GitHub Personal Access Token with `write:packages` permission

#### Step 1: Authenticate with GitHub Container Registry

```bash
# Create a Personal Access Token at https://github.com/settings/tokens
# With permissions: write:packages, read:packages, delete:packages

# Login to GitHub Container Registry
echo "YOUR_GITHUB_TOKEN" | docker login ghcr.io -u YOUR_GITHUB_USERNAME --password-stdin
```

#### Step 2: Build the Docker Image

The Dockerfile is located at `containers/Dockerfile`. To build:

```bash
# Navigate to the project root
cd /path/to/aisec

# Build the Docker image
docker build -f containers/Dockerfile -t ghcr.io/cybersec/aisec-sandbox:0.1.10 .

# Also tag as latest for convenience
docker tag ghcr.io/cybersec/aisec-sandbox:0.1.10 ghcr.io/cybersec/aisec-sandbox:latest
```

**Note:** If you're not using the `cybersec` organization, replace with your GitHub username:
```bash
docker build -f containers/Dockerfile -t ghcr.io/YOUR_USERNAME/aisec-sandbox:0.1.10 .
```

#### Step 3: Push to GitHub Container Registry

```bash
# Push version-tagged image
docker push ghcr.io/cybersec/aisec-sandbox:0.1.10

# Push latest tag
docker push ghcr.io/cybersec/aisec-sandbox:latest
```

#### Step 4: Make the Image Public (Optional)

1. Go to https://github.com/orgs/cybersec/packages (or your user packages)
2. Find `aisec-sandbox`
3. Go to Package Settings
4. Change visibility to "Public"

### Option 2: Use Local Docker Image (Development)

For local development, you can build and use the image locally without pushing:

```bash
# Build locally
docker build -f containers/Dockerfile -t aisec-sandbox:local .

# Set environment variable to use local image
export AISEC_IMAGE="aisec-sandbox:local"

# Run AISEC
aisec --target https://example.com
```

### Option 3: Use Alternative Registry

If you prefer Docker Hub or another registry:

```bash
# Docker Hub
docker build -f containers/Dockerfile -t cybersec/aisec-sandbox:0.1.10 .
docker push cybersec/aisec-sandbox:0.1.10

# Then update in your code or use env var
export AISEC_IMAGE="cybersec/aisec-sandbox:0.1.10"
```

### Dockerfile Requirements

The `containers/Dockerfile` should include:

1. **Base Image**: Kali Linux or similar security-focused OS
2. **Security Tools**:
   - nmap, sqlmap, nuclei, ffuf, dirsearch
   - subfinder, httpx, katana
   - semgrep, bandit, trufflehog
   - And all tools listed in the system prompt
3. **Programming Environments**:
   - Python 3.12+
   - Node.js
   - Go
   - Poetry
4. **Caido Proxy**: HTTP proxy for traffic analysis
5. **Development Tools**: git, curl, wget, etc.

### Update Dockerfile for AISEC

Make sure to update `containers/Dockerfile` to reflect AISEC branding:

```dockerfile
# Example updates needed:
LABEL org.opencontainers.image.title="AISEC Sandbox"
LABEL org.opencontainers.image.description="Docker sandbox for AISEC cybersecurity agent"
LABEL org.opencontainers.image.vendor="CYBERSEC"

# Copy AISEC code (not strix)
COPY aisec /app/aisec
COPY pyproject.toml poetry.lock /app/
```

---

## PyPI Package Publishing

### Prerequisites

1. **PyPI Account**: Create account at https://pypi.org/account/register/
2. **PyPI API Token**: Generate at https://pypi.org/manage/account/token/
3. **Poetry**: Already installed for this project

### Step 1: Configure PyPI Credentials

```bash
# Configure Poetry with PyPI token
poetry config pypi-token.pypi YOUR_PYPI_API_TOKEN
```

Alternatively, create `~/.pypirc`:

```ini
[distutils]
index-servers =
    pypi

[pypi]
username = __token__
password = pypi-YOUR_API_TOKEN_HERE
```

### Step 2: Update Version (if needed)

```bash
# Bump version in pyproject.toml
poetry version patch  # 0.3.4 -> 0.3.5
# or
poetry version minor  # 0.3.4 -> 0.4.0
# or
poetry version major  # 0.3.4 -> 1.0.0

# Or manually edit pyproject.toml
```

### Step 3: Build the Package

```bash
# Clean previous builds
rm -rf dist/ build/ *.egg-info

# Build the package
poetry build
```

This creates:
- `dist/aisec_agent-0.3.4-py3-none-any.whl` (wheel)
- `dist/aisec-agent-0.3.4.tar.gz` (source distribution)

### Step 4: Test the Build Locally (Recommended)

```bash
# Create a test virtual environment
python -m venv test_env
source test_env/bin/activate  # or `test_env\Scripts\activate` on Windows

# Install from local build
pip install dist/aisec_agent-0.3.4-py3-none-any.whl

# Test the installation
aisec --help

# Cleanup
deactivate
rm -rf test_env
```

### Step 5: Publish to TestPyPI (Recommended First)

```bash
# Configure TestPyPI token
poetry config repositories.testpypi https://test.pypi.org/legacy/
poetry config pypi-token.testpypi YOUR_TEST_PYPI_TOKEN

# Publish to TestPyPI
poetry publish -r testpypi

# Test installation from TestPyPI
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ aisec-agent
```

### Step 6: Publish to PyPI

```bash
# Publish to PyPI
poetry publish

# Alternatively, if using twine:
pip install twine
twine upload dist/*
```

### Step 7: Verify Publication

1. Visit https://pypi.org/project/aisec-agent/
2. Check version and metadata
3. Test installation:

```bash
pip install aisec-agent
aisec --help
```

### Troubleshooting

**Issue: Package name already taken**
```bash
# Check if name is available
pip search aisec-agent

# If taken, choose alternative name in pyproject.toml
name = "aisec-cybersec-agent"  # or similar
```

**Issue: Upload fails**
```bash
# Clear Poetry cache
poetry cache clear pypi --all

# Rebuild
poetry build

# Try again
poetry publish
```

---

## Quick Start for Development

### 1. Local Development Without Publishing

```bash
# Clone the repository
git clone <repository-url>
cd aisec

# Install dependencies
poetry install

# Build local Docker image
docker build -f containers/Dockerfile -t aisec-sandbox:local .

# Configure environment
export AISEC_IMAGE="aisec-sandbox:local"
export AISEC_LLM="openai/gpt-5"
export LLM_API_KEY="your-api-key"

# Run in development mode
poetry run aisec --target https://example.com
```

### 2. Install from Local Source

```bash
# Install in editable mode
pip install -e .

# Or with Poetry
poetry install
```

---

## GitHub Actions CI/CD (Optional)

Create `.github/workflows/publish.yml` for automated publishing:

```yaml
name: Publish to PyPI and GHCR

on:
  release:
    types: [published]

jobs:
  publish-docker:
    runs-on: ubuntu-latest
    permissions:
      packages: write
      contents: read
    steps:
      - uses: actions/checkout@v4

      - name: Login to GitHub Container Registry
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push Docker image
        uses: docker/build-push-action@v5
        with:
          context: .
          file: containers/Dockerfile
          push: true
          tags: |
            ghcr.io/cybersec/aisec-sandbox:${{ github.event.release.tag_name }}
            ghcr.io/cybersec/aisec-sandbox:latest

  publish-pypi:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install Poetry
        run: |
          curl -sSL https://install.python-poetry.org | python3 -
          echo "$HOME/.local/bin" >> $GITHUB_PATH

      - name: Build package
        run: poetry build

      - name: Publish to PyPI
        env:
          POETRY_PYPI_TOKEN_PYPI: ${{ secrets.PYPI_API_TOKEN }}
        run: poetry publish
```

---

## Environment Variables Reference

```bash
# Required
export AISEC_LLM="openai/gpt-5"              # LLM model to use
export LLM_API_KEY="sk-..."                  # API key for LLM

# Optional
export LLM_API_BASE="http://localhost:11434" # Custom API endpoint
export PERPLEXITY_API_KEY="pplx-..."        # For web search
export AISEC_IMAGE="ghcr.io/cybersec/aisec-sandbox:0.1.10"  # Custom Docker image
```

---

## Support

For issues with deployment:
1. Check Docker logs: `docker logs <container-id>`
2. Verify PyPI credentials
3. Ensure all dependencies are in `pyproject.toml`
4. Create an issue in the repository

**AISEC** - AI-Powered Cybersecurity Agent by **CYBERSEC**

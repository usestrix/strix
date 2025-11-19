# Local Development Setup for AISEC

Run AISEC directly from source without needing PyPI or pre-built Docker images.

## 📋 Prerequisites

- **Git** - To clone the repository
- **Docker** - For the sandbox environment (must be running)
- **Python 3.12+** - For running AISEC
- **Poetry** - Python dependency manager (will be installed if missing)
- **LLM API Key** - OpenAI, Anthropic, or local LLM setup

---

## 🚀 Quick Local Setup (5 Minutes)

### Step 1: Clone the Repository

```bash
# Clone the repository
git clone https://github.com/iniaslihas/strix.git
cd strix

# Switch to the AISEC branch (if needed)
git checkout claude/aisec-cybersec-agent-01GC4T2TSGYGyK7GciuP4fWV
```

### Step 2: Install Poetry (if not already installed)

```bash
# Linux/Mac
curl -sSL https://install.python-poetry.org | python3 -

# Add Poetry to PATH (if needed)
export PATH="$HOME/.local/bin:$PATH"

# Verify installation
poetry --version
```

**Windows:**
```powershell
(Invoke-WebRequest -Uri https://install.python-poetry.org -UseBasicParsing).Content | py -
```

### Step 3: Install Dependencies

```bash
# Install all dependencies
poetry install

# This creates a virtual environment and installs:
# - AISEC and all its dependencies
# - Development tools (optional, but recommended)
```

### Step 4: Build Local Docker Image

```bash
# Build the sandbox Docker image locally
./scripts/build-docker.sh --local

# This creates: aisec-sandbox:local
# Takes ~10-15 minutes on first build
```

### Step 5: Configure Environment

```bash
# Create a .env file or export variables
export AISEC_LLM="openai/gpt-5"
export LLM_API_KEY="your-api-key-here"
export AISEC_IMAGE="aisec-sandbox:local"
```

**For persistent configuration**, add to your shell profile (`~/.bashrc`, `~/.zshrc`, etc.):

```bash
# Add to ~/.bashrc or ~/.zshrc
export AISEC_LLM="openai/gpt-5"
export LLM_API_KEY="your-api-key-here"
export AISEC_IMAGE="aisec-sandbox:local"
```

### Step 6: Run AISEC

```bash
# Run AISEC using Poetry
poetry run aisec --target https://example.com

# Or activate the virtual environment first
poetry shell
aisec --target https://example.com
```

---

## 🎯 Complete Step-by-Step Guide

### Option A: Using Poetry (Recommended)

```bash
# 1. Clone
git clone https://github.com/iniaslihas/strix.git
cd strix

# 2. Install dependencies
poetry install

# 3. Build Docker image
./scripts/build-docker.sh --local

# 4. Configure
export AISEC_LLM="openai/gpt-5"
export LLM_API_KEY="sk-..."
export AISEC_IMAGE="aisec-sandbox:local"

# 5. Run
poetry run aisec --target https://example.com
```

### Option B: Using pip + venv

```bash
# 1. Clone
git clone https://github.com/iniaslihas/strix.git
cd strix

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install in editable mode
pip install -e .

# 4. Build Docker image
./scripts/build-docker.sh --local

# 5. Configure
export AISEC_LLM="openai/gpt-5"
export LLM_API_KEY="sk-..."
export AISEC_IMAGE="aisec-sandbox:local"

# 6. Run
aisec --target https://example.com
```

---

## 📁 Directory Structure After Setup

```
strix/
├── aisec/                      # Source code (already renamed)
├── containers/                 # Docker configuration
│   └── Dockerfile             # Sandbox image
├── scripts/                    # Build scripts
│   ├── build-docker.sh        # Docker builder
│   └── publish-pypi.sh        # PyPI publisher (not needed for local)
├── pyproject.toml             # Package configuration
├── poetry.lock                # Dependency lock file
├── .venv/                     # Virtual environment (created by Poetry)
└── dist/                      # Build artifacts (if you build)
```

---

## 🔧 Configuration Options

### Using Configuration File

Create `.env` in the project root:

```bash
# .env file
AISEC_LLM=openai/gpt-5
LLM_API_KEY=sk-your-key-here
AISEC_IMAGE=aisec-sandbox:local
PERPLEXITY_API_KEY=pplx-your-key  # Optional
```

Then load it before running:

```bash
# Load environment variables
export $(cat .env | xargs)

# Run AISEC
poetry run aisec --target https://example.com
```

### Different LLM Providers

**OpenAI:**
```bash
export AISEC_LLM="openai/gpt-4"
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
# No API key needed for local models
```

---

## 🎮 Usage Examples

### Basic Web Application Test

```bash
poetry run aisec --target https://example.com
```

### Local Code Analysis

```bash
poetry run aisec --target ./path/to/your/project
```

### GitHub Repository

```bash
poetry run aisec --target https://github.com/user/repo
```

### Multiple Targets

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

### Non-Interactive Mode (for CI/CD)

```bash
poetry run aisec --target ./app --non-interactive
```

---

## 🛠️ Development Workflow

### Making Changes to Code

```bash
# 1. Make your changes to the code in aisec/

# 2. No need to reinstall - editable install picks up changes

# 3. Run to test
poetry run aisec --target <target>

# 4. Run tests (if available)
poetry run pytest

# 5. Run linting/formatting
poetry run ruff check .
poetry run ruff format .
```

### Rebuilding Docker Image

If you modify the Dockerfile or dependencies:

```bash
# Rebuild the Docker image
./scripts/build-docker.sh --local

# This creates a new aisec-sandbox:local image
```

### Running Without Docker Image Pull

The local build script creates `aisec-sandbox:local` which is automatically used when you set:

```bash
export AISEC_IMAGE="aisec-sandbox:local"
```

---

## 🔍 Troubleshooting

### Issue: "poetry: command not found"

```bash
# Install Poetry
curl -sSL https://install.python-poetry.org | python3 -

# Add to PATH
export PATH="$HOME/.local/bin:$PATH"
```

### Issue: "Docker daemon not running"

```bash
# Start Docker
# Linux: sudo systemctl start docker
# Mac: Open Docker Desktop
# Windows: Start Docker Desktop

# Verify
docker info
```

### Issue: "AISEC_LLM not set"

```bash
# Set required environment variables
export AISEC_LLM="openai/gpt-5"
export LLM_API_KEY="your-api-key"
```

### Issue: "Module 'aisec' not found"

```bash
# Reinstall in editable mode
poetry install

# Or if using pip
pip install -e .
```

### Issue: Docker image build fails

```bash
# Check Docker has enough resources
# Recommended: 4GB RAM, 50GB disk space

# Try building without cache
docker build --no-cache -f containers/Dockerfile -t aisec-sandbox:local .
```

### Issue: "Cannot connect to LLM"

```bash
# For OpenAI/Claude, verify API key
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer $LLM_API_KEY"

# For local Ollama, verify it's running
curl http://localhost:11434/api/tags
```

---

## 📊 Checking Installation

Verify everything is set up correctly:

```bash
# 1. Check Poetry installation
poetry --version

# 2. Check Docker
docker info

# 3. Check Docker image exists
docker images | grep aisec-sandbox

# 4. Check Python environment
poetry run python --version

# 5. Check AISEC installation
poetry run aisec --help

# 6. Check environment variables
echo $AISEC_LLM
echo $AISEC_IMAGE
```

---

## 🚀 Quick Test Run

Run a quick test to verify everything works:

```bash
# Set minimal configuration
export AISEC_LLM="openai/gpt-5"
export LLM_API_KEY="your-key"
export AISEC_IMAGE="aisec-sandbox:local"

# Run a quick test (use --help to avoid actual scan)
poetry run aisec --help

# If that works, try a real scan on a test target
poetry run aisec --target https://example.com
```

---

## 💡 Tips for Local Development

1. **Use a Python version manager** like `pyenv` to manage Python versions:
   ```bash
   pyenv install 3.12
   pyenv local 3.12
   ```

2. **Cache the Docker image** - It takes time to build, so don't delete it:
   ```bash
   # List images
   docker images

   # Keep aisec-sandbox:local
   ```

3. **Use poetry shell** for easier development:
   ```bash
   poetry shell
   # Now you can run commands without 'poetry run'
   aisec --target https://example.com
   ```

4. **Set up environment variables permanently**:
   ```bash
   # Add to ~/.bashrc or ~/.zshrc
   echo 'export AISEC_LLM="openai/gpt-5"' >> ~/.bashrc
   echo 'export LLM_API_KEY="your-key"' >> ~/.bashrc
   echo 'export AISEC_IMAGE="aisec-sandbox:local"' >> ~/.bashrc
   source ~/.bashrc
   ```

5. **Monitor Docker resources**:
   ```bash
   # Check Docker usage
   docker system df

   # Clean up old containers/images if needed
   docker system prune
   ```

---

## 📝 Complete Example: From Clone to First Scan

```bash
# 1. Clone repository
git clone https://github.com/iniaslihas/strix.git
cd strix

# 2. Install Poetry (if needed)
curl -sSL https://install.python-poetry.org | python3 -

# 3. Install dependencies
poetry install

# 4. Build Docker image (10-15 minutes)
./scripts/build-docker.sh --local

# 5. Configure environment
cat > .env << EOF
AISEC_LLM=openai/gpt-5
LLM_API_KEY=sk-your-actual-key-here
AISEC_IMAGE=aisec-sandbox:local
EOF

# 6. Load environment
export $(cat .env | xargs)

# 7. Verify setup
poetry run aisec --help

# 8. Run first scan!
poetry run aisec --target https://example.com
```

That's it! You now have AISEC running locally from source. 🎉

---

## 🔄 Updating Local Installation

```bash
# Pull latest changes
git pull origin main

# Update dependencies
poetry install

# Rebuild Docker image (if Dockerfile changed)
./scripts/build-docker.sh --local

# Run with updated code
poetry run aisec --target <target>
```

---

<div align="center">

**AISEC** - AI-Powered Cybersecurity Agent

Developed by **CYBERSEC**

Now running locally from source! 🚀

</div>

#!/bin/bash
#
# AISEC Local Setup Script
# One-command setup for running AISEC locally
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

print_banner() {
    cat << "EOF"
    ___    ____  _____ ______
   /   |  /  _/ / ___// ____/
  / /| |  / /   \__ \/ __/
 / ___ |_/ /   ___/ / /___
/_/  |_/___/  /____/_____/

AI-Powered Cybersecurity Agent
Developed by CYBERSEC
EOF
    echo ""
}

check_command() {
    if ! command -v $1 &> /dev/null; then
        return 1
    fi
    return 0
}

main() {
    print_banner
    log_info "Setting up AISEC for local development..."
    echo ""

    # Check prerequisites
    log_info "Checking prerequisites..."

    # Check Docker
    if ! check_command docker; then
        log_error "Docker is not installed"
        log_info "Please install Docker: https://docs.docker.com/get-docker/"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        log_info "Please start Docker and try again"
        exit 1
    fi
    log_success "Docker is installed and running"

    # Check Python
    if ! check_command python3; then
        log_error "Python 3 is not installed"
        log_info "Please install Python 3.12+: https://www.python.org/downloads/"
        exit 1
    fi

    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    log_success "Python $PYTHON_VERSION is installed"

    # Install Poetry if needed
    if ! check_command poetry; then
        log_warning "Poetry not found, installing..."
        curl -sSL https://install.python-poetry.org | python3 -
        export PATH="$HOME/.local/bin:$PATH"

        if ! check_command poetry; then
            log_error "Poetry installation failed"
            log_info "Please install manually: https://python-poetry.org/docs/#installation"
            exit 1
        fi
    fi
    log_success "Poetry is installed"

    echo ""
    log_info "Installing AISEC dependencies..."
    poetry install

    echo ""
    log_info "Checking for Docker image..."

    if docker images | grep -q "aisec-sandbox.*local"; then
        log_success "Docker image 'aisec-sandbox:local' already exists"
        read -p "Rebuild Docker image? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_info "Building Docker image (this may take 10-15 minutes)..."
            ./scripts/build-docker.sh --local
        fi
    else
        log_warning "Docker image not found"
        log_info "Building Docker image (this may take 10-15 minutes)..."
        ./scripts/build-docker.sh --local
    fi

    echo ""
    log_info "Configuring environment variables..."

    # Check if .env already exists
    if [ -f ".env" ]; then
        log_warning ".env file already exists"
        read -p "Overwrite .env file? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Keeping existing .env file"
        else
            rm .env
        fi
    fi

    if [ ! -f ".env" ]; then
        log_info "Creating .env file..."
        echo "# AISEC Configuration" > .env
        echo "AISEC_IMAGE=aisec-sandbox:local" >> .env
        echo "" >> .env

        # Get LLM configuration
        echo ""
        log_info "Select your LLM provider:"
        echo "  1) OpenAI (gpt-4, gpt-5)"
        echo "  2) Anthropic Claude"
        echo "  3) Local Ollama"
        echo "  4) Skip (configure manually later)"
        read -p "Choice (1-4): " -n 1 -r choice
        echo ""

        case $choice in
            1)
                echo "AISEC_LLM=openai/gpt-5" >> .env
                read -p "Enter your OpenAI API key: " api_key
                echo "LLM_API_KEY=$api_key" >> .env
                ;;
            2)
                echo "AISEC_LLM=anthropic/claude-sonnet-3-5" >> .env
                read -p "Enter your Anthropic API key: " api_key
                echo "LLM_API_KEY=$api_key" >> .env
                ;;
            3)
                echo "AISEC_LLM=ollama/llama3.1" >> .env
                echo "LLM_API_BASE=http://localhost:11434" >> .env
                log_warning "Make sure Ollama is running: ollama serve"
                ;;
            *)
                log_warning "Skipping LLM configuration"
                echo "# AISEC_LLM=openai/gpt-5" >> .env
                echo "# LLM_API_KEY=your-api-key-here" >> .env
                ;;
        esac

        log_success ".env file created"
    fi

    echo ""
    log_success "Setup complete!"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    log_info "To run AISEC, use one of these commands:"
    echo ""
    echo "  # Load environment and run"
    echo "  export \$(cat .env | xargs) && poetry run aisec --target https://example.com"
    echo ""
    echo "  # Or enter poetry shell first"
    echo "  poetry shell"
    echo "  export \$(cat .env | xargs)"
    echo "  aisec --target https://example.com"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    log_info "Documentation:"
    echo "  - Quick Start: LOCAL_SETUP.md"
    echo "  - Full Guide:  README.md"
    echo "  - Deployment:  DEPLOYMENT.md"
    echo ""
    log_info "Need help? Check the documentation or create an issue"
    echo ""
}

main

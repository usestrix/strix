#!/bin/bash
#
# AISEC PyPI Publishing Script
# This script builds and publishes the AISEC package to PyPI
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Build and publish the AISEC package to PyPI.

OPTIONS:
    -h, --help              Show this help message
    -t, --test              Publish to TestPyPI instead of PyPI
    -b, --build-only        Build the package without publishing
    -c, --check             Run package checks only
    -v, --bump VERSION      Bump version (patch|minor|major)

EXAMPLES:
    # Build and publish to TestPyPI (recommended first)
    $0 --test

    # Build only (no publish)
    $0 --build-only

    # Bump version and publish to PyPI
    $0 --bump patch

    # Run package checks
    $0 --check

PREREQUISITES:
    - Poetry installed
    - PyPI account and API token configured
    - For TestPyPI, configure token with: poetry config pypi-token.testpypi YOUR_TOKEN

EOF
}

check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check if poetry is installed
    if ! command -v poetry &> /dev/null; then
        log_error "Poetry is not installed. Please install it first:"
        echo "  curl -sSL https://install.python-poetry.org | python3 -"
        exit 1
    fi

    # Check if pyproject.toml exists
    if [ ! -f "pyproject.toml" ]; then
        log_error "pyproject.toml not found. Are you in the project root?"
        exit 1
    fi

    log_success "Prerequisites check passed"
}

bump_version() {
    local bump_type=$1
    log_info "Bumping version ($bump_type)..."

    if poetry version "$bump_type"; then
        local new_version=$(poetry version -s)
        log_success "Version bumped to $new_version"
    else
        log_error "Failed to bump version"
        exit 1
    fi
}

run_checks() {
    log_info "Running package checks..."
    echo ""

    # Check for common issues
    log_info "Checking package structure..."
    if [ ! -d "aisec" ]; then
        log_error "aisec/ directory not found"
        exit 1
    fi

    # Validate pyproject.toml
    log_info "Validating pyproject.toml..."
    if poetry check; then
        log_success "pyproject.toml is valid"
    else
        log_error "pyproject.toml validation failed"
        exit 1
    fi

    # Check for __init__.py
    if [ ! -f "aisec/__init__.py" ]; then
        log_error "aisec/__init__.py not found"
        exit 1
    fi

    log_success "All checks passed"
}

build_package() {
    log_info "Cleaning previous builds..."
    rm -rf dist/ build/ *.egg-info

    log_info "Building package..."
    echo ""

    if poetry build; then
        log_success "Package built successfully!"
        echo ""
        log_info "Build artifacts:"
        ls -lh dist/
    else
        log_error "Build failed"
        exit 1
    fi
}

test_local_install() {
    log_info "Testing local installation..."

    # Create temporary virtual environment
    local test_venv="test_install_$$"
    python3 -m venv "$test_venv"

    if source "$test_venv/bin/activate"; then
        log_info "Installing from wheel..."

        local wheel_file=$(ls -t dist/*.whl | head -1)
        if pip install "$wheel_file" &> /dev/null; then
            log_success "Package installed successfully"

            # Test import
            if python -c "import aisec" &> /dev/null; then
                log_success "Import test passed"
            else
                log_error "Import test failed"
                deactivate
                rm -rf "$test_venv"
                exit 1
            fi

            # Test CLI
            if aisec --help &> /dev/null; then
                log_success "CLI test passed"
            else
                log_warning "CLI test failed (this may be OK if dependencies are missing)"
            fi
        else
            log_error "Installation test failed"
            deactivate
            rm -rf "$test_venv"
            exit 1
        fi

        deactivate
    fi

    rm -rf "$test_venv"
    log_success "Local installation test passed"
}

publish_package() {
    local repository=$1

    if [ "$repository" = "testpypi" ]; then
        log_warning "Publishing to TestPyPI..."
        echo ""
        log_info "Ensure you have configured TestPyPI token:"
        echo "  poetry config pypi-token.testpypi YOUR_TOKEN"
        echo ""

        # Configure TestPyPI repository if not already configured
        poetry config repositories.testpypi https://test.pypi.org/legacy/ 2>/dev/null || true

        read -p "Continue with TestPyPI publish? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Publish cancelled"
            exit 0
        fi

        if poetry publish -r testpypi; then
            log_success "Successfully published to TestPyPI!"
            echo ""
            log_info "Test installation with:"
            echo "  pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ aisec-agent"
        else
            log_error "Publish to TestPyPI failed"
            exit 1
        fi

    else
        log_warning "Publishing to PyPI..."
        echo ""
        log_info "Ensure you have configured PyPI token:"
        echo "  poetry config pypi-token.pypi YOUR_TOKEN"
        echo ""

        local version=$(poetry version -s)
        log_warning "About to publish version $version to PyPI"
        log_warning "This action CANNOT be undone!"
        echo ""

        read -p "Are you sure you want to publish to PyPI? (yes/NO): " -r
        echo
        if [[ ! $REPLY =~ ^yes$ ]]; then
            log_info "Publish cancelled"
            exit 0
        fi

        if poetry publish; then
            log_success "Successfully published to PyPI!"
            echo ""
            log_info "Package is now available at:"
            echo "  https://pypi.org/project/aisec-agent/"
            echo ""
            log_info "Install with:"
            echo "  pip install aisec-agent"
        else
            log_error "Publish to PyPI failed"
            exit 1
        fi
    fi
}

# Parse arguments
TEST_PYPI=false
BUILD_ONLY=false
CHECK_ONLY=false
BUMP_VERSION=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            print_usage
            exit 0
            ;;
        -t|--test)
            TEST_PYPI=true
            shift
            ;;
        -b|--build-only)
            BUILD_ONLY=true
            shift
            ;;
        -c|--check)
            CHECK_ONLY=true
            shift
            ;;
        -v|--bump)
            BUMP_VERSION="$2"
            shift 2
            ;;
        *)
            log_error "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

# Main execution
main() {
    log_info "AISEC PyPI Publishing Script"
    echo "==============================="
    echo ""

    # Run checks
    check_prerequisites
    run_checks

    if [ "$CHECK_ONLY" = true ]; then
        log_success "All checks passed. Package is ready to build."
        exit 0
    fi

    # Bump version if requested
    if [ -n "$BUMP_VERSION" ]; then
        bump_version "$BUMP_VERSION"
        echo ""
    fi

    # Show current version
    local current_version=$(poetry version -s)
    log_info "Package version: $current_version"
    echo ""

    # Build package
    build_package
    echo ""

    # Test local installation
    test_local_install
    echo ""

    # Publish if not build-only
    if [ "$BUILD_ONLY" = false ]; then
        if [ "$TEST_PYPI" = true ]; then
            publish_package "testpypi"
        else
            publish_package "pypi"
        fi
    else
        log_success "Build complete (publish skipped)"
        echo ""
        log_info "To publish manually, run:"
        echo "  poetry publish              # PyPI"
        echo "  poetry publish -r testpypi  # TestPyPI"
    fi

    echo ""
    log_success "All done!"
}

# Run main function
main

#!/bin/bash
#
# AISEC Docker Image Build and Publish Script
# This script builds and optionally publishes the AISEC sandbox Docker image
#

set -e

# Configuration
IMAGE_NAME="${AISEC_IMAGE_NAME:-ghcr.io/cybersec/aisec-sandbox}"
VERSION="${AISEC_VERSION:-0.1.10}"
DOCKER_FILE="containers/Dockerfile"

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

Build and optionally publish the AISEC Docker sandbox image.

OPTIONS:
    -h, --help              Show this help message
    -b, --build-only        Build the image without pushing
    -p, --push              Build and push the image
    -t, --tag TAG           Custom image tag (default: $VERSION)
    -n, --name NAME         Custom image name (default: $IMAGE_NAME)
    -l, --local             Build with 'local' tag for local development

EXAMPLES:
    # Build locally for development
    $0 --local

    # Build with custom tag
    $0 --build-only --tag 0.2.0

    # Build and push to registry
    $0 --push

    # Build and push with custom name
    $0 --push --name ghcr.io/myorg/aisec-sandbox

ENVIRONMENT VARIABLES:
    AISEC_IMAGE_NAME        Override default image name
    AISEC_VERSION           Override default version tag

EOF
}

# Parse arguments
BUILD_ONLY=false
PUSH=false
LOCAL=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            print_usage
            exit 0
            ;;
        -b|--build-only)
            BUILD_ONLY=true
            shift
            ;;
        -p|--push)
            PUSH=true
            shift
            ;;
        -t|--tag)
            VERSION="$2"
            shift 2
            ;;
        -n|--name)
            IMAGE_NAME="$2"
            shift 2
            ;;
        -l|--local)
            LOCAL=true
            IMAGE_NAME="aisec-sandbox"
            VERSION="local"
            shift
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
    log_info "AISEC Docker Image Build Script"
    echo "=================================="
    echo ""

    # Check if Docker is running
    if ! docker info &> /dev/null; then
        log_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi

    # Check if Dockerfile exists
    if [ ! -f "$DOCKER_FILE" ]; then
        log_error "Dockerfile not found at $DOCKER_FILE"
        exit 1
    fi

    # Build the image
    FULL_IMAGE_TAG="${IMAGE_NAME}:${VERSION}"
    log_info "Building Docker image: $FULL_IMAGE_TAG"
    echo ""

    if docker build -f "$DOCKER_FILE" -t "$FULL_IMAGE_TAG" .; then
        log_success "Image built successfully!"
    else
        log_error "Failed to build Docker image"
        exit 1
    fi

    # Tag as latest if not local build
    if [ "$LOCAL" = false ]; then
        LATEST_TAG="${IMAGE_NAME}:latest"
        log_info "Tagging as latest: $LATEST_TAG"
        docker tag "$FULL_IMAGE_TAG" "$LATEST_TAG"
    fi

    echo ""
    log_success "Build complete!"
    echo ""
    echo "Image details:"
    echo "  Name:    $FULL_IMAGE_TAG"
    echo "  Size:    $(docker images "$FULL_IMAGE_TAG" --format '{{.Size}}')"
    echo ""

    # Push if requested
    if [ "$PUSH" = true ]; then
        log_warning "Preparing to push image to registry..."
        echo ""

        # Check if logged in to registry
        REGISTRY=$(echo "$IMAGE_NAME" | cut -d'/' -f1)
        log_info "Checking authentication for registry: $REGISTRY"

        if ! docker info 2>&1 | grep -q "Username"; then
            log_warning "You may not be logged in to the registry"
            log_info "Please log in with: docker login $REGISTRY"
            read -p "Continue with push? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log_info "Push cancelled"
                exit 0
            fi
        fi

        # Push version tag
        log_info "Pushing: $FULL_IMAGE_TAG"
        if docker push "$FULL_IMAGE_TAG"; then
            log_success "Successfully pushed $FULL_IMAGE_TAG"
        else
            log_error "Failed to push $FULL_IMAGE_TAG"
            exit 1
        fi

        # Push latest tag
        if [ "$LOCAL" = false ]; then
            log_info "Pushing: $LATEST_TAG"
            if docker push "$LATEST_TAG"; then
                log_success "Successfully pushed $LATEST_TAG"
            else
                log_error "Failed to push $LATEST_TAG"
                exit 1
            fi
        fi

        echo ""
        log_success "All images pushed successfully!"
        echo ""
        echo "Published images:"
        echo "  - $FULL_IMAGE_TAG"
        [ "$LOCAL" = false ] && echo "  - $LATEST_TAG"

    elif [ "$LOCAL" = true ]; then
        log_info "Local build complete. Use with:"
        echo ""
        echo "  export AISEC_IMAGE=\"$FULL_IMAGE_TAG\""
        echo "  aisec --target https://example.com"

    else
        log_info "Build complete (not pushed to registry)"
        log_info "To push this image, run:"
        echo ""
        echo "  docker push $FULL_IMAGE_TAG"
        [ "$LOCAL" = false ] && echo "  docker push $LATEST_TAG"
    fi

    echo ""
}

# Run main function
main

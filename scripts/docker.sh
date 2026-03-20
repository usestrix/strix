#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

IMAGE="strix-sandbox"
TAG="${1:-dev}"

echo "Building $IMAGE:$TAG ..."
docker build \
  -f "$PROJECT_ROOT/containers/Dockerfile" \
  -t "$IMAGE:$TAG" \
  "$PROJECT_ROOT"

echo "Done: $IMAGE:$TAG"

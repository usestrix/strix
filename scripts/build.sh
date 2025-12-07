#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🦉 Strix Build Script${NC}"
echo "================================"

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux*)     OS_NAME="linux";;
    Darwin*)    OS_NAME="macos";;
    MINGW*|MSYS*|CYGWIN*) OS_NAME="windows";;
    *)          OS_NAME="unknown";;
esac

case "$ARCH" in
    x86_64|amd64)   ARCH_NAME="x86_64";;
    arm64|aarch64)  ARCH_NAME="arm64";;
    *)              ARCH_NAME="$ARCH";;
esac

echo -e "${YELLOW}Platform:${NC} $OS_NAME-$ARCH_NAME"

cd "$PROJECT_ROOT"

if ! command -v poetry &> /dev/null; then
    echo -e "${RED}Error: Poetry is not installed${NC}"
    echo "Please install Poetry first: https://python-poetry.org/docs/#installation"
    exit 1
fi

echo -e "\n${BLUE}Installing dependencies...${NC}"
poetry install --with dev

VERSION=$(poetry version -s)
echo -e "${YELLOW}Version:${NC} $VERSION"

echo -e "\n${BLUE}Cleaning previous builds...${NC}"
rm -rf build/ dist/

echo -e "\n${BLUE}Building binary with PyInstaller...${NC}"
poetry run pyinstaller strix.spec --noconfirm

RELEASE_DIR="dist/release"
mkdir -p "$RELEASE_DIR"

BINARY_NAME="strix-${VERSION}-${OS_NAME}-${ARCH_NAME}"

if [ "$OS_NAME" = "windows" ]; then
    if [ ! -f "dist/strix.exe" ]; then
        echo -e "${RED}Build failed: Binary not found${NC}"
        exit 1
    fi
    BINARY_NAME="${BINARY_NAME}.exe"
    cp "dist/strix.exe" "$RELEASE_DIR/$BINARY_NAME"
    echo -e "\n${BLUE}Creating zip...${NC}"
    ARCHIVE_NAME="${BINARY_NAME%.exe}.zip"

    if command -v 7z &> /dev/null; then
        7z a "$RELEASE_DIR/$ARCHIVE_NAME" "$RELEASE_DIR/$BINARY_NAME"
    else
        powershell -Command "Compress-Archive -Path '$RELEASE_DIR/$BINARY_NAME' -DestinationPath '$RELEASE_DIR/$ARCHIVE_NAME'"
    fi
    echo -e "${GREEN}Created:${NC} $RELEASE_DIR/$ARCHIVE_NAME"
else
    if [ ! -f "dist/strix" ]; then
        echo -e "${RED}Build failed: Binary not found${NC}"
        exit 1
    fi
    cp "dist/strix" "$RELEASE_DIR/$BINARY_NAME"
    chmod +x "$RELEASE_DIR/$BINARY_NAME"
    echo -e "\n${BLUE}Creating tarball...${NC}"
    ARCHIVE_NAME="${BINARY_NAME}.tar.gz"
    tar -czvf "$RELEASE_DIR/$ARCHIVE_NAME" -C "$RELEASE_DIR" "$BINARY_NAME"
    echo -e "${GREEN}Created:${NC} $RELEASE_DIR/$ARCHIVE_NAME"
fi

echo -e "\n${GREEN}Build successful!${NC}"
echo "================================"
echo -e "${YELLOW}Binary:${NC} $RELEASE_DIR/$BINARY_NAME"

SIZE=$(ls -lh "$RELEASE_DIR/$BINARY_NAME" | awk '{print $5}')
echo -e "${YELLOW}Size:${NC} $SIZE"

echo -e "\n${BLUE}Testing binary...${NC}"
"$RELEASE_DIR/$BINARY_NAME" --help > /dev/null 2>&1 && echo -e "${GREEN}Binary test passed!${NC}" || echo -e "${RED}Binary test failed${NC}"

echo -e "\n${GREEN}Done!${NC}"

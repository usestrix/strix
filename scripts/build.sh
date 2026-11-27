#!/bin/bash
# Strix Build Script (Enhanced Edition)

set -euo pipefail

###############################################
#                CONFIG & COLORS              #
###############################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🦉 Strix Build Script — Enhanced Edition${NC}"
echo "=============================================="

###############################################
#                VERBOSE MODE                 #
###############################################

if [[ "${1:-}" == "--verbose" ]]; then
    echo -e "${YELLOW}Verbose mode enabled${NC}"
    set -x
fi

###############################################
#                FAILURE TRAP                 #
###############################################

trap 'echo -e "${RED}Build interrupted or failed.${NC}"' ERR

###############################################
#                PLATFORM DETECTION           #
###############################################

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux*) OS_NAME="linux" ;;
    Darwin*) OS_NAME="macos" ;;
    *MINGW*|*MSYS*|*CYGWIN*) OS_NAME="windows" ;;
    *) OS_NAME="unknown" ;;
esac

case "$ARCH" in
    x86_64|amd64) ARCH_NAME="x86_64" ;;
    arm64|aarch64) ARCH_NAME="arm64" ;;
    *) ARCH_NAME="$ARCH" ;;
esac

echo -e "${YELLOW}Platform:${NC} $OS_NAME-$ARCH_NAME"

###############################################
#                DEPENDENCY CHECKS            #
###############################################

cd "$PROJECT_ROOT"

if ! command -v uv &>/dev/null; then
    echo -e "${RED}Error: uv is not installed${NC}"
    exit 1
fi

if ! command -v go &>/dev/null; then
    echo -e "${RED}Error: Go is not installed${NC}"
    echo "Go 1.24+ required."
    exit 1
fi

###############################################
#                INSTALL DEPS                 #
###############################################

echo -e "\n${BLUE}Installing dependencies...${NC}"
uv sync --frozen

###############################################
#                VERSION EXTRACTION           #
###############################################

VERSION=$(uv run python3 - << 'EOF'
import tomllib
with open("pyproject.toml", "rb") as f:
    data = tomllib.load(f)
print(data["project"]["version"])
EOF
)

echo -e "${YELLOW}Version:${NC} $VERSION"

###############################################
#                CLEANUP                      #
###############################################

echo -e "\n${BLUE}Cleaning previous builds...${NC}"
rm -rf build/ dist/

###############################################
#                BUILD TUI (Go)               #
###############################################

echo -e "\n${BLUE}Building Bubble Tea sidecar...${NC}"

TUI_BINARY="build/sidecar/strix-tui"
[[ "$OS_NAME" == "windows" ]] && TUI_BINARY="${TUI_BINARY}.exe"

mkdir -p build/sidecar

(
    cd strix/interface/tui
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
        -o "../../../$TUI_BINARY" ./cmd/strix-tui
) &

###############################################
#                BUILD PYINSTALLER            #
###############################################

echo -e "\n${BLUE}Building binary with PyInstaller...${NC}"
uv run pyinstaller strix.spec --noconfirm &

wait

###############################################
#                VERIFY BUILD                 #
###############################################

if [[ "$OS_NAME" == "windows" ]]; then
    [[ ! -f "dist/strix.exe" ]] && {
        echo -e "${RED}Build failed: dist/strix.exe missing${NC}"
        exit 1
    }
else
    [[ ! -f "dist/strix" ]] && {
        echo -e "${RED}Build failed: dist/strix missing${NC}"
        exit 1
    }
fi

###############################################
#                RELEASE PACKAGING            #
###############################################

RELEASE_DIR="dist/release"
mkdir -p "$RELEASE_DIR"

BINARY_NAME="strix-${VERSION}-${OS_NAME}-${ARCH_NAME}"
ARCHIVE_NAME=""

if [[ "$OS_NAME" == "windows" ]]; then
    BINARY_NAME="${BINARY_NAME}.exe"
    cp "dist/strix.exe" "$RELEASE_DIR/$BINARY_NAME"

    echo -e "\n${BLUE}Creating zip archive...${NC}"
    ARCHIVE_NAME="${BINARY_NAME%.exe}.zip"

    if command -v 7z &>/dev/null; then
        7z a "$RELEASE_DIR/$ARCHIVE_NAME" "$RELEASE_DIR/$BINARY_NAME"
    else
        powershell -Command \
            "Compress-Archive -Path '$RELEASE_DIR/$BINARY_NAME' -DestinationPath '$RELEASE_DIR/$ARCHIVE_NAME'"
    fi
else
    cp "dist/strix" "$RELEASE_DIR/$BINARY_NAME"
    chmod +x "$RELEASE_DIR/$BINARY_NAME"

    echo -e "\n${BLUE}Creating tarball...${NC}"
    ARCHIVE_NAME="${BINARY_NAME}.tar.gz"
    tar -czvf "$RELEASE_DIR/$ARCHIVE_NAME" -C "$RELEASE_DIR" "$BINARY_NAME"
fi

echo -e "${GREEN}Created:${NC} $RELEASE_DIR/$ARCHIVE_NAME"

###############################################
#                CHECKSUM                     #
###############################################

echo -e "\n${BLUE}Generating SHA-256 checksum...${NC}"
if command -v sha256sum &>/dev/null; then
    sha256sum "$RELEASE_DIR/$BINARY_NAME" > "$RELEASE_DIR/$BINARY_NAME.sha256"
else
    shasum -a 256 "$RELEASE_DIR/$BINARY_NAME" > "$RELEASE_DIR/$BINARY_NAME.sha256"
fi
echo -e "${GREEN}Checksum:${NC} $RELEASE_DIR/$BINARY_NAME.sha256"

###############################################
#                SMOKE TEST                   #
###############################################

echo -e "\n${BLUE}Testing binary...${NC}"
"$RELEASE_DIR/$BINARY_NAME" --help >/dev/null 2>&1 \
    && echo -e "${GREEN}Binary test passed!${NC}" \
    || echo -e "${RED}Binary test failed${NC}"

###############################################
#                DONE                         #
###############################################

SIZE=$(ls -lh "$RELEASE_DIR/$BINARY_NAME" | awk '{print $5}')
echo -e "\n${GREEN}Build successful!${NC}"
echo "=============================================="
echo -e "${YELLOW}Binary:${NC} $RELEASE_DIR/$BINARY_NAME"
echo -e "${YELLOW}Size:${NC} $SIZE"
echo -e "${GREEN}Done!${NC}"


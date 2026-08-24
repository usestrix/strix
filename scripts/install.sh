#!/usr/bin/env bash

set -euo pipefail

APP=strix
REPO="usestrix/strix"
STRIX_IMAGE="ghcr.io/usestrix/strix-sandbox:1.3.0"

MUTED='\033[0;2m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

requested_version=${VERSION:-}
SKIP_DOWNLOAD=false

raw_os=$(uname -s)
os=$(echo "$raw_os" | tr '[:upper:]' '[:lower:]')
case "$raw_os" in
  Darwin*) os="macos" ;;
  Linux*) os="linux" ;;
  MINGW*|MSYS*|CYGWIN*) os="windows" ;;
esac

arch=$(uname -m)
if [[ "$arch" == "aarch64" ]]; then
  arch="arm64"
fi
if [[ "$arch" == "x86_64" ]]; then
  arch="x86_64"
fi

if [ "$os" = "macos" ] && [ "$arch" = "x86_64" ]; then
  rosetta_flag=$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)
  if [ "$rosetta_flag" = "1" ]; then
    arch="arm64"
  fi
fi

combo="$os-$arch"
case "$combo" in
  linux-x86_64|linux-arm64|macos-x86_64|macos-arm64|windows-x86_64)
    ;;
  *)
    echo -e "${RED}Unsupported OS/Arch: $os/$arch${NC}"
    exit 1
    ;;
esac

archive_ext=".tar.gz"
if [ "$os" = "windows" ]; then
  archive_ext=".zip"
fi

target="$os-$arch"

if [ "$os" = "linux" ]; then
    if ! command -v tar >/dev/null 2>&1; then
         echo -e "${RED}Error: 'tar' is required but not installed.${NC}"
         exit 1
    fi
fi

if [ "$os" = "windows" ]; then
    if ! command -v unzip >/dev/null 2>&1; then
        echo -e "${RED}Error: 'unzip' is required but not installed.${NC}"
        exit 1
    fi
fi

INSTALL_DIR=$HOME/.strix/bin
mkdir -p "$INSTALL_DIR"

if [ -z "$requested_version" ]; then
    specific_version=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p')
    if [[ $? -ne 0 || -z "$specific_version" ]]; then
        echo -e "${RED}Failed to fetch version information${NC}"
        exit 1
    fi
else
    specific_version=$requested_version
fi

filename="$APP-${specific_version}-${target}${archive_ext}"
url="https://github.com/$REPO/releases/download/v${specific_version}/$filename"

print_message() {
    local level=$1
    local message=$2
    local color=""
    case $level in
        info) color="${NC}" ;;
        success) color="${GREEN}" ;;
        warning) color="${YELLOW}" ;;
        error) color="${RED}" ;;
    esac
    echo -e "${color}${message}${NC}"
}

check_existing_installation() {
    local found_paths=()
    while IFS= read -r -d '' path; do
        found_paths+=("$path")
    done < <(which -a strix 2>/dev/null | tr '\n' '\0' || true)

    if [ ${#found_paths[@]} -gt 0 ]; then
        for path in "${found_paths[@]}"; do
            if [[ ! -e "$path" ]] || [[ "$path" == "$INSTALL_DIR/strix"* ]]; then
                continue
            fi

            if [[ -n "$path" ]]; then
                echo -e "${MUTED}Found existing strix at: ${NC}$path"

                if [[ "$path" == *".local/bin"* ]]; then
                    echo -e "${MUTED}Removing old pipx installation...${NC}"
                    if command -v pipx >/dev/null 2>&1; then
                        pipx uninstall strix-agent 2>/dev/null || true
                    fi
                    rm -f "$path" 2>/dev/null || true
                elif [[ -L "$path" || -f "$path" ]]; then
                    echo -e "${MUTED}Removing old installation...${NC}"
                    rm -f "$path" 2>/dev/null || true
                fi
            fi
        done
    fi
}

check_version() {
    check_existing_installation

    if [[ -x "$INSTALL_DIR/strix" ]]; then
        installed_version=$("$INSTALL_DIR/strix" --version 2>/dev/null | awk '{print $2}' || echo "")
        if [[ "$installed_version" == "$specific_version" ]]; then
            print_message info "${GREEN}✓ Strix ${NC}$specific_version${GREEN} already installed${NC}"
            SKIP_DOWNLOAD=true
        elif [[ -n "$installed_version" ]]; then
            print_message info "${MUTED}Installed: ${NC}$installed_version ${MUTED}→ Upgrading to ${NC}$specific_version"
        fi
    fi
}

# Security: the release tarball is downloaded over the network and then executed,
# so TLS alone is not enough — a compromised/mirrored release or a MITM that can
# present a valid cert for github.com would otherwise run arbitrary code as the
# user. Verify a published SHA256 checksum before extracting.
#
# FAIL-CLOSED contract:
#   * If a SHA256SUMS (or <filename>.sha256) is published for this release and it
#     does NOT match the downloaded file, abort — do not extract or install.
#   * If NO checksum file is published yet, we cannot verify integrity. We do NOT
#     silently proceed as if verified: print a loud warning and continue only as
#     an explicit "at your own risk" fallback.
#
# TODO(release-workflow): .github/workflows/build-release.yml must be updated to
# publish a SHA256SUMS file (and/or per-asset <filename>.sha256) alongside the
# release assets so this verification is actually enforced. That workflow is not
# edited here. The real end-to-end fix is publisher signing (cosign / build
# provenance attestation), since a same-origin checksum only detects corruption,
# not a compromise of the release pipeline itself.
verify_checksum() {
    local file=$1

    # Pick an available SHA-256 checker: coreutils sha256sum or BSD/macOS shasum.
    local sha_cmd=""
    if command -v sha256sum >/dev/null 2>&1; then
        sha_cmd="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then
        sha_cmd="shasum -a 256"
    else
        echo -e "${YELLOW}⚠ Neither 'sha256sum' nor 'shasum' is available; cannot verify integrity.${NC}"
        echo -e "${YELLOW}⚠ Proceeding WITHOUT checksum verification — install at your own risk.${NC}"
        return 0
    fi

    local sums_url="https://github.com/$REPO/releases/download/v${specific_version}/SHA256SUMS"
    local asset_sum_url="${url}.sha256"

    # Prefer a combined SHA256SUMS manifest; fall back to a per-asset .sha256.
    if curl -sfL -o SHA256SUMS "$sums_url" 2>/dev/null && [ -s SHA256SUMS ]; then
        echo -e "${MUTED}Verifying checksum (SHA256SUMS)...${NC}"
        # Check only our file's line; a mismatch or missing entry is fatal.
        if grep -E "[[:space:]]\*?${file}\$" SHA256SUMS > SHA256SUMS.filtered 2>/dev/null \
            && [ -s SHA256SUMS.filtered ]; then
            if $sha_cmd -c SHA256SUMS.filtered >/dev/null 2>&1; then
                echo -e "${GREEN}✓ Checksum verified${NC}"
                return 0
            fi
            echo -e "${RED}✗ Checksum verification FAILED for ${file}.${NC}"
            echo -e "${RED}Refusing to install a binary whose checksum does not match.${NC}"
            exit 1
        fi
        echo -e "${YELLOW}⚠ SHA256SUMS did not contain an entry for ${file}.${NC}"
        echo -e "${YELLOW}⚠ Proceeding WITHOUT checksum verification — install at your own risk.${NC}"
        return 0
    fi

    if curl -sfL -o "${file}.sha256" "$asset_sum_url" 2>/dev/null && [ -s "${file}.sha256" ]; then
        echo -e "${MUTED}Verifying checksum (${file}.sha256)...${NC}"
        # Normalize to "<hash>  <file>" so `-c` checks against the real filename
        # regardless of whether the published file is a bare hash or "hash name".
        local expected_hash
        expected_hash=$(awk '{print $1}' "${file}.sha256")
        if [ -n "$expected_hash" ]; then
            printf '%s  %s\n' "$expected_hash" "$file" > "${file}.sha256.check"
            if $sha_cmd -c "${file}.sha256.check" >/dev/null 2>&1; then
                echo -e "${GREEN}✓ Checksum verified${NC}"
                return 0
            fi
            echo -e "${RED}✗ Checksum verification FAILED for ${file}.${NC}"
            echo -e "${RED}Refusing to install a binary whose checksum does not match.${NC}"
            exit 1
        fi
    fi

    # No checksum published yet: cannot verify. Warn loudly, do not pretend it's verified.
    echo -e "${YELLOW}⚠ No published checksum (SHA256SUMS or ${file}.sha256) found for this release.${NC}"
    echo -e "${YELLOW}⚠ Integrity could NOT be verified — the binary is run at your own risk.${NC}"
    echo -e "${MUTED}  (Release integrity is only guaranteed once SHA256SUMS is published.)${NC}"
    return 0
}

download_and_install() {
    print_message info "\n${CYAN}🦉 Installing Strix${NC} ${MUTED}version: ${NC}$specific_version"
    print_message info "${MUTED}Platform: ${NC}$target\n"

    local tmp_dir=$(mktemp -d)
    cd "$tmp_dir"

    echo -e "${MUTED}Downloading...${NC}"
    curl -# -L -o "$filename" "$url"

    if [ ! -f "$filename" ]; then
        echo -e "${RED}Download failed${NC}"
        exit 1
    fi

    verify_checksum "$filename"

    echo -e "${MUTED}Extracting...${NC}"
    if [ "$os" = "windows" ]; then
        unzip -q "$filename"
        mv "strix-${specific_version}-${target}.exe" "$INSTALL_DIR/strix.exe"
    else
        tar -xzf "$filename"
        mv "strix-${specific_version}-${target}" "$INSTALL_DIR/strix"
        chmod 755 "$INSTALL_DIR/strix"
    fi

    cd - > /dev/null
    rm -rf "$tmp_dir"

    echo -e "${GREEN}✓ Strix installed to $INSTALL_DIR${NC}"
}

check_docker() {
    echo ""
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠ Docker not found${NC}"
        echo -e "${MUTED}Strix requires Docker to run the security sandbox.${NC}"
        echo -e "${MUTED}Please install Docker: ${NC}https://docs.docker.com/get-docker/"
        echo ""
        return 1
    fi

    if ! docker info >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠ Docker daemon not running${NC}"
        echo -e "${MUTED}Please start Docker and run: ${NC}docker pull $STRIX_IMAGE"
        echo ""
        return 1
    fi

    echo -e "${MUTED}Checking for sandbox image...${NC}"
    if docker image inspect "$STRIX_IMAGE" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Sandbox image already available${NC}"
    else
        echo -e "${MUTED}Pulling sandbox image (this may take a few minutes)...${NC}"
        if docker pull "$STRIX_IMAGE"; then
            echo -e "${GREEN}✓ Sandbox image pulled successfully${NC}"
        else
            echo -e "${YELLOW}⚠ Failed to pull sandbox image${NC}"
            echo -e "${MUTED}You can pull it manually later: ${NC}docker pull $STRIX_IMAGE"
        fi
    fi
    return 0
}

add_to_path() {
    local config_file=$1
    local command=$2

    if grep -Fxq "$command" "$config_file" 2>/dev/null; then
        print_message info "${MUTED}PATH already configured in ${NC}$config_file"
    elif [[ -w $config_file ]]; then
        echo -e "\n# strix" >> "$config_file"
        echo "$command" >> "$config_file"
        print_message info "${MUTED}Successfully added ${NC}strix ${MUTED}to \$PATH in ${NC}$config_file"
    else
        print_message warning "Manually add the directory to $config_file (or similar):"
        print_message info "  $command"
    fi
}

setup_path() {
    XDG_CONFIG_HOME=${XDG_CONFIG_HOME:-$HOME/.config}
    current_shell=$(basename "$SHELL")

    case $current_shell in
        fish)
            config_files="$HOME/.config/fish/config.fish"
            ;;
        zsh)
            config_files="${ZDOTDIR:-$HOME}/.zshrc ${ZDOTDIR:-$HOME}/.zshenv $XDG_CONFIG_HOME/zsh/.zshrc $XDG_CONFIG_HOME/zsh/.zshenv"
            ;;
        bash)
            config_files="$HOME/.bashrc $HOME/.bash_profile $HOME/.profile $XDG_CONFIG_HOME/bash/.bashrc $XDG_CONFIG_HOME/bash/.bash_profile"
            ;;
        ash)
            config_files="$HOME/.ashrc $HOME/.profile /etc/profile"
            ;;
        sh)
            config_files="$HOME/.ashrc $HOME/.profile /etc/profile"
            ;;
        *)
            config_files="$HOME/.bashrc $HOME/.bash_profile $XDG_CONFIG_HOME/bash/.bashrc $XDG_CONFIG_HOME/bash/.bash_profile"
            ;;
    esac

    config_file=""
    for file in $config_files; do
        if [[ -f $file ]]; then
            config_file=$file
            break
        fi
    done

    if [[ -z $config_file ]]; then
        print_message warning "No config file found for $current_shell. You may need to manually add to PATH:"
        print_message info "  export PATH=$INSTALL_DIR:\$PATH"
    elif [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        case $current_shell in
            fish)
                add_to_path "$config_file" "fish_add_path $INSTALL_DIR"
                ;;
            zsh)
                add_to_path "$config_file" "export PATH=$INSTALL_DIR:\$PATH"
                ;;
            bash)
                add_to_path "$config_file" "export PATH=$INSTALL_DIR:\$PATH"
                ;;
            ash)
                add_to_path "$config_file" "export PATH=$INSTALL_DIR:\$PATH"
                ;;
            sh)
                add_to_path "$config_file" "export PATH=$INSTALL_DIR:\$PATH"
                ;;
            *)
                export PATH=$INSTALL_DIR:$PATH
                print_message warning "Manually add the directory to $config_file (or similar):"
                print_message info "  export PATH=$INSTALL_DIR:\$PATH"
                ;;
        esac
    fi

    if [ -n "${GITHUB_ACTIONS-}" ] && [ "${GITHUB_ACTIONS}" == "true" ]; then
        echo "$INSTALL_DIR" >> "$GITHUB_PATH"
        print_message info "Added $INSTALL_DIR to \$GITHUB_PATH"
    fi
}

verify_installation() {
    export PATH="$INSTALL_DIR:$PATH"

    local which_strix=$(which strix 2>/dev/null || echo "")

    if [[ "$which_strix" != "$INSTALL_DIR/strix" && "$which_strix" != "$INSTALL_DIR/strix.exe" ]]; then
        if [[ -n "$which_strix" ]]; then
            # Security: never delete a binary outside the install dir we own. The
            # file first on PATH named "strix" may be an unrelated tool (or a
            # deliberate user override); auto-`rm`-ing it would destroy data we
            # don't control. Only report the conflict and let the user resolve it.
            echo -e "${YELLOW}⚠ Found another 'strix' earlier on your PATH: ${NC}$which_strix"
            echo -e "${MUTED}Strix was installed to ${NC}$INSTALL_DIR${MUTED}, but the above will run first.${NC}"
            echo -e "${MUTED}If that is a different tool, keep it. To use this install, put ${NC}$INSTALL_DIR${MUTED} ahead on your PATH,${NC}"
            echo -e "${MUTED}or remove the other one yourself: ${NC}rm $which_strix"
        fi
    fi

    if [[ -x "$INSTALL_DIR/strix" ]]; then
        local version=$("$INSTALL_DIR/strix" --version 2>/dev/null | awk '{print $2}' || echo "unknown")
        echo -e "${GREEN}✓ Strix ${NC}$version${GREEN} ready${NC}"
    fi
}

check_version
if [ "$SKIP_DOWNLOAD" = false ]; then
    download_and_install
fi
setup_path
verify_installation
check_docker

echo ""
echo -e "${CYAN}"
echo "   ███████╗████████╗██████╗ ██╗██╗  ██╗"
echo "   ██╔════╝╚══██╔══╝██╔══██╗██║╚██╗██╔╝"
echo "   ███████╗   ██║   ██████╔╝██║ ╚███╔╝ "
echo "   ╚════██║   ██║   ██╔══██╗██║ ██╔██╗ "
echo "   ███████║   ██║   ██║  ██║██║██╔╝ ██╗"
echo "   ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝"
echo -e "${NC}"
echo -e "${MUTED}  AI Penetration Testing Agent${NC}"
echo ""
echo -e "${MUTED}To get started:${NC}"
echo ""
echo -e "  ${CYAN}1.${NC} Set your environment:"
echo -e "     ${MUTED}export LLM_API_KEY='your-api-key'${NC}"
echo -e "     ${MUTED}export STRIX_LLM='openai/gpt-5.4'${NC}"
echo ""
echo -e "  ${CYAN}2.${NC} Run a penetration test:"
echo -e "     ${MUTED}strix --target https://example.com${NC}"
echo ""
echo -e "${MUTED}For more information visit ${NC}https://strix.ai"
echo -e "${MUTED}Supported models ${NC}https://docs.strix.ai/llm-providers/overview"
echo -e "${MUTED}Join our community ${NC}https://discord.gg/strix-ai"
echo ""

echo -e "${YELLOW}→${NC} Run ${MUTED}source ~/.$(basename $SHELL)rc${NC} or open a new terminal"
echo ""

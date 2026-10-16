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
sums_name="SHA256SUMS"
sums_url="https://github.com/$REPO/releases/download/v${specific_version}/$sums_name"
bundle_name="strix-${target}.intoto.jsonl"
bundle_url="https://github.com/$REPO/releases/download/v${specific_version}/$bundle_name"
SIGNER_WORKFLOW="$REPO/.github/workflows/build-release.yml"
CERT_IDENTITY_REGEXP="^https://github.com/${REPO}/.github/workflows/build-release.yml"

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

# Remove other copies of strix from PATH (pipx, leftover binaries) only after
# a verified install has been written to INSTALL_DIR. Calling this earlier
# would leave the user with no working Strix if checksum/provenance then fail.
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

abort_unverified() {
    echo -e "${RED}✗ Refusing to install an unverified binary.${NC}"
    if [[ -x "$INSTALL_DIR/strix" || -x "$INSTALL_DIR/strix.exe" ]]; then
        echo -e "${MUTED}Existing Strix installation left unchanged.${NC}"
    fi
    echo -e "${RED}Re-run with: curl -sSL https://strix.ai/install | STRIX_INSTALL_SKIP_VERIFY=1 bash${NC}"
    echo -e "${MUTED}(at your own risk)${NC}"
    exit 1
}

# Fail-closed checksum check against the published SHA256SUMS manifest.
# Same-origin only (detects corruption / single-asset swap). Exact field
# match — do not grep the filename as a regex ('.' would be wild).
verify_checksum() {
    local file=$1

    if [ -n "${STRIX_INSTALL_SKIP_VERIFY:-}" ]; then
        echo -e "${YELLOW}⚠ STRIX_INSTALL_SKIP_VERIFY set — skipping checksum verification (at your own risk).${NC}"
        return 0
    fi

    local sha_cmd=""
    if command -v sha256sum >/dev/null 2>&1; then
        sha_cmd="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then
        sha_cmd="shasum -a 256"
    else
        echo -e "${RED}✗ Neither 'sha256sum' nor 'shasum' is available; cannot verify integrity.${NC}"
        abort_unverified
    fi

    if [ ! -s "$sums_name" ]; then
        echo -e "${RED}✗ Missing checksum manifest ${sums_name}.${NC}"
        abort_unverified
    fi

    echo -e "${MUTED}Verifying checksum...${NC}"

    local expected
    expected=$(awk -v file="$file" '
        $2 == file || $2 == ("*" file) { print $1; exit }
    ' "$sums_name")
    if [ -z "$expected" ]; then
        echo -e "${RED}✗ No SHA256SUMS entry for ${file}.${NC}"
        abort_unverified
    fi

    local actual
    actual=$($sha_cmd "$file" | awk '{print $1}')
    if [ "$actual" != "$expected" ]; then
        echo -e "${RED}✗ Checksum mismatch for ${file}.${NC}"
        echo -e "${MUTED}Expected: ${NC}$expected"
        echo -e "${MUTED}Actual:   ${NC}$actual"
        abort_unverified
    fi

    echo -e "${GREEN}✓ Checksum verified${NC}"
}

gh_can_verify_attestation() {
    command -v gh >/dev/null 2>&1 && gh attestation verify --help >/dev/null 2>&1
}

cosign_can_verify_attestation() {
    command -v cosign >/dev/null 2>&1 && cosign verify-blob-attestation --help >/dev/null 2>&1
}

# Fail-closed provenance check. The bundle is signed Sigstore SLSA provenance
# for this workflow; checksum verification (same-origin) is a separate step.
# Prefer `gh attestation verify`; otherwise a local `cosign`. We do not
# bootstrap cosign — current releases are ~140MB, which is too heavy for
# curl|bash. Missing verifier or a failed check aborts before extract.
verify_provenance() {
    local file=$1
    local bundle=$2

    if [ -n "${STRIX_INSTALL_SKIP_VERIFY:-}" ]; then
        echo -e "${YELLOW}⚠ STRIX_INSTALL_SKIP_VERIFY set — skipping provenance verification (at your own risk).${NC}"
        return 0
    fi

    if [ ! -s "$bundle" ]; then
        echo -e "${RED}✗ Missing provenance bundle ${bundle}.${NC}"
        abort_unverified
    fi

    echo -e "${MUTED}Verifying Sigstore provenance...${NC}"

    if gh_can_verify_attestation; then
        if gh attestation verify "$file" \
            --repo "$REPO" \
            --bundle "$bundle" \
            --signer-workflow "$SIGNER_WORKFLOW" \
            --predicate-type "https://slsa.dev/provenance/v1" \
            --deny-self-hosted-runners; then
            echo -e "${GREEN}✓ Provenance verified${NC} ${MUTED}(gh)${NC}"
            return 0
        fi
        echo -e "${RED}✗ gh attestation verify failed.${NC}"
        abort_unverified
    fi

    if cosign_can_verify_attestation; then
        if cosign verify-blob-attestation \
            --bundle "$bundle" \
            --new-bundle-format \
            --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
            --certificate-identity-regexp "$CERT_IDENTITY_REGEXP" \
            --type slsaprovenance1 \
            "$file"; then
            echo -e "${GREEN}✓ Provenance verified${NC} ${MUTED}(cosign)${NC}"
            return 0
        fi
        echo -e "${RED}✗ cosign verify-blob-attestation failed.${NC}"
        abort_unverified
    fi

    echo -e "${RED}✗ Neither a usable 'gh' nor 'cosign' was found; cannot verify provenance.${NC}"
    echo -e "${MUTED}Install GitHub CLI (gh) or cosign, then re-run.${NC}"
    abort_unverified
}

check_version() {
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

download_and_install() {
    print_message info "\n${CYAN}🦉 Installing Strix${NC} ${MUTED}version: ${NC}$specific_version"
    print_message info "${MUTED}Platform: ${NC}$target\n"

    local tmp_dir
    tmp_dir=$(mktemp -d)

    # Never leave a half-written binary in INSTALL_DIR. Stage to *.new and only
    # rename into place after a verified archive has been extracted. On any
    # abort (including verification failure), remove the staging file and the
    # download temp dir; the current install stays untouched.
    cleanup_install_temps() {
        cd / >/dev/null 2>&1 || true
        rm -rf "$tmp_dir"
        rm -f "$INSTALL_DIR/strix.new" "$INSTALL_DIR/strix.exe.new"
    }
    trap cleanup_install_temps EXIT

    cd "$tmp_dir"

    echo -e "${MUTED}Downloading...${NC}"
    curl -# -L -o "$filename" "$url"

    if [ ! -f "$filename" ]; then
        echo -e "${RED}Download failed${NC}"
        exit 1
    fi

    if [ -n "${STRIX_INSTALL_SKIP_VERIFY:-}" ]; then
        echo -e "${YELLOW}⚠ STRIX_INSTALL_SKIP_VERIFY set — skipping checksum and provenance checks.${NC}"
    else
        echo -e "${MUTED}Downloading checksums...${NC}"
        if ! curl -sfL -o "$sums_name" "$sums_url" || [ ! -s "$sums_name" ]; then
            echo -e "${RED}✗ Failed to download checksum manifest.${NC}"
            abort_unverified
        fi
        verify_checksum "$filename"

        echo -e "${MUTED}Downloading provenance...${NC}"
        if ! curl -sfL -o "$bundle_name" "$bundle_url" || [ ! -s "$bundle_name" ]; then
            echo -e "${RED}✗ Failed to download provenance bundle.${NC}"
            abort_unverified
        fi
        verify_provenance "$filename" "$bundle_name"
    fi

    echo -e "${MUTED}Extracting...${NC}"
    if [ "$os" = "windows" ]; then
        unzip -q "$filename"
        mv "strix-${specific_version}-${target}.exe" "$INSTALL_DIR/strix.exe.new"
        mv -f "$INSTALL_DIR/strix.exe.new" "$INSTALL_DIR/strix.exe"
    else
        tar -xzf "$filename"
        mv "strix-${specific_version}-${target}" "$INSTALL_DIR/strix.new"
        chmod 755 "$INSTALL_DIR/strix.new"
        mv -f "$INSTALL_DIR/strix.new" "$INSTALL_DIR/strix"
    fi

    trap - EXIT
    cleanup_install_temps

    echo -e "${GREEN}✓ Strix installed to $INSTALL_DIR${NC}"
    check_existing_installation
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
            echo -e "${YELLOW}⚠ Found conflicting strix at: ${NC}$which_strix"
            echo -e "${MUTED}Attempting to remove...${NC}"

            if rm -f "$which_strix" 2>/dev/null; then
                echo -e "${GREEN}✓ Removed conflicting installation${NC}"
            else
                echo -e "${YELLOW}Could not remove automatically.${NC}"
                echo -e "${MUTED}Please remove manually: ${NC}rm $which_strix"
            fi
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
echo -e "${MUTED}Run a pentest in Strix Cloud ${NC}https://app.strix.ai"
echo -e "${MUTED}Enterprise ${NC}https://strix.ai/demo"
echo ""

echo -e "${YELLOW}→${NC} Run ${MUTED}source ~/.$(basename $SHELL)rc${NC} or open a new terminal"
echo ""

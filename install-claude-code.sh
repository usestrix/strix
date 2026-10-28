#!/usr/bin/env bash
#
# One-line installer: run Strix as an MCP server inside Claude Code.
#
#   curl -LsSf https://raw.githubusercontent.com/IshanKulkarni02/strix-ClaudeCode/feat/mcp-server/install-claude-code.sh | bash
#
# It installs the `strix` CLI (via uv, installing uv first if needed) and
# registers it with Claude Code so the agent can drive Strix's tools. No
# STRIX_LLM or LLM_API_KEY is needed: Claude Code supplies the model.
#
# Requirements the script checks for: Claude Code (`claude`) and Docker.

set -euo pipefail

REPO="${STRIX_REPO:-github.com/IshanKulkarni02/strix-ClaudeCode}"
BRANCH="${STRIX_BRANCH:-feat/mcp-server}"
SPEC="git+https://${REPO}@${BRANCH}"

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
info() { printf '  %s\n' "$1"; }
warn() { printf '\033[33m!\033[0m %s\n' "$1"; }
die()  { printf '\033[31m✗\033[0m %s\n' "$1" >&2; exit 1; }

bold "Strix → Claude Code installer"

# 1. Claude Code must be present (it is the model + orchestration loop).
if ! command -v claude >/dev/null 2>&1; then
  die "Claude Code not found. Install it first: https://claude.com/claude-code"
fi
info "Claude Code: $(command -v claude)"

# 2. uv: install if missing, then make sure its bin dir is on PATH now.
export PATH="$HOME/.local/bin:$PATH"
if ! command -v uv >/dev/null 2>&1; then
  info "Installing uv (Python package manager)…"
  curl -LsSf https://astral.sh/uv/install.sh | sh
  # shellcheck disable=SC1090
  [ -f "$HOME/.local/bin/env" ] && . "$HOME/.local/bin/env"
fi
command -v uv >/dev/null 2>&1 || die "uv install failed; see https://docs.astral.sh/uv/"
info "uv: $(command -v uv)"

# 3. Install the strix CLI from the fork branch as a global tool.
info "Installing strix from ${REPO}@${BRANCH} (first run downloads deps)…"
uv tool install --force "$SPEC" >/dev/null
# Resolve the binary uv just created explicitly — do not trust PATH order, in
# case an official strix (e.g. ~/.strix/bin/strix) shadows this one.
UV_BIN_DIR="$(uv tool dir --bin 2>/dev/null || echo "$HOME/.local/bin")"
STRIX_BIN="$UV_BIN_DIR/strix"
[ -x "$STRIX_BIN" ] || die "strix was not installed at $STRIX_BIN"
info "strix: $STRIX_BIN"

# 4. Register the MCP server with Claude Code (user scope = all projects).
#    Use the absolute path so it resolves regardless of the shell's PATH.
claude mcp remove strix -s user >/dev/null 2>&1 || true
claude mcp add strix -s user -- "$STRIX_BIN" mcp-server
info "Registered 'strix' as an MCP server (user scope)."

# 5. Docker is needed for the sandbox; warn but don't fail if it is down.
if command -v docker >/dev/null 2>&1; then
  if docker info >/dev/null 2>&1; then
    info "Docker: running."
  else
    warn "Docker is installed but not running — start it before the first scan."
  fi
else
  warn "Docker not found — install and start Docker Desktop before the first scan."
fi

printf '\n'
bold "Done."
info "Open Claude Code and ask, e.g.:  \"use strix to test https://example.com\""
info "The sandbox container is pulled automatically on the first tool call."

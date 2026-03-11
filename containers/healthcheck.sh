#!/bin/bash
# Healthcheck script for the strix sandbox container.
# Checks: tool server, Caido proxy, Chromium CDP (via socat).
# Exit 0 = healthy, exit 1 = unhealthy.

set -e

TOOL_SERVER_PORT="${TOOL_SERVER_PORT:-48081}"
CAIDO_PORT=48080
CDP_PORT="${BROWSER_CDP_PORT:-9222}"

# 1. Tool server must respond healthy
if ! curl -sf --max-time 3 "http://127.0.0.1:${TOOL_SERVER_PORT}/health" | grep -q '"status":"healthy"'; then
  echo "UNHEALTHY: tool server not responding on port ${TOOL_SERVER_PORT}"
  exit 1
fi

# 2. Caido proxy must be reachable
if ! curl -sf --max-time 3 -o /dev/null "http://127.0.0.1:${CAIDO_PORT}/graphql/"; then
  echo "UNHEALTHY: Caido proxy not responding on port ${CAIDO_PORT}"
  exit 1
fi

# 3. Chromium CDP must be reachable (via socat forwarder)
if ! curl -sf --max-time 3 "http://127.0.0.1:${CDP_PORT}/json/version" | grep -q "webSocketDebuggerUrl"; then
  echo "UNHEALTHY: Chromium CDP not responding on port ${CDP_PORT}"
  exit 1
fi

echo "healthy"
exit 0

#!/bin/bash
# Healthcheck script for the strix sandbox container.
# Checks: tool server, Caido proxy, Chromium CDP.
# Exit 0 = healthy, exit 1 = unhealthy.

set -e

TOOL_SERVER_PORT="${TOOL_SERVER_PORT:-48081}"
CAIDO_PORT=48080

# 1. Tool server must respond healthy
if ! curl -sf --max-time 3 -H "Authorization: Bearer ${TOOL_SERVER_TOKEN}" "http://127.0.0.1:${TOOL_SERVER_PORT}/health" | grep -q '"status":"healthy"'; then
  echo "UNHEALTHY: tool server not responding on port ${TOOL_SERVER_PORT}"
  exit 1
fi

# 2. Caido proxy must be reachable. A bare /graphql/ probe may legitimately return
# 400, which the entrypoint already treats as ready.
if ! curl -s -o /dev/null -w "%{http_code}" --max-time 3 "http://127.0.0.1:${CAIDO_PORT}/graphql/" | grep -qE "^(200|400)$"; then
  echo "UNHEALTHY: Caido proxy not responding on port ${CAIDO_PORT}"
  exit 1
fi

# 3. Chromium CDP must be reachable (probe internal port directly — no auth needed inside the container)
if ! curl -sf --max-time 3 "http://127.0.0.1:${CDP_INTERNAL_PORT:-19222}/json/version" | grep -q "webSocketDebuggerUrl"; then
  echo "UNHEALTHY: Chromium CDP not responding on internal port ${CDP_INTERNAL_PORT:-19222}"
  exit 1
fi

echo "healthy"
exit 0

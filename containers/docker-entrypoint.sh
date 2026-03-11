#!/bin/bash
set -e

CAIDO_PORT=48080
CAIDO_LOG="/tmp/caido_startup.log"

if [ ! -f /app/certs/ca.p12 ]; then
  echo "ERROR: CA certificate file /app/certs/ca.p12 not found."
  exit 1
fi

caido-cli --listen 0.0.0.0:${CAIDO_PORT} \
          --allow-guests \
          --no-logging \
          --no-open \
          --import-ca-cert /app/certs/ca.p12 \
          --import-ca-cert-pass "" > "$CAIDO_LOG" 2>&1 &

CAIDO_PID=$!
echo "Started Caido with PID $CAIDO_PID on port $CAIDO_PORT"

echo "Waiting for Caido API to be ready..."
CAIDO_READY=false
for i in {1..30}; do
  if ! kill -0 $CAIDO_PID 2>/dev/null; then
    echo "ERROR: Caido process died while waiting for API (iteration $i)."
    echo "=== Caido log ==="
    cat "$CAIDO_LOG" 2>/dev/null || echo "(no log available)"
    exit 1
  fi

  if curl -s -o /dev/null -w "%{http_code}" http://localhost:${CAIDO_PORT}/graphql/ | grep -qE "^(200|400)$"; then
    echo "Caido API is ready (attempt $i)."
    CAIDO_READY=true
    break
  fi
  sleep 1
done

if [ "$CAIDO_READY" = false ]; then
  echo "ERROR: Caido API did not become ready within 30 seconds."
  echo "Caido process status: $(kill -0 $CAIDO_PID 2>&1 && echo 'running' || echo 'dead')"
  echo "=== Caido log ==="
  cat "$CAIDO_LOG" 2>/dev/null || echo "(no log available)"
  exit 1
fi

sleep 2

echo "Fetching API token..."
TOKEN=""
for attempt in 1 2 3 4 5; do
  RESPONSE=$(curl -sL -X POST \
    -H "Content-Type: application/json" \
    -d '{"query":"mutation LoginAsGuest { loginAsGuest { token { accessToken } } }"}' \
    http://localhost:${CAIDO_PORT}/graphql)

  TOKEN=$(echo "$RESPONSE" | jq -r '.data.loginAsGuest.token.accessToken // empty')

  if [ -n "$TOKEN" ] && [ "$TOKEN" != "null" ]; then
    echo "Successfully obtained API token (attempt $attempt)."
    break
  fi

  echo "Token fetch attempt $attempt failed: $RESPONSE"
  sleep $((attempt * 2))
done

if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
  echo "ERROR: Failed to get API token from Caido after 5 attempts."
  echo "=== Caido log ==="
  cat "$CAIDO_LOG" 2>/dev/null || echo "(no log available)"
  exit 1
fi

export CAIDO_API_TOKEN=$TOKEN
echo "Caido API token has been set."

echo "Creating a new Caido project..."
CREATE_PROJECT_RESPONSE=$(curl -sL -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"mutation CreateProject { createProject(input: {name: \"sandbox\", temporary: true}) { project { id } } }"}' \
  http://localhost:${CAIDO_PORT}/graphql)

PROJECT_ID=$(echo $CREATE_PROJECT_RESPONSE | jq -r '.data.createProject.project.id')

if [ -z "$PROJECT_ID" ] || [ "$PROJECT_ID" == "null" ]; then
  echo "Failed to create Caido project."
  echo "Response: $CREATE_PROJECT_RESPONSE"
  exit 1
fi

echo "Caido project created with ID: $PROJECT_ID"

echo "Selecting Caido project..."
SELECT_RESPONSE=$(curl -sL -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"mutation SelectProject { selectProject(id: \"'$PROJECT_ID'\") { currentProject { project { id } } } }"}' \
  http://localhost:${CAIDO_PORT}/graphql)

SELECTED_ID=$(echo $SELECT_RESPONSE | jq -r '.data.selectProject.currentProject.project.id')

if [ "$SELECTED_ID" != "$PROJECT_ID" ]; then
    echo "Failed to select Caido project."
    echo "Response: $SELECT_RESPONSE"
    exit 1
fi

echo "✅ Caido project selected successfully."

echo "Configuring system-wide proxy settings..."

cat << EOF | sudo tee /etc/profile.d/proxy.sh
export http_proxy=http://127.0.0.1:${CAIDO_PORT}
export https_proxy=http://127.0.0.1:${CAIDO_PORT}
export HTTP_PROXY=http://127.0.0.1:${CAIDO_PORT}
export HTTPS_PROXY=http://127.0.0.1:${CAIDO_PORT}
export ALL_PROXY=http://127.0.0.1:${CAIDO_PORT}
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
export CAIDO_API_TOKEN=${TOKEN}
EOF

cat << EOF | sudo tee /etc/environment
http_proxy=http://127.0.0.1:${CAIDO_PORT}
https_proxy=http://127.0.0.1:${CAIDO_PORT}
HTTP_PROXY=http://127.0.0.1:${CAIDO_PORT}
HTTPS_PROXY=http://127.0.0.1:${CAIDO_PORT}
ALL_PROXY=http://127.0.0.1:${CAIDO_PORT}
CAIDO_API_TOKEN=${TOKEN}
EOF

cat << EOF | sudo tee /etc/wgetrc
use_proxy=yes
http_proxy=http://127.0.0.1:${CAIDO_PORT}
https_proxy=http://127.0.0.1:${CAIDO_PORT}
EOF

echo "source /etc/profile.d/proxy.sh" >> ~/.bashrc
echo "source /etc/profile.d/proxy.sh" >> ~/.zshrc

source /etc/profile.d/proxy.sh

echo "✅ System-wide proxy configuration complete"

echo "Adding CA to browser trust store..."
sudo -u pentester mkdir -p /home/pentester/.pki/nssdb
sudo -u pentester certutil -N -d sql:/home/pentester/.pki/nssdb --empty-password
sudo -u pentester certutil -A -n "Testing Root CA" -t "C,," -i /app/certs/ca.crt -d sql:/home/pentester/.pki/nssdb
echo "✅ CA added to browser trust store"

CDP_PORT="${BROWSER_CDP_PORT:-9222}"
# Chromium always binds CDP to 127.0.0.1 regardless of --remote-debugging-address.
# We launch it on an internal port and use socat to expose it on 0.0.0.0.
CDP_INTERNAL_PORT=19222
CHROMIUM_BIN=""
CHROMIUM_RESTART_COUNT=0
CHROMIUM_MAX_RESTARTS=10

echo "Launching Chromium with CDP (internal port $CDP_INTERNAL_PORT, exposed on $CDP_PORT)..."
CHROMIUM_BIN=$(find /usr/lib/chromium* /usr/bin -name "chromium" -o -name "chromium-browser" -o -name "chrome" 2>/dev/null | head -1)
if [ -z "$CHROMIUM_BIN" ]; then
  # Playwright-installed Chromium
  CHROMIUM_BIN=$(find /home/pentester/.cache/ms-playwright -name "chrome" -type f 2>/dev/null | head -1)
fi

# ---------------------------------------------------------------------------
# start_chromium: launches Chromium + socat, waits for CDP readiness.
# Sets CHROMIUM_PID and SOCAT_PID on success.
# ---------------------------------------------------------------------------
start_chromium() {
  if [ -z "$CHROMIUM_BIN" ]; then
    echo "WARNING: Chromium binary not found, browser CDP will not be available"
    return 1
  fi

  # Clean up stale profile lock files from previous crashes
  rm -f /tmp/chromium-profile/SingletonLock /tmp/chromium-profile/SingletonCookie /tmp/chromium-profile/SingletonSocket 2>/dev/null || true

  sudo -u pentester "$CHROMIUM_BIN" \
    --headless \
    --no-sandbox \
    --disable-dev-shm-usage \
    --disable-gpu \
    --remote-debugging-port="$CDP_INTERNAL_PORT" \
    --proxy-server="http://127.0.0.1:${CAIDO_PORT}" \
    --ignore-certificate-errors \
    --user-data-dir=/tmp/chromium-profile \
    > /tmp/chromium.log 2>&1 &

  CHROMIUM_PID=$!
  echo "Started Chromium with PID $CHROMIUM_PID"

  echo "Waiting for Chromium CDP to be ready..."
  local cdp_ready=false
  for i in {1..20}; do
    if ! kill -0 $CHROMIUM_PID 2>/dev/null; then
      echo "WARNING: Chromium process died during startup (iteration $i)"
      echo "=== Chromium log ==="
      cat /tmp/chromium.log 2>/dev/null || echo "(no log)"
      return 1
    fi
    if curl -s "http://127.0.0.1:${CDP_INTERNAL_PORT}/json/version" | grep -q "webSocketDebuggerUrl"; then
      echo "✅ Chromium CDP ready on internal port $CDP_INTERNAL_PORT (attempt $i)"
      cdp_ready=true
      break
    fi
    sleep 1
  done

  if [ "$cdp_ready" = false ]; then
    echo "WARNING: Chromium CDP did not become ready within 20s"
    return 1
  fi

  # Kill any leftover socat from a previous run
  if [ -n "${SOCAT_PID:-}" ] && kill -0 "$SOCAT_PID" 2>/dev/null; then
    kill "$SOCAT_PID" 2>/dev/null || true
    wait "$SOCAT_PID" 2>/dev/null || true
  fi

  # Expose CDP on 0.0.0.0 so Docker port mapping can reach it from the host.
  socat TCP-LISTEN:${CDP_PORT},fork,reuseaddr,bind=0.0.0.0 TCP:127.0.0.1:${CDP_INTERNAL_PORT} &
  SOCAT_PID=$!
  echo "Started socat CDP forwarder (PID $SOCAT_PID): 0.0.0.0:${CDP_PORT} -> 127.0.0.1:${CDP_INTERNAL_PORT}"

  # Verify the socat-forwarded CDP port is reachable
  local fwd_ready=false
  for i in 1 2 3 4 5; do
    if curl -s "http://127.0.0.1:${CDP_PORT}/json/version" | grep -q "webSocketDebuggerUrl"; then
      echo "✅ CDP forwarded and reachable on port ${CDP_PORT} (attempt $i)"
      fwd_ready=true
      break
    fi
    sleep 1
  done
  if [ "$fwd_ready" = false ]; then
    echo "WARNING: CDP not reachable via socat on port ${CDP_PORT}"
    echo "  socat PID $SOCAT_PID alive: $(kill -0 $SOCAT_PID 2>&1 && echo yes || echo no)"
    echo "  ss output: $(ss -tlnp 2>/dev/null | grep ${CDP_PORT} || echo 'port not listening')"
    return 1
  fi

  return 0
}

# Initial Chromium launch
if ! start_chromium; then
  echo "WARNING: Initial Chromium launch failed — browser_use_local may not work"
fi

# ---------------------------------------------------------------------------
# Chromium watchdog: runs in the background, checks every 10s, restarts on
# crash. Stops after CHROMIUM_MAX_RESTARTS consecutive failures.
# ---------------------------------------------------------------------------
chromium_watchdog() {
  sleep 15  # let everything settle before first check
  local consecutive_failures=0

  while true; do
    sleep 10

    # If we don't have a Chromium binary, nothing to watch
    [ -z "$CHROMIUM_BIN" ] && return

    # Check if Chromium is still alive
    if [ -n "${CHROMIUM_PID:-}" ] && kill -0 "$CHROMIUM_PID" 2>/dev/null; then
      # Process alive — also verify CDP is actually responding
      if curl -sf --max-time 3 "http://127.0.0.1:${CDP_INTERNAL_PORT}/json/version" | grep -q "webSocketDebuggerUrl"; then
        consecutive_failures=0
        continue
      fi
      echo "WATCHDOG: Chromium PID $CHROMIUM_PID alive but CDP not responding, killing..."
      kill "$CHROMIUM_PID" 2>/dev/null || true
      wait "$CHROMIUM_PID" 2>/dev/null || true
    fi

    CHROMIUM_RESTART_COUNT=$((CHROMIUM_RESTART_COUNT + 1))
    consecutive_failures=$((consecutive_failures + 1))

    if [ $consecutive_failures -gt $CHROMIUM_MAX_RESTARTS ]; then
      echo "WATCHDOG: Exceeded $CHROMIUM_MAX_RESTARTS consecutive restart failures, giving up"
      return
    fi

    echo "WATCHDOG: Chromium died — restarting (attempt $CHROMIUM_RESTART_COUNT, consecutive=$consecutive_failures)..."
    if start_chromium; then
      echo "WATCHDOG: Chromium restarted successfully (PID $CHROMIUM_PID)"
      consecutive_failures=0
    else
      echo "WATCHDOG: Chromium restart failed"
    fi
  done
}

chromium_watchdog &
WATCHDOG_PID=$!
echo "Started Chromium watchdog with PID $WATCHDOG_PID"

echo "Starting tool server..."
cd /app
export PYTHONPATH=/app
export STRIX_SANDBOX_MODE=true
export TOOL_SERVER_TIMEOUT="${STRIX_SANDBOX_EXECUTION_TIMEOUT:-120}"
export CDP_INTERNAL_PORT
export CDP_PORT
TOOL_SERVER_LOG="/tmp/tool_server.log"

sudo -E -u pentester \
  /app/.venv/bin/python -m strix.runtime.tool_server \
  --token="$TOOL_SERVER_TOKEN" \
  --host=0.0.0.0 \
  --port="$TOOL_SERVER_PORT" \
  --timeout="$TOOL_SERVER_TIMEOUT" > "$TOOL_SERVER_LOG" 2>&1 &

TOOL_SERVER_PID=$!

for i in {1..10}; do
  if curl -s "http://127.0.0.1:$TOOL_SERVER_PORT/health" | grep -q '"status":"healthy"'; then
    echo "✅ Tool server healthy on port $TOOL_SERVER_PORT"
    break
  fi
  if [ $i -eq 10 ]; then
    echo "ERROR: Tool server failed to become healthy"
    echo "=== Tool server log ==="
    cat "$TOOL_SERVER_LOG" 2>/dev/null || echo "(no log)"
    exit 1
  fi
  sleep 1
done

echo "✅ Container ready"

cd /workspace
exec "$@"

#!/bin/bash
set -e

CAIDO_PORT=48080
CAIDO_LOG="/tmp/caido_startup.log"

proxy_component() {
  local proxy_url="$1"
  local component="$2"

  python3 - "$proxy_url" "$component" <<'PY'
import sys
from urllib.parse import urlparse

proxy_url, component = sys.argv[1], sys.argv[2]
parsed = urlparse(proxy_url)

if component == "host":
    print(parsed.hostname or "")
elif component == "port":
    if parsed.port:
        print(parsed.port)
    elif parsed.scheme == "https":
        print("443")
    elif parsed.scheme == "http":
        print("80")
    elif parsed.scheme.startswith("socks"):
        print("1080")
    else:
        print("")
PY
}

configure_proxy_enforcement() {
  if [ "${STRIX_ENFORCE_PROXY:-false}" != "true" ]; then
    return 0
  fi

  if [ -z "${STRIX_EXTERNAL_PROXY:-}" ]; then
    echo "ERROR: STRIX_ENFORCE_PROXY=true requires STRIX_EXTERNAL_PROXY."
    exit 1
  fi

  if ! command -v iptables >/dev/null 2>&1; then
    echo "ERROR: iptables is required for strict proxy enforcement."
    exit 1
  fi

  local proxy_host
  local proxy_port
  local proxy_ips

  proxy_host="$(proxy_component "$STRIX_EXTERNAL_PROXY" host)"
  proxy_port="$(proxy_component "$STRIX_EXTERNAL_PROXY" port)"

  if [ -z "$proxy_host" ] || [ -z "$proxy_port" ]; then
    echo "ERROR: Could not parse proxy host/port from STRIX_EXTERNAL_PROXY=$STRIX_EXTERNAL_PROXY"
    exit 1
  fi

  proxy_ips="$(getent ahostsv4 "$proxy_host" 2>/dev/null | awk '{print $1}' | sort -u || true)"
  if [ -z "$proxy_ips" ]; then
    proxy_ips="$(getent hosts "$proxy_host" 2>/dev/null | awk '{print $1}' | grep -E '^[0-9.]+' | sort -u || true)"
  fi

  if [ -z "$proxy_ips" ]; then
    echo "ERROR: Could not resolve proxy host '$proxy_host' for strict proxy enforcement."
    exit 1
  fi

  echo "Enforcing proxy-only egress via $proxy_host:$proxy_port"

  sudo iptables -w -F OUTPUT
  sudo iptables -w -A OUTPUT -o lo -j ACCEPT
  sudo iptables -w -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  for proxy_ip in $proxy_ips; do
    sudo iptables -w -A OUTPUT -p tcp -d "$proxy_ip" --dport "$proxy_port" -j ACCEPT
  done
  sudo iptables -w -P OUTPUT DROP

  if command -v ip6tables >/dev/null 2>&1; then
    sudo ip6tables -w -F OUTPUT || true
    sudo ip6tables -w -A OUTPUT -o lo -j ACCEPT || true
    sudo ip6tables -w -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true
    sudo ip6tables -w -P OUTPUT DROP || true
  fi

  echo "✅ Strict proxy-only egress enabled"
}

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

# Check if external proxy (e.g., Tor) is configured
if [ -n "$STRIX_EXTERNAL_PROXY" ]; then
    echo "External proxy configured: $STRIX_EXTERNAL_PROXY"
    PROXY_URL="$STRIX_EXTERNAL_PROXY"
else
    PROXY_URL="http://127.0.0.1:${CAIDO_PORT}"
fi

cat << EOF | sudo tee /etc/profile.d/proxy.sh
export http_proxy=${PROXY_URL}
export https_proxy=${PROXY_URL}
export HTTP_PROXY=${PROXY_URL}
export HTTPS_PROXY=${PROXY_URL}
export ALL_PROXY=${PROXY_URL}
export no_proxy=localhost,127.0.0.1,::1
export NO_PROXY=localhost,127.0.0.1,::1
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
export CAIDO_API_TOKEN=${TOKEN}
EOF

cat << EOF | sudo tee /etc/environment
http_proxy=${PROXY_URL}
https_proxy=${PROXY_URL}
HTTP_PROXY=${PROXY_URL}
HTTPS_PROXY=${PROXY_URL}
ALL_PROXY=${PROXY_URL}
no_proxy=localhost,127.0.0.1,::1
NO_PROXY=localhost,127.0.0.1,::1
CAIDO_API_TOKEN=${TOKEN}
EOF

cat << EOF | sudo tee /etc/wgetrc
use_proxy=yes
http_proxy=${PROXY_URL}
https_proxy=${PROXY_URL}
EOF

echo "source /etc/profile.d/proxy.sh" >> ~/.bashrc
echo "source /etc/profile.d/proxy.sh" >> ~/.zshrc

source /etc/profile.d/proxy.sh

echo "✅ System-wide proxy configuration complete"

configure_proxy_enforcement

echo "Adding CA to browser trust store..."
sudo -u pentester mkdir -p /home/pentester/.pki/nssdb
sudo -u pentester certutil -N -d sql:/home/pentester/.pki/nssdb --empty-password
sudo -u pentester certutil -A -n "Testing Root CA" -t "C,," -i /app/certs/ca.crt -d sql:/home/pentester/.pki/nssdb
echo "✅ CA added to browser trust store"

echo "Starting tool server..."
cd /app
export PYTHONPATH=/app
export STRIX_SANDBOX_MODE=true
export TOOL_SERVER_TIMEOUT="${STRIX_SANDBOX_EXECUTION_TIMEOUT:-120}"
TOOL_SERVER_LOG="/tmp/tool_server.log"

sudo -E -u pentester \
  /app/.venv/bin/python -m strix.runtime.tool_server \
  --token="$TOOL_SERVER_TOKEN" \
  --host=0.0.0.0 \
  --port="$TOOL_SERVER_PORT" \
  --timeout="$TOOL_SERVER_TIMEOUT" > "$TOOL_SERVER_LOG" 2>&1 &

for i in {1..10}; do
  if curl --noproxy '*' -s "http://127.0.0.1:$TOOL_SERVER_PORT/health" | grep -q '"status":"healthy"'; then
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

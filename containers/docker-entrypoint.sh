#!/bin/bash
set -e

if [ -n "${STRIX_HOST_UID:-}" ] && [ "${STRIX_HOST_UID}" != "0" ] && [ "${STRIX_HOST_UID}" != "$(id -u)" ]; then
  exec sudo -E -- bash -c '
    set -e
    gid="${STRIX_HOST_GID:-$STRIX_HOST_UID}"
    old_uid="$1"
    old_gid="$2"
    export PATH="$3"
    shift 3
    sed -i "s|^pentester:x:${old_uid}:${old_gid}:|pentester:x:${STRIX_HOST_UID}:${gid}:|" /etc/passwd
    sed -i "s|^pentester:x:${old_gid}:|pentester:x:${gid}:|" /etc/group
    chown -R "${STRIX_HOST_UID}:${gid}" /home/pentester /app/certs
    chown "${STRIX_HOST_UID}:${gid}" /workspace
    exec setpriv --reuid "${STRIX_HOST_UID}" --regid "${gid}" --init-groups "$0" "$@"
  ' "$0" "$(id -u)" "$(id -g)" "$PATH" "$@"
fi

CAIDO_PORT=48080
CAIDO_LOG="/tmp/caido_startup.log"

# --- Generate a FRESH MITM CA per container start (SECURITY) -----------------
# The CA private key must never be baked into the published image: a shared key
# would let anyone who pulled the image forge trusted TLS for every Strix user.
# Generate a unique CA here, before caido-cli (which imports it) and before the
# system-wide + nssdb browser trust steps below.
CERT_DIR="/app/certs"
CA_KEY="${CERT_DIR}/ca.key"
CA_CRT="${CERT_DIR}/ca.crt"
CA_P12="${CERT_DIR}/ca.p12"
CA_P12_PASS_FILE="${CERT_DIR}/ca.p12.pass"

echo "Generating per-container MITM CA in ${CERT_DIR}..."

# Random per-container PKCS#12 password, written 0600 (subshell-scoped umask so
# the rest of the script is unaffected). Replaces the previous empty password,
# which offered no protection to the key material in the .p12 bundle.
CA_P12_PASS="$(openssl rand -hex 32)"
( umask 077; printf '%s' "${CA_P12_PASS}" > "${CA_P12_PASS_FILE}" )

openssl ecparam -name prime256v1 -genkey -noout -out "${CA_KEY}"
openssl req -x509 -new -key "${CA_KEY}" \
    -out "${CA_CRT}" \
    -days 3650 \
    -subj "/C=US/ST=CA/O=Security Testing/CN=Testing Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign"
openssl pkcs12 -export \
    -out "${CA_P12}" \
    -inkey "${CA_KEY}" \
    -in "${CA_CRT}" \
    -passout "pass:${CA_P12_PASS}" \
    -name "Testing Root CA"
chmod 644 "${CA_CRT}"
chmod 600 "${CA_KEY}" "${CA_P12}"

# Trust the freshly-generated CA system-wide (needs root; sudo is NOPASSWD).
sudo cp "${CA_CRT}" /usr/local/share/ca-certificates/ca.crt
sudo update-ca-certificates
echo "✅ Per-container MITM CA generated and trusted"

# Caido enforces a Host allowlist (DNS-rebinding protection) and rejects requests
# whose Host header is a hostname it doesn't recognize. To reach Caido over a
# hostname (rather than an IP literal), set STRIX_CAIDO_ALLOWED_DOMAINS to a
# comma-separated list of hostnames to allow. Unset by default.
# See https://docs.caido.io/app/guides/domain_allowlist
CAIDO_UI_DOMAIN_ARGS=()
if [ -n "${STRIX_CAIDO_ALLOWED_DOMAINS:-}" ]; then
  IFS=',' read -ra _caido_domains <<< "${STRIX_CAIDO_ALLOWED_DOMAINS}"
  for _d in "${_caido_domains[@]}"; do
    [ -n "$_d" ] && CAIDO_UI_DOMAIN_ARGS+=(--ui-domain "$_d")
  done
fi

# SECURITY: bind Caido to loopback INSIDE the container, not 0.0.0.0. The host
# reaches it via Docker's published-port mapping (the SDK publishes the port on
# 127.0.0.1) and the in-container Python client curls http://127.0.0.1:48080, so
# a wildcard bind is unnecessary and exposes Caido — which proxies and archives
# every intercepted request/response, including captured credentials — to any
# other container on the same Docker bridge network. --allow-guests is retained
# because the local Python client authenticates via loginAsGuest; the loopback
# bind is what removes the container-network exposure.
caido-cli --listen 127.0.0.1:${CAIDO_PORT} \
          --allow-guests \
          --no-logging \
          --no-open \
          "${CAIDO_UI_DOMAIN_ARGS[@]}" \
          --import-ca-cert "${CA_P12}" \
          --import-ca-cert-pass "${CA_P12_PASS}" > "$CAIDO_LOG" 2>&1 &

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

echo "Caido is up — host bootstraps the guest token + project via the Python SDK."

echo "Configuring system-wide proxy settings..."

cat << EOF | sudo tee /etc/profile.d/proxy.sh
export http_proxy=http://127.0.0.1:${CAIDO_PORT}
export https_proxy=http://127.0.0.1:${CAIDO_PORT}
export HTTP_PROXY=http://127.0.0.1:${CAIDO_PORT}
export HTTPS_PROXY=http://127.0.0.1:${CAIDO_PORT}
export ALL_PROXY=http://127.0.0.1:${CAIDO_PORT}
export NO_PROXY=localhost,127.0.0.1
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
EOF

cat << EOF | sudo tee /etc/environment
http_proxy=http://127.0.0.1:${CAIDO_PORT}
https_proxy=http://127.0.0.1:${CAIDO_PORT}
HTTP_PROXY=http://127.0.0.1:${CAIDO_PORT}
HTTPS_PROXY=http://127.0.0.1:${CAIDO_PORT}
ALL_PROXY=http://127.0.0.1:${CAIDO_PORT}
NO_PROXY=localhost,127.0.0.1
EOF

cat << EOF | sudo tee /etc/wgetrc
use_proxy=yes
http_proxy=http://127.0.0.1:${CAIDO_PORT}
https_proxy=http://127.0.0.1:${CAIDO_PORT}
EOF

# Use POSIX `.` (not the bashism `source`) so these lines are safe when the rc
# files are read by a POSIX shell (e.g. `sh -lc`), which otherwise fails with
# "source: not found". `.` is understood by bash, zsh, and dash alike.
echo ". /etc/profile.d/proxy.sh" >> ~/.bashrc
echo ". /etc/profile.d/proxy.sh" >> ~/.zshrc

. /etc/profile.d/proxy.sh

echo "✅ System-wide proxy configuration complete"

echo "Adding CA to browser trust store..."
sudo -u pentester mkdir -p /home/pentester/.pki/nssdb
sudo -u pentester certutil -N -d sql:/home/pentester/.pki/nssdb --empty-password
sudo -u pentester certutil -A -n "Testing Root CA" -t "C,," -i /app/certs/ca.crt -d sql:/home/pentester/.pki/nssdb
echo "✅ CA added to browser trust store"

mkdir -p /workspace/.agent-browser-screenshots

echo "✅ Container ready"

cd /workspace
exec "$@"

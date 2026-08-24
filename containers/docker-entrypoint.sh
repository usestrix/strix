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
# Caido must bind 0.0.0.0 inside the container: the host-side SDK reaches it via
# the container's BRIDGE IP (docker_client resolves NetworkSettings.IPAddress and
# session_manager.resolve_exposed_port), not via container loopback — a
# 127.0.0.1 bind makes it listen only on container-loopback and the host client
# cannot connect (SDK bootstrap fails). The bind therefore cannot itself remove
# the sibling-container exposure that Caido (which archives every intercepted
# request/response, captured credentials included) presents on a shared bridge.
# That exposure is instead contained by running the sandbox on its own network
# and by host port-publishing staying loopback-only (docker_client binds
# 127.0.0.1 on the host side); --allow-guests is retained for the loginAsGuest
# client. Left as 0.0.0.0 deliberately — do not "harden" to 127.0.0.1, it breaks
# the host proxy bootstrap.
caido-cli --listen 0.0.0.0:${CAIDO_PORT} \
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

# --- SECURITY: drop egress to cloud-metadata endpoints -----------------------
# A prompt-injected agent can run exec_command("curl http://169.254.169.254/...")
# (or the ECS 169.254.170.2 / IPv6 fd00:ec2::254 variants) to steal cloud
# instance-metadata / IAM credentials, bypassing the per-tool scope guard
# entirely. These link-local metadata addresses are never a legitimate pentest
# target, so block egress to them here — after the network is up and BEFORE the
# agent (exec "$@") can run. We deliberately do NOT blanket-block RFC1918: local
# apps under test are commonly on private ranges, and dropping those would break
# real scans.
#
# Best-effort: needs NET_ADMIN (added by strix/runtime/docker_client.py) plus an
# iptables binary. A missing capability or binary logs a warning and continues
# rather than failing container startup. Set STRIX_ALLOW_METADATA=1 to skip
# (rare, e.g. deliberately testing a metadata service).
if [ "${STRIX_ALLOW_METADATA:-0}" = "1" ]; then
  echo "⚠️  STRIX_ALLOW_METADATA=1 — NOT blocking cloud-metadata egress"
else
  metadata_blocked=true
  if command -v iptables >/dev/null 2>&1; then
    for _ip in 169.254.169.254 169.254.170.2; do
      sudo iptables -I OUTPUT -d "$_ip" -j REJECT 2>/dev/null \
        || sudo iptables -I OUTPUT -d "$_ip" -j DROP 2>/dev/null \
        || metadata_blocked=false
    done
  else
    metadata_blocked=false
  fi
  # IPv6 metadata is best-effort only (host may have no IPv6 stack / ip6tables).
  if command -v ip6tables >/dev/null 2>&1; then
    sudo ip6tables -I OUTPUT -d fd00:ec2::254 -j REJECT 2>/dev/null \
      || sudo ip6tables -I OUTPUT -d fd00:ec2::254 -j DROP 2>/dev/null \
      || true
  fi
  if [ "$metadata_blocked" = true ]; then
    echo "✅ Cloud-metadata egress blocked (169.254.169.254, 169.254.170.2, fd00:ec2::254)"
  else
    echo "⚠️  Could not block cloud-metadata egress (iptables/NET_ADMIN unavailable) — continuing"
  fi
fi

mkdir -p /workspace/.agent-browser-screenshots

echo "✅ Container ready"

cd /workspace
exec "$@"

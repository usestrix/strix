#!/bin/bash
set -e

if [ -z "$CAIDO_PORT" ]; then
    echo "Error: CAIDO_PORT must be set."
    exit 1
fi

caido-cli --listen 127.0.0.1:${CAIDO_PORT} \
          --allow-guests \
          --no-logging \
          --no-open \
          --import-ca-cert /app/certs/ca.p12 \
          --import-ca-cert-pass "" > /dev/null 2>&1 &

echo "Waiting for Caido API to be ready..."
for i in {1..30}; do
  if curl -s -o /dev/null http://localhost:${CAIDO_PORT}/graphql; then
    echo "Caido API is ready."
    break
  fi
  sleep 1
done

sleep 2

echo "Fetching API token..."
TOKEN=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation LoginAsGuest { loginAsGuest { token { accessToken } } }"}' \
  http://localhost:${CAIDO_PORT}/graphql | jq -r '.data.loginAsGuest.token.accessToken')

if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
  echo "Failed to get API token from Caido."
  curl -s -X POST -H "Content-Type: application/json" -d '{"query":"mutation { loginAsGuest { token { accessToken } } }"}' http://localhost:${CAIDO_PORT}/graphql
  exit 1
fi

export CAIDO_API_TOKEN=$TOKEN
echo "Caido API token has been set."

echo "Creating a new Caido project..."
CREATE_PROJECT_RESPONSE=$(curl -s -X POST \
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
SELECT_RESPONSE=$(curl -s -X POST \
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

echo "Container initialization complete - agents will start their own tool servers as needed"
echo "✅ Shared container ready for multi-agent use"

cd /workspace

exec "$@"

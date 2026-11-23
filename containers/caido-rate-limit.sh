#!/bin/bash
# Installs the Strix rate-limit plugin into the running Caido when
# STRIX_RATE_LIMITS is set (a JSON map of domain to requests per second, such
# as {"example.com": 5}). The plugin cannot read the environment, so the map
# is written to the file the plugin reads when it starts. Any failure exits
# non-zero: a scan that asked for a limit must not run without it.
set -euo pipefail

CAIDO_URL="${CAIDO_URL:-http://127.0.0.1:48080}"
PLUGIN_PACKAGE="${STRIX_RATE_LIMIT_PLUGIN:-/opt/strix-caido/rate-limit.zip}"
LIMITS_FILE="/tmp/strix-rate-limits.json"

if [ -z "${STRIX_RATE_LIMITS:-}" ]; then
  exit 0
fi

if ! jq -e 'type == "object" and length > 0' <<< "${STRIX_RATE_LIMITS}" > /dev/null; then
  echo "ERROR: STRIX_RATE_LIMITS must be a non-empty JSON object." >&2
  exit 1
fi
jq -c . <<< "${STRIX_RATE_LIMITS}" > "${LIMITS_FILE}"

token=$(curl -fsS -X POST -H "Content-Type: application/json" \
  -d '{"query":"mutation { loginAsGuest { token { accessToken } } }"}' \
  "${CAIDO_URL}/graphql" | jq -er '.data.loginAsGuest.token.accessToken')

plugin_id=$(curl -fsS "${CAIDO_URL}/graphql" -H "Authorization: Bearer ${token}" \
  -F operations='{"query":"mutation($f: Upload!) { installPluginPackage(input: {source: {file: $f}, force: true}) { package { plugins { id } } error { __typename } } }","variables":{"f":null}}' \
  -F map='{"0":["variables.f"]}' \
  -F "0=@${PLUGIN_PACKAGE}" | jq -er '.data.installPluginPackage.package.plugins[0].id')

curl -fsS -X POST "${CAIDO_URL}/graphql" -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${token}" \
  -d "$(jq -cn --arg id "${plugin_id}" '{query: "mutation($id: ID!) { createUpstreamPlugin(input: {enabled: true, pluginId: $id, allowlist: [\"*\"], denylist: []}) { upstream { id } } }", variables: {id: $id}}')" \
  | jq -e '.data.createUpstreamPlugin.upstream.id' > /dev/null

echo "Rate limits active: $(cat "${LIMITS_FILE}")"

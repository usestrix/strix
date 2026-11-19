#!/usr/bin/env bash
# Stub del CLI de strix para pruebas sin LLM ni target real.
# Escribe un run directory con la forma que espera el ingest y sale con 2
# (código de "vulnerabilidades encontradas"). Ignora todos los flags.
set -euo pipefail
run="strix_runs/run_$$"
mkdir -p "$run"
cat > "$run/run.json" <<'JSON'
{"run_name":"dev-stub","status":"completed","start_time":"2026-01-01T00:00:00+00:00","end_time":"2026-01-01T00:01:00+00:00","llm_usage":{"cost":0.0}}
JSON
cat > "$run/vulnerabilities.json" <<'JSON'
[{"id":"VULN-0001","title":"SQL Injection login bypass","severity":"critical","cvss":9.8,"endpoint":"/rest/user/login","method":"POST"}]
JSON
exit 2

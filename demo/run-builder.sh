#!/usr/bin/env bash
# Solo el frontal (FastAPI + consola), sin Docker ni Kafka. Sirve para el builder
# de instrucciones y para navegar la consola con los renders del servidor.
#
#   ./demo/run-builder.sh            # http://127.0.0.1:8160
#
# Kafka no está: "Usar en un escaneo" rellena el wizard, pero lanzar falla con
# "No se pudo publicar en Kafka". Para el flujo completo: demo/run-audit-local.sh
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${1:-8160}"
DATA="$(mktemp -d /tmp/strix-builder.XXXXXX)"

export FRONTAL_DATABASE_URL="sqlite:///${DATA}/frontal.db"
export FRONTAL_ARTIFACT_STORE="file"
export FRONTAL_ARTIFACTS_DIR="${DATA}/artifacts"

echo "Frontal en http://127.0.0.1:${PORT}  (datos temporales en ${DATA})"
echo "Ctrl+C para parar."
# Kafka no está: el consumidor reintenta cada 10 s. Todo el flujo del builder
# (render, copiar, descargar, previsualizar en el wizard) funciona sin Kafka.
cd frontal && ../.venv/bin/python -m uvicorn frontal.app.main:app --host 127.0.0.1 --port "${PORT}" --log-level warning 2>&1 | grep -v -E "kafka\.conn|kafka\.cluster|kafka\.coordinator|kafka\.consumer"

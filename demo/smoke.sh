#!/usr/bin/env bash
# Smoke test end-to-end vía la web: crea app -> lanza scan -> espera -> lee findings.
# Requiere el frontal corriendo (run-frontal.sh) y un worker/launcher procesando.
#   ./demo/smoke.sh            # usa el stub por defecto
set -euo pipefail
BASE="${1:-http://127.0.0.1:8000}"

json() { python3 -c "import sys,json;print(json.load(sys.stdin)[\"$1\"])"; }

echo "== creando app =="
APP=$(curl -sf -X POST "$BASE/manage/apps" -H 'content-type: application/json' \
  -d "{\"name\":\"juice-$RANDOM\",\"target\":\"http://localhost:3000\"}")
echo "$APP"
APP_ID=$(printf '%s' "$APP" | json id)

echo "== lanzando scan en app $APP_ID =="
SCAN=$(curl -sf -X POST "$BASE/manage/apps/$APP_ID/scans" -H 'content-type: application/json' \
  -d '{"scan_mode":"quick","instruction":"test only the login bypass"}')
echo "$SCAN"
SCAN_ID=$(printf '%s' "$SCAN" | json id)

echo "== esperando scan $SCAN_ID (lánzale un worker/launcher si no avanza) =="
STATUS="queued"
for _ in $(seq 1 90); do
  STATUS=$(curl -sf "$BASE/manage/scans/$SCAN_ID" | json status)
  echo "  status=$STATUS"
  if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then
    break
  fi
  sleep 2
done

echo "== findings =="
curl -sf "$BASE/manage/apps/$APP_ID/findings" | python3 -m json.tool

if [ "$STATUS" = "completed" ]; then
  echo "OK: loop web -> Kafka -> strix -> ingest -> web completado"
else
  echo "scan terminó como '$STATUS' (revisa logs del worker/launcher)"
  exit 1
fi

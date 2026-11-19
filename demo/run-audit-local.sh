#!/usr/bin/env bash
# Despliegue local completo del flujo de auditorías:
#
#   Docker:  Kafka, MinIO, MongoDB, Juice Shop, el backend del frontal (API, sin
#            puerto publicado) y el frontend nginx (consola, http://localhost:8000)
#   Host:    el orquestador real (k8s/kafka_orchestrator.py) en bucle, que hace
#            de KEDA ScaledJob: consume UN audit.request, ejecuta Strix (sandbox
#            Docker), sube el run a MongoDB GridFS (o a MinIO con AUDIT_STORE=s3),
#            publica audit.result y vuelve a empezar.
#
#   ./demo/run-audit-local.sh          # levanta todo y deja el orquestador en primer plano
#   AUDIT_STORE=s3 ./demo/run-audit-local.sh   # artefactos en MinIO en vez de Mongo
#   ./demo/run-audit-local.sh down     # para los contenedores (los datos se conservan)
#
# Desde WSL sin integración de Docker Desktop:  DOCKER=docker.exe ./demo/run-audit-local.sh
# El LLM lo toma Strix de ~/.strix/cli-config.json (o de STRIX_LLM / LLM_API_KEY).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
DOCKER="${DOCKER:-docker}"
export AUDIT_STORE="${AUDIT_STORE:-mongo}"   # mongo | s3 (lo lee también el compose)
PROJECT=demo   # mismo proyecto que docker-compose.dev.yml → red demo_default

compose_file() {  # docker.exe necesita rutas de Windows
  if [[ "$DOCKER" == *.exe ]]; then wslpath -w "$1"; else echo "$1"; fi
}
compose() {
  "$DOCKER" compose -p "$PROJECT" \
    -f "$(compose_file "$HERE/docker-compose.dev.yml")" \
    -f "$(compose_file "$HERE/docker-compose.audit.yml")" "$@"
}

if [[ "${1:-}" == "down" ]]; then
  compose down
  exit 0
fi

echo "== levantando Kafka, MinIO, MongoDB, Juice Shop, backend y frontend (artefactos: $AUDIT_STORE) =="
compose up -d --build kafka minio mongo juice-shop frontal frontend

echo "== esperando al frontal =="
for _ in $(seq 60); do
  curl -fsS -m 2 http://localhost:8000/health >/dev/null 2>&1 && break
  sleep 2
done
curl -fsS -m 2 http://localhost:8000/health >/dev/null && echo "   consola: http://localhost:8000"

# --- Orquestador (lo que en el clúster es el Job de KEDA) ---
export KAFKA_BOOTSTRAP_SERVERS=localhost:9092
export KAFKA_REQUEST_TOPIC=audit.request KAFKA_RESULT_TOPIC=audit.result KAFKA_STATUS_TOPIC=audit.status
export MINIO_ENDPOINT=http://localhost:9000 MINIO_BUCKET=strix-runs
export MINIO_ACCESS_KEY=minio MINIO_SECRET_KEY=minio12345
export MINIO_SECRET_DIR=/nonexistent MONGO_SECRET_DIR=/nonexistent
# El orquestador usa GridFS si MONGO_URI está definida; si no, MinIO.
if [[ "$AUDIT_STORE" == "mongo" ]]; then
  export MONGO_URI="mongodb://strix:strix12345@localhost:27017/?authSource=admin"
  export MONGO_DB=strix MONGO_BUCKET=strix_runs
else
  unset MONGO_URI
fi
# Strix con sandbox Docker. El sandbox se queda en la red por defecto (Strix habla
# con su Caido por el puerto publicado; desde WSL no se llega a las IPs de la red
# del compose), y los nombres de servicio del compose apuntan al host, donde sus
# puertos están publicados. Así los targets se escriben como en el clúster:
# http://juice-shop:3000. Para otro target: AUDIT_TARGET_HOSTS="juice-shop mi-app".
export STRIX_RUNTIME_BACKEND=docker
unset STRIX_DOCKER_SANDBOX_NETWORK
STRIX_DOCKER_EXTRA_HOSTS=""
for h in ${AUDIT_TARGET_HOSTS:-juice-shop}; do
  STRIX_DOCKER_EXTRA_HOSTS+="${STRIX_DOCKER_EXTRA_HOSTS:+,}$h=host-gateway"
done
export STRIX_DOCKER_EXTRA_HOSTS
unset STRIX_WORKSPACE_ROOT
export PYTHONPATH="$HERE/audit${PYTHONPATH:+:$PYTHONPATH}"
export HOSTNAME="${HOSTNAME:-$(hostname)}"

# confluent-kafka no está en el índice corporativo de uv: se baja de PyPI.
ORCH_INDEX="${ORCH_INDEX:-https://pypi.org/simple}"

RUNS="$HERE/data/audit-runs"   # aquí deja Strix strix_runs/ antes de subirlo a MinIO
mkdir -p "$RUNS"
cd "$RUNS"

trap 'echo; echo "== orquestador parado (los contenedores siguen; \"$0 down\" para pararlos) =="; exit 0' INT TERM
echo "== orquestador escuchando en audit.request (Ctrl-C para parar) =="
while true; do
  uv run --project "$ROOT" --frozen --default-index "$ORCH_INDEX" \
    --with confluent-kafka --with boto3 --with pymongo \
    python "$ROOT/k8s/kafka_orchestrator.py" 2>&1 | grep --line-buffered -v -e "No event within poll window" -e "Listening on" || true
  sleep 1   # si algo falla de forma persistente, no girar en vacío
done

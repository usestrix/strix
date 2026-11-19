#!/usr/bin/env bash
# Simulador local de KEDA (modelo ScaledJob) para el modelo one-shot.
#
# En producción KEDA vigila el lag del grupo de consumidores sobre scan.requests
# y lanza UN Job (frontal.launcher) por cada unidad de lag, hasta maxReplicaCount,
# y escala a cero cuando la cola se vacía. Aquí no hay KEDA, así que este script
# hace exactamente eso desde el host: mide el lag y va spawneando launchers
# one-shot segun llegan mensajes.
#
#   ./demo/run-keda-sim.sh            # maxConcurrency=3 (usa create-topics.sh: 3 particiones)
#   ./demo/run-keda-sim.sh 5          # hasta 5 launchers en paralelo
#
# Cada launcher consume 1 mensaje, corre strix (el stub por defecto) y sale.
# Ctrl-C para parar (espera a que terminen los launchers en curso).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE/.."                       # raíz del repo (para `uv run` / `python -m`)
source demo/env.sh

COMPOSE="$HERE/docker-compose.dev.yml"
TOPIC="${FRONTAL_KAFKA_TOPIC_REQUESTS:-scan.requests}"
GROUP="${FRONTAL_KAFKA_WORKER_GROUP:-strix-workers}"
MAX="${1:-3}"                       # maxReplicaCount: launchers en paralelo
POLL="${KEDA_POLL_SECONDS:-5}"      # cada cuánto se mira la cola (pollingInterval)
# Un launcher que pierda la carrera (sin partición/mensaje libre) sale rápido en
# vez de esperar el minuto por defecto.
export FRONTAL_LAUNCHER_CONSUME_TIMEOUT="${FRONTAL_LAUNCHER_CONSUME_TIMEOUT:-30}"

# Herramientas de Kafka dentro del contenedor (igual que create-topics.sh).
# Con timeout para que una consulta colgada salte el tick en vez de congelar el
# bucle. KEDA_KAFKA_EXEC permite sustituir el 'docker compose exec' por otro
# acceso (p.ej. 'docker exec -i demo-kafka-1') en entornos donde compose exec es
# lento; por defecto usa el mismo comando que el resto de la demo.
KX_TIMEOUT="${KEDA_KX_TIMEOUT:-20}"
kx() {
  if [ -n "${KEDA_KAFKA_EXEC:-}" ]; then
    timeout "$KX_TIMEOUT" $KEDA_KAFKA_EXEC /opt/kafka/bin/"$@" 2>/dev/null
  else
    timeout "$KX_TIMEOUT" docker compose -f "$COMPOSE" exec -T kafka \
      /opt/kafka/bin/"$@" 2>/dev/null
  fi
}

# Offset final (suma de high-watermarks de todas las particiones del topic).
end_offsets() {
  local out
  if out="$(kx kafka-get-offsets.sh --bootstrap-server localhost:9092 \
             --topic "$TOPIC" --time -1)" && [ -n "$out" ]; then
    printf '%s\n' "$out" | awk -F: '{s+=$3} END{print s+0}'
    return
  fi
  # Fallback para imágenes sin kafka-get-offsets.sh.
  kx kafka-run-class.sh kafka.tools.GetOffsetShell \
    --broker-list localhost:9092 --topic "$TOPIC" --time -1 \
    | awk -F: '{s+=$3} END{print s+0}'
}

# Offset confirmado por el grupo (0 si el grupo aún no existe: como el launcher
# lee desde earliest, "sin commit" equivale a lag = todos los mensajes).
committed_offsets() {
  kx kafka-consumer-groups.sh --bootstrap-server localhost:9092 \
     --describe --group "$GROUP" \
    | awk -v t="$TOPIC" '$2==t && $4 ~ /^[0-9]+$/ {s+=$4} END{print s+0}'
}

lag() {
  local end cur l
  end="$(end_offsets)"; cur="$(committed_offsets)"
  l=$(( end - cur ))
  (( l < 0 )) && l=0
  echo "$l"
}

pids=()

reap() {  # descarta del pool los launchers que ya terminaron
  local alive=() p
  for p in "${pids[@]}"; do
    kill -0 "$p" 2>/dev/null && alive+=("$p")
  done
  pids=("${alive[@]}")
}

spawn() {  # un Job KEDA = un frontal.launcher one-shot en segundo plano
  uv run --with-requirements frontal/requirements.txt python -m frontal.launcher &
  pids+=("$!")
}

trap 'echo; echo "== parando: esperando ${#pids[@]} launcher(s) en curso =="; wait; exit 0' INT TERM

echo "== KEDA-sim: topic=$TOPIC grupo=$GROUP maxConcurrency=$MAX poll=${POLL}s =="
echo "   (cada mensaje -> un frontal.launcher one-shot; Ctrl-C para parar)"
echo "   nota: el paralelismo real lo limita el nº de particiones de $TOPIC"

while true; do
  reap
  running="${#pids[@]}"
  l="$(lag)"

  pending=$(( l - running ))       # mensajes que aún no tiene ningún launcher
  (( pending < 0 )) && pending=0
  free=$(( MAX - running ))        # cupo libre hasta maxConcurrency
  (( free < 0 )) && free=0
  n=$(( pending < free ? pending : free ))

  if (( n > 0 )); then
    echo "$(date +%T) lag=$l running=$running -> spawn $n"
    for ((i = 0; i < n; i++)); do spawn; done
  fi
  sleep "$POLL"
done

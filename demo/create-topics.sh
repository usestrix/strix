#!/usr/bin/env bash
# Pre-crea los topics con particiones explícitas. Opcional: con auto-create se
# crean con 1 partición. Las particiones de scan.requests = paralelismo máximo
# de workers/Jobs (el modelo KEDA). Ajusta --partitions a lo que quieras.
set -euo pipefail
COMPOSE="$(dirname "$0")/docker-compose.dev.yml"
#kt() { docker compose -f "$COMPOSE" exec -T kafka kafka-topics.sh --bootstrap-server localhost:9092 "$@"; }
kt() { docker compose -f "$COMPOSE" exec -T kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 "$@"; }

kt --create --if-not-exists --topic scan.requests --partitions 3 --replication-factor 1
kt --create --if-not-exists --topic scan.status   --partitions 1 --replication-factor 1
kt --create --if-not-exists --topic scan.results  --partitions 1 --replication-factor 1
echo "== topics =="
kt --list

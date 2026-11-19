# Demo local — frontal + Kafka + worker/launcher

Levanta la infra (Kafka, Postgres, MinIO, Juice Shop) con docker-compose y corre
el frontal y el worker/launcher en el host. Sirve para probar el flujo completo
**web → Kafka → strix → BBDD/S3 → web** sin k8s.

## Requisitos

- Docker + docker compose
- `uv` (para correr el frontal/worker sin instalar nada global)
- Java no hace falta (Kafka va dentro de Docker)

## 1. Levantar la infra

```bash
docker compose -f demo/docker-compose.dev.yml up -d
# opcional: topics con 3 particiones en scan.requests (paralelismo de workers)
./demo/create-topics.sh
```

Servicios: Kafka `localhost:9092`, Postgres `localhost:5432` (strix/strix/strix),
MinIO API `localhost:9000` + consola `localhost:9001` (minio/minio12345),
Juice Shop `localhost:3000`.

## 2. Arrancar el frontal y un consumidor

En terminales separadas (cada script carga `demo/env.sh` solo):

```bash
./demo/run-frontal.sh          # web en http://127.0.0.1:8000

# elige UNO de los modelos de consumidor:
./demo/run-worker.sh           # long-running (modelo Deployment)
./demo/run-launcher.sh         # one-shot (modelo KEDA); procesa 1 mensaje y sale
./demo/run-keda-sim.sh         # simula KEDA: spawnea un launcher por mensaje según llegan
```

> `run-keda-sim.sh` es el que "va levantando según llegan mensajes": vigila el lag
> de `scan.requests` y lanza un `frontal.launcher` one-shot por cada mensaje
> pendiente, hasta `maxConcurrency` (arg 1, por defecto 3), y para cuando la cola
> se vacía. Corre `create-topics.sh` antes: el paralelismo real lo limita el nº de
> particiones. Ej.: `./demo/run-keda-sim.sh 5`.

Por defecto usa el **stub** `fake_strix.sh` (sin LLM) y el **store `file`**
(`demo/data/`). Los cambios de config están en `demo/env.sh`.

> Nota: en el modelo one-shot, el **launcher** escribe la BBDD. Si además dejas
> corriendo el worker/`ResultConsumer`, ingestarían por duplicado (converge
> igual porque el ingest es idempotente). Para el demo, usa uno u otro.

## 3. Disparar un scan

```bash
./demo/smoke.sh                # crea app, lanza scan, espera y muestra findings
```

o a mano:

```bash
curl -s -X POST localhost:8000/manage/apps -H 'content-type: application/json' \
  -d '{"name":"juice","target":"http://localhost:3000"}'
curl -s -X POST localhost:8000/manage/apps/1/scans -H 'content-type: application/json' \
  -d '{"scan_mode":"quick","instruction":"test the login bypass"}'
```

Si usas `run-launcher.sh`, lánzalo **después** de publicar el mensaje (consume 1 y sale).

## 4. Variantes

- **Probar MinIO/S3**: en `demo/env.sh` comenta el bloque `file` y descomenta el
  bloque `s3` (el bucket `strix-artifacts` lo crea `minio-init`). Reinicia frontal/worker.
- **Scan REAL** (sin stub): exporta en la shell del worker/launcher
  `FRONTAL_STRIX_BIN=strix`, `STRIX_LLM=...`, `LLM_API_KEY=...`, y usa
  `http://localhost:3000` (Juice Shop) como target.

## 5. Parar

```bash
docker compose -f demo/docker-compose.dev.yml down       # conserva volúmenes
docker compose -f demo/docker-compose.dev.yml down -v     # borra datos
```

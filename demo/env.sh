# Variables de entorno para el frontal + worker/launcher en local.
# Los scripts run-*.sh la cargan solos; para usarla a mano:  source demo/env.sh
_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Kafka ---
export FRONTAL_KAFKA_BOOTSTRAP="localhost:9092"
export FRONTAL_KAFKA_TOPIC_REQUESTS="scan.requests"
export FRONTAL_KAFKA_TOPIC_STATUS="scan.status"
export FRONTAL_KAFKA_TOPIC_RESULTS="scan.results"

# --- Postgres (el del docker-compose) ---
export FRONTAL_DATABASE_URL="postgresql+psycopg://strix:strix@localhost:5432/strix"

# --- Store de artefactos: S3/MinIO (activo) ---
export FRONTAL_ARTIFACT_STORE="s3"
export FRONTAL_S3_ENDPOINT_URL="http://localhost:9000"
export FRONTAL_S3_BUCKET="strix-artifacts"
export FRONTAL_S3_REGION="us-east-1"
export AWS_ACCESS_KEY_ID="minio"
export AWS_SECRET_ACCESS_KEY="minio12345"
# artifacts_dir se sigue usando en modo s3: es la caché local donde el frontal
# "localiza" (descarga) los runs desde MinIO, y el workdir del worker/launcher.
export FRONTAL_ARTIFACTS_DIR="$_HERE/data"

# --- Alternativa store 'file' (simple, sin MinIO). Para volver a ella, comenta
#     el bloque s3 de arriba y descomenta estas dos líneas: ---
# export FRONTAL_ARTIFACT_STORE="file"
# export FRONTAL_ARTIFACTS_DIR="$_HERE/data"

# --- Strix: REAL (backend local, sin sandbox Docker). El wrapper real_strix.sh
#     ejecuta `uv run strix` desde el repo. La config del LLM (STRIX_LLM /
#     LLM_API_KEY) la toma strix de ~/.strix/cli-config.json o del entorno. ---
export FRONTAL_STRIX_BIN="$_HERE/real_strix.sh"
export STRIX_RUNTIME_BACKEND="local"
export FRONTAL_MAX_BUDGET_USD="5"
# Un scan real puede tardar; sube el límite si hace falta (por defecto 7200s).
export FRONTAL_SCAN_TIMEOUT_SECONDS="1800"

# --- Alternativa: stub sin LLM (para probar solo la fontanería Kafka/BBDD/S3).
#     Comenta el bloque real de arriba y descomenta esta línea: ---
# export FRONTAL_STRIX_BIN="$_HERE/fake_strix.sh"

# --- LLM: si no usas ~/.strix/cli-config.json, expórtalo aquí o en la shell del
#     worker/launcher: ---
# export STRIX_LLM="openrouter/z-ai/glm-5.3"
# export LLM_API_KEY="<tu-key>"

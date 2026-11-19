from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


def _env_float(name: str) -> float | None:
    raw = os.environ.get(name)
    return float(raw) if raw else None


@dataclass(frozen=True)
class Settings:
    database_url: str
    artifacts_dir: Path
    strix_bin: str
    max_concurrent_scans: int
    max_budget_usd: float | None
    scan_timeout_seconds: int

    # --- Kafka, shared by both contracts ---
    kafka_bootstrap_servers: str
    consumer_group: str

    # --- Kafka: the orchestrator contract (k8s/kafka_orchestrator.py) ---
    # The frontal publishes to audit.request and folds audit.result (and the
    # optional audit.status "running" event) back into the database.
    audit_topic_request: str
    audit_topic_result: str
    audit_topic_status: str
    # Results whose request did not come from this frontal (someone used
    # kafka-console-producer by hand) are imported as "external" scans.
    import_external_results: bool

    # --- Kafka: legacy frontal <-> worker split (frontal/runner.py) ---
    topic_requests: str
    topic_status: str
    topic_results: str
    worker_group: str

    # --- Artifact store ("file" shared volume, "s3" object storage, "mongo" GridFS) ---
    artifact_store: str
    s3_endpoint_url: str | None
    s3_bucket: str
    s3_region: str | None
    s3_access_key: str | None
    s3_secret_key: str | None
    s3_verify_tls: bool
    mongo_uri: str | None
    mongo_db: str
    mongo_bucket: str

    # --- Web: False when the nginx frontend serves the console (split deploy) ---
    serve_console: bool


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    # The MINIO_* names are the ones the orchestrator reads (and the keys of the
    # minio-secret Secret), so one Secret can feed both pods.
    s3_endpoint = os.environ.get("FRONTAL_S3_ENDPOINT_URL") or os.environ.get("MINIO_ENDPOINT")
    # Same for MONGO_*: the orchestrator's mongo-secret feeds both pods.
    mongo_uri = os.environ.get("FRONTAL_MONGO_URI") or os.environ.get("MONGO_URI")
    default_store = "mongo" if mongo_uri else "s3" if s3_endpoint else "file"
    return Settings(
        database_url=os.environ.get(
            "FRONTAL_DATABASE_URL", "postgresql+psycopg://strix:strix@localhost:5432/strix"
        ),
        artifacts_dir=Path(os.environ.get("FRONTAL_ARTIFACTS_DIR", "./frontal_data")).resolve(),
        strix_bin=os.environ.get("FRONTAL_STRIX_BIN", "strix"),
        max_concurrent_scans=int(os.environ.get("FRONTAL_MAX_CONCURRENT_SCANS", "2")),
        max_budget_usd=_env_float("FRONTAL_MAX_BUDGET_USD"),
        scan_timeout_seconds=int(os.environ.get("FRONTAL_SCAN_TIMEOUT_SECONDS", "7200")),
        kafka_bootstrap_servers=os.environ.get("FRONTAL_KAFKA_BOOTSTRAP", "localhost:9092"),
        consumer_group=os.environ.get("FRONTAL_KAFKA_GROUP", "strix-frontal"),
        audit_topic_request=os.environ.get("FRONTAL_KAFKA_TOPIC_AUDIT_REQUEST", "audit.request"),
        audit_topic_result=os.environ.get("FRONTAL_KAFKA_TOPIC_AUDIT_RESULT", "audit.result"),
        audit_topic_status=os.environ.get("FRONTAL_KAFKA_TOPIC_AUDIT_STATUS", "audit.status"),
        import_external_results=os.environ.get("FRONTAL_IMPORT_EXTERNAL_RESULTS", "true").lower()
        == "true",
        topic_requests=os.environ.get("FRONTAL_KAFKA_TOPIC_REQUESTS", "scan.requests"),
        topic_status=os.environ.get("FRONTAL_KAFKA_TOPIC_STATUS", "scan.status"),
        topic_results=os.environ.get("FRONTAL_KAFKA_TOPIC_RESULTS", "scan.results"),
        # Every worker replica shares the strix-workers group so scan.requests
        # fan out across them.
        worker_group=os.environ.get("FRONTAL_KAFKA_WORKER_GROUP", "strix-workers"),
        artifact_store=os.environ.get("FRONTAL_ARTIFACT_STORE", default_store).lower(),
        s3_endpoint_url=s3_endpoint or None,
        s3_bucket=(
            os.environ.get("FRONTAL_S3_BUCKET") or os.environ.get("MINIO_BUCKET", "strix-runs")
        ),
        s3_region=os.environ.get("FRONTAL_S3_REGION") or os.environ.get("MINIO_REGION") or None,
        s3_access_key=os.environ.get("FRONTAL_S3_ACCESS_KEY") or os.environ.get("MINIO_ACCESS_KEY"),
        s3_secret_key=os.environ.get("FRONTAL_S3_SECRET_KEY") or os.environ.get("MINIO_SECRET_KEY"),
        s3_verify_tls=os.environ.get("MINIO_VERIFY_TLS", "false").lower() == "true",
        mongo_uri=mongo_uri or None,
        mongo_db=os.environ.get("FRONTAL_MONGO_DB") or os.environ.get("MONGO_DB", "strix"),
        mongo_bucket=(
            os.environ.get("FRONTAL_MONGO_BUCKET") or os.environ.get("MONGO_BUCKET", "strix_runs")
        ),
        serve_console=os.environ.get("FRONTAL_SERVE_CONSOLE", "true").lower() == "true",
    )

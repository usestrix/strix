# Strix frontal: web console + API that publishes to audit.request and folds
# audit.result back into its database. It never runs a scan itself — the KEDA
# orchestrator (k8s/kafka_orchestrator.py) does.
#
# The Strix package IS installed (Python only, no Kali toolchain): the frontal
# serves Strix's own viewer SPA for the agent transcript, and that reads run
# directories through strix.interface.viewer. Everything else (launch, results,
# retest) works without it; main.py drops the viewer if the import fails.
#
# Build — the context is the REPO ROOT (frontal/Dockerfile.dockerignore keeps it small):
#   docker build -f frontal/Dockerfile -t <REGISTRY>/strix-frontal:<TAG> .
#
# Run locally against demo/docker-compose.dev.yml:
#   docker run --rm -p 8000:8000 \
#     -e FRONTAL_DATABASE_URL=sqlite:////data/frontal.db \
#     -e FRONTAL_KAFKA_BOOTSTRAP=host.docker.internal:9092 \
#     -e MINIO_ENDPOINT=http://host.docker.internal:9000 \
#     -e MINIO_ACCESS_KEY=minio -e MINIO_SECRET_KEY=minio12345 \
#     -v strix_frontal_data:/data <REGISTRY>/strix-frontal:<TAG>

FROM python:3.12-slim

# PYTHONPATH=/app so `frontal.app.main` resolves: frontal/ has no __init__.py
# and is imported as a namespace package from the directory that contains it.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Layers ordered by how often they change: deps, then Strix, then the app.
COPY frontal/requirements.txt ./requirements.txt
RUN pip install -r requirements.txt

# Editable on purpose: a regular wheel build runs scripts/tui_sidecar_hook.py,
# which compiles the Go TUI (needs a Go toolchain); the hook no-ops for editable
# installs, and the frontal never uses the TUI.
COPY pyproject.toml README.md LICENSE /opt/strix-src/
COPY scripts/tui_sidecar_hook.py /opt/strix-src/scripts/
COPY strix /opt/strix-src/strix
RUN pip install -e /opt/strix-src

COPY frontal/app ./frontal/app

# /data holds the SQLite database (if used) and the run directories pulled from
# MinIO for the report and the transcript viewer. Mount a PVC here.
ENV FRONTAL_ARTIFACTS_DIR=/data/artifacts \
    FRONTAL_DATABASE_URL=sqlite:////data/frontal.db
RUN mkdir -p /data/artifacts

# OpenShift-friendly: an arbitrary UID with GID 0 can still write /app and /data.
RUN chgrp -R 0 /app /data && chmod -R g=u /app /data
USER 10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status==200 else 1)"

# --proxy-headers: the frontal sits behind an Ingress that terminates TLS.
CMD ["uvicorn", "frontal.app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]

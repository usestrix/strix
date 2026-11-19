#!/usr/bin/env bash
# Arranca la web (FastAPI) en http://127.0.0.1:8000
set -euo pipefail
cd "$(dirname "$0")/.."                 # raíz del repo
source demo/env.sh
exec uv run --with-requirements frontal/requirements.txt \
  uvicorn frontal.app.main:app --host 127.0.0.1 --port 8000

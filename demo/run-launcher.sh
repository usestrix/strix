#!/usr/bin/env bash
# Launcher one-shot (modelo KEDA ScaledJob): consume 1 mensaje, lanza strix y sale.
# Ejecútalo cada vez que quieras procesar un mensaje de la cola.
set -euo pipefail
cd "$(dirname "$0")/.."
source demo/env.sh
exec uv run --with-requirements frontal/requirements.txt python -m frontal.launcher

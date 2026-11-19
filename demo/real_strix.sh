#!/usr/bin/env bash
# strix REAL (sin stub) para el worker/launcher: se usa como FRONTAL_STRIX_BIN.
#
# strix no está en el PATH aquí y vive como paquete del repo, así que se ejecuta
# con `uv run --project <repo>`. Corre con el backend 'local' (STRIX_RUNTIME_BACKEND),
# que ejecuta el scan en el propio proceso sin sandbox Docker.
#
# La config del LLM (STRIX_LLM / LLM_API_KEY) la toma strix de ~/.strix/cli-config.json
# (o de las variables de entorno si las exportas). El scan_exec del frontal invoca
# este script con --target/--scan-mode/--instruction-file/--max-budget-usd y en el
# cwd (workdir) donde strix escribe strix_runs/, que es justo lo que espera el ingest.
set -euo pipefail

# Raíz del repo, sin cambiar el cwd (strix debe correr en el workdir que fija scan_exec).
REPO="$(cd "$(dirname "$0")/.." && pwd)"

export STRIX_RUNTIME_BACKEND="${STRIX_RUNTIME_BACKEND:-local}"

# El backend local necesita un WORKDIR escribible (el "/workspace" fijo del
# sandbox Docker no existe en el host). Uno por invocación evita colisiones entre
# launchers concurrentes. Se deja en /tmp (efímero); bórralo si quieres.
export STRIX_WORKSPACE_ROOT="${STRIX_WORKSPACE_ROOT:-$(mktemp -d "${TMPDIR:-/tmp}/strix-workspace.XXXXXX")}"

exec uv run --project "$REPO" strix "$@"

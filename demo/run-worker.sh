#!/usr/bin/env bash
# Worker long-running (modelo Deployment): consume scan.requests en bucle.
set -euo pipefail
cd "$(dirname "$0")/.."
source demo/env.sh
exec uv run --with-requirements frontal/requirements.txt python -m frontal.worker

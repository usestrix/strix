"""Long-running Strix scan consumer (Deployment model).

Thin entrypoint over :mod:`frontal.runner`: consumes ``scan.requests`` in a loop,
runs Strix, and persists each scan to BOTH Postgres and Kafka. All logic lives in
``frontal.runner``; ``python -m frontal.launcher`` is the one-shot (KEDA) variant.

    python -m frontal.worker
"""

from __future__ import annotations

import sys

from frontal.runner import run


def main() -> int:
    return run(once=False)


if __name__ == "__main__":
    sys.exit(main())

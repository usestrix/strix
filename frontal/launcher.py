"""One-shot Strix scan consumer (KEDA ScaledJob model).

Thin entrypoint over :mod:`frontal.runner`: consumes ONE ``scan.requests``
message, runs Strix, persists the outcome to BOTH Postgres and Kafka, commits,
and exits. All logic lives in ``frontal.runner``; ``python -m frontal.worker`` is
the long-running (Deployment) variant.

    python -m frontal.launcher

Exit code: ``0`` when the message was handled and committed (whether the scan
passed or errored); ``2`` only on a runner-level failure before commit, leaving
the offset uncommitted for KEDA to retry.
"""

from __future__ import annotations

import sys

from frontal.runner import run


def main() -> int:
    return run(once=True)


if __name__ == "__main__":
    sys.exit(main())

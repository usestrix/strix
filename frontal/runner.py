"""Unified Strix scan runner: consume ``scan.requests``, run Strix, persist to
BOTH Postgres and Kafka, commit, and either loop or exit.

One code path, two lifecycles selected by ``--once``:

    python -m frontal.runner            # long-running loop (Deployment model)
    python -m frontal.runner --once     # process one message and exit (KEDA ScaledJob)

``frontal.worker`` and ``frontal.launcher`` are thin entrypoints over this module
(``run(once=False)`` and ``run(once=True)``) kept for the existing scripts.

Persistence — every scan is written to **both** stores:

- **Postgres**: ``_claim`` marks it ``running``, then ``_persist`` ingests findings
  and sets the terminal status. This is self-contained, so a run does not depend
  on the frontal's ``ResultConsumer`` being up. (If that consumer *is* running it
  re-ingests the same ``scan.results``; ``ingest_run`` is idempotent, so it
  converges rather than duplicating.)
- **Kafka**: ``scan.status`` (running / terminal) and ``scan.results`` (artifact
  location) are published so the frontal and any other listener see the lifecycle.

Delivery is at-least-once: the offset is committed only after Postgres and Kafka
are both written. A redelivered message whose scan is already ``completed`` is
skipped (idempotent claim), so a scan is never paid for twice while one that died
mid-run is retried. ``max_poll_records=1`` keeps a single poll from advancing the
position past records it will not process (see ``make_consumer``).

Exit code (``--once``): ``0`` when the message was handled and committed (whether
the scan passed or errored — the error is recorded); ``2`` only on a runner-level
failure before commit, leaving the offset for a retry.
"""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import socket
import sys
from datetime import UTC, datetime
from typing import Any

from frontal.app.artifacts import ArtifactStore, get_artifact_store
from frontal.app.config import Settings, get_settings
from frontal.app.db import SessionLocal, init_db
from frontal.app.ingest import ingest_run
from frontal.app.messaging import make_consumer, make_producer, publish
from frontal.app.models import Scan
from frontal.app.retest import reconcile_retest
from frontal.app.scan_exec import ScanOutcome, ScanRequest, run_scan


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("strix.runner")

_VALID_MODES = frozenset({"quick", "standard", "deep"})
# How long a one-shot run waits for its message before giving up (KEDA scaled us
# up for exactly one). Ignored in loop mode.
_CONSUME_TIMEOUT_S = int(os.environ.get("FRONTAL_LAUNCHER_CONSUME_TIMEOUT", "60"))
# Pod/host name is the natural worker id.
_WORKER_ID = os.environ.get("HOSTNAME") or socket.gethostname()


def _now() -> datetime:
    return datetime.now(UTC)


def _validate(req: ScanRequest) -> None:
    if not req.target:
        raise ValueError("payload missing target")
    if req.scan_mode not in _VALID_MODES:
        raise ValueError(f"invalid scan_mode: {req.scan_mode!r}")


def _consume_one(consumer: Any, deadline: float) -> Any:
    """Poll until one record arrives or the deadline passes (one-shot mode)."""
    while _now().timestamp() < deadline:
        batch = consumer.poll(timeout_ms=1000)
        for records in batch.values():
            if records:
                return records[0]
    return None


def _claim(session_factory: Any, req: ScanRequest) -> bool:
    """Mark the scan running in Postgres. Return False if it is already completed."""
    with session_factory() as session:
        scan = session.get(Scan, req.scan_id)
        if scan is None:
            # No row (e.g. a runner-only deploy without the web front): run anyway,
            # but there is nothing to ingest into afterwards.
            logger.warning("scan %s has no DB row; running without persistence", req.scan_id)
            return True
        if scan.status == "completed":
            logger.info("scan %s already completed; skipping (idempotent)", req.scan_id)
            return False
        scan.status = "running"
        scan.started_at = _now()
        scan.error = None
        session.commit()
    return True


def _persist(
    settings: Settings,
    producer: Any,
    store: ArtifactStore,
    session_factory: Any,
    req: ScanRequest,
    outcome: ScanOutcome,
) -> None:
    """Store artifacts, publish results/status to Kafka, and ingest into Postgres."""
    uri: str | None = None
    if outcome.run_dir is not None:
        uri = store.publish_run(req.scan_id, outcome.run_dir)
        publish(
            producer,
            settings.topic_results,
            req.scan_id,
            {"scan_id": req.scan_id, "artifact_uri": uri},
        )

    with session_factory() as session:
        scan = session.get(Scan, req.scan_id)
        if scan is not None:
            if uri is not None:
                run_dir = store.localize(req.scan_id, uri)
                scan.artifact_path = f"runs/{req.scan_id}"
                ingest_run(session, scan, run_dir)
                session.flush()
                if scan.kind == "retest":
                    reconcile_retest(session, scan, run_dir)
            scan.status = "failed" if outcome.failure else "completed"
            scan.error = outcome.failure
            scan.ended_at = _now()
            session.commit()

    publish(
        producer,
        settings.topic_status,
        req.scan_id,
        {
            "scan_id": req.scan_id,
            "status": "failed" if outcome.failure else "completed",
            "ended_at": _now().isoformat(),
            "error": outcome.failure,
            "worker": _WORKER_ID,
        },
    )
    producer.flush(timeout=10)


def process_scan(
    settings: Settings,
    producer: Any,
    store: ArtifactStore,
    session_factory: Any,
    req: ScanRequest,
) -> None:
    """Run one scan end-to-end: running status -> Strix -> persist (DB + Kafka)."""
    publish(
        producer,
        settings.topic_status,
        req.scan_id,
        {
            "scan_id": req.scan_id,
            "status": "running",
            "started_at": _now().isoformat(),
            "worker": _WORKER_ID,
        },
    )
    producer.flush(timeout=10)

    workdir = settings.artifacts_dir / "work" / str(req.scan_id)
    outcome = run_scan(settings, req, workdir)
    _persist(settings, producer, store, session_factory, req, outcome)
    shutil.rmtree(workdir / "strix_runs", ignore_errors=True)
    logger.info("scan %s done (%s)", req.scan_id, outcome.failure or "ok")


def _handle_record(
    settings: Settings,
    producer: Any,
    store: ArtifactStore,
    session_factory: Any,
    consumer: Any,
    record: Any,
) -> None:
    """Claim + process one record, then commit its offset. Raises on a real
    failure (offset left uncommitted for redelivery). Poison messages and
    already-completed scans are committed so they are not redelivered forever."""
    try:
        req = ScanRequest.from_message(record.value)
        _validate(req)
    except (KeyError, ValueError, TypeError):
        logger.exception("invalid payload, dropping: %s", record.value)
        consumer.commit()
        return

    logger.info(
        "scan %s claimed by %s: target=%s mode=%s",
        req.scan_id,
        _WORKER_ID,
        req.target,
        req.scan_mode,
    )
    if not _claim(session_factory, req):
        consumer.commit()
        return

    process_scan(settings, producer, store, session_factory, req)
    # At-least-once: commit only now that Kafka + Postgres are both written.
    consumer.commit()


def run(once: bool) -> int:
    settings = get_settings()
    settings.artifacts_dir.mkdir(parents=True, exist_ok=True)
    init_db()

    # One record per poll: each scan runs (minutes to hours) between polls, and
    # the offset is committed per scan, so never fetch more than one at a time.
    consumer = make_consumer(
        settings, settings.worker_group, [settings.topic_requests], max_poll_records=1
    )
    producer = make_producer(settings)
    store = get_artifact_store(settings)
    logger.info(
        "runner up (%s); consuming %s as group %s",
        "one-shot" if once else "loop",
        settings.topic_requests,
        settings.worker_group,
    )

    try:
        if once:
            record = _consume_one(consumer, _now().timestamp() + _CONSUME_TIMEOUT_S)
            if record is None:
                logger.info("no message within %ss; nothing to do", _CONSUME_TIMEOUT_S)
                return 0
            try:
                _handle_record(settings, producer, store, SessionLocal, consumer, record)
            except Exception:
                logger.exception("runner failed before commit; message left for retry")
                return 2
            return 0

        while True:
            batch = consumer.poll(timeout_ms=1000)
            for records in batch.values():
                for record in records:
                    try:
                        _handle_record(settings, producer, store, SessionLocal, consumer, record)
                    except Exception:
                        # Left uncommitted on purpose; redelivered on restart/rebalance.
                        logger.exception("failed processing %s", record.value)
        return 0  # noqa: TRY300 - unreachable; the loop only exits via KeyboardInterrupt
    except KeyboardInterrupt:
        return 0
    finally:
        consumer.close()
        producer.flush(timeout=5)
        producer.close(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--once",
        action="store_true",
        help="Process one message and exit (KEDA ScaledJob model). Default: loop.",
    )
    args = parser.parse_args()
    return run(once=args.once)


if __name__ == "__main__":
    sys.exit(main())

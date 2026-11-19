"""Consumes ``scan.status`` / ``scan.results`` and folds them into Postgres.

The mirror image of :class:`~frontal.app.launcher.ScanProducer`: a background
thread that listens for what the worker reports and does the DB-side work the
old in-process runner used to do inline — status transitions, artifact
localization, and ingest.

Status and results arrive on different topics, so their relative order is not
guaranteed. Both converge on ``completed``: whichever the results handler and
the terminal status message run in, the run ends up ingested and marked done.
"""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime
from typing import Any

from frontal.app.artifacts import ArtifactStore, get_artifact_store
from frontal.app.config import Settings, get_settings
from frontal.app.ingest import ingest_run
from frontal.app.messaging import make_consumer
from frontal.app.models import Scan
from frontal.app.retest import reconcile_retest


logger = logging.getLogger(__name__)


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


class ResultConsumer:
    def __init__(
        self,
        session_factory,
        settings: Settings | None = None,
        store: ArtifactStore | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._session_factory = session_factory
        self._store = store or get_artifact_store(self._settings)
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="strix-frontal-consumer", daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def shutdown(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        consumer = make_consumer(
            self._settings,
            self._settings.consumer_group,
            [self._settings.topic_status, self._settings.topic_results],
        )
        try:
            while not self._stop.is_set():
                batch = consumer.poll(timeout_ms=500)
                for records in batch.values():
                    for record in records:
                        try:
                            self._handle(record.topic, record.value)
                        except Exception:
                            logger.exception("failed handling %s: %s", record.topic, record.value)
                if batch:
                    consumer.commit()
        except Exception:
            logger.exception("frontal consumer crashed")
        finally:
            consumer.close()

    def _handle(self, topic: str, value: dict[str, Any]) -> None:
        if topic == self._settings.topic_status:
            self._on_status(value)
        elif topic == self._settings.topic_results:
            self._on_results(value)

    def _on_status(self, value: dict[str, Any]) -> None:
        scan_id = int(value["scan_id"])
        with self._session_factory() as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                return
            if value.get("status"):
                scan.status = value["status"]
            if started := _parse_time(value.get("started_at")):
                scan.started_at = started
            if ended := _parse_time(value.get("ended_at")):
                scan.ended_at = ended
            if value.get("error") is not None:
                scan.error = value["error"]
            session.commit()

    def _on_results(self, value: dict[str, Any]) -> None:
        scan_id = int(value["scan_id"])
        run_dir = self._store.localize(scan_id, value["artifact_uri"])
        with self._session_factory() as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                return
            scan.artifact_path = f"runs/{scan_id}"
            ingest_run(session, scan, run_dir)
            session.flush()
            if scan.kind == "retest":
                reconcile_retest(session, scan, run_dir)
            # The worker's terminal status may not have arrived yet; a failed
            # run stays failed, anything else is complete once ingested.
            if scan.status != "failed":
                scan.status = "completed"
                scan.ended_at = scan.ended_at or datetime.now(UTC)
            session.commit()
        logger.info("scan %s results ingested", scan_id)

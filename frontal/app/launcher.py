"""Publishes scan requests to Kafka; a worker runs them.

The frontal no longer runs Strix in-process. :class:`ScanProducer` turns a scan
id into a ``scan.requests`` message; a worker in the ``strix-workers`` group
consumes it, runs Strix, and reports back over ``scan.status`` /
``scan.results`` (see :mod:`frontal.app.consumer`).

``ScanRunner`` remains as an alias so callers that predate the split keep
working.
"""

from __future__ import annotations

import logging

from kafka import KafkaProducer

from frontal.app.config import Settings, get_settings
from frontal.app.messaging import make_producer, publish
from frontal.app.models import Scan
from frontal.app.scan_exec import ScanRequest


logger = logging.getLogger(__name__)


class ScanProducer:
    def __init__(
        self,
        session_factory,
        settings: Settings | None = None,
        producer: KafkaProducer | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._session_factory = session_factory
        self._producer = producer or make_producer(self._settings)

    def submit(self, scan_id: int) -> None:
        with self._session_factory() as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                logger.warning("scan %s vanished before publish", scan_id)
                return
            req = ScanRequest(
                scan_id=scan.id,
                target=scan.app.target,
                scan_mode=scan.scan_mode,
                instruction=scan.instruction,
                kind=scan.kind,
            )
            scan.status = "queued"
            session.commit()

        publish(self._producer, self._settings.topic_requests, req.scan_id, req.to_message())
        # Block until the request is on the broker: losing it would strand a
        # scan that the UI already reported as accepted.
        self._producer.flush(timeout=10)
        logger.info("scan %s published to %s", scan_id, self._settings.topic_requests)

    def shutdown(self) -> None:
        self._producer.flush(timeout=5)
        self._producer.close(timeout=5)


# Backwards-compatible name for the pre-Kafka in-process runner.
ScanRunner = ScanProducer

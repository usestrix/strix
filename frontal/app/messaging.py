"""Kafka wiring for the frontal <-> worker split.

Three topics carry a scan's lifecycle:

  - ``scan.requests``  frontal -> worker   a scan to run
  - ``scan.status``    worker  -> frontal  running / failed / completed transitions
  - ``scan.results``   worker  -> frontal  a finished run's artifact location

Messages are JSON, keyed by scan id (as a string) so everything about one scan
lands on the same partition and stays ordered relative to itself.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from kafka import KafkaConsumer, KafkaProducer


if TYPE_CHECKING:
    from frontal.app.config import Settings


logger = logging.getLogger(__name__)


def make_producer(settings: Settings) -> KafkaProducer:
    return KafkaProducer(
        bootstrap_servers=settings.kafka_bootstrap_servers.split(","),
        key_serializer=lambda k: str(k).encode(),
        value_serializer=lambda v: json.dumps(v).encode(),
        acks="all",
        retries=5,
        linger_ms=50,
    )


def make_consumer(
    settings: Settings,
    group_id: str,
    topics: Iterable[str],
    max_poll_records: int = 10,
) -> KafkaConsumer:
    # Manual commits only: an offset is committed after its records are handled,
    # so a crash mid-batch redelivers rather than silently drops a scan.
    #
    # ``max_poll_records`` bounds how many records a single ``poll()`` returns.
    # The long-running worker handles the whole batch before committing, so 10 is
    # fine. The one-shot launcher handles exactly ONE record and then commits, so
    # it MUST pass 1: otherwise a poll that fetches several (a partition with a
    # backlog) advances the position past all of them, and the blanket commit
    # marks the unprocessed ones consumed — silently dropping scans.
    #
    # A worker/launcher runs a whole scan between poll() calls — minutes to hours.
    # Kafka evicts a consumer that does not poll() within max_poll_interval_ms
    # (default 5 min) and then rejects its commit ("group already rebalanced"), so
    # the interval must exceed the longest scan. Default to the scan timeout plus
    # a margin; the frontal's fast status/results consumer is unaffected (it polls
    # continuously). The heartbeat thread keeps the session alive meanwhile.
    max_poll_interval_ms = (settings.scan_timeout_seconds + 300) * 1000
    return KafkaConsumer(
        *topics,
        bootstrap_servers=settings.kafka_bootstrap_servers.split(","),
        group_id=group_id,
        key_deserializer=lambda k: k.decode() if k else None,
        value_deserializer=lambda v: json.loads(v.decode()),
        enable_auto_commit=False,
        auto_offset_reset="earliest",
        max_poll_records=max_poll_records,
        max_poll_interval_ms=max_poll_interval_ms,
    )


def publish(producer: KafkaProducer, topic: str, scan_id: int, value: dict[str, Any]) -> None:
    producer.send(topic, key=scan_id, value=value)

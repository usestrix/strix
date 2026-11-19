"""The frontal's side of the orchestrator contract (``k8s/kafka_orchestrator.py``).

    frontal ──audit.request──►  orchestrator (KEDA ScaledJob, one pod per scan)
    frontal ◄──audit.status───  "running" when the pod accepts the request (optional)
    frontal ◄──audit.result───  outcome + finding summary + MinIO object keys

``audit.request`` is exactly the JSON you would type into
``kafka-console-producer``::

    {"id": "frontal-12-3fa9c1d2", "target": "http://juice-shop:3000",
     "scan_mode": "quick", "max_budget": 2, "instruction": "..."}

The orchestrator echoes the whole request back inside ``audit.result`` as
``request``, so ``request.id`` is how a result finds its scan row. The id carries
a random suffix: scan ids restart when the database is reset, Kafka topics do not.

The orchestrator is at-most-once (it commits before scanning), so a pod that
dies mid-scan never produces a result. Such a scan stays ``queued``/``running``
until someone marks it failed from the UI.
"""

from __future__ import annotations

import json
import logging
import math
import secrets
import shutil
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from frontal.app.artifacts import ArtifactStore, get_artifact_store
from frontal.app.config import Settings, get_settings
from frontal.app.ingest import ingest_run, record_observation, upsert_finding
from frontal.app.models import App, Scan
from frontal.app.retest import reconcile_retest, reconcile_verify


if TYPE_CHECKING:
    from sqlalchemy.orm import Session


logger = logging.getLogger(__name__)

# Mirrors the orchestrator's own validation (build_strix_argv), so a bad value is
# rejected by the API instead of becoming a failed audit.result minutes later.
SCAN_MODES = ("quick", "standard", "deep")
SCOPE_MODES = ("auto", "diff", "full")
REQUEST_ID_PREFIX = "frontal-"
# Fields of audit.result kept on the scan row; the rest is the echoed request
# (already stored as request_payload) and the finding list (ingested as rows).
_RESULT_SKIP = frozenset({"request", "vulnerabilities"})


class AuditRequestError(ValueError):
    """The scan cannot be turned into a request the orchestrator would accept."""


def new_request_id(scan_id: int) -> str:
    return f"{REQUEST_ID_PREFIX}{scan_id}-{secrets.token_hex(4)}"


def build_audit_request(
    *,
    request_id: str,
    target: str,
    scan_mode: str,
    instruction: str | None = None,
    max_budget: float | None = None,
    scope_mode: str | None = None,
    kind: str = "scan",
) -> dict[str, Any]:
    """The ``audit.request`` payload. Raises :class:`AuditRequestError` on bad input."""
    target = (target or "").strip()
    if not target:
        raise AuditRequestError("target is required")
    if scan_mode not in SCAN_MODES:
        raise AuditRequestError(f"scan_mode must be one of {SCAN_MODES}")
    payload: dict[str, Any] = {"id": request_id, "target": target, "scan_mode": scan_mode}
    if scope_mode:
        if scope_mode not in SCOPE_MODES:
            raise AuditRequestError(f"scope_mode must be one of {SCOPE_MODES}")
        payload["scope_mode"] = scope_mode
    if max_budget is not None:
        if not math.isfinite(max_budget) or max_budget <= 0:
            raise AuditRequestError("max_budget must be a number > 0")
        payload["max_budget"] = max_budget
    if instruction and instruction.strip():
        payload["instruction"] = instruction.strip()
    # Ignored by the orchestrator; lets anyone reading the topic tell them apart.
    payload["kind"] = kind
    payload["source"] = "strix-frontal"
    return payload


def scan_request_payload(scan: Scan) -> dict[str, Any]:
    return build_audit_request(
        request_id=scan.request_id or new_request_id(scan.id),
        target=scan.target or scan.app.target,
        scan_mode=scan.scan_mode,
        instruction=scan.instruction,
        max_budget=scan.max_budget,
        scope_mode=scan.scope_mode,
        kind=scan.kind,
    )


# ── Producer ────────────────────────────────────────────────────────────────


class AuditProducer:
    """Publishes a scan row to ``audit.request``.

    The Kafka producer is created lazily, so the API starts (and can show
    history) while Kafka is down; launching then fails per request instead.
    """

    def __init__(self, session_factory, settings: Settings | None = None, producer=None) -> None:
        self._settings = settings or get_settings()
        self._session_factory = session_factory
        self._producer = producer
        self._lock = threading.Lock()

    def _get_producer(self):
        with self._lock:
            if self._producer is None:
                from kafka import KafkaProducer  # noqa: PLC0415

                self._producer = KafkaProducer(
                    bootstrap_servers=self._settings.kafka_bootstrap_servers.split(","),
                    key_serializer=lambda k: str(k).encode(),
                    value_serializer=lambda v: json.dumps(v).encode(),
                    acks="all",
                    retries=5,
                )
            return self._producer

    def submit(self, scan_id: int) -> Scan:
        """Publish the scan and return it; on failure the row is marked failed."""
        with self._session_factory() as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                raise LookupError(f"scan {scan_id} not found")
            scan.request_id = scan.request_id or new_request_id(scan.id)
            scan.target = scan.target or scan.app.target
            payload = scan_request_payload(scan)
            scan.request_payload = payload
            topic = self._settings.audit_topic_request
            try:
                # .get() blocks until the broker acks: a request lost here would
                # leave a scan the UI reported as accepted waiting forever.
                self._get_producer().send(topic, key=scan.request_id, value=payload).get(timeout=15)
            except Exception as exc:
                logger.exception("scan %s: publish to %s failed", scan_id, topic)
                scan.status = "failed"
                scan.error = f"No se pudo publicar en Kafka ({topic}): {exc}"
                scan.ended_at = datetime.now(UTC)
            else:
                scan.status = "queued"
                logger.info("scan %s published to %s as %s", scan_id, topic, scan.request_id)
            session.commit()
            return scan

    def shutdown(self) -> None:
        if self._producer is not None:
            self._producer.flush(timeout=5)
            self._producer.close(timeout=5)


# ── Result handling (pure DB + store; no Kafka) ─────────────────────────────


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _request_targets(request: dict[str, Any]) -> list[str]:
    targets = request.get("targets") or request.get("target") or []
    if not isinstance(targets, list):
        targets = [targets]
    return [str(t).strip() for t in targets if str(t).strip()]


def _find_scan(session: Session, request_id: str | None, run_name: str | None) -> Scan | None:
    if not request_id:
        return None
    scan = session.scalar(
        select(Scan).where(Scan.request_id == request_id).order_by(Scan.id.desc()).limit(1)
    )
    # Hand-typed ids get reused ("audit-dev-002" twice): a different run under an
    # id we already imported is a new external scan, not an update of the old one.
    if (
        scan is not None
        and scan.kind == "external"
        and run_name
        and scan.run_name
        and scan.run_name != run_name
    ):
        return None
    return scan


def _app_for_target(session: Session, target: str) -> App:
    app = session.scalar(select(App).where(App.target == target).order_by(App.id).limit(1))
    if app is not None:
        return app
    name = target[:200]
    suffix = 2
    while session.scalar(select(App).where(App.name == name)) is not None:
        name = f"{target[:190]} ({suffix})"
        suffix += 1
    app = App(name=name, target=target, environment="externo")
    session.add(app)
    session.flush()
    return app


def _import_external(session: Session, request: dict[str, Any]) -> Scan | None:
    targets = _request_targets(request)
    if not targets:
        return None
    app = _app_for_target(session, targets[0])
    scan = Scan(
        app_id=app.id,
        kind="external",
        status="running",
        scan_mode=str(request.get("scan_mode") or "quick"),
        target=targets[0],
        instruction=request.get("instruction"),
        request_id=str(request.get("id") or "") or None,
        request_payload=request,
    )
    try:
        scan.max_budget = float(request["max_budget"]) if request.get("max_budget") else None
    except (TypeError, ValueError):
        scan.max_budget = None
    session.add(scan)
    session.flush()
    logger.info("imported external request %s as scan %s", scan.request_id, scan.id)
    return scan


def _localize_run(
    settings: Settings, store: ArtifactStore, scan: Scan, value: dict[str, Any]
) -> Path | None:
    """Bring the run directory next to the frontal; None if it is unreachable."""
    storage = value.get("storage") or {}
    download = getattr(store, "download_prefix", None)
    if storage.get("uploaded") and storage.get("prefix"):
        # Orchestrators older than the GridFS backend send no "backend": S3.
        backend = storage.get("backend") or "s3"
        if download is None or backend != store.backend:
            logger.warning(
                "scan %s: artifacts are in '%s' storage but FRONTAL_ARTIFACT_STORE is "
                "'%s'; only the summary will be shown",
                scan.id,
                backend,
                store.backend,
            )
            return None
        default_bucket = settings.mongo_bucket if backend == "mongo" else settings.s3_bucket
        try:
            return download(scan.id, storage.get("bucket") or default_bucket, storage["prefix"])
        except Exception:
            logger.exception("scan %s: artifact download failed", scan.id)
            return None

    # No object storage: works only when both pods share the strix_runs volume.
    run_dir = value.get("run_dir")
    if run_dir and Path(run_dir).is_dir():
        dest = settings.artifacts_dir / "runs" / str(scan.id)
        shutil.rmtree(dest, ignore_errors=True)
        shutil.copytree(run_dir, dest)
        return dest
    return None


def apply_result(
    session: Session,
    value: dict[str, Any],
    *,
    settings: Settings,
    store: ArtifactStore,
) -> Scan | None:
    """Fold one ``audit.result`` event into the database. Caller commits."""
    request = value.get("request") if isinstance(value.get("request"), dict) else {}
    request_id = str(request.get("id") or "") or None
    run_name = value.get("run_name")

    scan = _find_scan(session, request_id, run_name)
    if scan is None:
        if request_id and request_id.startswith(REQUEST_ID_PREFIX):
            logger.warning("result for unknown frontal request %s ignored", request_id)
            return None
        if not settings.import_external_results:
            return None
        scan = _import_external(session, request)
        if scan is None:
            logger.warning("result without a usable request ignored: %s", value.get("error"))
            return None

    scan.result = {k: v for k, v in value.items() if k not in _RESULT_SKIP}
    scan.run_name = run_name or scan.run_name

    run_dir = _localize_run(settings, store, scan, value)
    if run_dir is not None and (run_dir / "run.json").is_file():
        scan.artifact_path = f"runs/{scan.id}"
        ingest_run(session, scan, run_dir)
    else:
        # Summary only: the event carries id/title/severity/cvss/cwe/endpoint/method.
        for vuln in value.get("vulnerabilities") or []:
            if isinstance(vuln, dict):
                finding = upsert_finding(session, scan, vuln)
                record_observation(session, scan, finding, vuln, "observed")
    if not scan.llm_usage and value.get("cost") is not None:
        scan.llm_usage = {"cost": value.get("cost"), "requests": value.get("requests")}

    session.flush()
    if scan.kind in ("retest", "verify"):
        reconcile = reconcile_retest if scan.kind == "retest" else reconcile_verify
        reconcile(session, scan, run_dir or settings.artifacts_dir / "runs" / "_none")

    succeeded = bool(value.get("succeeded"))
    scan.status = "completed" if succeeded else "failed"
    scan.error = None if succeeded else (value.get("error") or f"status={value.get('status')}")
    scan.ended_at = scan.ended_at or datetime.now(UTC)
    return scan


def apply_status(session: Session, value: dict[str, Any]) -> Scan | None:
    """Fold an ``audit.status`` event (the pod accepted the request)."""
    scan = _find_scan(session, str(value.get("id") or "") or None, None)
    if scan is None or scan.status not in ("queued", "running"):
        return None
    if value.get("status") == "running":
        scan.status = "running"
        scan.started_at = _parse_time(value.get("started_at")) or scan.started_at
    return scan


# ── Consumer thread ─────────────────────────────────────────────────────────


class AuditResultConsumer:
    """Background thread: ``audit.result`` / ``audit.status`` → database."""

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
        self._thread = threading.Thread(target=self._run, name="audit-consumer", daemon=True)
        self.connected = False

    def start(self) -> None:
        self._thread.start()

    def shutdown(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        # Reconnect forever: Kafka being down must not take the UI down with it.
        while not self._stop.is_set():
            try:
                self._consume()
            except Exception:
                self.connected = False
                logger.exception("audit consumer failed; retrying in 10s")
                self._stop.wait(10)

    def _consume(self) -> None:
        from kafka import KafkaConsumer  # noqa: PLC0415

        topics = [self._settings.audit_topic_result]
        if self._settings.audit_topic_status:
            topics.append(self._settings.audit_topic_status)
        # Raw bytes on purpose: a malformed message must be skipped by
        # handle_message, not raise inside poll() and stall the partition.
        consumer = KafkaConsumer(
            *topics,
            bootstrap_servers=self._settings.kafka_bootstrap_servers.split(","),
            group_id=self._settings.consumer_group,
            enable_auto_commit=False,
            auto_offset_reset="earliest",
        )
        self.connected = True
        logger.info("audit consumer listening on %s", topics)
        try:
            while not self._stop.is_set():
                batch = consumer.poll(timeout_ms=1000)
                for records in batch.values():
                    for record in records:
                        self.handle_message(record.topic, record.value)
                if batch:
                    consumer.commit()
        finally:
            consumer.close()

    def handle_message(self, topic: str, raw: bytes | None) -> None:
        try:
            value = json.loads(raw.decode("utf-8")) if raw else None
        except (UnicodeDecodeError, json.JSONDecodeError):
            logger.warning("skipping non-JSON message on %s", topic)
            return
        if not isinstance(value, dict):
            return
        started = time.monotonic()
        try:
            with self._session_factory() as session:
                if topic == self._settings.audit_topic_result:
                    scan = apply_result(session, value, settings=self._settings, store=self._store)
                else:
                    scan = apply_status(session, value)
                session.commit()
        except Exception:
            # Logged and skipped: one poisoned result must not block every later one.
            logger.exception("failed handling %s message", topic)
            return
        if scan is not None:
            elapsed = time.monotonic() - started
            logger.info("%s → scan %s (%s) in %.1fs", topic, scan.id, scan.status, elapsed)

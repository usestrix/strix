"""Kafka-triggered, in-process Strix orchestrator (one KEDA ScaledJob per scan).

WHAT THIS IS

The bridge between a Kafka work queue and the Strix pentest engine. One Pod =
one scan: KEDA spawns this Job when a request lands on the queue, the Job runs
exactly one scan, reports the outcome, and exits so KEDA can scale back to zero.

THE PIPELINE (top to bottom of ``main``)

    audit.request  ──poll one event──►  parse_request()         (bytes → JSON)
                                        build_strix_argv()      (JSON → CLI args)
                                        run_strix_inprocess()   (run Strix here)
                                        harvest_results()       (read run output)
                                        upload_run_artifacts()  (push artifacts)
    audit.result   ◄──publish summary──┘

Two design choices worth understanding before changing anything:

1. IN-PROCESS, NOT A SUBPROCESS. ``run_strix_inprocess`` imports Strix and calls
   its ``main()`` inside *this* interpreter. That is what the ``local`` sandbox
   backend expects (orchestrator and agent share one process/Pod — see
   ``strix/runtime/local_backend.py``). The cost is that Strix signals results by
   calling ``sys.exit()``, which we must translate back into a return value.

2. COMMIT-BEFORE-SCAN (at-most-once). The Kafka offset is committed the moment
   the event is polled, before it is even parsed and long before the scan starts,
   so KEDA sees the queue drain and does not keep spawning Jobs for a message
   already being worked. A malformed request is committed too, and reported on
   the result topic, instead of crashing every Job KEDA starts for it. The
   trade-off: a Pod that dies mid-scan is NOT retried from Kafka. If you need
   retries, carry an idempotent request id and dedupe upstream.

PERSISTENCE. The run directory lives on the Pod's ephemeral volume and dies with
the scale-to-zero Pod. ``upload_run_artifacts`` pushes the finished artifacts
(report, SARIF, vulnerabilities, run.json) so they outlive the Pod, and the
result event carries their keys instead of dead local paths. The store is
MongoDB GridFS when ``MONGO_URI`` is set, else MinIO/S3 when ``MINIO_ENDPOINT``
is set; with neither, the upload is SKIPPED (not an error), so the same image
still runs without object storage configured.

The heavy imports (``strix_local_boot``, ``confluent_kafka``, ``boto3``,
``pymongo``) are
deferred into the functions that need them so the pure helpers can be imported
and unit-tested without a Kafka cluster, object storage, or the sandbox image,
and so the environment is initialized before any Strix module is first imported.
"""

from __future__ import annotations

import importlib
import json
import math
import os
import sys
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from pathlib import Path


# ── Topics / config (all env-overridable so the same image serves any queue) ──
REQUEST_TOPIC = os.environ.get("KAFKA_REQUEST_TOPIC", "audit.request")
RESULT_TOPIC = os.environ.get("KAFKA_RESULT_TOPIC", "audit.result")
# Best-effort "running" event when a request is accepted, so a UI can tell a
# queued scan from one a Pod is working on. Set to "" to disable.
STATUS_TOPIC = os.environ.get("KAFKA_STATUS_TOPIC", "audit.status")
CONSUMER_GROUP = os.environ.get("KAFKA_CONSUMER_GROUP", "strix-unified-group")
POLL_TIMEOUT_S = float(os.environ.get("KAFKA_POLL_TIMEOUT", "15.0"))
# Where the group starts when it has no committed offset (first deploy, or offsets
# expired). "earliest" so the requests that made KEDA start this Job are not skipped.
# Keep it equal to the ScaledJob trigger's ``offsetResetPolicy`` so both count lag alike.
OFFSET_RESET = os.environ.get("KAFKA_AUTO_OFFSET_RESET", "earliest")

# ── MinIO / S3 artifact storage (all env-overridable)
# Where finished-run artifacts are pushed so they outlive the scale-to-zero Pod.
# When MINIO_ENDPOINT is unset the upload is SKIPPED (not an error), so the same
# image still runs without object storage configured.
# Settings are read from the environment FIRST, then (as a fallback) from a
# Secret mounted as a volume: ``<MINIO_SECRET_DIR>/<KEY>``, one file per key
# (filename == key, contents == value — exactly how Kubernetes exposes a Secret
# mounted as a volume). Env wins, so wiring the Secret with ``envFrom``/``env``
# keeps working unchanged; the file fallback lets you INSTEAD mount the
# ``minio-secret`` Secret as a volume and have this script read it with no env
# mapping at all. ``MINIO_SECRET_DIR`` itself comes from the environment because
# it says where to look.
MINIO_SECRET_DIR = os.environ.get("MINIO_SECRET_DIR", "/etc/minio-secret")


def _minio_cfg(name: str, default: str | None = None) -> str | None:
    """Return a MinIO setting from the environment, else a mounted-secret file.

    Looks up ``name`` in ``os.environ`` first; if unset, reads
    ``<MINIO_SECRET_DIR>/<name>`` (how a Secret mounted as a volume exposes each
    key). Returns ``default`` when neither source has it.
    """
    return _secret_cfg(MINIO_SECRET_DIR, name, default)


def _secret_cfg(secret_dir: str, name: str, default: str | None = None) -> str | None:
    """``name`` from the environment, else from ``<secret_dir>/<name>``, else ``default``."""
    value = os.environ.get(name)
    if value is not None:
        return value
    try:
        with open(os.path.join(secret_dir, name), encoding="utf-8") as fh:  # noqa: PTH118, PTH123
            return fh.read().strip()
    except OSError:
        return default


# Host and port only, e.g. http://minio-s3.minio-s3.svc.cluster.local:9000. No path:
# the bucket goes in MINIO_BUCKET; a path here turns every bucket call into NoSuchBucket.
MINIO_ENDPOINT = _minio_cfg("MINIO_ENDPOINT")
MINIO_BUCKET = _minio_cfg("MINIO_BUCKET", "strix-runs")
MINIO_ACCESS_KEY = _minio_cfg("MINIO_ACCESS_KEY")
MINIO_SECRET_KEY = _minio_cfg("MINIO_SECRET_KEY")
MINIO_PREFIX = _minio_cfg("MINIO_PREFIX", "") or ""  # optional key prefix, e.g. "prod"
MINIO_REGION = _minio_cfg("MINIO_REGION", "us-east-1")
# "true"/"false": verify TLS. Default off so a self-signed in-cluster MinIO works;
# set to "true" with a real cert.
MINIO_VERIFY_TLS = str(_minio_cfg("MINIO_VERIFY_TLS", "false")).lower() == "true"

# ── MongoDB GridFS artifact storage. Takes precedence over MinIO when MONGO_URI is
# set. Same env-then-mounted-Secret lookup, from the ``mongo-secret`` Secret.
MONGO_SECRET_DIR = os.environ.get("MONGO_SECRET_DIR", "/etc/mongo-secret")
# e.g. mongodb://user:pass@mongo.strix-apps.svc.cluster.local:27017/?authSource=admin
MONGO_URI = _secret_cfg(MONGO_SECRET_DIR, "MONGO_URI")
MONGO_DB = _secret_cfg(MONGO_SECRET_DIR, "MONGO_DB", "strix") or "strix"
# GridFS bucket: the run files land in <MONGO_BUCKET>.files / <MONGO_BUCKET>.chunks.
MONGO_BUCKET = _secret_cfg(MONGO_SECRET_DIR, "MONGO_BUCKET", "strix_runs") or "strix_runs"
MONGO_PREFIX = _secret_cfg(MONGO_SECRET_DIR, "MONGO_PREFIX", "") or ""

# Strix headless exit codes: 0 = clean, 2 = vulnerabilities found. BOTH mean the
# scan ran successfully; any other code is a real failure. argparse ALSO exits 2
# when it rejects the command line, so an OK code only counts if a run exists.
_OK_EXIT_CODES = frozenset({0, 2})
# Values Strix accepts for --scan-mode and --scope-mode (strix/interface/cli_args.py).
_VALID_MODES = frozenset({"quick", "standard", "deep"})
_VALID_SCOPE_MODES = frozenset({"auto", "diff", "full"})
# Fields copied from each finding into the result event (the full record, with
# evidence and reproduction, stays in the run directory / SARIF).
_SUMMARY_FIELDS = ("id", "title", "severity", "cvss", "cwe", "endpoint", "method")


def _apply_repo_artifact(payload: dict[str, Any]) -> None:
    """Render a repository artifact locally so the engine never touches GitHub.

    When ``audit.request`` carries ``artifact_id``, the repo is fetched from GridFS
    and the target list swaps the repo URL for the unpacked local path (Strix reads
    it as a ``local_code`` target). The repo URL stays in the payload as metadata;
    the scan record in the backend keeps it for display. Raises ``ValueError`` on a
    missing/unrenderable artifact, so the run fails with a clear message instead of
    the engine trying to clone a URL the pod cannot reach.
    """
    from artifact_fetch import ArtifactError, artifact_from_payload, render_artifact  # noqa: PLC0415

    artifact_id = artifact_from_payload(payload)
    if not artifact_id:
        return
    if not MONGO_URI:
        raise ValueError("audit.request carries artifact_id but MONGO_URI is not configured")
    try:
        local = render_artifact(
            artifact_id, mongo_uri=MONGO_URI, mongo_db=MONGO_DB, bucket=MONGO_BUCKET
        )
    except (ArtifactError, Exception) as exc:  # noqa: BLE001 - any Mongo/tar error must fail the scan cleanly
        raise ValueError(f"Could not render repository artifact {artifact_id}: {exc}") from exc
    targets = _targets(payload)
    payload["targets"] = [str(local) if t == (payload.get("target") or t) else t for t in targets]
    payload["target"] = str(local)
    print(f"[ORCHESTRATOR] Repo artifact {artifact_id} rendered at {local}", flush=True)


def parse_request(raw: bytes | None) -> dict[str, Any]:
    """Decode an ``audit.request`` message value into its JSON object.

    Raises ``ValueError`` for an empty (tombstone), non-UTF-8, non-JSON or
    non-object value, so ``main`` can report the bad request instead of dying.
    """
    if raw is None:
        raise ValueError("request message has no value")
    # UnicodeDecodeError and JSONDecodeError are both ValueErrors.
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        kind = type(payload).__name__
        # A bad request, not a caller bug: keep it a ValueError like the rest.
        raise ValueError(f"request must be a JSON object, got {kind}")  # noqa: TRY004
    return payload


def _targets(payload: dict[str, Any]) -> list[str]:
    """The request's targets as a list of non-empty strings.

    ``targets`` may be a list or a single string (not iterated character by
    character); ``target`` is the single-target form.
    """
    targets = payload.get("targets") or payload.get("target") or []
    if not isinstance(targets, list):
        targets = [targets]
    return [str(t).strip() for t in targets if str(t).strip()]


def build_strix_argv(payload: dict[str, Any]) -> list[str]:
    """Translate an ``audit.request`` JSON payload into a Strix headless argv.

    The event only carries *what* to scan; this turns it into the exact command
    line the engine expects. Recognised fields:

        target / targets  one URL/repo/host, or a list of them   (required)
        scan_mode         "quick" | "standard" | "deep"          (default quick)
        scope_mode        "auto" | "diff" | "full"               (optional)
        instruction       free-text focus for the pentest         (optional)
        max_budget        USD ceiling for the run, > 0            (optional)

    Returns the argv list (always headless via ``-n``). Raises ``ValueError`` if
    no target is given or a value would be rejected by Strix's own parser, so a
    bad request fails loudly here instead of as an ambiguous exit code 2.
    """
    targets = _targets(payload)
    if not targets:
        raise ValueError("payload has no 'target' or 'targets'")

    argv: list[str] = ["strix", "-n"]  # -n: non-interactive (exit on completion)
    for target in targets:
        argv += ["-t", target]  # -t is repeatable for multi-target scans

    mode = str(payload.get("scan_mode", "quick"))
    if mode not in _VALID_MODES:
        raise ValueError(f"invalid scan_mode: {mode!r} (want one of {sorted(_VALID_MODES)})")
    argv += ["--scan-mode", mode]

    # Optional flags: only appended when present so Strix uses its own defaults.
    if payload.get("scope_mode"):
        scope = str(payload["scope_mode"])
        if scope not in _VALID_SCOPE_MODES:
            raise ValueError(
                f"invalid scope_mode: {scope!r} (want one of {sorted(_VALID_SCOPE_MODES)})"
            )
        argv += ["--scope-mode", scope]
    if payload.get("instruction"):
        argv += ["--instruction", str(payload["instruction"])]
    if payload.get("max_budget") is not None:
        try:
            budget = float(payload["max_budget"])
        except (TypeError, ValueError):
            budget = math.nan
        if not math.isfinite(budget) or budget <= 0:
            raise ValueError(f"invalid max_budget: {payload['max_budget']!r} (want a number > 0)")
        argv += ["--max-budget", str(budget)]

    return argv


def run_strix_inprocess(argv: list[str]) -> int:
    """Run the Strix engine in *this* process with ``argv`` and return its exit code.

    Strix has no "run a scan" function to call directly — its entrypoint is a CLI
    ``main()`` that reads ``sys.argv`` and, when done, calls ``sys.exit()``. So we
    set ``sys.argv`` and invoke ``main()`` here.

    ``main()`` reports findings by calling ``sys.exit(2)`` (0 = clean). That raises
    ``SystemExit``, which is a ``BaseException`` and NOT an ``Exception`` — a bare
    ``except Exception`` would let it sail past. We catch it explicitly and turn
    the exit code back into a plain int so the caller can decide success (see
    ``_OK_EXIT_CODES``). A normal return (no ``sys.exit``) is treated as 0.
    """
    sys.argv = argv
    strix_main = importlib.import_module("strix.interface.main")
    try:
        strix_main.main()
        return 0
    except SystemExit as exc:  # 0 = clean, 2 = vulns found (or bad args), 1 = setup error
        code = exc.code
        # exc.code may be an int, None (== 0), or a message string (== failure).
        return int(code) if isinstance(code, int) else (0 if code is None else 1)


def _scan_run_dir() -> Path | None:
    """Return the run directory of the scan that just ran in this process, or None.

    Strix names the run itself, so we ask it (the report state its CLI registers
    when a scan starts) rather than guessing the newest folder under
    ``strix_runs/``, which on a shared volume can be another Pod's run. None means
    Strix never started a scan, e.g. argparse rejected the command line.
    """
    report_state = importlib.import_module("strix.report.state").get_global_report_state()
    return report_state.get_run_dir() if report_state is not None else None


def harvest_results(run_dir: Path | None, exit_code: int | None = None) -> dict[str, Any]:
    """Read the finished run's output into a compact summary for the result event.

    ``run_dir`` is *this* scan's run directory (see ``_scan_run_dir``). Pulls the
    run metadata (``run.json``) and the findings (``vulnerabilities.json``) that
    Strix wrote there, and points at the full artifacts (SARIF, Markdown report)
    rather than inlining them. ``succeeded`` is derived from ``exit_code`` when we
    have it (0/2 = ok), else from the recorded run status — and is always False
    when there is no run, since a 2 without one is a rejected command line.
    """
    if run_dir is None or not (run_dir / "run.json").is_file():
        # The scan never produced a run (bad arguments, or it died before starting).
        return {
            "run_dir": None,
            "status": "no_run",
            "succeeded": False,
            "exit_code": exit_code,
            "vulnerability_count": 0,
            "vulnerabilities": [],
        }

    run = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))

    # Findings are optional: a clean scan writes no vulnerabilities.json.
    vulns: list[dict[str, Any]] = []
    vuln_file = run_dir / "vulnerabilities.json"
    if vuln_file.is_file():
        for item in json.loads(vuln_file.read_text(encoding="utf-8")):
            vulns.append({field: item.get(field) for field in _SUMMARY_FIELDS})

    usage = run.get("llm_usage", {}) or {}
    succeeded = (
        exit_code in _OK_EXIT_CODES if exit_code is not None else run.get("status") == "completed"
    )
    sarif = run_dir / "findings.sarif"
    report = run_dir / "penetration_test_report.md"
    return {
        "run_dir": str(run_dir),
        "run_name": run.get("run_name"),
        "status": run.get("status"),
        "succeeded": succeeded,
        "exit_code": exit_code,
        "cost": usage.get("cost"),
        "requests": usage.get("requests"),
        "sarif": str(sarif) if sarif.is_file() else None,
        "report": str(report) if report.is_file() else None,
        "vulnerability_count": len(vulns),
        "vulnerabilities": vulns,
    }


def _minio_client() -> Any:
    """Build an S3 client pointed at MinIO. Deferred ``boto3`` import.

    MinIO speaks the S3 API, so the standard AWS SDK works against it with an
    explicit ``endpoint_url`` and path-style addressing (MinIO does not do the
    virtual-host ``<bucket>.<host>`` form by default).
    """
    import boto3  # noqa: PLC0415 - deferred; only needed when uploading
    from botocore.config import Config  # noqa: PLC0415

    return boto3.client(
        "s3",
        endpoint_url=MINIO_ENDPOINT,
        aws_access_key_id=MINIO_ACCESS_KEY,
        aws_secret_access_key=MINIO_SECRET_KEY,
        region_name=MINIO_REGION,
        use_ssl=str(MINIO_ENDPOINT).startswith("https"),
        verify=MINIO_VERIFY_TLS,
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )


def upload_run_to_minio(run_dir: Path | None) -> dict[str, Any]:
    """Upload every file under *run_dir* to MinIO/S3 and return an upload summary.

    Objects are keyed ``<prefix>/<run_name>/<relative path>`` so one bucket holds
    many runs without collision. This NEVER raises: it returns
    ``{"uploaded": False, "reason": ...}`` when storage is unconfigured or a
    transfer fails, so a storage problem after a successful scan degrades to
    "artifacts stayed local" instead of crashing the Pod. The per-file object
    keys go into the result event so a consumer can fetch them once this
    scale-to-zero Pod is gone.
    """
    if run_dir is None or not run_dir.is_dir():
        return {"uploaded": False, "reason": "no run directory"}
    if not MINIO_ENDPOINT:
        return {"uploaded": False, "reason": "MINIO_ENDPOINT not set"}

    try:
        s3 = _minio_client()
    except Exception as exc:  # noqa: BLE001 - e.g. boto3 not installed in the image
        print(f"[WARN] MinIO client unavailable: {exc}", flush=True)
        return {"uploaded": False, "reason": f"client unavailable: {exc}"}

    # Create the bucket on first use; tolerate "already exists / owned by you".
    try:
        s3.head_bucket(Bucket=MINIO_BUCKET)
    except Exception:  # noqa: BLE001 - not found or no head permission; try to create
        try:
            s3.create_bucket(Bucket=MINIO_BUCKET)
        except Exception as exc:  # noqa: BLE001
            # A race or a pre-existing bucket owned by us is fine; anything else is fatal.
            if "BucketAlreadyOwnedByYou" not in str(exc) and "BucketAlreadyExists" not in str(exc):
                print(f"[WARN] MinIO bucket unavailable: {exc}", flush=True)
                return {"uploaded": False, "reason": f"bucket unavailable: {exc}"}

    prefix = "/".join(p for p in (MINIO_PREFIX.strip("/"), run_dir.name) if p)
    keys: list[str] = []
    for path in sorted(run_dir.rglob("*")):
        if not path.is_file():
            continue
        key = f"{prefix}/{path.relative_to(run_dir).as_posix()}"
        try:
            s3.upload_file(str(path), MINIO_BUCKET, key)
            keys.append(key)
        except Exception as exc:  # noqa: BLE001 - one bad file must not lose the rest
            print(f"[WARN] MinIO upload failed for {key}: {exc}", flush=True)

    if not keys:
        return {"uploaded": False, "reason": "no files uploaded", "bucket": MINIO_BUCKET}

    def _key_for(name: str) -> str | None:
        return f"{prefix}/{name}" if f"{prefix}/{name}" in keys else None

    print(
        f"[ORCHESTRATOR] Uploaded {len(keys)} artifact(s) to s3://{MINIO_BUCKET}/{prefix}/.",
        flush=True,
    )
    return {
        "uploaded": True,
        "backend": "s3",
        "endpoint": MINIO_ENDPOINT,
        "bucket": MINIO_BUCKET,
        "prefix": prefix,
        "object_count": len(keys),
        "objects": keys,
        # Convenience pointers to the two headline artifacts, as object keys.
        "report_key": _key_for("penetration_test_report.md"),
        "sarif_key": _key_for("findings.sarif"),
    }


def upload_run_to_mongo(run_dir: Path | None) -> dict[str, Any]:
    """Upload every file under *run_dir* to MongoDB GridFS; same contract as MinIO.

    Each file becomes a GridFS file named ``<prefix>/<run_name>/<relative path>``
    with ``metadata.run = <prefix>/<run_name>`` (indexed), which is what the
    frontal queries to download a run. A previous upload of the same run is
    replaced. NEVER raises: failures come back as ``{"uploaded": False, ...}``.
    """
    if run_dir is None or not run_dir.is_dir():
        return {"uploaded": False, "reason": "no run directory"}
    if not MONGO_URI:
        return {"uploaded": False, "reason": "MONGO_URI not set"}

    prefix = "/".join(p for p in (MONGO_PREFIX.strip("/"), run_dir.name) if p)
    client: Any = None
    keys: list[str] = []
    try:
        try:
            import gridfs  # noqa: PLC0415 - deferred; only needed when uploading
            from pymongo import MongoClient  # noqa: PLC0415

            client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=15_000)
            db = client[MONGO_DB]
            db[f"{MONGO_BUCKET}.files"].create_index("metadata.run")
            fs = gridfs.GridFSBucket(db, bucket_name=MONGO_BUCKET)
            for old in fs.find({"metadata.run": prefix}):
                fs.delete(old._id)
        except Exception as exc:  # noqa: BLE001 - e.g. pymongo missing, auth, unreachable
            print(f"[WARN] MongoDB unavailable: {exc}", flush=True)
            return {"uploaded": False, "reason": f"mongo unavailable: {exc}"}

        for path in sorted(run_dir.rglob("*")):
            if not path.is_file():
                continue
            key = f"{prefix}/{path.relative_to(run_dir).as_posix()}"
            try:
                with path.open("rb") as fh:
                    fs.upload_from_stream(key, fh, metadata={"run": prefix})
                keys.append(key)
            except Exception as exc:  # noqa: BLE001 - one bad file must not lose the rest
                print(f"[WARN] GridFS upload failed for {key}: {exc}", flush=True)
    finally:
        if client is not None:
            client.close()

    if not keys:
        return {"uploaded": False, "reason": "no files uploaded", "backend": "mongo"}

    def _key_for(name: str) -> str | None:
        return f"{prefix}/{name}" if f"{prefix}/{name}" in keys else None

    print(
        f"[ORCHESTRATOR] Uploaded {len(keys)} artifact(s) to GridFS "
        f"{MONGO_DB}.{MONGO_BUCKET} run={prefix}.",
        flush=True,
    )
    return {
        "uploaded": True,
        "backend": "mongo",
        "database": MONGO_DB,
        "bucket": MONGO_BUCKET,
        "prefix": prefix,
        "object_count": len(keys),
        "objects": keys,
        "report_key": _key_for("penetration_test_report.md"),
        "sarif_key": _key_for("findings.sarif"),
    }


def upload_run_artifacts(run_dir: Path | None) -> dict[str, Any]:
    """GridFS when MONGO_URI is set, else MinIO/S3 (skipped if that is unset too)."""
    if MONGO_URI:
        return upload_run_to_mongo(run_dir)
    return upload_run_to_minio(run_dir)


def _result_key(payload: dict[str, Any], request_key: bytes | None) -> str | bytes | None:
    """Key for the ``audit.result`` event, so it can be matched to its request.

    The target, else the request id, else the first of ``targets``, else the
    request's own Kafka key — never an empty string, which matches nothing.
    """
    key = payload.get("target") or payload.get("id") or next(iter(_targets(payload)), None)
    return str(key) if key else request_key


def _publish_running(producer: Any, payload: dict[str, Any], request_key: bytes | None) -> None:
    """Announce on ``STATUS_TOPIC`` that this Pod accepted the request. Never raises."""
    if not STATUS_TOPIC:
        return
    from datetime import UTC, datetime  # noqa: PLC0415

    event = {
        "id": payload.get("id"),
        "status": "running",
        "started_at": datetime.now(UTC).isoformat(),
        "pod": os.environ.get("HOSTNAME"),
    }
    try:
        producer.produce(
            STATUS_TOPIC,
            key=_result_key(payload, request_key),
            value=json.dumps(event).encode("utf-8"),
        )
        producer.flush(timeout=5)
    except Exception as exc:  # noqa: BLE001 - a status hint must never block the scan
        print(f"[WARN] Could not publish status: {exc}", flush=True)


def main() -> int:
    """Consume one audit request, run the scan, publish the result, and exit.

    Returns a process exit code (0). The scan's own pass/fail is carried in the
    published ``audit.result`` event, not in this exit code: the Job's purpose is
    to *handle the message*, and it did that whether the scan found vulns or not.
    """
    # 1. Initialise the local sandbox environment (baked into the image). This
    #    MUST run before any Strix module is imported, so it is the first thing
    #    we do and the import is deferred to here rather than the module top.
    import strix_local_boot  # noqa: PLC0415

    strix_local_boot.initialize_local_environment()

    # 2. Connect to Kafka. Deferred import so the helpers above can be unit-tested
    #    without the confluent-kafka dependency installed.
    from confluent_kafka import Consumer, Producer  # noqa: PLC0415

    broker = os.environ.get("KAFKA_BOOTSTRAP_SERVERS")
    consumer = Consumer(
        {
            "bootstrap.servers": broker,
            "group.id": CONSUMER_GROUP,
            # Only used while the group has no committed offset (see OFFSET_RESET).
            "auto.offset.reset": OFFSET_RESET,
            # We commit by hand (below), right when the event is polled.
            "enable.auto.commit": False,
            "enable.auto.offset.store": True,
        }
    )
    consumer.subscribe([REQUEST_TOPIC])
    producer = Producer({"bootstrap.servers": broker})

    print(f"[ORCHESTRATOR] Listening on '{REQUEST_TOPIC}' for audit events...", flush=True)
    msg = consumer.poll(timeout=POLL_TIMEOUT_S)

    # No message (KEDA over-provisioned, or a transient Kafka error): nothing to
    # do, exit cleanly so the Job succeeds and the Pod is reaped.
    if msg is None or msg.error():
        if msg is not None and msg.error():
            print(f"[ORCHESTRATOR] Kafka error: {msg.error()}", flush=True)
        else:
            print("[ORCHESTRATOR] No event within poll window; exiting.", flush=True)
        consumer.close()
        return 0

    # 3. Commit NOW, before parsing or scanning (see the module docstring: KEDA
    #    cooldown / at-most-once). Once committed, the queue no longer counts this
    #    message, so KEDA stops spawning Jobs for it — even if it is malformed.
    consumer.commit(msg, asynchronous=False)

    # Grab what we need from the message, then close the consumer BEFORE the (long)
    # scan. A scan easily outlasts max.poll.interval.ms (5 min default), and a
    # consumer that stops polling for that long is kicked from the group with a
    # MAXPOLL warning. We already committed and only handle one message, so we have
    # no further use for it — closing now leaves the group cleanly instead.
    raw_value, request_key = msg.value(), msg.key()
    consumer.close()

    # Everything the scan learns is collected into `result` and published once at
    # the end, whatever happens in between.
    payload: dict[str, Any] = {}
    result: dict[str, Any] = {"request": None}
    try:
        payload = parse_request(raw_value)
        result["request"] = payload
        _apply_repo_artifact(payload)
        argv = build_strix_argv(payload)
        print(f"[ORCHESTRATOR] Accepted {argv[2:]}; launching Strix engine...", flush=True)
        _publish_running(producer, payload, request_key)

        # 4. Run the Strix core engine in-process, then read what it produced.
        exit_code = run_strix_inprocess(argv)
        run_dir = _scan_run_dir()
        result.update(harvest_results(run_dir, exit_code=exit_code))

        # 5. Push the artifacts (GridFS or MinIO) so they survive this scale-to-zero
        #    Pod. Best effort: a storage failure is reported in `storage`, never fatal.
        result["storage"] = upload_run_artifacts(run_dir)

        if result["succeeded"]:
            outcome = "with findings" if exit_code == 2 else "clean"
            print(
                f"[ORCHESTRATOR] Scan complete ({outcome}): "
                f"{result['vulnerability_count']} vuln(s), cost={result.get('cost')}.",
                flush=True,
            )
        else:
            result["error"] = f"strix exited with code {exit_code}" + (
                "" if result["run_dir"] else " before starting a scan"
            )
            print(f"[CRITICAL] Engine failed: {result['error']}.", flush=True)
    except Exception as exc:  # noqa: BLE001 - never crash the Pod without reporting
        result.update({"status": "error", "succeeded": False, "error": str(exc)})
        print(f"[CRITICAL] Orchestrator failure: {exc}", flush=True)

    # 6. Publish the outcome to the result topic (best effort — a publish failure
    #    must not mask the scan result already logged above).
    try:
        producer.produce(
            RESULT_TOPIC,
            key=_result_key(payload, request_key),
            value=json.dumps(result).encode("utf-8"),
        )
        producer.flush(timeout=10)
        print(f"[ORCHESTRATOR] Result published to '{RESULT_TOPIC}'.", flush=True)
    except Exception as exc:  # noqa: BLE001
        print(f"[WARN] Could not publish result: {exc}", flush=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Frontal ↔ orchestrator contract: audit.request out, audit.result/status in.

Runs against SQLite and fakes for Kafka and MinIO; the orchestrator module is
imported for real so the request the frontal builds is checked against the
argv the orchestrator would actually hand to Strix.
"""

from __future__ import annotations

import dataclasses
import importlib.util
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

import pytest


_TMP = Path(tempfile.mkdtemp(prefix="frontal-test-"))
# FRONTAL_TEST_DATABASE_URL runs the suite against a real server (prod uses Postgres);
# every test drops and recreates the tables, so point it at a throwaway database.
os.environ["FRONTAL_DATABASE_URL"] = os.environ.get(
    "FRONTAL_TEST_DATABASE_URL", f"sqlite:///{_TMP / 'frontal.db'}"
)
os.environ["FRONTAL_ARTIFACTS_DIR"] = str(_TMP / "artifacts")
os.environ["FRONTAL_ARTIFACT_STORE"] = "file"
os.environ.pop("MINIO_ENDPOINT", None)
os.environ.pop("MONGO_URI", None)
os.environ.pop("FRONTAL_MAX_BUDGET_USD", None)

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import select  # noqa: E402

from frontal.app import audit  # noqa: E402
from frontal.app.config import get_settings  # noqa: E402
from frontal.app.db import SessionLocal, engine, init_db  # noqa: E402
from frontal.app.fingerprint import finding_fingerprint  # noqa: E402
from frontal.app.models import App, Base, Finding, Scan  # noqa: E402


ORCHESTRATOR = Path(__file__).resolve().parents[1] / "k8s" / "kafka_orchestrator.py"


def _load_orchestrator() -> Any:
    spec = importlib.util.spec_from_file_location("kafka_orchestrator", ORCHESTRATOR)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


VULN = {
    "id": "vuln-0001",
    "title": "SQL Injection Auth Bypass in /rest/user/login",
    "severity": "critical",
    "description": "The login endpoint concatenates the email into SQL.",
    "poc_script_code": "curl -X POST http://juice-shop:3000/rest/user/login ...",
    "evidence": "HTTP 200 with admin JWT",
    "cvss": "9.1",
    "endpoint": "/rest/user/login",
    "method": "POST",
    "cwe": "CWE-89",
}


def _make_run(root: Path, name: str, vulns: list[dict[str, Any]], report: str = "# Report") -> Path:
    run = root / name
    run.mkdir(parents=True)
    (run / "run.json").write_text(
        json.dumps(
            {
                "run_name": name,
                "status": "completed",
                "start_time": "2026-10-09T10:00:00+00:00",
                "end_time": "2026-10-09T10:05:00+00:00",
                "llm_usage": {"cost": 0.42, "requests": 17},
            }
        )
    )
    (run / "vulnerabilities.json").write_text(json.dumps(vulns))
    (run / "penetration_test_report.md").write_text(report)
    return run


class FakeStore:
    """Stands in for S3ArtifactStore: 'bucket/prefix' is a directory on disk."""

    backend = "s3"

    def __init__(self, bucket_root: Path) -> None:
        self.bucket_root = bucket_root
        self.calls: list[tuple[int, str, str]] = []

    def download_prefix(self, scan_id: int, bucket: str, prefix: str) -> Path:
        self.calls.append((scan_id, bucket, prefix))
        dest = get_settings().artifacts_dir / "runs" / str(scan_id)
        shutil.rmtree(dest, ignore_errors=True)
        shutil.copytree(self.bucket_root / bucket / prefix, dest)
        return dest


class FakeFuture:
    def __init__(self, exc: Exception | None) -> None:
        self.exc = exc

    def get(self, timeout: float | None = None) -> None:  # noqa: ARG002
        if self.exc:
            raise self.exc


class FakeProducer:
    def __init__(self, fail: Exception | None = None) -> None:
        self.sent: list[tuple[str, str, dict[str, Any]]] = []
        self.fail = fail

    def send(self, topic: str, key: str, value: dict[str, Any]) -> FakeFuture:
        if not self.fail:
            self.sent.append((topic, key, value))
        return FakeFuture(self.fail)

    def flush(self, timeout: float | None = None) -> None:
        pass

    def close(self, timeout: float | None = None) -> None:
        pass


@pytest.fixture(autouse=True)
def fresh_db() -> None:
    Base.metadata.drop_all(engine)
    init_db()
    shutil.rmtree(get_settings().artifacts_dir, ignore_errors=True)


def _new_scan(**kw: Any) -> int:
    with SessionLocal() as session:
        app = App(name="juice", target="http://juice-shop:3000")
        session.add(app)
        session.flush()
        scan = Scan(app_id=app.id, scan_mode="quick", **kw)
        session.add(scan)
        session.commit()
        return scan.id


def _result(request: dict[str, Any], **kw: Any) -> dict[str, Any]:
    return {"request": request, "succeeded": True, "status": "completed", **kw}


# ── Request contract ────────────────────────────────────────────────────────


def test_request_is_accepted_by_the_real_orchestrator() -> None:
    orchestrator = _load_orchestrator()
    payload = audit.build_audit_request(
        request_id="frontal-1-abcd",
        target=" http://juice-shop:3000 ",
        scan_mode="quick",
        instruction="Prueba SQLi en el login",
        max_budget=2,
        scope_mode="full",
    )
    # Round-trip through bytes exactly as Kafka would deliver it.
    parsed = orchestrator.parse_request(json.dumps(payload).encode())
    argv = orchestrator.build_strix_argv(parsed)
    assert argv[:4] == ["strix", "-n", "-t", "http://juice-shop:3000"]
    assert argv[argv.index("--scan-mode") + 1] == "quick"
    assert argv[argv.index("--instruction") + 1] == "Prueba SQLi en el login"
    assert argv[argv.index("--max-budget") + 1] == "2.0"
    assert argv[argv.index("--scope-mode") + 1] == "full"
    assert orchestrator._result_key(parsed, None) == "http://juice-shop:3000"


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"target": "  "}, "target"),
        ({"scan_mode": "turbo"}, "scan_mode"),
        ({"scope_mode": "partial"}, "scope_mode"),
        ({"max_budget": 0}, "max_budget"),
        ({"max_budget": float("nan")}, "max_budget"),
    ],
)
def test_request_validation_mirrors_orchestrator(kwargs: dict[str, Any], message: str) -> None:
    base = {"request_id": "x", "target": "http://t", "scan_mode": "quick"}
    with pytest.raises(audit.AuditRequestError, match=message):
        audit.build_audit_request(**{**base, **kwargs})


def test_empty_instruction_is_omitted() -> None:
    payload = audit.build_audit_request(
        request_id="x", target="http://t", scan_mode="deep", instruction="   "
    )
    assert "instruction" not in payload
    assert "max_budget" not in payload


# ── Producer ────────────────────────────────────────────────────────────────


def test_submit_publishes_and_queues() -> None:
    scan_id = _new_scan(instruction="go", max_budget=2.0)
    fake = FakeProducer()
    scan = audit.AuditProducer(SessionLocal, get_settings(), producer=fake).submit(scan_id)

    assert scan.status == "queued"
    assert scan.request_id.startswith(f"frontal-{scan_id}-")
    topic, key, value = fake.sent[0]
    assert topic == "audit.request"
    assert key == scan.request_id
    assert value["id"] == scan.request_id
    assert value["target"] == "http://juice-shop:3000"
    assert value["max_budget"] == 2.0
    with SessionLocal() as session:
        assert session.get(Scan, scan_id).request_payload == value


def test_submit_failure_marks_scan_failed() -> None:
    scan_id = _new_scan()
    fake = FakeProducer(fail=RuntimeError("NoBrokersAvailable"))
    scan = audit.AuditProducer(SessionLocal, get_settings(), producer=fake).submit(scan_id)
    assert scan.status == "failed"
    assert "NoBrokersAvailable" in scan.error


# ── Results ─────────────────────────────────────────────────────────────────


def test_result_with_minio_artifacts_is_ingested(tmp_path: Path) -> None:
    scan_id = _new_scan(request_id="frontal-1-aaaa", status="queued")
    _make_run(tmp_path / "strix-runs", "juice-shop-3000_ab12", [VULN], "# Informe\nSQLi")
    store = FakeStore(tmp_path)
    value = _result(
        {"id": "frontal-1-aaaa", "target": "http://juice-shop:3000"},
        run_name="juice-shop-3000_ab12",
        cost=0.42,
        vulnerability_count=1,
        vulnerabilities=[{"id": "vuln-0001", "title": VULN["title"], "severity": "critical"}],
        storage={"uploaded": True, "bucket": "strix-runs", "prefix": "juice-shop-3000_ab12"},
    )
    with SessionLocal() as session:
        audit.apply_result(session, value, settings=get_settings(), store=store)
        session.commit()

    assert store.calls == [(scan_id, "strix-runs", "juice-shop-3000_ab12")]
    with SessionLocal() as session:
        scan = session.get(Scan, scan_id)
        assert scan.status == "completed"
        assert scan.artifact_path == f"runs/{scan_id}"
        assert scan.run_name == "juice-shop-3000_ab12"
        assert scan.llm_usage["cost"] == 0.42
        assert "request" not in scan.result
        assert "vulnerabilities" not in scan.result
        finding = session.scalar(select(Finding))
        # Full record from MinIO, not just the event summary.
        assert finding.data["poc_script_code"].startswith("curl")
        assert finding.cwe == "CWE-89"


def test_result_in_another_backend_falls_back_to_summary(tmp_path: Path) -> None:
    scan_id = _new_scan(request_id="frontal-1-mmmm", status="queued")
    store = FakeStore(tmp_path)  # an S3 frontal fed by a GridFS orchestrator
    value = _result(
        {"id": "frontal-1-mmmm"},
        vulnerability_count=1,
        vulnerabilities=[{"id": "vuln-0001", "title": VULN["title"], "severity": "critical"}],
        storage={"uploaded": True, "backend": "mongo", "bucket": "strix_runs", "prefix": "r"},
    )
    with SessionLocal() as session:
        audit.apply_result(session, value, settings=get_settings(), store=store)
        session.commit()

    assert store.calls == []
    with SessionLocal() as session:
        assert session.get(Scan, scan_id).status == "completed"
        assert session.scalar(select(Finding)).title == VULN["title"]


# FRONTAL_TEST_MONGO_URI runs the GridFS round trip against a real MongoDB: the real
# orchestrator uploads a run, the frontal's MongoArtifactStore downloads it.
MONGO_URI = os.environ.get("FRONTAL_TEST_MONGO_URI")
needs_mongo = pytest.mark.skipif(not MONGO_URI, reason="FRONTAL_TEST_MONGO_URI not set")


@pytest.fixture
def mongo(monkeypatch: pytest.MonkeyPatch) -> Any:
    pymongo = pytest.importorskip("pymongo")
    from frontal.app.artifacts import MongoArtifactStore  # noqa: PLC0415

    db_name = f"strix_test_{os.getpid()}"
    orchestrator = _load_orchestrator()
    monkeypatch.setattr(orchestrator, "MONGO_URI", MONGO_URI)
    monkeypatch.setattr(orchestrator, "MONGO_DB", db_name)
    monkeypatch.setattr(orchestrator, "MONGO_PREFIX", "ci")
    settings = dataclasses.replace(
        get_settings(), artifact_store="mongo", mongo_uri=MONGO_URI, mongo_db=db_name
    )
    client = pymongo.MongoClient(MONGO_URI)
    yield orchestrator, MongoArtifactStore(settings), settings, client[db_name]
    client.drop_database(db_name)
    client.close()


@needs_mongo
def test_gridfs_run_round_trips_from_orchestrator_to_frontal(mongo: Any, tmp_path: Path) -> None:
    orchestrator, store, settings, _db = mongo
    run = _make_run(tmp_path, "juice-shop-3000_gf01", [VULN], "# Informe\nSQLi")
    (run / "vulnerabilities").mkdir()
    (run / "vulnerabilities" / "vuln-0001.md").write_text("# detalle")

    storage = orchestrator.upload_run_artifacts(run)
    assert storage["uploaded"] is True
    assert storage["backend"] == "mongo"
    assert storage["prefix"] == "ci/juice-shop-3000_gf01"
    assert storage["report_key"] == "ci/juice-shop-3000_gf01/penetration_test_report.md"

    scan_id = _new_scan(request_id="frontal-1-gfgf", status="queued")
    value = _result(
        {"id": "frontal-1-gfgf"},
        run_name="juice-shop-3000_gf01",
        vulnerability_count=1,
        vulnerabilities=[{"id": "vuln-0001", "title": VULN["title"], "severity": "critical"}],
        storage=json.loads(json.dumps(storage)),  # as it travels over Kafka
    )
    with SessionLocal() as session:
        audit.apply_result(session, value, settings=settings, store=store)
        session.commit()

    local = settings.artifacts_dir / "runs" / str(scan_id)
    assert (local / "penetration_test_report.md").read_text() == "# Informe\nSQLi"
    assert (local / "vulnerabilities" / "vuln-0001.md").read_text() == "# detalle"
    with SessionLocal() as session:
        assert session.get(Scan, scan_id).artifact_path == f"runs/{scan_id}"
        # Full record from GridFS, not just the event summary.
        assert session.scalar(select(Finding)).data["poc_script_code"].startswith("curl")


@needs_mongo
def test_gridfs_reupload_replaces_the_run(mongo: Any, tmp_path: Path) -> None:
    orchestrator, store, _settings, db = mongo
    run = _make_run(tmp_path, "rerun", [VULN], "v1")
    orchestrator.upload_run_to_mongo(run)
    (run / "penetration_test_report.md").write_text("v2")
    storage = orchestrator.upload_run_to_mongo(run)

    files = db["strix_runs.files"]
    assert files.count_documents({"metadata.run": storage["prefix"]}) == storage["object_count"]
    local = store.download_prefix(7, storage["bucket"], storage["prefix"])
    assert (local / "penetration_test_report.md").read_text() == "v2"


@needs_mongo
def test_gridfs_names_cannot_escape_the_run_dir(mongo: Any, tmp_path: Path) -> None:
    import gridfs  # noqa: PLC0415

    _orchestrator, store, settings, db = mongo
    fs = gridfs.GridFSBucket(db, bucket_name="strix_runs")
    fs.upload_from_stream("evil/../../../pwned", b"x", metadata={"run": "evil"})
    fs.upload_from_stream("evil/ok.md", b"ok", metadata={"run": "evil"})

    local = store.download_prefix(9, None, "evil")
    assert (local / "ok.md").read_bytes() == b"ok"
    assert not (settings.artifacts_dir / "pwned").exists()
    assert not (tmp_path.parent / "pwned").exists()


@needs_mongo
def test_gridfs_publish_and_localize(mongo: Any, tmp_path: Path) -> None:
    _orchestrator, store, _settings, _db = mongo
    run = _make_run(tmp_path, "legacy", [VULN], "legacy report")
    uri = store.publish_run(11, run)
    assert uri.endswith("/strix_runs/runs/11")
    local = store.localize(11, uri)
    assert (local / "penetration_test_report.md").read_text() == "legacy report"


def test_result_without_storage_falls_back_to_summary() -> None:
    _new_scan(request_id="frontal-1-bbbb", status="running")
    value = _result(
        {"id": "frontal-1-bbbb"},
        storage={"uploaded": False, "reason": "MINIO_ENDPOINT not set"},
        vulnerabilities=[
            {"id": "vuln-0001", "title": "XSS", "severity": "high", "endpoint": "/search"}
        ],
    )
    with SessionLocal() as session:
        scan = audit.apply_result(session, value, settings=get_settings(), store=object())
        session.commit()
        assert scan.status == "completed"
        assert scan.artifact_path is None
        assert session.scalar(select(Finding)).title == "XSS"


def test_failed_result_keeps_error() -> None:
    _new_scan(request_id="frontal-1-cccc", status="running")
    value = {
        "request": {"id": "frontal-1-cccc"},
        "succeeded": False,
        "status": "no_run",
        "error": "strix exited with code 1 before starting a scan",
    }
    with SessionLocal() as session:
        scan = audit.apply_result(session, value, settings=get_settings(), store=object())
        session.commit()
        assert scan.status == "failed"
        assert "code 1" in scan.error


def test_unknown_frontal_request_is_ignored() -> None:
    value = _result({"id": "frontal-999-dead", "target": "http://x"})
    with SessionLocal() as session:
        assert audit.apply_result(session, value, settings=get_settings(), store=object()) is None
        assert session.scalar(select(Scan)) is None


def test_external_results_are_imported_and_deduped_by_run() -> None:
    request = {"id": "audit-dev-002", "target": "http://juice-shop:3000", "max_budget": 2}
    with SessionLocal() as session:
        first = audit.apply_result(
            session, _result(request, run_name="run-a"), settings=get_settings(), store=object()
        )
        # Same message redelivered: same scan.
        again = audit.apply_result(
            session, _result(request, run_name="run-a"), settings=get_settings(), store=object()
        )
        # Same hand-typed id, new run: a new scan on the same app.
        second = audit.apply_result(
            session, _result(request, run_name="run-b"), settings=get_settings(), store=object()
        )
        session.commit()
        assert first.id == again.id != second.id
        assert first.kind == second.kind == "external"
        assert first.app_id == second.app_id
        assert first.max_budget == 2.0


def test_retest_verdicts_are_reconciled(tmp_path: Path) -> None:
    with SessionLocal() as session:
        app = App(name="juice", target="http://juice-shop:3000")
        session.add(app)
        session.flush()
        sqli = Finding(app_id=app.id, fingerprint="a", title="SQLi", severity="critical")
        xss = Finding(app_id=app.id, fingerprint="b", title="XSS", severity="high")
        session.add_all([sqli, xss])
        session.flush()
        scan = Scan(
            app_id=app.id,
            kind="retest",
            scan_mode="quick",
            request_id="frontal-9-ffff",
            retest_finding_ids=[sqli.id, xss.id],
        )
        session.add(scan)
        session.commit()
        ids = (scan.id, sqli.id, xss.id)

    report = (
        "# Retest\n```json\n"
        + json.dumps(
            [
                {"finding_id": f"F-{ids[1]}", "verdict": "fixed", "evidence": "403 now"},
                {"finding_id": f"F-{ids[2]}", "verdict": "inconclusive", "evidence": "down"},
            ]
        )
        + "\n```\n"
    )
    _make_run(tmp_path / "b", "retest-run", [], report)
    value = _result(
        {"id": "frontal-9-ffff"},
        run_name="retest-run",
        storage={"uploaded": True, "bucket": "b", "prefix": "retest-run"},
    )
    with SessionLocal() as session:
        audit.apply_result(session, value, settings=get_settings(), store=FakeStore(tmp_path))
        session.commit()
        assert session.get(Finding, ids[1]).status == "fixed"
        assert session.get(Finding, ids[1]).last_verdict == "fixed"
        assert session.get(Finding, ids[2]).status == "open"
        assert session.get(Finding, ids[2]).last_verdict == "inconclusive"


def _verify_setup(status: str = "doubtful") -> tuple[int, int]:
    with SessionLocal() as session:
        app = App(name="juice", target="http://juice-shop:3000")
        session.add(app)
        session.flush()
        finding = Finding(
            app_id=app.id,
            fingerprint=finding_fingerprint(VULN),
            title="SQLi",
            severity="critical",
            status=status,
            triage="doubtful",
        )
        session.add(finding)
        session.flush()
        scan = Scan(
            app_id=app.id,
            kind="verify",
            scan_mode="quick",
            request_id="frontal-7-eeee",
            retest_finding_ids=[finding.id],
        )
        session.add(scan)
        session.commit()
        return scan.id, finding.id


def _apply_verify(tmp_path: Path, vulns: list[dict[str, Any]], report: str) -> None:
    _make_run(tmp_path / "b", "verify-run", vulns, report)
    value = _result(
        {"id": "frontal-7-eeee"},
        run_name="verify-run",
        storage={"uploaded": True, "bucket": "b", "prefix": "verify-run"},
    )
    with SessionLocal() as session:
        audit.apply_result(session, value, settings=get_settings(), store=FakeStore(tmp_path))
        session.commit()


def test_verify_refuted_only_proposes_a_false_positive(tmp_path: Path) -> None:
    _, finding_id = _verify_setup()
    report = (
        "```json\n"
        + json.dumps(
            [{"finding_id": f"F-{finding_id}", "verdict": "refuted", "evidence": "param is bound"}]
        )
        + "\n```"
    )
    _apply_verify(tmp_path, [], report)
    with SessionLocal() as session:
        finding = session.get(Finding, finding_id)
        # A human still has to mark it, with a justification.
        assert finding.status == "doubtful"
        assert finding.last_verdict == "refuted"
        assert finding.observations[-1].evidence == "param is bound"


def test_verify_reobservation_confirms_a_true_positive(tmp_path: Path) -> None:
    scan_id, finding_id = _verify_setup()
    # No verdict block: re-reporting the vuln with fresh evidence is enough.
    _apply_verify(tmp_path, [VULN], "# Report")
    with SessionLocal() as session:
        finding = session.get(Finding, finding_id)
        assert finding.status == "open"
        assert finding.triage == "true_positive"
        assert finding.last_verdict == "confirmed"
        entry = finding.triage_log[-1]
        assert (entry.decision, entry.author, entry.scan_id) == ("true_positive", "strix", scan_id)


def test_verify_folds_a_rereport_under_another_fingerprint(tmp_path: Path) -> None:
    # Seen in a real run: the original finding had no endpoint, the verify run
    # re-reported it with one, so the fingerprints differ and no verdict block
    # survived into the report.
    scan_id, finding_id = _verify_setup()
    with SessionLocal() as session:
        finding = session.get(Finding, finding_id)
        finding.fingerprint, finding.cwe, finding.endpoint = "title-based", "CWE-89", None
        session.commit()
    _apply_verify(tmp_path, [VULN], "# Report")
    with SessionLocal() as session:
        findings = session.scalars(select(Finding)).all()
        assert [f.id for f in findings] == [finding_id]
        finding = findings[0]
        assert (finding.status, finding.last_verdict) == ("open", "confirmed")
        assert finding.endpoint == "/rest/user/login"
        assert finding.fingerprint == finding_fingerprint(VULN)
        assert finding.last_seen_scan_id == scan_id
        assert finding.observations[-1].evidence == "HTTP 200 with admin JWT"


def test_verify_does_not_count_an_unrelated_report(tmp_path: Path) -> None:
    _, finding_id = _verify_setup()
    with SessionLocal() as session:
        finding = session.get(Finding, finding_id)
        finding.fingerprint, finding.cwe = "other", "CWE-79"
        session.commit()
    _apply_verify(tmp_path, [VULN], "# Report")
    with SessionLocal() as session:
        finding = session.get(Finding, finding_id)
        assert (finding.status, finding.last_verdict) == ("doubtful", "inconclusive")
        assert len(session.scalars(select(Finding)).all()) == 2


def test_verify_does_not_override_a_decision_taken_meanwhile(tmp_path: Path) -> None:
    _, finding_id = _verify_setup(status="false_positive")
    _apply_verify(tmp_path, [VULN], "# Report")
    with SessionLocal() as session:
        finding = session.get(Finding, finding_id)
        assert finding.status == "false_positive"
        assert finding.last_verdict == "confirmed"
        assert finding.triage_log == []


def test_status_event_marks_running_once() -> None:
    scan_id = _new_scan(request_id="frontal-1-dddd", status="queued")
    event = {"id": "frontal-1-dddd", "status": "running", "started_at": "2026-10-09T10:00:00+00:00"}
    with SessionLocal() as session:
        assert audit.apply_status(session, event).status == "running"
        session.commit()
        session.get(Scan, scan_id).status = "completed"
        session.commit()
        # A late status event must not reopen a finished scan.
        assert audit.apply_status(session, event) is None


def test_consumer_skips_garbage_messages() -> None:
    consumer = audit.AuditResultConsumer(SessionLocal, get_settings(), store=object())
    consumer.handle_message("audit.result", b"not json")
    consumer.handle_message("audit.result", b"[1, 2]")
    consumer.handle_message("audit.result", None)
    with SessionLocal() as session:
        assert session.scalar(select(Scan)) is None


# ── HTTP API ────────────────────────────────────────────────────────────────


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    from frontal.app import main  # noqa: PLC0415 - after the env is set up

    fake = FakeProducer()
    monkeypatch.setattr(main.AuditResultConsumer, "start", lambda _self: None)
    with TestClient(main.app) as test_client:
        main.app.state.producer = audit.AuditProducer(SessionLocal, get_settings(), producer=fake)
        test_client.fake_producer = fake  # type: ignore[attr-defined]
        yield test_client


def test_api_launch_flow(client: TestClient) -> None:
    app = client.post("/manage/apps", json={"name": "juice", "target": "http://juice-shop:3000"})
    assert app.status_code == 201
    app_id = app.json()["id"]

    preview = client.post(
        "/manage/scans/preview", json={"app_id": app_id, "scan_mode": "quick", "max_budget": 2}
    )
    assert preview.json()["payload"]["target"] == "http://juice-shop:3000"
    assert preview.json()["topic"] == "audit.request"

    bad = client.post(f"/manage/apps/{app_id}/scans", json={"scan_mode": "turbo"})
    assert bad.status_code == 422

    launched = client.post(
        f"/manage/apps/{app_id}/scans",
        json={"scan_mode": "quick", "instruction": "SQLi only", "max_budget": 2},
    )
    assert launched.status_code == 202
    scan = launched.json()
    assert scan["status"] == "queued"
    assert client.fake_producer.sent[-1][2]["instruction"] == "SQLi only"

    detail = client.get(f"/manage/scans/{scan['id']}").json()
    assert detail["request_payload"]["id"] == scan["request_id"]

    rerun = client.post(f"/manage/scans/{scan['id']}/rerun").json()
    assert rerun["parent_scan_id"] == scan["id"]
    assert rerun["request_id"] != scan["request_id"]

    failed = client.post(f"/manage/scans/{scan['id']}/mark-failed")
    assert failed.json()["status"] == "failed"
    assert client.post(f"/manage/scans/{scan['id']}/mark-failed").status_code == 409

    assert client.get("/manage/stats").json()["scans_by_status"]["queued"] == 1
    assert client.get("/manage/config").json()["topics"]["request"] == "audit.request"
    assert "Nuevo escaneo" in client.get("/").text


def test_api_retest_needs_open_findings(client: TestClient) -> None:
    app_id = client.post("/manage/apps", json={"name": "a", "target": "http://a"}).json()["id"]
    assert client.post(f"/manage/apps/{app_id}/retest", json={}).status_code == 400

    with SessionLocal() as session:
        session.add(Finding(app_id=app_id, fingerprint="f", title="SQLi", severity="critical"))
        session.commit()
    response = client.post(f"/manage/apps/{app_id}/retest", json={"scan_mode": "quick"})
    assert response.status_code == 202
    sent = client.fake_producer.sent[-1][2]
    assert sent["kind"] == "retest"
    assert "RETEST" in sent["instruction"]


def test_console_route_follows_serve_console(monkeypatch: pytest.MonkeyPatch) -> None:
    from frontal.app import main  # noqa: PLC0415

    def routes() -> set[str]:
        return {getattr(r, "path", "") for r in importlib.reload(main).app.routes}

    try:
        assert "/" in routes()
        monkeypatch.setenv("FRONTAL_SERVE_CONSOLE", "false")  # nginx frontend serves it
        get_settings.cache_clear()
        served = routes()
        assert "/" not in served
        assert "/manage/apps" in served
        assert "/health" in served
    finally:
        monkeypatch.delenv("FRONTAL_SERVE_CONSOLE", raising=False)
        get_settings.cache_clear()
        importlib.reload(main)


def _api_finding(client: TestClient, status: str = "open") -> int:
    app_id = client.post("/manage/apps", json={"name": "a", "target": "http://a"}).json()["id"]
    with SessionLocal() as session:
        finding = Finding(
            app_id=app_id, fingerprint="f", title="SQLi", severity="critical", status=status
        )
        session.add(finding)
        session.commit()
        return finding.id


def test_api_false_positive_requires_a_justification(client: TestClient) -> None:
    finding_id = _api_finding(client)
    url = f"/manage/findings/{finding_id}/triage"

    for body in ({}, {"justification": "   "}, {"justification": "no es"}):
        response = client.post(url, json={"decision": "false_positive", **body})
        assert response.status_code == 422
    # The plain status PATCH is not a way around it.
    patch = client.patch(f"/manage/findings/{finding_id}", json={"status": "false_positive"})
    assert patch.status_code == 422
    assert client.get(f"/manage/findings/{finding_id}").json()["status"] == "open"

    marked = client.post(
        url,
        json={
            "decision": "false_positive",
            "justification": "  El parámetro va con bind; el 500 es de validación  ",
            "author": "ana",
        },
    )
    assert marked.status_code == 200
    assert marked.json()["scan"] is None
    detail = client.get(f"/manage/findings/{finding_id}").json()
    assert (detail["status"], detail["triage"]) == ("false_positive", "false_positive")
    assert detail["triage_log"][-1]["justification"].startswith("El parámetro")
    assert detail["triage_log"][-1]["author"] == "ana"

    # Leaving false_positive is a decision too: only through triage.
    assert (
        client.patch(f"/manage/findings/{finding_id}", json={"status": "open"}).status_code == 422
    )
    reopened = client.post(url, json={"decision": "true_positive"}).json()["finding"]
    assert (reopened["status"], reopened["triage"]) == ("open", "true_positive")
    assert len(client.get(f"/manage/findings/{finding_id}").json()["triage_log"]) == 2


def test_api_doubtful_launches_a_verify_scan_of_that_finding(client: TestClient) -> None:
    finding_id = _api_finding(client)
    url = f"/manage/findings/{finding_id}/triage"

    response = client.post(
        url, json={"decision": "doubtful", "justification": "El 500 puede ser del WAF"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["finding"]["status"] == "doubtful"
    assert body["scan"]["kind"] == "verify"
    assert body["scan"]["retest_finding_ids"] == [finding_id]

    sent = client.fake_producer.sent[-1][2]
    assert sent["kind"] == "verify"
    assert sent["scan_mode"] == "quick"
    assert f"VERIFY — a — F-{finding_id}" in sent["instruction"]
    assert "ONLY this finding" in sent["instruction"]
    assert "El 500 puede ser del WAF" in sent["instruction"]

    detail = client.get(f"/manage/findings/{finding_id}").json()
    assert detail["verifying_scan_id"] == body["scan"]["id"]
    assert detail["triage_log"][-1]["scan_id"] == body["scan"]["id"]

    # One verification at a time per finding.
    again = client.post(url, json={"decision": "doubtful"})
    assert again.status_code == 409
    assert len(client.fake_producer.sent) == 1

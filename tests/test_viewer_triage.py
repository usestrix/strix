"""The viewer's authenticated triage boundary and shared on-disk projection."""

from __future__ import annotations

import http.client
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import pytest

from strix.interface.viewer.server import serve
from strix.interface.viewer.transcript import read_vulnerabilities
from strix.report.triage import read_triaged_vulnerabilities, triage_finding


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@dataclass
class ViewerClient:
    run_dir: Path
    url: str
    cookie: str

    def request(
        self,
        path: str,
        body: Any = None,
        *,
        authorized: bool = True,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, Any]:
        request_headers = {"Content-Type": "application/json", "Origin": self.url}
        if authorized:
            request_headers["Cookie"] = self.cookie
        request_headers.update(headers or {})
        parts = urlsplit(self.url)
        connection = http.client.HTTPConnection(str(parts.hostname), parts.port, timeout=5)
        raw = body if isinstance(body, bytes) else json.dumps(body)
        connection.request(
            "GET" if body is None else "POST",
            path,
            body=None if body is None else raw,
            headers=request_headers,
        )
        response = connection.getresponse()
        status = response.status
        data = json.loads(response.read())
        connection.close()
        return status, data

    def finding(self) -> dict[str, Any]:
        status, findings = self.request("/api/vulnerabilities")
        assert status == 200
        return dict(findings[0])

    def change(self, finding: dict[str, Any], **changes: Any) -> tuple[int, Any]:
        return self.request(
            f"/api/vulnerabilities/{finding['id']}/triage",
            {
                "status": "closed",
                "expected_revision": finding["triage_revision"],
                "reviewed_digest": finding["finding_digest"],
                **changes,
            },
        )


@pytest.fixture
def viewer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[ViewerClient]:
    run_dir = tmp_path / "runs" / "example"
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps({"run_name": "example", "status": "completed", "end_time": "2026-09-16"}),
        encoding="utf-8",
    )
    (run_dir / "vulnerabilities.json").write_text(
        json.dumps(
            [
                {
                    "id": "vuln-0001",
                    "title": "Example finding",
                    "severity": "high",
                    "evidence": "original evidence",
                }
            ]
        ),
        encoding="utf-8",
    )
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "index.html").write_text("<!doctype html><title>Test</title>", encoding="utf-8")
    monkeypatch.setattr("strix.interface.viewer.server.bundle_dir", lambda: assets)
    monkeypatch.setattr("strix.interface.viewer.auth.is_verified", lambda: False)
    monkeypatch.setattr("strix.telemetry.triage.record_triage", lambda *_args, **_kwargs: None)
    server, url, token = serve(run_dir, open_browser=False)
    parts = urlsplit(url)
    connection = http.client.HTTPConnection(str(parts.hostname), parts.port, timeout=5)
    connection.request("GET", f"/?token={token}")
    response = connection.getresponse()
    cookie = str(response.getheader("Set-Cookie")).split(";", 1)[0]
    response.read()
    connection.close()
    try:
        yield ViewerClient(run_dir, url, cookie)
    finally:
        server.shutdown()
        server.server_close()


def test_close_and_reopen_preserve_raw_finding_and_refresh_projection(viewer: ViewerClient) -> None:
    original = read_vulnerabilities(viewer.run_dir)
    finding = viewer.finding()
    _, before = viewer.request("/api/triage/revision")
    status, result = viewer.change(
        finding, reason_code="incorrect_assumption", note="<script>local note</script>"
    )
    assert status == 200
    assert result["changed"] is True
    saved = viewer.finding()
    assert saved["status"] == "closed"
    assert saved["resolution_reason"] == "false_positive"
    assert saved["status_note"] == "<script>local note</script>"
    assert saved["evidence"] == "original evidence"
    assert read_triaged_vulnerabilities(viewer.run_dir)[0] == saved
    assert read_vulnerabilities(viewer.run_dir) == original
    _, after = viewer.request("/api/triage/revision")
    assert before != after

    status, result = viewer.change(saved, status="open")
    assert status == 200
    assert result["finding"]["status"] == "open"
    assert result["finding"]["resolution_reason"] is None
    assert result["finding"]["status_note"] is None
    assert read_vulnerabilities(viewer.run_dir) == original


def test_external_change_and_new_evidence_are_visible_to_finished_viewer(
    viewer: ViewerClient,
) -> None:
    finding = viewer.finding()
    _, before = viewer.request("/api/triage/revision")
    triage_finding(
        viewer.run_dir,
        finding["id"],
        status="closed",
        expected_revision=0,
        reviewed_digest=finding["finding_digest"],
        surface="tui",
    )
    assert viewer.finding()["status"] == "closed"
    _, after = viewer.request("/api/triage/revision")
    assert before != after
    raw = read_vulnerabilities(viewer.run_dir)
    raw[0]["evidence"] = "materially different evidence"
    (viewer.run_dir / "vulnerabilities.json").write_text(json.dumps(raw), encoding="utf-8")
    changed = viewer.finding()
    assert changed["review_stale"] is True
    assert changed["status"] == "open"
    assert viewer.change(finding)[0] == 409
    _, evidence_revision = viewer.request("/api/triage/revision")
    assert evidence_revision != after
    assert viewer.change(changed)[0] == 200


@pytest.mark.parametrize(
    ("headers", "authorized", "status"),
    [
        ({}, False, 403),
        ({"Origin": "http://untrusted.example"}, True, 403),
        ({"Origin": "null"}, True, 403),
        ({"Origin": ""}, True, 403),
        ({"Sec-Fetch-Site": "cross-site"}, True, 403),
        ({"Content-Type": "text/plain"}, True, 415),
    ],
)
def test_mutations_require_authorized_same_origin_json(
    viewer: ViewerClient, headers: dict[str, str], authorized: bool, status: int
) -> None:
    actual, _ = viewer.request(
        "/api/vulnerabilities/vuln-0001/triage",
        {"status": "closed"},
        headers=headers,
        authorized=authorized,
    )
    assert actual == status
    assert not (viewer.run_dir / "triage.json").exists()


@pytest.mark.parametrize(
    "body",
    [
        b"{",
        [],
        {"status": "closed"},
        {"expected_revision": True},
        {"reason_code": []},
        {"note": "x" * 2001},
        {"surface": "tui"},
        {"status": "fixed"},
    ],
)
def test_bad_payloads_cannot_create_a_decision(viewer: ViewerClient, body: Any) -> None:
    finding = viewer.finding()
    if isinstance(body, dict):
        body = {
            "status": "closed",
            "expected_revision": 0,
            "reviewed_digest": finding["finding_digest"],
            **body,
        }
        if body == {
            "status": "closed",
            "expected_revision": 0,
            "reviewed_digest": finding["finding_digest"],
        }:
            body.pop("reviewed_digest")
    status, _ = viewer.request("/api/vulnerabilities/vuln-0001/triage", body)
    assert status == 400
    assert not (viewer.run_dir / "triage.json").exists()


def test_oversized_payload_rejected_before_parsing(viewer: ViewerClient) -> None:
    status, _ = viewer.request("/api/vulnerabilities/vuln-0001/triage", b"x" * 32769)
    assert status == 413


def test_mutation_run_selection_and_history_gate(
    viewer: ViewerClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    other = viewer.run_dir.parent / "other"
    other.mkdir()
    for filename in ("run.json", "vulnerabilities.json"):
        (other / filename).write_bytes((viewer.run_dir / filename).read_bytes())
    finding = viewer.finding()
    body = {
        "status": "closed",
        "expected_revision": 0,
        "reviewed_digest": finding["finding_digest"],
    }
    route = "/api/vulnerabilities/vuln-0001/triage"
    assert viewer.request(route + "?run=other", body)[0] == 401
    assert viewer.request(route + "?run=../other", body)[0] == 404
    assert viewer.request(route + "?run=other&run=example", body)[0] == 404
    (viewer.run_dir.parent / "alias").symlink_to(other, target_is_directory=True)
    assert viewer.request(route + "?run=alias", body)[0] == 403
    monkeypatch.setattr("strix.interface.viewer.auth.is_verified", lambda: True)
    assert viewer.request(route + "?run=other", body)[0] == 200
    assert viewer.finding()["status"] == "open"


def test_corrupt_sidecar_is_a_visible_error_not_empty_findings(viewer: ViewerClient) -> None:
    (viewer.run_dir / "triage.json").write_text("{", encoding="utf-8")
    status, error = viewer.request("/api/vulnerabilities")
    assert status == 409
    assert error["error"] == "invalid_triage"
    assert read_vulnerabilities(viewer.run_dir)[0]["evidence"] == "original evidence"


@pytest.mark.parametrize("damage", ["malformed", "null", "schema", "identity", "findings"])
def test_invalid_historical_run_does_not_break_history(
    viewer: ViewerClient, monkeypatch: pytest.MonkeyPatch, damage: str
) -> None:
    other = viewer.run_dir.parent / "damaged"
    other.mkdir()
    (other / "run.json").write_text(
        json.dumps({"run_name": "damaged", "status": "completed", "end_time": "2026-09-15"}),
        encoding="utf-8",
    )
    (other / "vulnerabilities.json").write_bytes(
        (viewer.run_dir / "vulnerabilities.json").read_bytes()
    )
    finding = read_triaged_vulnerabilities(other)[0]
    triage_finding(
        other,
        finding["id"],
        status="closed",
        expected_revision=0,
        reviewed_digest=finding["finding_digest"],
        surface="tui",
    )
    sidecar = other / "triage.json"
    document = json.loads(sidecar.read_text(encoding="utf-8"))
    if damage == "malformed":
        sidecar.write_text("{", encoding="utf-8")
    elif damage == "null":
        sidecar.write_text("null", encoding="utf-8")
    elif damage == "findings":
        (other / "vulnerabilities.json").write_text("[null]", encoding="utf-8")
    else:
        if damage == "schema":
            document["schema_version"] = 2
        else:
            document["run_identity"]["run_id"] = "another-run"
        sidecar.write_text(json.dumps(document), encoding="utf-8")
    saved = sidecar.read_bytes()
    evidence = (other / "vulnerabilities.json").read_bytes()

    # The locked history must not try to read the damaged run's findings.
    assert viewer.request("/api/runs") == (200, {"locked": True, "count": 2, "runs": []})
    monkeypatch.setattr("strix.interface.viewer.auth.is_verified", lambda: True)
    status, payload = viewer.request("/api/runs")
    assert status == 200
    assert payload["count"] == 2
    runs = {run["name"]: run for run in payload["runs"]}
    assert runs["example"]["open_count"] == 1
    assert runs["example"]["severity_counts"]["high"] == 1
    assert runs["damaged"]["status"] == "completed"
    assert runs["damaged"]["severity_counts"] is None
    assert all(
        key not in runs["damaged"] for key in ("open_count", "closed_count", "detected_count")
    )
    assert viewer.finding()["status"] == "open"
    assert viewer.request("/api/vulnerabilities?run=damaged")[0] == 409
    body = {
        "status": "open",
        "expected_revision": 1,
        "reviewed_digest": finding["finding_digest"],
    }
    assert viewer.request("/api/vulnerabilities/vuln-0001/triage?run=damaged", body)[0] == 409
    assert sidecar.read_bytes() == saved
    assert (other / "vulnerabilities.json").read_bytes() == evidence


def test_read_only_run_has_no_write_capability(viewer: ViewerClient) -> None:
    viewer.run_dir.chmod(0o500)
    try:
        finding = viewer.finding()
        assert finding["can_triage"] is False
        assert viewer.change(finding)[0] == 403
    finally:
        viewer.run_dir.chmod(0o700)

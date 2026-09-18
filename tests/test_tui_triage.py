from __future__ import annotations

import argparse
import asyncio
import json
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

import pytest

from strix.config import loader
from strix.interface.tui.backend.controller import TuiController
from strix.interface.tui.backend.protocol import PROTOCOL_VERSION
from strix.interface.tui.backend.server import TuiBackendServer
from strix.report.triage import TriageError, read_triaged_vulnerabilities, triage_finding


if TYPE_CHECKING:
    from pathlib import Path

    from strix.report.state import ReportState


@pytest.fixture
def triage_controller(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TuiController:
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(loader, "_override", tmp_path / "config.json")
    reports = [{"id": "vuln-0001", "title": "Example", "severity": "high", "evidence": "proof"}]
    (tmp_path / "vulnerabilities.json").write_text(json.dumps(reports))
    (tmp_path / "run.json").write_text(json.dumps({"run_id": "test-run"}))
    args = argparse.Namespace(
        needs_setup=False,
        targets_info=[],
        instruction=None,
        scan_mode="standard",
        max_budget_usd=None,
        max_turns=50,
        scope_mode="auto",
        diff_base=None,
    )
    state = SimpleNamespace(vulnerability_reports=reports, get_run_dir=lambda: tmp_path)
    return TuiController(args, report_state=cast("ReportState", state))


def _request(finding: dict[str, Any], status: str = "closed") -> dict[str, Any]:
    return {
        "finding_id": finding["id"],
        "status": status,
        "expected_revision": finding["triage_revision"],
        "reviewed_digest": finding["finding_digest"],
        "reason_code": "incorrect_assumption",
        "note": "Local explanation",
    }


@pytest.mark.asyncio
async def test_native_close_reopen_updates_shared_overlay_without_mutating_evidence(
    triage_controller: TuiController,
) -> None:
    controller = triage_controller
    finding = controller.collection("vulnerabilities")[0]
    state = controller.report_state
    assert state is not None
    raw = json.loads((state.get_run_dir() / "vulnerabilities.json").read_text())
    result = await controller.handle("vulnerability.triage", _request(finding))
    assert result["changed"] is True
    assert result["finding"]["status"] == "closed"
    assert "evidence" not in result["finding"]
    assert (
        read_triaged_vulnerabilities(state.get_run_dir())[0]["status_note"] == "Local explanation"
    )
    assert controller.collection("vulnerabilities")[0]["status"] == "closed"
    assert state.vulnerability_reports == raw
    assert json.loads((state.get_run_dir() / "vulnerabilities.json").read_text()) == raw
    reopened = await controller.handle("vulnerability.triage", _request(result["finding"], "open"))
    assert reopened["finding"]["status"] == "open"
    assert reopened["finding"]["resolution_reason"] is None
    assert len(read_triaged_vulnerabilities(state.get_run_dir())[0]["triage_history"]) == 2


@pytest.mark.asyncio
async def test_native_stale_review_is_a_structured_conflict(
    triage_controller: TuiController,
) -> None:
    controller = triage_controller
    finding = controller.collection("vulnerabilities")[0]
    assert controller.report_state is not None
    path = controller.report_state.get_run_dir() / "vulnerabilities.json"
    reports = json.loads(path.read_text())
    reports[0]["evidence"] = "New evidence"
    path.write_text(json.dumps(reports))
    server = TuiBackendServer(controller)
    response, _ = await server._handle_message(
        json.dumps(
            {
                "version": PROTOCOL_VERSION,
                "type": "vulnerability.triage",
                "request_id": "review",
                "payload": _request(finding),
            }
        ).encode()
    )
    assert response is not None
    assert response["payload"]["ok"] is False
    assert response["payload"]["error"]["code"] == "conflict"
    assert not (path.parent / "triage.json").exists()


@pytest.mark.asyncio
async def test_native_retries_do_not_duplicate_reviews(triage_controller: TuiController) -> None:
    controller = triage_controller
    request = _request(controller.collection("vulnerabilities")[0])
    await controller.handle("vulnerability.triage", request)
    repeated = await controller.handle("vulnerability.triage", request)
    assert repeated["changed"] is False
    assert repeated["finding"]["triage_revision"] == 1


def test_corrupt_sidecar_leaves_evidence_visible_without_write_capability(
    triage_controller: TuiController,
) -> None:
    assert triage_controller.report_state is not None
    (triage_controller.report_state.get_run_dir() / "triage.json").write_text("broken")
    finding = triage_controller.collection("vulnerabilities")[0]
    assert finding["evidence"] == "proof"
    assert finding["can_triage"] is False
    assert finding["triage_error"]


@pytest.mark.asyncio
async def test_external_decision_notifies_idle_terminal(triage_controller: TuiController) -> None:
    controller = triage_controller
    server = TuiBackendServer(controller)
    changed = asyncio.Event()
    controller.set_change_callback(changed.set)
    server.activated = True
    # Observe the real watcher callback without opening another socket.
    server.notify_changed = changed.set  # type: ignore[method-assign]
    task = asyncio.create_task(server._watch_triage())
    try:
        await asyncio.wait_for(changed.wait(), 2)
        changed.clear()
        finding = controller.collection("vulnerabilities")[0]
        assert controller.report_state is not None
        triage_finding(
            controller.report_state.get_run_dir(),
            finding["id"],
            status="closed",
            expected_revision=0,
            reviewed_digest=finding["finding_digest"],
            surface="viewer",
        )
        await asyncio.wait_for(changed.wait(), 2)
        assert controller.collection("vulnerabilities")[0]["status"] == "closed"
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


@pytest.mark.asyncio
async def test_native_missing_finding_cannot_be_created(triage_controller: TuiController) -> None:
    request = _request(triage_controller.collection("vulnerabilities")[0])
    request["finding_id"] = "vulnerability-0"
    with pytest.raises(TriageError) as failure:
        await triage_controller.handle("vulnerability.triage", request)
    assert failure.value.code == "unknown_finding"

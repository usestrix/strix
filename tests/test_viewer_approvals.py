from __future__ import annotations

import asyncio
import json
import urllib.request
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

import pytest
from agents import RunContextWrapper

from strix.config.settings import ActionApprovalSettings
from strix.core.action_approvals import ActionApprovalGuard
from strix.core.agents import AgentCoordinator
from strix.interface.tui.approval_history import read_approval_history, record_approval_history
from strix.interface.tui.backend.controller import TuiController
from strix.interface.tui.runtime import GoTuiRuntime
from strix.interface.viewer.server import serve
from strix.interface.viewer.transcript import build_run_state
from tests.test_tui_backend_controller import args
from tests.test_viewer import _bundle, _get_status, _make_run, _post, _session_cookie


if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize("approved", [True, False])
def test_approval_endpoint_authorization_and_exact_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, approved: bool
) -> None:
    run_dir = _make_run(tmp_path, "approval", status="running", end_time=None)
    _bundle(tmp_path, monkeypatch)
    choices: list[tuple[str, bool]] = []
    pending = {"request"}

    def decide(approval_id: str, decision: bool) -> bool:
        if approval_id not in pending:
            return False
        pending.remove(approval_id)
        choices.append((approval_id, decision))
        return True

    httpd, url, token = serve(
        run_dir,
        open_browser=False,
        approval_state=lambda: {"pending": list(pending), "can_decide": True},
        approval_decide=decide,
    )
    try:
        body = {"approval_id": "request", "approved": approved}
        assert _post(url, "/api/approvals/decide", body)[0] == 403
        assert _get_status(url + "/api/approvals") == 403
        assert not choices
        cookie = _session_cookie(url, token)
        assert _get_status(url + "/api/approvals", cookie=cookie) == 200
        assert (
            _post(url, "/api/approvals/decide", {**body, "run": "other"}, cookie=cookie)[0] == 409
        )
        assert (
            _post(url, "/api/approvals/decide", {**body, "approved": "true"}, cookie=cookie)[0]
            == 400
        )
        assert not choices
        assert _post(url, "/api/approvals/decide", body, cookie=cookie)[0] == 200
        assert choices == [("request", approved)]
        assert _post(url, "/api/approvals/decide", body, cookie=cookie)[0] == 409
        assert (
            _post(url, "/api/approvals/decide", {**body, "approval_id": "unknown"}, cookie=cookie)[
                0
            ]
            == 409
        )
        assert choices == [("request", approved)]
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.mark.parametrize("finished", [True, False])
def test_standalone_and_finished_approvals_are_read_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, finished: bool
) -> None:
    run_dir = _make_run(
        tmp_path, "history", status="completed" if finished else "running", end_time=None
    )
    _bundle(tmp_path, monkeypatch)
    decide = Mock(return_value=True)
    snapshot = Mock(return_value={"pending": [{"approval_id": "request"}], "can_decide": True})
    httpd, url, token = serve(
        run_dir,
        open_browser=False,
        approval_state=snapshot if finished else None,
        approval_decide=decide if finished else None,
    )
    try:
        cookie = _session_cookie(url, token)
        request = urllib.request.Request(url + "/api/approvals", headers={"Cookie": cookie})  # noqa: S310
        with urllib.request.urlopen(request) as response:  # noqa: S310  # nosec B310
            assert json.load(response) == {"pending": [], "can_decide": False}
        assert _post(
            url,
            "/api/approvals/decide",
            {"approval_id": "request", "approved": True},
            cookie=cookie,
        )[0] == (409 if finished else 403)
        decide.assert_not_called()
        snapshot.assert_not_called()
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.mark.asyncio
@pytest.mark.parametrize("approved", [True, False])
async def test_viewer_uses_terminal_controller_decision_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, approved: bool
) -> None:
    run_dir = _make_run(tmp_path, "live", status="running", end_time=None)
    _bundle(tmp_path, monkeypatch)
    monkeypatch.setattr("webbrowser.open", lambda *_args: True)
    coordinator = AgentCoordinator()
    guard = ActionApprovalGuard(
        ActionApprovalSettings.model_validate({"enabled": True, "mode": "ask"})
    )
    coordinator.action_approvals = guard
    requested = asyncio.Event()
    events: list[dict[str, Any]] = []

    def capture(event: dict[str, Any]) -> None:
        events.append(event)
        if event["type"] == "requested":
            requested.set()

    async def evaluate(_state: dict[str, Any]) -> tuple[float, str, str]:
        return 0.99, "deletes_data", "Deletes target data."

    guard.event_sink = capture
    monkeypatch.setattr(guard.judge, "evaluate", evaluate)
    controller = TuiController(args(), coordinator=coordinator)
    controller.report_state = Mock(get_run_dir=lambda: run_dir, run_record={"status": "running"})
    controller.scan_loop = asyncio.get_running_loop()
    context = RunContextWrapper(context={"agent_id": "root", "coordinator": coordinator})
    check = asyncio.create_task(guard.check(context, "exec_command", {"cmd": "test"}))
    try:
        await asyncio.wait_for(requested.wait(), 1)
        result = await controller.handle("viewer.open", {})
        assert result["status"] == "running"
        parts = urlsplit(result["url"])
        url = f"{parts.scheme}://{parts.netloc}"
        cookie = await asyncio.to_thread(_session_cookie, url, parse_qs(parts.query)["token"][0])
        approval_id = guard.pending()[0]["approval_id"]
        body = {"approval_id": approval_id, "approved": approved}
        status, _ = await asyncio.to_thread(
            _post, url, "/api/approvals/decide", body, cookie=cookie
        )
        assert status == 200
        assert ((await check) is None) is approved
        assert events[1]["decision"] == ("approved" if approved else "denied")
        assert events[1]["decided_by"] == "terminal"
        assert not guard.pending()
    finally:
        guard.block_pending()
        await asyncio.gather(check, return_exceptions=True)
        await asyncio.to_thread(controller.close_viewer)


def test_approval_history_replays_terminal_copy_and_ignores_partial_records(tmp_path: Path) -> None:
    run_dir = _make_run(tmp_path, "history", status="completed", end_time="2026-01-01T00:00:00Z")
    assert read_approval_history(run_dir) == []
    runtime = GoTuiRuntime.__new__(GoTuiRuntime)
    live_view = Mock()
    runtime.live_view = live_view
    runtime.controller = Mock()
    runtime.coordinator = AgentCoordinator()
    runtime.report_state = Mock(get_run_dir=lambda: run_dir)
    runtime.capture_approval({"type": "requested", "agent_id": "root", "summary": "test"})
    assert read_approval_history(run_dir) == []
    runtime.capture_approval(
        {"type": "resolved", "agent_id": "root", "decision": "approved", "decided_by": "terminal"}
    )
    history = build_run_state(run_dir)["approval_history"]
    assert history[0]["content"] == "Approved by you"
    assert history[0]["agent_id"] == "root"
    assert live_view.record_approval.call_args.args == ("root", history[0]["content"])
    record_approval_history(run_dir, "child", "Denied by you")
    with (run_dir / ".state" / "action_approvals.jsonl").open("a") as stream:
        stream.write('{"agent_id":\nnull\n{}\n')
    assert [row["content"] for row in read_approval_history(run_dir)] == [
        "Approved by you",
        "Denied by you",
    ]


@pytest.mark.parametrize("decision", ["approved", "denied", "timed_out", "blocked"])
def test_settled_history_preserves_proposed_command(tmp_path: Path, decision: str) -> None:
    run_dir = _make_run(tmp_path, "command-history", status="completed", end_time="2026-01-01")
    runtime = GoTuiRuntime.__new__(GoTuiRuntime)
    runtime.live_view = Mock()
    runtime.controller = Mock()
    runtime.coordinator = AgentCoordinator()
    runtime.report_state = Mock(get_run_dir=lambda: run_dir)
    command = "curl -X DELETE http://localhost:8080/items/3\nprintf done"
    runtime.capture_approval(
        {
            "type": "resolved",
            "agent_id": "root",
            "decision": decision,
            "decided_by": "terminal",
            "summary": command,
        }
    )
    history = build_run_state(run_dir)["approval_history"]
    assert len(history) == 1
    assert history[0]["summary"] == command
    assert history[0]["content"]
    assert "summary" not in history[0]["content"]


def test_approval_history_accepts_empty_commands_and_ignores_invalid_command_types(
    tmp_path: Path,
) -> None:
    run_dir = _make_run(
        tmp_path, "empty-command-history", status="completed", end_time="2026-01-01"
    )
    record_approval_history(run_dir, "root", "Approved by you", summary="")
    record_approval_history(run_dir, "child", "Denied by you")
    with (run_dir / ".state" / "action_approvals.jsonl").open("a") as stream:
        stream.write(
            json.dumps(
                {"agent_id": "root", "content": "Blocked", "timestamp": "now", "summary": []}
            )
            + "\n"
        )
    history = read_approval_history(run_dir)
    assert history[0]["summary"] == ""
    assert "summary" not in history[1]
    assert "summary" not in history[2]

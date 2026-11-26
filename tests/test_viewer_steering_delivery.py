"""Tests for truthful viewer steering delivery timeouts (#1724)."""

from __future__ import annotations

import asyncio
import http.client
import json
import threading
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from strix.core.agents import AgentCoordinator
from strix.interface.tui.backend.live_view import TuiLiveView
from strix.interface.tui.backend.messages import (
    deliver_user_message_to_agent,
    send_user_message_to_agent,
)
from strix.interface.viewer import server as viewer_server


if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def _run_loop_blocking_repro() -> tuple[str, bool, int, int, list[str], int]:
    """Exercise Race A: deadline expires while the event loop is blocked."""

    async def scenario() -> tuple[str, bool, int, int, list[str], int]:
        coordinator = AgentCoordinator()
        await coordinator.register("root", "root", parent_id=None)
        live_view = TuiLiveView()
        loop = asyncio.get_running_loop()
        notifications = 0

        def on_notify() -> None:
            nonlocal notifications
            notifications += 1

        results: list[tuple[str, bool]] = []

        def worker_fn() -> None:
            outcome = deliver_user_message_to_agent(
                coordinator=coordinator,
                loop=loop,
                live_view=live_view,
                target_agent_id="root",
                message="use the staging tenant only",
                notify_changed=on_notify,
                wait_for_delivery=True,
                timeout=0.05,
            )
            legacy_ok = send_user_message_to_agent(
                coordinator=coordinator,
                loop=loop,
                live_view=live_view,
                target_agent_id="root",
                message="use the staging tenant only",
                notify_changed=on_notify,
                wait_for_delivery=True,
                timeout=0.05,
            )
            results.append((outcome, legacy_ok))

        worker = threading.Thread(target=worker_fn, daemon=True)
        worker.start()
        # Hold the event loop thread synchronously past both 50ms timeouts.
        worker.join(timeout=2.0)
        assert not worker.is_alive()

        queued_before_resume = len(coordinator.runtimes["root"].mailbox)
        # Let any scheduled callbacks run once the event loop resumes.
        await asyncio.sleep(0.05)
        queued_after_resume = len(coordinator.runtimes["root"].mailbox)

        retry = await asyncio.to_thread(
            deliver_user_message_to_agent,
            coordinator=coordinator,
            loop=loop,
            live_view=live_view,
            target_agent_id="root",
            message="use the staging tenant only",
            notify_changed=on_notify,
            wait_for_delivery=True,
            timeout=1.0,
        )
        assert retry == "delivered"
        contents = [str(entry["content"]) for entry in coordinator.runtimes["root"].mailbox]
        outcome, legacy_ok = results[0]
        return (
            outcome,
            legacy_ok,
            queued_before_resume,
            queued_after_resume,
            contents,
            notifications,
        )

    return asyncio.run(asyncio.wait_for(scenario(), timeout=10.0))


def test_timeout_before_dispatch_cancels_cleanly_without_late_delivery() -> None:
    outcome, legacy_ok, before_resume, after_resume, contents, notifications = (
        _run_loop_blocking_repro()
    )
    assert outcome == "not_delivered"
    assert legacy_ok is False
    assert before_resume == 0
    assert after_resume == 0
    assert contents == ["use the staging tenant only"]
    assert notifications == 1


def test_timeout_while_send_in_flight_reports_delivery_unknown() -> None:
    async def scenario() -> None:
        live_view = TuiLiveView()
        loop = asyncio.get_running_loop()
        started = asyncio.Event()
        release = asyncio.Event()
        mailbox: list[dict[str, Any]] = []
        notified = asyncio.Event()

        class _SlowCoordinator:
            async def send(self, _agent_id: str, message: dict[str, Any]) -> bool:
                mailbox.append(dict(message))
                started.set()
                await release.wait()
                return True

        outcome_holder: list[str] = []

        def caller() -> None:
            outcome_holder.append(
                deliver_user_message_to_agent(
                    coordinator=_SlowCoordinator(),
                    loop=loop,
                    live_view=live_view,
                    target_agent_id="root",
                    message="check auth headers",
                    notify_changed=notified.set,
                    wait_for_delivery=True,
                    timeout=0.05,
                )
            )

        thread = threading.Thread(target=caller, daemon=True)
        thread.start()
        await asyncio.wait_for(started.wait(), timeout=2.0)
        # Wait for the caller thread's 50ms timeout while send() is still parked.
        await asyncio.to_thread(thread.join, 2.0)
        assert not thread.is_alive()
        assert outcome_holder == ["delivery_unknown"]
        assert len(mailbox) == 1

        release.set()
        await asyncio.wait_for(notified.wait(), timeout=2.0)

    asyncio.run(asyncio.wait_for(scenario(), timeout=10.0))


def test_confirmed_rejection_and_closed_loop_return_not_delivered() -> None:
    async def scenario() -> None:
        coordinator = AgentCoordinator()
        await coordinator.register("root", "root", parent_id=None)
        live_view = TuiLiveView()
        loop = asyncio.get_running_loop()

        unknown = await asyncio.to_thread(
            deliver_user_message_to_agent,
            coordinator=coordinator,
            loop=loop,
            live_view=live_view,
            target_agent_id="missing-agent",
            message="hello",
            wait_for_delivery=True,
            timeout=1.0,
        )
        assert unknown == "not_delivered"

        delivered = await asyncio.to_thread(
            send_user_message_to_agent,
            coordinator=coordinator,
            loop=loop,
            live_view=live_view,
            target_agent_id="root",
            message="hello",
            wait_for_delivery=True,
            timeout=1.0,
        )
        assert delivered is True

    asyncio.run(asyncio.wait_for(scenario(), timeout=10.0))

    closed_loop = asyncio.new_event_loop()
    closed_loop.close()
    assert (
        deliver_user_message_to_agent(
            coordinator=AgentCoordinator(),
            loop=closed_loop,
            live_view=TuiLiveView(),
            target_agent_id="root",
            message="hello",
            wait_for_delivery=True,
        )
        == "not_delivered"
    )


def _setup_viewer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, steer_handler: Any
) -> tuple[Any, str, str]:
    run_dir = tmp_path / "strix_runs" / "steer-run"
    (run_dir / ".state").mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps({"run_name": "steer-run", "status": "running", "end_time": None}),
        encoding="utf-8",
    )
    (run_dir / ".state" / "agents.json").write_text(
        json.dumps({"statuses": {"root": "running"}, "names": {"root": "strix"}}),
        encoding="utf-8",
    )
    bundle = tmp_path / "static"
    bundle.mkdir()
    (bundle / "index.html").write_text("<html></html>", encoding="utf-8")
    monkeypatch.setattr(viewer_server, "bundle_dir", lambda: bundle)
    return viewer_server.serve(run_dir, open_browser=False, steer_handler=steer_handler)


def _session_cookie(url: str, token: str) -> str:
    parsed = urlsplit(url)
    conn = http.client.HTTPConnection(str(parsed.hostname), parsed.port or 80, timeout=5)
    try:
        conn.request("GET", f"/?token={token}")
        resp = conn.getresponse()
        resp.read()
        header = str(resp.getheader("Set-Cookie") or "")
    finally:
        conn.close()
    return header.split(";", 1)[0]


def test_viewer_steer_endpoint_distinguishes_delivery_outcomes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outcomes = iter(["delivered", "not_delivered", "delivery_unknown", True, False])
    httpd, url, token = _setup_viewer(tmp_path, monkeypatch, lambda _a, _m: next(outcomes))
    try:
        cookie = _session_cookie(url, token)
        parsed = urlsplit(url)
        expected = [
            {"ok": True},
            {"ok": False, "error": "not_delivered"},
            {"ok": False, "error": "delivery_unknown"},
            {"ok": True},
            {"ok": False, "error": "not_delivered"},
        ]
        for exp in expected:
            payload = json.dumps({"agent_id": "root", "message": "pivot"}).encode("utf-8")
            conn = http.client.HTTPConnection(str(parsed.hostname), parsed.port or 80, timeout=5)
            try:
                conn.request(
                    "POST",
                    "/api/agents/steer",
                    body=payload,
                    headers={"Content-Type": "application/json", "Cookie": cookie},
                )
                resp = conn.getresponse()
                body = resp.read().decode("utf-8")
            finally:
                conn.close()
            assert resp.status == 200
            assert json.loads(body) == exp
    finally:
        httpd.shutdown()
        httpd.server_close()

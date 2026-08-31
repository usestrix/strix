"""Tests for the local run viewer (strix.interface.viewer) and its path helpers."""

from __future__ import annotations

import json
import os
import sqlite3
import urllib.error
import urllib.request
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from strix.core.paths import latest_run_dir, runs_base_dir
from strix.interface.viewer.cli import run_view
from strix.interface.viewer.server import serve
from strix.interface.viewer.transcript import (
    build_run_state,
    read_report_markdown,
    read_run_summary,
    read_vulnerabilities,
)


if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

    import pytest


def _make_run(base: Path, name: str, *, status: str, end_time: str | None) -> Path:
    run_dir = base / "strix_runs" / name
    state_dir = run_dir / ".state"
    state_dir.mkdir(parents=True)
    record = {"run_name": name, "status": status, "end_time": end_time}
    (run_dir / "run.json").write_text(json.dumps(record), encoding="utf-8")
    agents = {
        "statuses": {"root": "completed", "child": "running"},
        "names": {"root": "strix", "child": "recon"},
        "parent_of": {"root": None, "child": "root"},
    }
    (state_dir / "agents.json").write_text(json.dumps(agents), encoding="utf-8")
    return run_dir


def test_latest_run_dir_none_when_no_runs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert latest_run_dir() is None
    assert runs_base_dir() == tmp_path / "strix_runs"


def test_view_cli_help_includes_host(capsys: pytest.CaptureFixture[str]) -> None:
    try:
        run_view(["--help"])
    except SystemExit as exc:
        assert exc.code == 0
    else:
        raise AssertionError("--help should exit")

    help_text = capsys.readouterr().out
    assert "--host HOST" in help_text
    assert "0.0.0.0" in help_text


def test_server_can_bind_all_ipv4_interfaces(tmp_path: Path) -> None:
    run_dir = _make_run(tmp_path, "remote", status="running", end_time=None)

    httpd, url, _ = serve(run_dir, host="0.0.0.0", open_browser=False)
    try:
        assert httpd.server_address[0] == "0.0.0.0"
        assert url == f"http://0.0.0.0:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_latest_run_dir_picks_newest_by_record_mtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    older = _make_run(tmp_path, "old", status="completed", end_time="2026-01-01T00:00:00Z")
    newer = _make_run(tmp_path, "new", status="running", end_time=None)
    # Force a newer mtime on the second run's record.
    os.utime(newer / "run.json", (2_000_000_000, 2_000_000_000))
    os.utime(older / "run.json", (1_000_000_000, 1_000_000_000))
    assert latest_run_dir() == newer


def test_read_run_summary_finished_flag(tmp_path: Path) -> None:
    finished = _make_run(tmp_path, "done", status="completed", end_time="2026-01-01T00:00:00Z")
    live = _make_run(tmp_path, "live", status="running", end_time=None)
    assert read_run_summary(finished)["finished"] is True
    assert read_run_summary(live)["finished"] is False
    # A terminal status without an end_time is not "finished".
    partial = _make_run(tmp_path, "partial", status="failed", end_time=None)
    assert read_run_summary(partial)["finished"] is False


def test_read_run_summary_surfaces_mcp_connection_status(tmp_path: Path) -> None:
    """The engine persists the non-secret MCP roster under mcp_connection_status;
    read_run_summary spreads the whole record, so /api/run carries it to the
    viewer verbatim."""
    run_dir = _make_run(tmp_path, "mcp", status="running", end_time=None)
    roster = [
        {"name": "local_fs", "provider": None, "tool_count": 3, "dead": False},
        {"name": "db", "provider": "supabase", "tool_count": 7, "dead": True},
    ]
    record = {
        "run_name": "mcp",
        "status": "running",
        "end_time": None,
        "mcp_connection_status": roster,
    }
    (run_dir / "run.json").write_text(json.dumps(record), encoding="utf-8")
    assert read_run_summary(run_dir)["mcp_connection_status"] == roster


def test_read_missing_artifacts_return_defaults(tmp_path: Path) -> None:
    run_dir = _make_run(tmp_path, "empty", status="running", end_time=None)
    assert read_vulnerabilities(run_dir) == []
    assert read_report_markdown(run_dir) == ""


def test_build_run_state_from_agents_json(tmp_path: Path) -> None:
    run_dir = _make_run(tmp_path, "graph", status="running", end_time=None)
    state = build_run_state(run_dir)
    ids = {a["id"] for a in state["agents"]}
    assert ids == {"root", "child"}
    child = next(a for a in state["agents"] if a["id"] == "child")
    assert child["parent_id"] == "root"
    assert child["name"] == "recon"
    # No agents.db, so no message/tool events.
    assert state["events"] == []


def test_build_run_state_keeps_same_call_id_separate_per_agent(tmp_path: Path) -> None:
    run_dir = _make_run(tmp_path, "tools", status="completed", end_time=None)
    agents_db = run_dir / ".state" / "agents.db"
    rows = [
        (
            "root",
            {
                "type": "function_call",
                "call_id": "exec_command_0",
                "name": "exec_command",
                "arguments": json.dumps({"cmd": "echo root"}),
            },
        ),
        (
            "root",
            {
                "type": "function_call_output",
                "call_id": "exec_command_0",
                "output": json.dumps({"success": True, "output": "root"}),
            },
        ),
        (
            "child",
            {
                "type": "function_call",
                "call_id": "exec_command_0",
                "name": "exec_command",
                "arguments": json.dumps({"cmd": "echo child"}),
            },
        ),
        (
            "child",
            {
                "type": "function_call_output",
                "call_id": "exec_command_0",
                "output": json.dumps({"success": True, "output": "child"}),
            },
        ),
    ]
    with sqlite3.connect(agents_db) as conn:
        conn.execute(
            """
            create table agent_messages (
                id integer primary key,
                session_id text not null,
                message_data text not null,
                created_at text not null
            )
            """
        )
        conn.executemany(
            """
            insert into agent_messages (session_id, message_data, created_at)
            values (?, ?, '2026-01-01T00:00:00+00:00')
            """,
            [(agent_id, json.dumps(message)) for agent_id, message in rows],
        )

    state = build_run_state(run_dir)
    tools = [event for event in state["events"] if event["type"] == "tool"]

    assert len(tools) == 2
    by_agent = {event["agent_id"]: event for event in tools}
    assert by_agent["root"]["data"]["args"] == {"cmd": "echo root"}
    assert by_agent["root"]["data"]["result"]["output"] == "root"
    assert by_agent["child"]["data"]["args"] == {"cmd": "echo child"}
    assert by_agent["child"]["data"]["result"]["output"] == "child"


def _get(url: str, *, cookie: str | None = None) -> tuple[int, str, bytes]:
    headers = {"Cookie": cookie} if cookie else {}
    req = urllib.request.Request(url, headers=headers)  # noqa: S310 - localhost test server
    with urllib.request.urlopen(req) as resp:  # noqa: S310 - localhost test server  # nosec B310
        return resp.status, resp.headers.get("Content-Type", ""), resp.read()


def test_server_serves_api_and_static(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir = _make_run(tmp_path, "served", status="completed", end_time="2026-01-01T00:00:00Z")

    assets = tmp_path / "bundle"
    (assets / "assets").mkdir(parents=True)
    (assets / "index.html").write_text("<!doctype html><div id=root></div>", encoding="utf-8")
    (assets / "assets" / "app.js").write_text("console.log(1)", encoding="utf-8")
    monkeypatch.setattr("strix.interface.viewer.server.bundle_dir", lambda: assets)

    httpd, url, token = serve(run_dir, open_browser=False)
    try:
        cookie = _session_cookie(url, token)
        status, ctype, body = _get(f"{url}/api/run", cookie=cookie)
        assert status == 200
        assert "application/json" in ctype
        assert json.loads(body)["finished"] is True

        status, _, body = _get(f"{url}/api/transcript", cookie=cookie)
        assert {a["id"] for a in json.loads(body)["agents"]} == {"root", "child"}

        # Real asset is served.
        status, ctype, _ = _get(f"{url}/assets/app.js")
        assert status == 200

        # Unknown non-API route falls back to index.html (SPA routing).
        status, ctype, body = _get(f"{url}/agents/root")
        assert status == 200
        assert b"<div id=root>" in body
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_server_event_endpoint_forwards_cta(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = _make_run(tmp_path, "evt", status="running", end_time=None)
    assets = tmp_path / "bundle"
    assets.mkdir()
    (assets / "index.html").write_text("x", encoding="utf-8")
    monkeypatch.setattr("strix.interface.viewer.server.bundle_dir", lambda: assets)

    seen: list[tuple[str, str | None]] = []
    monkeypatch.setattr(
        "strix.telemetry.posthog.viewer_cta_clicked",
        lambda cta, surface=None: seen.append((cta, surface)),
    )

    httpd, url, _ = serve(run_dir, open_browser=False)
    try:
        body = json.dumps(
            {"event": "cta_clicked", "cta": "PR reviews", "surface": "sidebar_nav"}
        ).encode()
        req = urllib.request.Request(  # noqa: S310 - localhost test server
            f"{url}/api/event", data=body, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req) as resp:  # noqa: S310  # nosec B310
            assert resp.status == 204
        assert seen == [("PR reviews", "sidebar_nav")]
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_server_event_endpoint_forwards_email_funnel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = _make_run(tmp_path, "evt2", status="running", end_time=None)
    assets = tmp_path / "bundle"
    assets.mkdir()
    (assets / "index.html").write_text("x", encoding="utf-8")
    monkeypatch.setattr("strix.interface.viewer.server.bundle_dir", lambda: assets)

    seen: list[tuple[str, str | None]] = []
    monkeypatch.setattr(
        "strix.telemetry.posthog.viewer_email_event",
        lambda step, purpose=None: seen.append((step, purpose)),
    )

    httpd, url, _ = serve(run_dir, open_browser=False)
    try:
        # A whitelisted funnel event is forwarded; an unknown event is ignored.
        for payload, expected in (
            ({"event": "email_verified", "purpose": "report"}, [("email_verified", "report")]),
            ({"event": "not_a_real_event"}, [("email_verified", "report")]),
        ):
            req = urllib.request.Request(  # noqa: S310 - localhost test server
                f"{url}/api/event",
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req) as resp:  # noqa: S310  # nosec B310
                assert resp.status == 204
            assert seen == expected
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_server_event_endpoint_forwards_agent_steered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = _make_run(tmp_path, "steerevt", status="running", end_time=None)
    _bundle(tmp_path, monkeypatch)

    seen: list[bool] = []
    monkeypatch.setattr("strix.telemetry.posthog.viewer_agent_steered", lambda: seen.append(True))

    httpd, url, _ = serve(run_dir, open_browser=False)
    try:
        req = urllib.request.Request(  # noqa: S310 - localhost test server
            f"{url}/api/event",
            data=json.dumps({"event": "agent_steered"}).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as resp:  # noqa: S310  # nosec B310
            assert resp.status == 204
        assert seen == [True]
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_feedback_records_telemetry_on_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = _make_run(tmp_path, "fbtel", status="running", end_time=None)
    _bundle(tmp_path, monkeypatch)

    sent: list[bool] = []
    monkeypatch.setattr("strix.interface.viewer.auth.feedback_submit", lambda *_a: None)
    monkeypatch.setattr(
        "strix.telemetry.posthog.viewer_feedback_submitted", lambda: sent.append(True)
    )

    httpd, url, token = serve(run_dir, open_browser=False)
    try:
        cookie = _session_cookie(url, token)
        # A successful, session-holding submission relays and records telemetry.
        status, _ = _post(
            url, "/api/feedback", {"email": "a@b.com", "message": "hi"}, cookie=cookie
        )
        assert status == 200
        assert sent == [True]

        # A cookie-less caller is rejected and records nothing.
        sent.clear()
        status, _ = _post(url, "/api/feedback", {"email": "a@b.com", "message": "hi"})
        assert status == 403
        assert sent == []
    finally:
        httpd.shutdown()
        httpd.server_close()


def _post(
    url: str, path: str, payload: Mapping[str, object], *, cookie: str | None = None
) -> tuple[int, bytes]:
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(  # noqa: S310 - localhost test server
        url + path, data=json.dumps(payload).encode(), headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req) as resp:  # noqa: S310  # nosec B310
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _session_cookie(url: str, token: str) -> str:
    """Bootstrap a session via the tokened URL and return its ``name=value`` cookie."""
    bootstrap = f"{url}/?token={token}"
    with urllib.request.urlopen(bootstrap) as resp:  # noqa: S310 - localhost test server  # nosec B310
        raw = str(resp.headers.get("Set-Cookie", ""))
    return raw.split(";", 1)[0]


def _cookie_name(url: str) -> str:
    """The per-server session cookie name, derived from the bound port."""
    return f"strix_viewer_session_{urlsplit(url).port}"


def _get_status(url: str, *, cookie: str | None = None) -> int:
    headers = {"Cookie": cookie} if cookie else {}
    req = urllib.request.Request(url, headers=headers)  # noqa: S310 - localhost test server
    try:
        with urllib.request.urlopen(req) as resp:  # noqa: S310  # nosec B310
            return int(resp.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)


def _bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assets = tmp_path / "bundle"
    assets.mkdir()
    (assets / "index.html").write_text("<!doctype html><div id=root></div>", encoding="utf-8")
    monkeypatch.setattr("strix.interface.viewer.server.bundle_dir", lambda: assets)


def test_capability_issued_only_for_tokened_bootstrap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = _make_run(tmp_path, "cookie", status="running", end_time=None)
    assets = tmp_path / "bundle"
    (assets / "assets").mkdir(parents=True)
    (assets / "index.html").write_text("<!doctype html>index", encoding="utf-8")
    (assets / "assets" / "app.js").write_text("1", encoding="utf-8")
    monkeypatch.setattr("strix.interface.viewer.server.bundle_dir", lambda: assets)

    httpd, url, token = serve(run_dir, open_browser=False)
    try:
        # A bare index load -- all a reachable client can do -- hands out nothing.
        with urllib.request.urlopen(url + "/") as resp:  # noqa: S310  # nosec B310
            assert resp.headers.get("Set-Cookie") is None

        # A wrong token is likewise refused the capability.
        with urllib.request.urlopen(f"{url}/?token=wrong") as resp:  # noqa: S310  # nosec B310
            assert resp.headers.get("Set-Cookie") is None

        # Only the correct bootstrap token mints the session cookie.
        with urllib.request.urlopen(f"{url}/?token={token}") as resp:  # noqa: S310  # nosec B310
            cookie = str(resp.headers.get("Set-Cookie", ""))
        assert f"{_cookie_name(url)}=" in cookie
        assert "HttpOnly" in cookie and "SameSite=Strict" in cookie

        # Static assets never carry it.
        with urllib.request.urlopen(url + "/assets/app.js") as resp:  # noqa: S310  # nosec B310
            assert resp.headers.get("Set-Cookie") is None
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_unauthorized_client_cannot_acquire_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = _make_run(tmp_path, "exposed", status="running", end_time=None)
    _bundle(tmp_path, monkeypatch)

    delivered: list[tuple[str, str]] = []

    def handler(agent_id: str, message: str) -> bool:
        delivered.append((agent_id, message))
        return True

    httpd, url, _ = serve(run_dir, open_browser=False, steer_handler=handler)
    try:
        # A direct network client can reach the page but is handed no capability,
        # so replaying an empty/guessed cookie cannot steer a live scan.
        with urllib.request.urlopen(url + "/") as resp:  # noqa: S310  # nosec B310
            assert resp.headers.get("Set-Cookie") is None
        status, _ = _post(
            url,
            "/api/agents/steer",
            {"agent_id": "root", "message": "pwn"},
            cookie=f"{_cookie_name(url)}=",
        )
        assert status == 403
        assert delivered == []
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_run_data_requires_session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir = _make_run(tmp_path, "private", status="completed", end_time="2026-01-01T00:00:00Z")
    _bundle(tmp_path, monkeypatch)

    httpd, url, token = serve(run_dir, open_browser=False)
    try:
        cookie = _session_cookie(url, token)
        for path in ("/api/run", "/api/vulnerabilities", "/api/report", "/api/transcript"):
            assert _get_status(url + path) == 403, path
            assert _get_status(url + path, cookie=f"{_cookie_name(url)}=wrong") == 403, path
            assert _get_status(url + path, cookie=cookie) == 200, path
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_auth_status_reflects_expiry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir = _make_run(tmp_path, "status", status="running", end_time=None)
    _bundle(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "strix.interface.viewer.auth.read_auth", lambda: {"email": "a@b.com", "token": "t"}
    )
    verified = {"value": True}
    monkeypatch.setattr("strix.interface.viewer.auth.is_verified", lambda: verified["value"])

    httpd, url, token = serve(run_dir, open_browser=False)
    try:
        cookie = _session_cookie(url, token)
        _, _, body = _get(f"{url}/api/auth/status", cookie=cookie)
        assert json.loads(body) == {"verified": True, "email": "a@b.com"}

        # Once expired, status must advertise unverified so the SPA re-prompts.
        verified["value"] = False
        _, _, body = _get(f"{url}/api/auth/status", cookie=cookie)
        assert json.loads(body)["verified"] is False

        # A cookie-less caller never sees the cached email or verified state.
        verified["value"] = True
        _, _, body = _get(f"{url}/api/auth/status")
        assert json.loads(body) == {"verified": False, "email": None}
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_auth_mutations_require_session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir = _make_run(tmp_path, "authmut", status="running", end_time=None)
    _bundle(tmp_path, monkeypatch)
    forgotten = {"value": False}
    monkeypatch.setattr("strix.interface.viewer.auth.forget", lambda: forgotten.update(value=True))

    httpd, url, _ = serve(run_dir, open_browser=False)
    try:
        for path in ("/api/auth/forget", "/api/auth/otp/start", "/api/auth/otp/verify"):
            status, _ = _post(url, path, {"email": "a@b.com", "code": "123456"})
            assert status == 403, path
        assert forgotten["value"] is False
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_steer_requires_session_cookie(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir = _make_run(tmp_path, "steer", status="running", end_time=None)
    _bundle(tmp_path, monkeypatch)

    delivered: list[tuple[str, str]] = []

    def handler(agent_id: str, message: str) -> bool:
        delivered.append((agent_id, message))
        return True

    httpd, url, token = serve(run_dir, open_browser=False, steer_handler=handler)
    try:
        body = {"agent_id": "root", "message": "focus on auth"}
        # No cookie: rejected before reaching the live coordinator.
        status, _ = _post(url, "/api/agents/steer", body)
        assert status == 403
        assert delivered == []

        # With the session cookie the message is delivered.
        status, raw = _post(url, "/api/agents/steer", body, cookie=_session_cookie(url, token))
        assert status == 200
        assert json.loads(raw)["ok"] is True
        assert delivered == [("root", "focus on auth")]
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_report_send_requires_session_cookie(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = _make_run(tmp_path, "report", status="completed", end_time="2026-01-01T00:00:00Z")
    _bundle(tmp_path, monkeypatch)

    # A verified machine token exists, but that alone must not authorize a caller.
    monkeypatch.setattr(
        "strix.interface.viewer.auth.read_auth", lambda: {"email": "a@b.com", "token": "t"}
    )

    httpd, url, token = serve(run_dir, open_browser=False)
    try:
        # No cookie: forbidden before the machine token is ever consulted.
        status, _ = _post(url, "/api/report/send", {})
        assert status == 403

        # With the cookie the request clears the session gate; it then reaches
        # the run resolver, so an unknown run is a 404 rather than a 403.
        status, _ = _post(
            url, "/api/report/send", {"run": "does-not-exist"}, cookie=_session_cookie(url, token)
        )
        assert status == 404
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_report_send_rejects_live_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A running scan would only produce a partial report, so the endpoint must
    # fail closed even for a verified, session-holding caller.
    run_dir = _make_run(tmp_path, "live", status="running", end_time=None)
    _bundle(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "strix.interface.viewer.auth.read_auth", lambda: {"email": "a@b.com", "token": "t"}
    )

    httpd, url, token = serve(run_dir, open_browser=False)
    try:
        status, _ = _post(url, "/api/report/send", {}, cookie=_session_cookie(url, token))
        assert status == 409
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_historical_run_data_requires_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launched = _make_run(tmp_path, "launched", status="completed", end_time="2026-01-01T00:00:00Z")
    _make_run(tmp_path, "other", status="completed", end_time="2026-01-01T00:00:00Z")
    _bundle(tmp_path, monkeypatch)

    verified = {"value": False}
    monkeypatch.setattr("strix.interface.viewer.auth.is_verified", lambda: verified["value"])

    httpd, url, token = serve(launched, open_browser=False)
    try:
        # The launched run needs the session capability, but not email verification.
        assert _get_status(f"{url}/api/run") == 403
        cookie = _session_cookie(url, token)
        assert _get_status(f"{url}/api/run", cookie=cookie) == 200

        # A different run needs the session capability first: a cookie-less
        # caller is forbidden even once the machine is verified.
        verified["value"] = True
        assert _get_status(f"{url}/api/run?run=other") == 403

        # With the cookie but not verified, the history gate returns 401.
        verified["value"] = False
        assert _get_status(f"{url}/api/run?run=other", cookie=cookie) == 401

        # With both the cookie and verification, the historical run resolves.
        verified["value"] = True
        assert _get_status(f"{url}/api/run?run=other", cookie=cookie) == 200
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_runs_list_requires_session_and_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launched = _make_run(tmp_path, "launched", status="completed", end_time="2026-01-01T00:00:00Z")
    _make_run(tmp_path, "other", status="completed", end_time="2026-01-01T00:00:00Z")
    _bundle(tmp_path, monkeypatch)

    monkeypatch.setattr("strix.interface.viewer.auth.is_verified", lambda: True)

    def _runs(cookie: str | None) -> dict[str, object]:
        headers = {"Cookie": cookie} if cookie else {}
        req = urllib.request.Request(f"{url}/api/runs", headers=headers)  # noqa: S310
        with urllib.request.urlopen(req) as resp:  # noqa: S310 - localhost test server  # nosec B310
            return dict(json.loads(resp.read()))

    httpd, url, token = serve(launched, open_browser=False)
    try:
        # A cookie-less caller (even with the machine verified) only sees the
        # teaser count, never the run entries.
        payload = _runs(None)
        assert payload["locked"] is True
        assert payload["count"] == 2
        assert payload["runs"] == []

        # With the session cookie and verification, the entries unlock.
        payload = _runs(_session_cookie(url, token))
        assert payload["locked"] is False
        assert {r["name"] for r in payload["runs"]} == {"launched", "other"}  # type: ignore[attr-defined]
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_concurrent_servers_use_distinct_cookies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cookies are host-scoped, not port-scoped: two viewers on 127.0.0.1 must
    not share a cookie slot, and one server's cookie must not pass the other's
    session gate."""
    run_a = _make_run(tmp_path / "a", "run-a", status="running", end_time=None)
    run_b = _make_run(tmp_path / "b", "run-b", status="running", end_time=None)
    _bundle(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "strix.interface.viewer.auth.read_auth", lambda: {"email": "a@b.com", "token": "t"}
    )
    monkeypatch.setattr("strix.interface.viewer.auth.is_verified", lambda: True)

    httpd_a, url_a, token_a = serve(run_a, open_browser=False)
    httpd_b, url_b, token_b = serve(run_b, open_browser=False)
    try:
        cookie_a = _session_cookie(url_a, token_a)
        cookie_b = _session_cookie(url_b, token_b)

        # The two servers mint differently named cookies, so a browser stores both.
        assert cookie_a.split("=", 1)[0] == _cookie_name(url_a)
        assert cookie_b.split("=", 1)[0] == _cookie_name(url_b)
        assert cookie_a.split("=", 1)[0] != cookie_b.split("=", 1)[0]

        def _status(url: str, cookie: str) -> dict[str, object]:
            _, _, body = _get(f"{url}/api/auth/status", cookie=cookie)
            return dict(json.loads(body))

        # Each server honors its own cookie...
        assert _status(url_a, cookie_a)["verified"] is True
        assert _status(url_b, cookie_b)["verified"] is True
        # ...but treats the other server's cookie as session-less.
        assert _status(url_a, cookie_b)["verified"] is False
        assert _status(url_b, cookie_a)["verified"] is False
        # Even both cookies together (what a real browser would send) only
        # match the token minted by the receiving server.
        both = f"{cookie_a}; {cookie_b}"
        assert _status(url_a, both)["verified"] is True
        assert _status(url_b, both)["verified"] is True
    finally:
        httpd_a.shutdown()
        httpd_a.server_close()
        httpd_b.shutdown()
        httpd_b.server_close()


def test_server_rejects_path_traversal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir = _make_run(tmp_path, "guard", status="completed", end_time="2026-01-01T00:00:00Z")
    secret = tmp_path / "secret.txt"
    secret.write_text("top secret", encoding="utf-8")

    assets = tmp_path / "bundle"
    assets.mkdir()
    (assets / "index.html").write_text("<!doctype html>index", encoding="utf-8")
    monkeypatch.setattr("strix.interface.viewer.server.bundle_dir", lambda: assets)

    httpd, url, _ = serve(run_dir, open_browser=False)
    try:
        # A traversal target must never leak the file; it falls back to index.html.
        _, _, body = _get(f"{url}/..%2f..%2fsecret.txt")
        assert b"top secret" not in body
    finally:
        httpd.shutdown()
        httpd.server_close()

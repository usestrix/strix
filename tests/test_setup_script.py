"""Tests for sandbox setup-script mounting and execution."""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest

from strix.interface.tui.live_view import SETUP_SCRIPT_AGENT_ID, TuiLiveView
from strix.runtime import session_manager
from strix.runtime.session_manager import (
    build_setup_script_mount,
    execute_setup_script,
)


if TYPE_CHECKING:
    from pathlib import Path


class FakeExecResult:
    def __init__(
        self,
        *,
        exit_code: int = 0,
        stdout: str | bytes = "",
        stderr: str | bytes = "",
    ) -> None:
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr

    def ok(self) -> bool:
        return self.exit_code == 0


class FakeSession:
    def __init__(self, result: FakeExecResult | None = None) -> None:
        self.result = result or FakeExecResult()
        self.exec_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    async def exec(self, *args: Any, **kwargs: Any) -> FakeExecResult:
        self.exec_calls.append((args, kwargs))
        return self.result

    async def resolve_exposed_port(self, _port: int) -> SimpleNamespace:
        return SimpleNamespace(host="127.0.0.1", port=12345)


def test_build_setup_script_mount_resolves_file(tmp_path: Path) -> None:
    script = tmp_path / "setup.sh"
    script.write_text("#!/usr/bin/env bash\n", encoding="utf-8")

    assert build_setup_script_mount(str(script)) == {
        "source": str(script.resolve()),
        "target": "/tmp/strix-setup-script.sh",
        "read_only": True,
    }


def test_build_setup_script_mount_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="Setup script does not exist"):
        build_setup_script_mount(str(tmp_path / "missing.sh"))


def test_live_view_records_setup_script_output() -> None:
    live_view = TuiLiveView()

    live_view.record_setup_script_event(
        {
            "status": "running",
            "source_path": "/host/setup.sh",
            "container_path": "/tmp/strix-setup-script.sh",
            "command": "bash /tmp/strix-setup-script.sh",
        }
    )
    live_view.record_setup_script_event(
        {
            "status": "completed",
            "source_path": "/host/setup.sh",
            "container_path": "/tmp/strix-setup-script.sh",
            "command": "bash /tmp/strix-setup-script.sh",
            "stdout": "seeded database",
            "stderr": "",
            "exit_code": 0,
            "duration_seconds": 1.25,
        }
    )

    assert live_view.agents[SETUP_SCRIPT_AGENT_ID]["status"] == "completed"
    assert live_view.agents[SETUP_SCRIPT_AGENT_ID]["kind"] == "setup_script"
    events = live_view.events_for_agent(SETUP_SCRIPT_AGENT_ID)
    assert len(events) == 1
    assert events[0]["data"]["tool_name"] == "setup_script"
    assert events[0]["data"]["status"] == "completed"
    assert events[0]["data"]["result"]["stdout"] == "seeded database"


@pytest.mark.asyncio
async def test_execute_setup_script_runs_bash() -> None:
    session = FakeSession(FakeExecResult(stdout="ready\n"))
    events: list[dict[str, Any]] = []

    await execute_setup_script(
        session,
        source_path="/host/setup.sh",
        event_sink=events.append,
    )

    assert session.exec_calls == [
        (("bash", "/tmp/strix-setup-script.sh"), {"timeout": 3600}),
    ]
    assert [event["status"] for event in events] == ["running", "completed"]
    assert events[0]["source_path"] == "/host/setup.sh"
    assert events[0]["command"] == "bash /tmp/strix-setup-script.sh"
    assert events[1]["stdout"] == "ready"
    assert events[1]["stderr"] == ""
    assert events[1]["exit_code"] == 0


@pytest.mark.asyncio
async def test_execute_setup_script_raises_on_failure() -> None:
    events: list[dict[str, Any]] = []
    session = FakeSession(FakeExecResult(exit_code=12, stderr=b"boom"))

    with pytest.raises(RuntimeError, match="Setup script failed inside sandbox"):
        await execute_setup_script(
            session,
            source_path="/host/setup.sh",
            event_sink=events.append,
        )

    assert [event["status"] for event in events] == ["running", "failed"]
    assert events[1]["stderr"] == "boom"
    assert events[1]["exit_code"] == 12


@pytest.mark.asyncio
async def test_create_or_reuse_runs_setup_after_runtime_bootstrap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = tmp_path / "setup.sh"
    script.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    session = FakeSession()
    events: list[str] = []
    captured_mounts: list[dict[str, Any]] = []

    async def fake_backend(
        *,
        image: str,
        manifest: Any,
        exposed_ports: tuple[int, ...],
        bind_mounts: list[dict[str, Any]] | None = None,
    ) -> tuple[object, FakeSession]:
        del image, manifest, exposed_ports
        events.append("backend")
        captured_mounts.extend(bind_mounts or [])
        return object(), session

    async def fake_bootstrap_caido(
        sandbox_session: FakeSession,
        *,
        host_url: str,
        container_url: str,
    ) -> object:
        del sandbox_session, host_url, container_url
        events.append("caido")
        return object()

    original_execute_setup_script = session_manager.execute_setup_script

    async def record_execute_setup_script(
        sandbox_session: FakeSession,
        *,
        source_path: str,
        event_sink: Any,
    ) -> None:
        del event_sink
        events.append("setup")
        await original_execute_setup_script(sandbox_session, source_path=source_path)

    monkeypatch.setattr(session_manager, "_SESSION_CACHE", {})
    monkeypatch.setattr(
        session_manager,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(backend="docker")),
    )
    monkeypatch.setattr(session_manager, "get_backend", lambda _name: fake_backend)
    monkeypatch.setattr(session_manager, "bootstrap_caido", fake_bootstrap_caido)
    monkeypatch.setattr(session_manager, "execute_setup_script", record_execute_setup_script)

    await session_manager.create_or_reuse(
        "scan-with-setup",
        image="strix-test:latest",
        local_sources=[],
        setup_script=str(script),
    )

    assert events == ["backend", "caido", "setup"]
    assert captured_mounts == [
        {
            "source": str(script.resolve()),
            "target": "/tmp/strix-setup-script.sh",
            "read_only": True,
        }
    ]

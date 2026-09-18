from __future__ import annotations

import argparse
import asyncio
import socket
import subprocess
import sys
import threading
from types import SimpleNamespace
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, Mock

import pytest

from strix.interface.tui import runtime as go_tui
from strix.interface.tui import sidecar


if TYPE_CHECKING:
    from pathlib import Path


def _runtime() -> go_tui.GoTuiRuntime:
    return go_tui.GoTuiRuntime(
        argparse.Namespace(
            needs_setup=True,
            targets_info=[],
            instruction=None,
            scan_mode="quick",
            max_budget_usd=None,
            max_turns=10,
            scope_mode="auto",
            diff_base=None,
        )
    )


@pytest.mark.asyncio
async def test_source_build_overrides_toolchain_without_mutating_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    env = {"GOTOOLCHAIN": "local", "CGO_ENABLED": "1", "TERM": "xterm-256color"}
    original_env = env.copy()
    process = SimpleNamespace(returncode=0, communicate=AsyncMock(return_value=(None, b"")))
    create = AsyncMock(return_value=process)
    monkeypatch.setattr(sidecar, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)
    output = tmp_path / "strix-tui"

    await sidecar.build_tui_source(tmp_path, output, env)

    create.assert_awaited_once_with(
        "go",
        "build",
        "-o",
        str(output),
        "./cmd/strix-tui",
        cwd=str(tmp_path),
        env={**original_env, "GOTOOLCHAIN": "auto", "CGO_ENABLED": "0"},
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    process.communicate.assert_awaited_once()
    assert env == original_env


@pytest.mark.asyncio
async def test_source_build_error_preserves_diagnostic_and_sanitizes_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    diagnostic = b"go: requires go >= 1.24.0\n\x1b[31mcompiler failed\x1b[0m"
    process = SimpleNamespace(returncode=1, communicate=AsyncMock(return_value=(None, diagnostic)))
    monkeypatch.setattr(sidecar, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(asyncio, "create_subprocess_exec", AsyncMock(return_value=process))

    with pytest.raises(RuntimeError, match=r"requires go >= 1\.24\.0") as caught:
        await sidecar.build_tui_source(tmp_path, tmp_path / "strix-tui", {})

    message = str(caught.value)
    assert "compiler failed" in message
    assert "\x1b" not in message
    assert "handshake" not in message.lower()


@pytest.mark.asyncio
async def test_source_build_bounds_compiler_diagnostic(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    process = SimpleNamespace(
        returncode=1,
        communicate=AsyncMock(return_value=(None, b"compiler detail " + b"x" * 10_000)),
    )
    monkeypatch.setattr(sidecar, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(asyncio, "create_subprocess_exec", AsyncMock(return_value=process))

    with pytest.raises(RuntimeError) as caught:
        await sidecar.build_tui_source(tmp_path, tmp_path / "strix-tui", {})

    assert len(str(caught.value)) < 4500


@pytest.mark.asyncio
async def test_cancelled_source_build_terminates_compiler(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    process = SimpleNamespace(
        returncode=None, communicate=AsyncMock(side_effect=asyncio.CancelledError)
    )
    terminate = AsyncMock()
    monkeypatch.setattr(sidecar, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(asyncio, "create_subprocess_exec", AsyncMock(return_value=process))
    monkeypatch.setattr(sidecar, "terminate_process", terminate)

    with pytest.raises(asyncio.CancelledError):
        await sidecar.build_tui_source(tmp_path, tmp_path / "strix-tui", {})

    terminate.assert_awaited_once_with(process)


@pytest.mark.asyncio
@pytest.mark.parametrize("returncode", [0, 1])
async def test_windows_source_build_uses_thread_without_async_subprocess_support(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, returncode: int
) -> None:
    env = {"GOTOOLCHAIN": "local", "CGO_ENABLED": "1", "TERM": "xterm-256color"}
    original_env = env.copy()
    event_loop_thread = threading.get_ident()

    def communicate() -> tuple[None, bytes]:
        assert threading.get_ident() != event_loop_thread
        return None, b"\x1b[31mWindows compiler failed\x1b[0m"

    process = SimpleNamespace(returncode=returncode, communicate=Mock(side_effect=communicate))
    popen = Mock(return_value=process)
    async_subprocess = AsyncMock(side_effect=NotImplementedError("selector loop"))
    monkeypatch.setattr(sidecar, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(sidecar.subprocess, "Popen", popen)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", async_subprocess)
    output = tmp_path / "strix-tui.exe"

    if returncode:
        with pytest.raises(RuntimeError, match="Windows compiler failed") as caught:
            await sidecar.build_tui_source(tmp_path, output, env)
        assert "\x1b" not in str(caught.value)
    else:
        await sidecar.build_tui_source(tmp_path, output, env)

    popen.assert_called_once_with(
        ["go", "build", "-o", str(output), "./cmd/strix-tui"],
        cwd=str(tmp_path),
        env={**original_env, "GOTOOLCHAIN": "auto", "CGO_ENABLED": "0"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    async_subprocess.assert_not_called()
    process.communicate.assert_called_once()
    assert env == original_env


@pytest.mark.asyncio
async def test_windows_source_build_cancellation_waits_for_process_and_pipe_reader(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    communicating = threading.Event()
    communication_finished = threading.Event()
    original_communicate = process.communicate

    def communicate() -> tuple[bytes, bytes]:
        communicating.set()
        try:
            return original_communicate()
        finally:
            communication_finished.set()

    monkeypatch.setattr(process, "communicate", communicate)
    monkeypatch.setattr(sidecar, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(sidecar.subprocess, "Popen", Mock(return_value=process))
    task = asyncio.create_task(sidecar.build_tui_source(tmp_path, tmp_path / "strix-tui.exe", {}))
    try:
        assert await asyncio.to_thread(communicating.wait, 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=2)
        assert process.returncode is not None
        assert communication_finished.is_set()
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=2)
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_runtime_finishes_source_build_before_launch_and_handshake(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runtime = _runtime()
    backend, child = socket.socketpair()
    build_started = asyncio.Event()
    finish_build = asyncio.Event()
    calls: list[str] = []
    outputs: list[Path] = []
    process = SimpleNamespace(returncode=0)

    async def build(_source: Path, output: Path, env: dict[str, str]) -> None:
        assert env["GOTOOLCHAIN"] == "local"
        outputs.append(output)
        calls.append("build")
        build_started.set()
        await finish_build.wait()
        output.write_bytes(b"compiled test executable")
        calls.append("built")

    async def launch(
        command: list[str], env: dict[str, str], cwd: str | None
    ) -> tuple[SimpleNamespace, socket.socket]:
        assert command == [str(outputs[0])]
        assert outputs[0].is_file()
        assert cwd is None
        assert env["GOTOOLCHAIN"] == "local"
        calls.append("launch")
        return process, backend

    async def ready(connection: socket.socket) -> None:
        assert connection is backend
        calls.append("ready")
        runtime.server.activated = True

    def prepare() -> None:
        calls.append("prepare")

    monkeypatch.setattr(runtime, "binary_command", lambda: ["go", "run", "./cmd/strix-tui"])
    monkeypatch.setattr(go_tui, "tui_source_dir", lambda: tmp_path)
    monkeypatch.setattr(go_tui, "child_environment", lambda: {"GOTOOLCHAIN": "local"})
    monkeypatch.setattr(go_tui, "build_tui_source", build)
    monkeypatch.setattr(go_tui, "launch_tui_process", launch)
    monkeypatch.setattr(go_tui, "wait_process", AsyncMock(return_value=0))
    monkeypatch.setattr(runtime.server, "start", ready)
    monkeypatch.setattr(runtime, "_start_preparation", prepare)
    task = asyncio.create_task(runtime.run())
    try:
        await asyncio.wait_for(build_started.wait(), timeout=2)
        assert calls == ["build"]
        finish_build.set()
        await asyncio.wait_for(task, timeout=2)
    finally:
        finish_build.set()
        child.close()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    assert calls == ["build", "built", "launch", "ready", "prepare"]
    assert not outputs[0].parent.exists()


@pytest.mark.asyncio
async def test_runtime_source_build_failure_does_not_launch_or_prepare_scan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runtime = _runtime()
    outputs: list[Path] = []

    async def fail_build(_source: Path, output: Path, _env: dict[str, str]) -> None:
        outputs.append(output)
        output.write_bytes(b"partial executable")
        raise RuntimeError("Go compiler could not build the TUI: requires go >= 1.24.0")

    launch = AsyncMock()
    handshake = AsyncMock()
    prepare = Mock()
    monkeypatch.setattr(runtime, "binary_command", lambda: ["go", "run", "./cmd/strix-tui"])
    monkeypatch.setattr(go_tui, "tui_source_dir", lambda: tmp_path)
    monkeypatch.setattr(go_tui, "build_tui_source", fail_build)
    monkeypatch.setattr(go_tui, "launch_tui_process", launch)
    monkeypatch.setattr(runtime.server, "start", handshake)
    monkeypatch.setattr(runtime, "_start_preparation", prepare)
    original_stdout, original_stderr = sys.stdout, sys.stderr

    with pytest.raises(go_tui.GoTuiPreActivationError, match=r"requires go >= 1\.24\.0"):
        await runtime.run()

    launch.assert_not_called()
    handshake.assert_not_called()
    prepare.assert_not_called()
    assert not outputs[0].parent.exists()
    assert sys.stdout is original_stdout
    assert sys.stderr is original_stderr

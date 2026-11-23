"""Regression tests for Windows named-pipe half-close handling on Docker exec sockets."""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import io
import socket
import struct
import sys
import threading
import uuid
from pathlib import PurePosixPath
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import MagicMock

import docker.transport as docker_transport
import pytest
from agents.sandbox.manifest import Manifest
from agents.sandbox.sandboxes.docker import (
    DockerSandboxClientOptions,
    DockerSandboxSession,
    DockerSandboxSessionState,
)
from agents.sandbox.snapshot import NoopSnapshot

from strix.runtime.docker_client import StrixDockerSandboxClient, StrixDockerSandboxSession


if TYPE_CHECKING:
    from collections.abc import Callable


def _docker_frame(payload: bytes, *, stream_id: int = 1) -> bytes:
    """Encode a non-TTY Docker multiplexed stream frame."""
    return struct.pack(">BxxxL", stream_id, len(payload)) + payload


def _build_session(
    *,
    api: Any,
    session_cls: type[DockerSandboxSession] = StrixDockerSandboxSession,
) -> DockerSandboxSession:
    container = MagicMock()
    container.id = "container-123"
    container.client = SimpleNamespace(api=api)
    state = DockerSandboxSessionState(
        session_id=uuid.uuid4(),
        manifest=Manifest(),
        image="ghcr.io/usestrix/strix-sandbox:latest",
        snapshot=NoopSnapshot(id="snap"),
        container_id="container-123",
    )
    return session_cls(docker_client=MagicMock(), container=container, state=state)


class _FakeAPI:
    def __init__(self, start_socket_fn: Callable[[str, bool], Any]) -> None:
        self._start_socket_fn = start_socket_fn
        self.exec_id = "exec-1234567890ab"
        self.calls = 0

    def exec_create(self, *_args: Any, **_kwargs: Any) -> dict[str, str]:
        return {"Id": self.exec_id}

    def exec_start(self, exec_id: str, *, socket: bool = True, tty: bool = False) -> Any:
        assert exec_id == self.exec_id
        assert socket is True
        self.calls += 1
        return self._start_socket_fn(exec_id, tty)

    def exec_inspect(self, exec_id: str) -> dict[str, Any]:
        assert exec_id == self.exec_id
        return {"Running": False, "ExitCode": 0}


@pytest.mark.asyncio
async def test_cross_platform_npipe_shutdown_preserves_exec_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``shutdown(SHUT_WR)`` on ``NpipeSocket`` must preserve exec output."""

    class FakeNpipeSocket:
        def __init__(self) -> None:
            self._closed = False
            self.shutdown_calls: list[int] = []
            self.sent: list[bytes] = []
            self.close_calls = 0
            self._payload = _docker_frame(b"workspace/query.py\n")
            self._offset = 0

        def close(self) -> None:
            self.close_calls += 1
            self._closed = True

        def shutdown(self, how: int) -> None:
            self.shutdown_calls.append(how)
            self.close()

        def recv_into(self, buf: Any, nbytes: int = 0) -> int:
            if self._closed:
                raise RuntimeError("Can not reuse socket after connection was closed.")
            if self._offset >= len(self._payload):
                return 0
            view = memoryview(buf)
            limit = nbytes if nbytes else len(view)
            chunk = self._payload[self._offset : self._offset + limit]
            view[: len(chunk)] = chunk
            self._offset += len(chunk)
            return len(chunk)

        def recv(self, nbytes: int) -> bytes:
            buf = bytearray(nbytes)
            read = self.recv_into(buf, nbytes)
            return bytes(buf[:read])

        def sendall(self, data: bytes) -> None:
            if self._closed:
                raise RuntimeError("Can not reuse socket after connection was closed.")
            self.sent.append(data)

    monkeypatch.setattr(docker_transport, "NpipeSocket", FakeNpipeSocket, raising=False)
    monkeypatch.setattr("docker.utils.socket.NpipeSocket", FakeNpipeSocket, raising=False)

    created_sockets: list[FakeNpipeSocket] = []

    def start_socket(_exec_id: str, _tty: bool) -> FakeNpipeSocket:
        sock = FakeNpipeSocket()
        created_sockets.append(sock)
        return sock

    session = _build_session(api=_FakeAPI(start_socket))
    update = await session.pty_exec_start("cat", "/workspace/query.py", tty=False, shell=False)

    assert update.exit_code == 0
    assert update.output == b"workspace/query.py\n"
    assert len(created_sockets) == 1
    assert created_sockets[0].close_calls == 1

    # Explicit non-WR shutdowns (e.g. SHUT_RDWR) still delegate to close().
    api = _FakeAPI(start_socket)
    extra_sock = session._start_exec_socket(api=api, exec_id=api.exec_id, tty=False)
    cast("Any", extra_sock.raw_sock).shutdown(socket.SHUT_RDWR)
    assert cast("Any", extra_sock.raw_sock)._closed is True


@pytest.mark.asyncio
async def test_stream_into_exec_on_npipe_does_not_abort_before_draining_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Write-side ``shutdown(SHUT_WR)`` must keep ``NpipeSocket`` readable."""

    class FakeNpipeSocket:
        def __init__(self) -> None:
            self._closed = False
            self._reply_chunks = [b"ok\n", b""]
            self.sent = bytearray()
            self.drained_after_shutdown = False
            self.close_calls = 0

        def sendall(self, data: bytes) -> None:
            self.sent.extend(data)

        def shutdown(self, _how: int) -> None:
            self.close()

        def recv(self, _size: int) -> bytes:
            if self._closed:
                raise RuntimeError("Can not reuse socket after connection was closed.")
            self.drained_after_shutdown = True
            return self._reply_chunks.pop(0) if self._reply_chunks else b""

        def close(self) -> None:
            self.close_calls += 1
            self._closed = True

    monkeypatch.setattr(docker_transport, "NpipeSocket", FakeNpipeSocket, raising=False)

    sock = FakeNpipeSocket()
    api = _FakeAPI(lambda _id, _tty: sock)
    session = _build_session(api=api)

    await session._stream_into_exec(
        cmd=["cat"],
        stream=io.BytesIO(b"hello"),
        error_path=cast("Any", PurePosixPath("/workspace/test.txt")),
    )

    assert bytes(sock.sent) == b"hello"
    assert sock.drained_after_shutdown is True
    assert sock.close_calls == 1


@pytest.mark.asyncio
async def test_interactive_tty_exec_and_stdin_over_npipe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Interactive ``tty=True`` + ``pty_write_stdin`` works cleanly over ``NpipeSocket``."""

    class FakeNpipeSocket:
        def __init__(self) -> None:
            self._closed = False
            self.sent: list[bytes] = []
            self._chunks = [b"prompt> ", b"2\r\n"]

        def recv_into(self, buf: Any, nbytes: int = 0) -> int:
            if self._closed:
                raise RuntimeError("Can not reuse socket after connection was closed.")
            if not self._chunks:
                return 0
            chunk = self._chunks.pop(0)
            view = memoryview(buf)
            limit = nbytes if nbytes else len(view)
            out = chunk[:limit]
            view[: len(out)] = out
            return len(out)

        def recv(self, nbytes: int) -> bytes:
            buf = bytearray(nbytes)
            read = self.recv_into(buf, nbytes)
            return bytes(buf[:read])

        def sendall(self, data: bytes) -> None:
            if self._closed:
                raise RuntimeError("Can not reuse socket after connection was closed.")
            self.sent.append(data)

        def shutdown(self, _how: int) -> None:
            self.close()

        def close(self) -> None:
            self._closed = True

    monkeypatch.setattr(docker_transport, "NpipeSocket", FakeNpipeSocket, raising=False)
    monkeypatch.setattr("docker.utils.socket.NpipeSocket", FakeNpipeSocket, raising=False)

    sock = FakeNpipeSocket()

    class RunningThenExitedAPI(_FakeAPI):
        def exec_inspect(self, exec_id: str) -> dict[str, Any]:
            assert exec_id == self.exec_id
            return {"Running": len(sock.sent) == 0, "ExitCode": 0 if sock.sent else None}

    session = _build_session(api=RunningThenExitedAPI(lambda _id, _tty: sock))
    start_update = await session.pty_exec_start("python3", tty=True, yield_time_s=0.1, shell=False)
    assert start_update.process_id is not None

    write_update = await session.pty_write_stdin(
        session_id=start_update.process_id,
        chars="print(1 + 1)\n",
        yield_time_s=0.2,
    )
    assert sock.sent == [b"print(1 + 1)\n"]
    assert b"prompt> " in start_update.output + write_update.output
    assert b"2\r\n" in start_update.output + write_update.output


def test_non_npipe_socket_retains_shutdown_behavior(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regular Unix/TCP sockets still receive ``shutdown(SHUT_WR)``."""

    class FakeNpipeSocket:
        pass

    class FakeTcpSocket:
        def __init__(self) -> None:
            self.shutdown_calls: list[int] = []

        def shutdown(self, how: int) -> None:
            self.shutdown_calls.append(how)

    monkeypatch.setattr(docker_transport, "NpipeSocket", FakeNpipeSocket, raising=False)

    tcp_sock = FakeTcpSocket()
    api = _FakeAPI(lambda _id, _tty: tcp_sock)
    exec_socket = StrixDockerSandboxSession._start_exec_socket(
        api=api,
        exec_id=api.exec_id,
        tty=False,
    )
    cast("Any", exec_socket.raw_sock).shutdown(socket.SHUT_WR)
    assert tcp_sock.shutdown_calls == [socket.SHUT_WR]


def test_missing_npipe_socket_attribute_on_non_windows_is_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Platforms without ``docker.transport.NpipeSocket`` skip wrapping without error."""

    class FakeUnixSocket:
        def __init__(self) -> None:
            self.shutdown_calls: list[int] = []

        def shutdown(self, how: int) -> None:
            self.shutdown_calls.append(how)

    monkeypatch.delattr(docker_transport, "NpipeSocket", raising=False)

    unix_sock = FakeUnixSocket()
    api = _FakeAPI(lambda _id, _tty: unix_sock)
    exec_socket = StrixDockerSandboxSession._start_exec_socket(
        api=api,
        exec_id=api.exec_id,
        tty=False,
    )
    cast("Any", exec_socket.raw_sock).shutdown(socket.SHUT_WR)
    assert unix_sock.shutdown_calls == [socket.SHUT_WR]


@pytest.mark.asyncio
async def test_client_create_and_resume_attach_strix_session_without_custom_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Client attaches ``StrixDockerSandboxSession`` even without a custom network."""
    monkeypatch.delenv("STRIX_DOCKER_SANDBOX_NETWORK", raising=False)

    docker_client = MagicMock()
    container = MagicMock()
    container.id = "ctr-abc"
    docker_client.images.get.return_value = MagicMock()
    docker_client.containers.create.return_value = container
    docker_client.containers.get.return_value = container

    client = StrixDockerSandboxClient(docker_client)
    created = await client.create(options=DockerSandboxClientOptions(image="strix:latest"))
    assert isinstance(created._inner, StrixDockerSandboxSession)
    assert created._inner.sandbox_network == ""

    # Exposed port resolution without custom sandbox_network must still use base host port logic.
    container.attrs = {
        "NetworkSettings": {"Ports": {"48080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "54321"}]}}
    }
    endpoint = await created._inner._resolve_exposed_port(48080)
    assert endpoint.host == "127.0.0.1"
    assert endpoint.port == 54321

    resumed = await client.resume(created._inner.state)
    assert isinstance(resumed._inner, StrixDockerSandboxSession)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows named pipes require pywin32 on win32")
@pytest.mark.asyncio
async def test_windows_real_npipe_pty_exec_preserves_output_and_closes_cleanly() -> None:
    """End-to-end test over a real Win32 named pipe + ``docker.transport.NpipeSocket``."""
    win32file = importlib.import_module("win32file")
    win32pipe = importlib.import_module("win32pipe")
    win_error = cast("type[Exception]", importlib.import_module("pywintypes").error)
    npipe_cls = docker_transport.NpipeSocket

    pipe_name = rf"\\.\pipe\strix-test-{uuid.uuid4().hex}"
    pipe_handle = win32pipe.CreateNamedPipe(
        pipe_name,
        win32pipe.PIPE_ACCESS_DUPLEX,
        win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_WAIT,
        1,
        65536,
        65536,
        0,
        None,
    )

    server_connected = threading.Event()
    proceed_to_send = threading.Event()
    server_errors: list[Exception] = []

    def _serve_pipe() -> None:
        try:
            win32pipe.ConnectNamedPipe(pipe_handle, None)
            server_connected.set()
            # Delay until after pty_exec_start has run raw_sock.shutdown(SHUT_WR),
            # matching real container command latency.
            proceed_to_send.wait(timeout=5.0)
            frame = _docker_frame(b"hello from container\n")
            win32file.WriteFile(pipe_handle, frame)
            win32file.FlushFileBuffers(pipe_handle)
        except (OSError, win_error) as exc:  # pragma: no cover - asserted below
            server_errors.append(exc)
        finally:
            with contextlib.suppress(OSError, win_error):
                win32pipe.DisconnectNamedPipe(pipe_handle)
            win32file.CloseHandle(pipe_handle)

    server_thread = threading.Thread(target=_serve_pipe, daemon=True)
    server_thread.start()

    created_sockets: list[Any] = []

    def start_socket(_exec_id: str, _tty: bool) -> Any:
        sock = npipe_cls()
        sock.connect(pipe_name)
        created_sockets.append(sock)
        # Wait until ConnectNamedPipe finishes, then schedule output after a brief
        # delay so pty_exec_start reaches raw_sock.shutdown(SHUT_WR) first.
        server_connected.wait(timeout=5.0)
        threading.Timer(0.05, proceed_to_send.set).start()
        return sock

    session = _build_session(api=_FakeAPI(start_socket))
    update = await asyncio.wait_for(
        session.pty_exec_start("cat", "/workspace/fixture/query.py", tty=False, shell=False),
        timeout=5.0,
    )
    server_thread.join(timeout=5.0)

    assert not server_errors
    assert update.exit_code == 0
    assert update.output == b"hello from container\n"
    assert len(created_sockets) == 1
    assert created_sockets[0]._closed is True

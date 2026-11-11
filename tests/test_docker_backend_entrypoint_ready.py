"""``_docker_backend`` must not return before the entrypoint is ready.

Issue #1704: the host marks a sandbox session "ready" as soon as
``session.start()`` returns, while the image's ``docker-entrypoint.sh`` is
still mid-bootstrap (Caido API poll, ``sleep 2``, profile writes to
``/etc/profile.d/proxy.sh`` / ``~/.bashrc`` / ``~/.zshrc``, NSS trust store).
The agent's first ``exec_command`` runs through ``sh -lc`` — a login shell
that sources ``/etc/profile`` (hence ``/etc/profile.d/proxy.sh``) — so it
can land on partially-written profile files.

The gate is the entrypoint's final readiness line, ``"✅ Container
ready"``, read from the container logs: no ``exec`` into the container is
needed to observe it, so the wait itself cannot race the bootstrap.
"""

from __future__ import annotations

import asyncio
import threading
import time
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from agents.sandbox.manifest import Manifest

from strix.runtime import backends
from strix.runtime.backends import _docker_backend


_MARKER = "✅ Container ready"


class _FakeContainer:
    """Container whose logs gain the readiness marker after ``delay_s``."""

    def __init__(self, *, delay_s: float = 0.6, marker: str = _MARKER) -> None:
        self._started = time.monotonic()
        self._delay_s = delay_s
        self._marker = marker
        self.status = "running"
        self.logs_calls = 0

    def logs(self, **_kwargs: Any) -> bytes:
        self.logs_calls += 1
        if time.monotonic() - self._started >= self._delay_s:
            return (
                f"Started Caido with PID 42\nCaido API is ready (attempt 1).\n{self._marker}\n"
            ).encode()
        return b"Started Caido with PID 42\nWaiting for Caido API to be ready...\n"

    def reload(self) -> None:
        return None


class _DeadContainer(_FakeContainer):
    """Container that exits before ever printing the readiness marker."""

    def __init__(self) -> None:
        super().__init__(delay_s=10**9)
        self.status = "exited"

    def logs(self, **_kwargs: Any) -> bytes:
        self.logs_calls += 1
        return b"ERROR: Caido process died while waiting for API (iteration 1).\n"


def _fake_session() -> Any:
    session = SimpleNamespace()
    session.start = AsyncMock()
    session._inner = SimpleNamespace(state=SimpleNamespace(container_id="abc123"))
    return session


def _fake_client(fake_container: _FakeContainer, session: Any) -> MagicMock:
    client = MagicMock()
    client.create = AsyncMock(return_value=session)
    client.delete = AsyncMock()
    client.docker_client.containers.get.return_value = fake_container
    return client


@pytest.mark.asyncio
async def test_backend_waits_for_entrypoint_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    """The backend returns only after the entrypoint prints its ready line.

    Pre-fix this fails: ``_docker_backend`` returns the instant
    ``session.start()`` does, ~0.6 s before the marker appears.
    """
    monkeypatch.setenv("STRIX_SANDBOX_ENTRYPOINT_READY_POLL_S", "0.05")
    container = _FakeContainer(delay_s=0.6)
    session = _fake_session()
    client = _fake_client(container, session)

    started = time.monotonic()
    with (
        patch("strix.runtime.docker_client.StrixDockerSandboxClient", return_value=client),
        patch("strix.runtime.docker_connection.connect_docker", return_value=MagicMock()),
    ):
        returned_client, returned_session = await _docker_backend(
            image="ghcr.io/usestrix/strix-sandbox:1.3.0",
            manifest=Manifest(),
            exposed_ports=(48080,),
        )
    elapsed = time.monotonic() - started

    assert returned_client is client
    assert returned_session is session
    session.start.assert_awaited_once()
    assert container.logs_calls >= 1
    assert elapsed >= 0.6, f"backend returned after {elapsed:.2f}s, before the entrypoint was ready"


@pytest.mark.asyncio
async def test_backend_returns_promptly_when_entrypoint_already_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A container that already printed the marker adds no waiting."""
    monkeypatch.setenv("STRIX_SANDBOX_ENTRYPOINT_READY_POLL_S", "0.05")
    container = _FakeContainer(delay_s=0.0)
    session = _fake_session()
    client = _fake_client(container, session)

    started = time.monotonic()
    with (
        patch("strix.runtime.docker_client.StrixDockerSandboxClient", return_value=client),
        patch("strix.runtime.docker_connection.connect_docker", return_value=MagicMock()),
    ):
        await _docker_backend(
            image="ghcr.io/usestrix/strix-sandbox:1.3.0",
            manifest=Manifest(),
            exposed_ports=(48080,),
        )
    assert time.monotonic() - started < 2.0


@pytest.mark.asyncio
async def test_backend_proceeds_with_warning_when_entrypoint_never_reports_ready(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Fail-open on timeout: a custom image without the marker must not hang
    scans forever — the wait gives up (loudly) and the session is returned."""
    monkeypatch.setenv("STRIX_SANDBOX_ENTRYPOINT_READY_TIMEOUT_S", "0.3")
    monkeypatch.setenv("STRIX_SANDBOX_ENTRYPOINT_READY_POLL_S", "0.05")
    container = _FakeContainer(delay_s=10**9)
    session = _fake_session()
    client = _fake_client(container, session)

    started = time.monotonic()
    with (
        patch("strix.runtime.docker_client.StrixDockerSandboxClient", return_value=client),
        patch("strix.runtime.docker_connection.connect_docker", return_value=MagicMock()),
        caplog.at_level("WARNING"),
    ):
        returned_session = (
            await _docker_backend(
                image="custom-image:latest",
                manifest=Manifest(),
                exposed_ports=(48080,),
            )
        )[1]
    elapsed = time.monotonic() - started

    assert returned_session is session
    assert 0.3 <= elapsed < 5.0
    assert "did not report ready" in caplog.text


@pytest.mark.asyncio
async def test_backend_raises_when_container_exits_before_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An entrypoint that dies (e.g. Caido never comes up) must fail fast
    with the log tail, instead of waiting out the whole timeout and then
    handing back a dead container."""
    monkeypatch.setenv("STRIX_SANDBOX_ENTRYPOINT_READY_TIMEOUT_S", "30")
    monkeypatch.setenv("STRIX_SANDBOX_ENTRYPOINT_READY_POLL_S", "0.05")
    container = _DeadContainer()
    session = _fake_session()
    client = _fake_client(container, session)

    started = time.monotonic()
    with (
        patch("strix.runtime.docker_client.StrixDockerSandboxClient", return_value=client),
        patch("strix.runtime.docker_connection.connect_docker", return_value=MagicMock()),
        pytest.raises(RuntimeError, match="exited before its entrypoint reported ready"),
    ):
        await _docker_backend(
            image="ghcr.io/usestrix/strix-sandbox:1.3.0",
            manifest=Manifest(),
            exposed_ports=(48080,),
        )
    assert time.monotonic() - started < 5.0


@pytest.mark.asyncio
async def test_backend_deletes_session_when_container_exits_before_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P1 (Greptile review of #1733): the early-exit error must not strand
    the stopped container — the backend deletes the session and closes
    the Docker client before re-raising, because the caller never got
    the client/session back to cache for ``cleanup(scan_id)``.

    Pre-fix this fails: ``client.delete`` is never awaited.
    """
    monkeypatch.setenv("STRIX_SANDBOX_ENTRYPOINT_READY_TIMEOUT_S", "30")
    monkeypatch.setenv("STRIX_SANDBOX_ENTRYPOINT_READY_POLL_S", "0.05")
    container = _DeadContainer()
    session = _fake_session()
    client = _fake_client(container, session)

    with (
        patch("strix.runtime.docker_client.StrixDockerSandboxClient", return_value=client),
        patch("strix.runtime.docker_connection.connect_docker", return_value=MagicMock()),
        pytest.raises(RuntimeError, match="exited before its entrypoint reported ready"),
    ):
        await _docker_backend(
            image="ghcr.io/usestrix/strix-sandbox:1.3.0",
            manifest=Manifest(),
            exposed_ports=(48080,),
        )

    client.delete.assert_awaited_once_with(session)
    client.docker_client.close.assert_called_once_with()


@pytest.mark.asyncio
async def test_backend_deletes_session_when_wait_is_cancelled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P1 (Greptile review of #1733): quitting mid-wait must not leave the
    sandbox running — a cancelled wait deletes the session and closes
    the Docker client before the CancelledError propagates.

    Pre-fix this fails: ``client.delete`` is never awaited.
    """
    monkeypatch.setenv("STRIX_SANDBOX_ENTRYPOINT_READY_TIMEOUT_S", "30")
    monkeypatch.setenv("STRIX_SANDBOX_ENTRYPOINT_READY_POLL_S", "0.05")
    container = _FakeContainer(delay_s=10**9)
    session = _fake_session()
    client = _fake_client(container, session)

    async def _run() -> tuple[Any, Any]:
        with (
            patch(
                "strix.runtime.docker_client.StrixDockerSandboxClient",
                return_value=client,
            ),
            patch(
                "strix.runtime.docker_connection.connect_docker",
                return_value=MagicMock(),
            ),
        ):
            return await _docker_backend(
                image="ghcr.io/usestrix/strix-sandbox:1.3.0",
                manifest=Manifest(),
                exposed_ports=(48080,),
            )

    task = asyncio.create_task(_run())
    await asyncio.sleep(0.2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    client.delete.assert_awaited_once_with(session)
    client.docker_client.close.assert_called_once_with()


@pytest.mark.asyncio
async def test_backend_skips_wait_when_timeout_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``STRIX_SANDBOX_ENTRYPOINT_READY_TIMEOUT_S<=0`` disables the wait."""
    monkeypatch.setenv("STRIX_SANDBOX_ENTRYPOINT_READY_TIMEOUT_S", "0")
    container = _FakeContainer(delay_s=10**9)
    session = _fake_session()
    client = _fake_client(container, session)

    with (
        patch("strix.runtime.docker_client.StrixDockerSandboxClient", return_value=client),
        patch("strix.runtime.docker_connection.connect_docker", return_value=MagicMock()),
    ):
        await _docker_backend(
            image="custom-image:latest",
            manifest=Manifest(),
            exposed_ports=(48080,),
        )
    assert container.logs_calls == 0


@pytest.mark.asyncio
async def test_backend_proceeds_when_container_cannot_be_fetched(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """If the daemon cannot hand back the container, log and proceed rather
    than failing a session that may be perfectly usable."""
    monkeypatch.setenv("STRIX_SANDBOX_ENTRYPOINT_READY_POLL_S", "0.05")
    session = _fake_session()
    client = MagicMock()
    client.create = AsyncMock(return_value=session)
    client.docker_client.containers.get.side_effect = RuntimeError("daemon gone")

    with (
        patch("strix.runtime.docker_client.StrixDockerSandboxClient", return_value=client),
        patch("strix.runtime.docker_connection.connect_docker", return_value=MagicMock()),
        caplog.at_level("WARNING"),
    ):
        returned_session = (
            await _docker_backend(
                image="ghcr.io/usestrix/strix-sandbox:1.3.0",
                manifest=Manifest(),
                exposed_ports=(48080,),
            )
        )[1]

    assert returned_session is session
    assert "Could not fetch sandbox container" in caplog.text


class _ReloadBlockingContainer(_FakeContainer):
    """Container whose first log read lacks the marker and whose reload blocks
    until released (simulates a slow daemon response mid-poll)."""

    def __init__(self) -> None:
        super().__init__(delay_s=10**9)
        self.reload_started = threading.Event()
        self.release_reload = threading.Event()

    def logs(self, **_kwargs: Any) -> bytes:
        self.logs_calls += 1
        if self.logs_calls >= 2:
            return f"Caido API is ready (attempt 1).\n{_MARKER}\n".encode()
        return b"Started Caido with PID 42\nWaiting for Caido API to be ready...\n"

    def reload(self) -> None:
        self.reload_started.set()
        assert self.release_reload.wait(timeout=5), "reload was never released"


class _StallingLogsContainer(_FakeContainer):
    """Container whose log reads stall (simulates a slow remote daemon)."""

    def logs(self, **_kwargs: Any) -> bytes:
        self.logs_calls += 1
        time.sleep(2)
        return b"Started Caido with PID 42\nWaiting for Caido API to be ready...\n"


def _run_block_probe(
    block_started: threading.Event, probe_ran: threading.Event, result: list[bool]
) -> None:
    """Observer thread: once a Docker call blocks, the event-loop probe must
    still fire within 1 s. This runs in its own thread because a blocked
    event loop cannot observe anything itself — a probe awaited from the
    test coroutine would only run after the block ends, which proves
    nothing (the pre-fix code swallows the block's timeout error and
    fails open, so such a test passes vacuously)."""
    if not block_started.wait(timeout=5):
        result.append(False)
        return
    result.append(probe_ran.wait(timeout=1.0))


async def _run_responsiveness_probe(
    block_started: threading.Event,
    release_block: threading.Event,
    wait_task: asyncio.Task[None],
) -> None:
    """Assert another task can run while a Docker call is blocked, then
    release the block and await the wait's completion."""
    probe_ran = threading.Event()
    probe_result: list[bool] = []
    observer = threading.Thread(
        target=_run_block_probe, args=(block_started, probe_ran, probe_result), daemon=True
    )
    observer.start()

    async def probe() -> None:
        await asyncio.sleep(0)
        probe_ran.set()

    probe_task = asyncio.create_task(probe())
    await asyncio.wait_for(asyncio.to_thread(observer.join), timeout=10)
    await probe_task
    assert probe_result and probe_result[0], "event loop stalled while a Docker request was blocked"
    release_block.set()
    await asyncio.wait_for(wait_task, timeout=5)


@pytest.mark.asyncio
async def test_blocked_container_lookup_does_not_stall_event_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P2 (Greptile review of #1733): the synchronous ``containers.get()``
    must run in a worker thread, so the TUI can still act on quit requests
    while the daemon is slow."""
    monkeypatch.setenv("STRIX_SANDBOX_ENTRYPOINT_READY_TIMEOUT_S", "30")
    monkeypatch.setenv("STRIX_SANDBOX_ENTRYPOINT_READY_POLL_S", "0.05")
    container = _FakeContainer(delay_s=0.0)
    session = _fake_session()
    client = _fake_client(container, session)
    lookup_started = threading.Event()
    release_lookup = threading.Event()

    def blocking_get(_container_id: str) -> _FakeContainer:
        lookup_started.set()
        assert release_lookup.wait(timeout=5), "lookup was never released"
        return container

    client.docker_client.containers.get = blocking_get

    wait_task = asyncio.create_task(
        backends._wait_for_entrypoint_ready(client, session)  # pyright: ignore[reportPrivateUsage]
    )
    await _run_responsiveness_probe(lookup_started, release_lookup, wait_task)


@pytest.mark.asyncio
async def test_blocked_container_reload_does_not_stall_event_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P2 (Greptile review of #1733): the synchronous ``container.reload()``
    must run in a worker thread, like ``container.logs`` already does."""
    monkeypatch.setenv("STRIX_SANDBOX_ENTRYPOINT_READY_TIMEOUT_S", "30")
    monkeypatch.setenv("STRIX_SANDBOX_ENTRYPOINT_READY_POLL_S", "0.05")
    container = _ReloadBlockingContainer()
    session = _fake_session()
    client = _fake_client(container, session)

    wait_task = asyncio.create_task(
        backends._wait_for_entrypoint_ready(client, session)  # pyright: ignore[reportPrivateUsage]
    )
    await _run_responsiveness_probe(container.reload_started, container.release_reload, wait_task)
    assert container.logs_calls >= 2


@pytest.mark.asyncio
async def test_wait_returns_within_timeout_when_log_request_stalls(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """P2 (Greptile review of #1733): a log request that outlasts the
    timeout must not hold startup — the wait gives up at the deadline
    instead of waiting out the stalled request.

    Pre-fix this fails: the wait holds startup for the full ~2 s stall.
    """
    monkeypatch.setenv("STRIX_SANDBOX_ENTRYPOINT_READY_TIMEOUT_S", "0.3")
    monkeypatch.setenv("STRIX_SANDBOX_ENTRYPOINT_READY_POLL_S", "0.05")
    container = _StallingLogsContainer(delay_s=10**9)
    session = _fake_session()
    client = _fake_client(container, session)

    started = time.monotonic()
    with (
        patch("strix.runtime.docker_client.StrixDockerSandboxClient", return_value=client),
        patch("strix.runtime.docker_connection.connect_docker", return_value=MagicMock()),
        caplog.at_level("WARNING"),
    ):
        await _docker_backend(
            image="ghcr.io/usestrix/strix-sandbox:1.3.0",
            manifest=Manifest(),
            exposed_ports=(48080,),
        )
    elapsed = time.monotonic() - started

    assert elapsed < 1.0, f"wait held startup for {elapsed:.2f}s past the 0.3s timeout"
    assert "did not report ready" in caplog.text


@pytest.mark.asyncio
async def test_wait_returns_within_timeout_when_poll_exceeds_timeout(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """P2 (Greptile review of #1733): a poll interval longer than the
    timeout must not delay the return until that full interval passes.

    Pre-fix this fails: the wait sleeps the whole 5 s poll interval.
    """
    monkeypatch.setenv("STRIX_SANDBOX_ENTRYPOINT_READY_TIMEOUT_S", "0.3")
    monkeypatch.setenv("STRIX_SANDBOX_ENTRYPOINT_READY_POLL_S", "5")
    container = _FakeContainer(delay_s=10**9)
    session = _fake_session()
    client = _fake_client(container, session)

    started = time.monotonic()
    with (
        patch("strix.runtime.docker_client.StrixDockerSandboxClient", return_value=client),
        patch("strix.runtime.docker_connection.connect_docker", return_value=MagicMock()),
        caplog.at_level("WARNING"),
    ):
        await _docker_backend(
            image="ghcr.io/usestrix/strix-sandbox:1.3.0",
            manifest=Manifest(),
            exposed_ports=(48080,),
        )
    elapsed = time.monotonic() - started

    assert elapsed < 1.5, f"wait held startup for {elapsed:.2f}s past the 0.3s timeout"
    assert "did not report ready" in caplog.text

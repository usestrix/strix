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

import inspect
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


# Keep the event loop honest: the wait polls in a worker thread via
# asyncio.to_thread, so a stuck docker-py call cannot wedge the loop.
def test_wait_uses_worker_thread() -> None:
    source = inspect.getsource(backends._wait_for_entrypoint_ready)
    assert "to_thread" in source
    assert "asyncio.sleep" in source

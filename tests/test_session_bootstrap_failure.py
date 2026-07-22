"""create_or_reuse must reap the container it started if bootstrap then fails."""

from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING, Any

import pytest

from strix.runtime import session_manager


if TYPE_CHECKING:
    from collections.abc import Iterator


class _FakeClient:
    def __init__(self, *, gate: asyncio.Event | None = None) -> None:
        self.deleted: list[object] = []
        self.docker_client = None
        self.delete_started = asyncio.Event()
        self._gate = gate

    async def delete(self, session: object) -> None:
        self.delete_started.set()
        if self._gate is not None:
            await self._gate.wait()
        self.deleted.append(session)


class _FakeSession:
    def __init__(self, *, port_error: Exception | None = None) -> None:
        self.port_error = port_error

    async def resolve_exposed_port(self, _port: int) -> Any:
        if self.port_error is not None:
            raise self.port_error
        raise AssertionError("unreachable in these tests")


@pytest.fixture(autouse=True)
def _clear_cache() -> Iterator[None]:
    session_manager._SESSION_CACHE.clear()
    yield
    session_manager._SESSION_CACHE.clear()


def _patch_backend(
    monkeypatch: pytest.MonkeyPatch,
    client: _FakeClient,
    session: _FakeSession,
) -> None:
    async def _backend(**_kwargs: Any) -> tuple[_FakeClient, _FakeSession]:
        return client, session

    monkeypatch.setattr(session_manager, "get_backend", lambda _name: _backend)


@pytest.mark.asyncio
async def test_container_is_deleted_when_port_resolution_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient()
    session = _FakeSession(port_error=TimeoutError("port never exposed"))
    _patch_backend(monkeypatch, client, session)

    with pytest.raises(TimeoutError, match="port never exposed"):
        await session_manager.create_or_reuse("scan-1", image="img", local_sources=[])

    assert client.deleted == [session], "started container was never reaped"
    assert "scan-1" not in session_manager._SESSION_CACHE


@pytest.mark.asyncio
async def test_container_is_deleted_when_caido_bootstrap_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient()
    session = _FakeSession()

    class _Endpoint:
        tls = False
        host = "127.0.0.1"
        port = 48080

    async def _resolve(_port: int) -> _Endpoint:
        return _Endpoint()

    monkeypatch.setattr(session, "resolve_exposed_port", _resolve)

    async def _bootstrap(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("caido guest login failed after 10 attempts")

    _patch_backend(monkeypatch, client, session)
    monkeypatch.setattr(session_manager, "bootstrap_caido", _bootstrap)

    with pytest.raises(RuntimeError, match="caido guest login failed"):
        await session_manager.create_or_reuse("scan-2", image="img", local_sources=[])

    assert client.deleted == [session], "started container was never reaped"
    assert "scan-2" not in session_manager._SESSION_CACHE


@pytest.mark.asyncio
async def test_container_is_deleted_even_when_teardown_is_cancelled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cancel landing mid-teardown must not abandon the container.

    Nothing else can reap it: it was never cached, so cleanup() is a no-op.
    """
    gate = asyncio.Event()
    client = _FakeClient(gate=gate)
    session = _FakeSession(port_error=TimeoutError("port never exposed"))
    _patch_backend(monkeypatch, client, session)

    task = asyncio.create_task(
        session_manager.create_or_reuse("scan-3", image="img", local_sources=[]),
    )
    await client.delete_started.wait()  # we are now inside client.delete

    task.cancel()  # second cancellation, arriving during teardown
    gate.set()  # let the delete finish

    with contextlib.suppress(asyncio.CancelledError, TimeoutError):
        await task
    for _ in range(10):  # let the shielded delete run to completion
        await asyncio.sleep(0)

    assert client.deleted == [session], "container abandoned when teardown was cancelled"
    assert "scan-3" not in session_manager._SESSION_CACHE


@pytest.mark.asyncio
async def test_cleanup_is_a_noop_for_an_unknown_scan() -> None:
    # Guards the reason the leak was invisible: cleanup only reaps cached bundles.
    await session_manager.cleanup("never-created")

"""A bootstrap that dies mid-setup must not leave its transport behind.

The bootstrap now runs concurrently with the scan start, so teardown can
cancel it at any await — including inside ``Client.connect()``, where the
client exists but no caller will ever see it to close it.
"""

from __future__ import annotations

import asyncio
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from strix.runtime.caido_bootstrap import bootstrap_caido
from strix.tools.proxy.caido_api import ACCESS_TOKEN_PATH


class _FakeExecResult:
    stderr = b""
    exit_code = 0

    def __init__(self, stdout: str) -> None:
        self.stdout = stdout

    def ok(self) -> bool:
        return True


class _FakeSession:
    async def exec(self, *_args: Any, **_kwargs: Any) -> _FakeExecResult:
        return _FakeExecResult('{"data":{"loginAsGuest":{"token":{"accessToken":"t"}}}}')


class _FakeClient:
    def __init__(self, connect_error: BaseException) -> None:
        self.connect_error = connect_error
        self.closed = False

    async def connect(self) -> None:
        raise self.connect_error

    async def aclose(self) -> None:
        self.closed = True


def _install_guest_sdk(monkeypatch: pytest.MonkeyPatch, client: Any) -> None:
    sdk = types.ModuleType("caido_sdk_client")
    sdk.Client = lambda *_a, **_k: client  # type: ignore[attr-defined]
    sdk.TokenAuthOptions = lambda token: token  # type: ignore[attr-defined]
    sdk.ConsoleLogger = lambda: None  # type: ignore[attr-defined]
    sdk_types = types.ModuleType("caido_sdk_client.types")
    sdk_types.CreateProjectOptions = lambda **_k: None  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "caido_sdk_client", sdk)
    monkeypatch.setitem(sys.modules, "caido_sdk_client.types", sdk_types)


async def _bootstrap_expecting(
    monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> _FakeClient:
    """Run a bootstrap whose ``connect()`` fails with ``error``."""
    client = _FakeClient(error)
    _install_guest_sdk(monkeypatch, client)
    with pytest.raises(type(error)):
        await bootstrap_caido(
            _FakeSession(),  # type: ignore[arg-type]
            host_url="http://host",
            container_url="http://container",
        )
    return client


async def test_cancellation_during_connect_closes_the_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = await _bootstrap_expecting(monkeypatch, asyncio.CancelledError())
    assert client.closed


async def test_failed_connect_closes_the_client(monkeypatch: pytest.MonkeyPatch) -> None:
    client = await _bootstrap_expecting(monkeypatch, RuntimeError("no listener"))
    assert client.closed


class _RecordingSession:
    def __init__(self) -> None:
        self.writes: list[tuple[Any, bytes]] = []

    async def exec(self, *_args: Any, **_kwargs: Any) -> _FakeExecResult:
        return _FakeExecResult("")

    async def write(self, path: Any, data: Any) -> None:
        self.writes.append((path, data.read()))


def _install_pat_sdk(
    monkeypatch: pytest.MonkeyPatch,
    client: Any,
    seen: dict[str, Any],
) -> None:
    def pat_auth(*, pat: str, cache: Any = None) -> Any:
        seen["pat"] = pat
        seen["cache"] = cache
        return types.SimpleNamespace(pat=pat, cache=cache)

    sdk = types.ModuleType("caido_sdk_client")
    sdk.Client = lambda *_a, **_k: client  # type: ignore[attr-defined]
    sdk.PATAuthOptions = pat_auth  # type: ignore[attr-defined]
    sdk.ConsoleLogger = lambda: None  # type: ignore[attr-defined]
    sdk_types = types.ModuleType("caido_sdk_client.types")
    sdk_types.CreateProjectOptions = lambda **_k: None  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "caido_sdk_client", sdk)
    monkeypatch.setitem(sys.modules, "caido_sdk_client.types", sdk_types)


async def test_pat_login_publishes_the_access_token_into_the_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _RecordingSession()
    seen: dict[str, Any] = {}

    class _Project:
        async def create(self, _options: Any) -> Any:
            return types.SimpleNamespace(id="project-1")

        async def select(self, _project_id: str) -> None:
            return None

    class _Client:
        project = _Project()

        async def connect(self) -> None:
            await seen["cache"].save(types.SimpleNamespace(access_token="access-token"))  # noqa: S106

        async def aclose(self) -> None:
            return None

    client = _Client()
    _install_pat_sdk(monkeypatch, client, seen)

    await bootstrap_caido(
        session,  # type: ignore[arg-type]
        host_url="http://host",
        container_url="http://container",
        pat="caido_pat",
    )

    assert seen["pat"] == "caido_pat"
    assert await seen["cache"].load() is None
    assert session.writes == [(Path(ACCESS_TOKEN_PATH), b"access-token")]


async def test_failed_pat_login_closes_the_client(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Client:
        closed = False

        async def connect(self) -> None:
            raise RuntimeError("pat rejected")

        async def aclose(self) -> None:
            self.closed = True

    client = _Client()
    _install_pat_sdk(monkeypatch, client, {})

    with pytest.raises(RuntimeError, match="pat rejected"):
        await bootstrap_caido(
            _RecordingSession(),  # type: ignore[arg-type]
            host_url="http://host",
            container_url="http://container",
            pat="caido_pat",
        )

    assert client.closed is True

"""A bootstrap that dies mid-setup must not leave its transport behind.

The bootstrap now runs concurrently with the scan start, so teardown can
cancel it at any await — including inside ``Client.connect()``, where the
client exists but no caller will ever see it to close it.
"""

from __future__ import annotations

import asyncio
import sys
import types
from typing import Any

import pytest

from strix.runtime.caido_bootstrap import bootstrap_caido, start_proxy_fallback


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


async def _bootstrap_expecting(
    monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> _FakeClient:
    """Run a bootstrap whose ``connect()`` fails with ``error``."""
    client = _FakeClient(error)
    # The SDK is imported inside bootstrap_caido (it is slow to import), so the
    # fakes are injected as the modules it imports.
    sdk = types.ModuleType("caido_sdk_client")
    sdk.Client = lambda *_a, **_k: client  # type: ignore[attr-defined]
    sdk.TokenAuthOptions = lambda token: token  # type: ignore[attr-defined]
    sdk_types = types.ModuleType("caido_sdk_client.types")
    sdk_types.CreateProjectOptions = lambda **_k: None  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "caido_sdk_client", sdk)
    monkeypatch.setitem(sys.modules, "caido_sdk_client.types", sdk_types)

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
        self.script = ""

    async def exec(self, *args: Any, **_kwargs: Any) -> _FakeExecResult:
        self.script = args[-1]
        return _FakeExecResult("")


async def test_fallback_goes_direct_without_an_upstream() -> None:
    session = _RecordingSession()
    assert await start_proxy_fallback(session, port=48080)  # type: ignore[arg-type]
    assert "pkill -x caido-cli" in session.script
    assert "mitmdump -q --listen-host 127.0.0.1 -p 48080 --ignore-hosts" in session.script
    assert "ncat -l 127.0.0.1 48080 -k --proxy-type http --allow 127.0.0.1" in session.script


async def test_fallback_only_relays_to_the_upstream() -> None:
    session = _RecordingSession()
    await start_proxy_fallback(session, port=48080, upstream="127.0.0.1:3128")  # type: ignore[arg-type]
    assert "ncat -l 127.0.0.1 48080 -k --sh-exec 'ncat 127.0.0.1 3128'" in session.script
    assert "mitmdump" not in session.script


async def test_fallback_rejects_a_malformed_upstream() -> None:
    session = _RecordingSession()
    with pytest.raises(ValueError, match="upstream"):
        await start_proxy_fallback(session, port=48080, upstream="x; rm -rf /")  # type: ignore[arg-type]
    assert session.script == ""

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

from strix.runtime.caido_bootstrap import bootstrap_caido


# A fake GraphQL loginAsGuest response for the session doubles below; not a secret.
_TOKEN_STDOUT = '{"data":{"loginAsGuest":{"token":{"accessToken":"t"}}}}'  # noqa: S105


class _FakeExecResult:
    def __init__(
        self, stdout: str, *, ok: bool = True, exit_code: int = 0, stderr: bytes = b""
    ) -> None:
        self.stdout = stdout
        self._ok = ok
        self.exit_code = exit_code
        self.stderr = stderr

    def ok(self) -> bool:
        return self._ok


class _FakeSession:
    async def exec(self, *_args: Any, **_kwargs: Any) -> _FakeExecResult:
        return _FakeExecResult(_TOKEN_STDOUT)


class _SlowCaidoSession:
    """Refuses the guest login ``refusals`` times, then returns a token — the
    shape of a Caido slow to bind because the UID-remap chown is still running."""

    def __init__(self, refusals: int) -> None:
        self.refusals = refusals
        self.calls = 0

    async def exec(self, *_args: Any, **_kwargs: Any) -> _FakeExecResult:
        self.calls += 1
        if self.calls <= self.refusals:
            return _FakeExecResult("", ok=False, exit_code=7, stderr=b"connection refused")
        return _FakeExecResult(_TOKEN_STDOUT)


class _OkProjectApi:
    async def create(self, _opts: Any) -> Any:
        return types.SimpleNamespace(id="pid")

    async def select(self, _id: str) -> None:
        return None


class _OkClient:
    def __init__(self) -> None:
        self.project = _OkProjectApi()
        self.closed = False

    async def connect(self) -> None:
        return None

    async def aclose(self) -> None:
        self.closed = True


def _inject_sdk(monkeypatch: pytest.MonkeyPatch, client: Any) -> None:
    sdk = types.ModuleType("caido_sdk_client")
    sdk.Client = lambda *_a, **_k: client  # type: ignore[attr-defined]
    sdk.TokenAuthOptions = lambda token: token  # type: ignore[attr-defined]
    sdk_types = types.ModuleType("caido_sdk_client.types")
    sdk_types.CreateProjectOptions = lambda **_k: None  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "caido_sdk_client", sdk)
    monkeypatch.setitem(sys.modules, "caido_sdk_client.types", sdk_types)


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
    _inject_sdk(monkeypatch, client)

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


async def test_login_waits_out_a_slow_caido(monkeypatch: pytest.MonkeyPatch) -> None:
    """A Caido that only binds after many refusals (e.g. still behind the
    UID-remap chown) is waited out, not abandoned, within the default budget."""

    async def _no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", _no_sleep)
    client = _OkClient()
    _inject_sdk(monkeypatch, client)
    session = _SlowCaidoSession(refusals=25)

    result = await bootstrap_caido(
        session,  # type: ignore[arg-type]
        host_url="http://host",
        container_url="http://container",
    )

    assert result is client
    assert session.calls == 26  # 25 refusals, then the guest token


async def test_login_gives_up_after_the_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """The readiness probe stays bounded: a Caido that never binds raises
    rather than hanging forever."""
    monkeypatch.setenv("STRIX_CAIDO_BOOTSTRAP_TIMEOUT", "0.05")
    _inject_sdk(monkeypatch, _OkClient())
    session = _SlowCaidoSession(refusals=10**9)  # never returns a token

    with pytest.raises(RuntimeError, match="loginAsGuest failed"):
        await bootstrap_caido(
            session,  # type: ignore[arg-type]
            host_url="http://host",
            container_url="http://container",
        )

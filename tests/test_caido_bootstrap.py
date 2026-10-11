"""Tests for the Caido readiness deadline."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
import sys
import types
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

import pytest

from strix.runtime import caido_bootstrap


if TYPE_CHECKING:
    from agents.sandbox.session import BaseSandboxSession


@dataclass
class _ExecResult:
    success: bool
    stdout: str = ""
    stderr: bytes = b"connection refused"
    exit_code: int = 7

    def ok(self) -> bool:
        return self.success


class _Session:
    def __init__(self, results: list[_ExecResult]) -> None:
        self._results = iter(results)
        self.calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []

    async def exec(self, *args: str, **kwargs: Any) -> _ExecResult:
        self.calls.append((args, kwargs))
        return next(self._results)


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    async def sleep(self, delay: float) -> None:
        self.sleeps.append(delay)
        self.now += delay


def _install_clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    clock = _Clock()
    monkeypatch.setattr("strix.runtime.caido_bootstrap.time.monotonic", clock.monotonic)
    monkeypatch.setattr("strix.runtime.caido_bootstrap.asyncio.sleep", clock.sleep)
    return clock


@pytest.mark.asyncio
async def test_login_as_guest_retries_until_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _install_clock(monkeypatch)
    session = _Session(
        [
            _ExecResult(success=False),
            _ExecResult(
                success=True,
                stdout='{"data":{"loginAsGuest":{"token":{"accessToken":"token"}}}}',
            ),
        ]
    )

    token = await caido_bootstrap._login_as_guest(
        cast("BaseSandboxSession", session),
        container_url="http://127.0.0.1:48080",
        wait_timeout_s=10,
    )

    assert token == "token"  # noqa: S105 - synthetic token fixture
    assert clock.sleeps == [2.0]
    assert [call[1]["timeout"] for call in session.calls] == [10, 8]


@pytest.mark.asyncio
async def test_login_as_guest_stops_at_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _install_clock(monkeypatch)
    session = _Session([_ExecResult(success=False), _ExecResult(success=False)])

    with pytest.raises(
        RuntimeError,
        match=r"loginAsGuest not ready after 5 seconds \(2 attempts\)",
    ):
        await caido_bootstrap._login_as_guest(
            cast("BaseSandboxSession", session),
            container_url="http://127.0.0.1:48080",
            wait_timeout_s=5,
        )

    assert clock.sleeps == [2.0, 3.0]
    assert [call[1]["timeout"] for call in session.calls] == [5, 3]


@pytest.mark.asyncio
async def test_login_as_guest_caps_final_attempt_to_subsecond_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _install_clock(monkeypatch)

    class _AdvancingSession(_Session):
        def __init__(self) -> None:
            super().__init__([_ExecResult(success=False), _ExecResult(success=False)])
            self._durations = iter([2.9, 0.1])

        async def exec(self, *args: str, **kwargs: Any) -> _ExecResult:
            result = await super().exec(*args, **kwargs)
            clock.now += next(self._durations)
            return result

    session = _AdvancingSession()

    with pytest.raises(RuntimeError, match=r"2 attempts"):
        await caido_bootstrap._login_as_guest(
            cast("BaseSandboxSession", session),
            container_url="http://127.0.0.1:48080",
            wait_timeout_s=5,
        )

    assert [call[1]["timeout"] for call in session.calls] == [5, pytest.approx(0.1)]


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
        await caido_bootstrap.bootstrap_caido(
            _FakeSession(),  # type: ignore[arg-type]
            host_url="http://host",
            container_url="http://container",
            wait_timeout_s=1,
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

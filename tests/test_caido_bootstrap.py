"""Tests for the Caido readiness deadline."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

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

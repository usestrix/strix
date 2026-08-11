from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import pytest

from strix.runtime.caido_bootstrap import _login_as_guest


@dataclass
class _FakeResult:
    exit_code: int
    stdout: str = ""
    stderr: bytes = b""

    def ok(self) -> bool:
        return self.exit_code == 0


@dataclass
class _FakeSession:
    """Stands in for BaseSandboxSession; returns queued exec() results."""

    results: list[_FakeResult]
    sleeps: list[float] = field(default_factory=list)
    calls: int = 0

    async def exec(self, *_args: Any, **_kwargs: Any) -> _FakeResult:
        result = self.results[min(self.calls, len(self.results) - 1)]
        self.calls += 1
        return result


_FAKE_TOKEN = "guest-token"  # noqa: S105 - test fixture, not a real credential


def _token_result() -> _FakeResult:
    body = {"data": {"loginAsGuest": {"token": {"accessToken": _FAKE_TOKEN}}}}
    return _FakeResult(exit_code=0, stdout=json.dumps(body))


def _refused_result() -> _FakeResult:
    return _FakeResult(exit_code=7, stderr=b"curl: (7) Failed to connect")


async def test_login_as_guest_succeeds_once_caido_is_up(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("strix.runtime.caido_bootstrap.asyncio.sleep", _no_sleep)
    session = _FakeSession(results=[_refused_result(), _refused_result(), _token_result()])

    token = await _login_as_guest(session, container_url="http://127.0.0.1:48080", max_wait_s=30)

    assert token == _FAKE_TOKEN
    assert session.calls == 3


async def test_login_as_guest_respects_configurable_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A slow-booting sandbox (connection refused throughout) should be given
    the full configured budget rather than giving up after a fixed attempt
    count, and the raised error should report elapsed time, not attempts.
    """
    monkeypatch.setattr("strix.runtime.caido_bootstrap.asyncio.sleep", _no_sleep)

    # Fake clock: each read advances by 25s, so a 180s budget survives
    # ~7 attempts (the old fixed-10-attempt loop only had ~68s total).
    fake_now = [0.0]

    def _fake_monotonic() -> float:
        fake_now[0] += 25.0
        return fake_now[0]

    monkeypatch.setattr("strix.runtime.caido_bootstrap.time.monotonic", _fake_monotonic)
    session = _FakeSession(results=[_refused_result()])

    with pytest.raises(RuntimeError) as exc_info:
        await _login_as_guest(session, container_url="http://127.0.0.1:48080", max_wait_s=180)

    assert "curl exit 7" in str(exc_info.value)
    assert "180s" in str(exc_info.value)
    assert session.calls >= 6


async def _no_sleep(_seconds: float) -> None:
    """asyncio.sleep stub so deadline-bound tests run instantly."""

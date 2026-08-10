"""Tests for Caido bootstrap readiness and the wall-clock boot budget."""

from __future__ import annotations

import re
import time
from typing import TYPE_CHECKING

import pytest

from strix.config.settings import RuntimeSettings
from strix.runtime.caido_bootstrap import _login_as_guest


if TYPE_CHECKING:
    from collections.abc import Sequence


class _FakeResult:
    def __init__(
        self,
        *,
        ok: bool,
        stdout: str = "",
        stderr: bytes = b"",
        exit_code: int = 0,
    ) -> None:
        self._ok = ok
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code

    def ok(self) -> bool:
        return self._ok


_SUCCESS_TOKEN = _FakeResult(
    ok=True,
    stdout='{"data":{"loginAsGuest":{"token":{"accessToken":"guest-token"}}}}',
)
_FAIL_CURL = _FakeResult(ok=False, exit_code=7, stderr=b"curl: (7) Failed to connect")


class _FakeSession:
    def __init__(self, responses: Sequence[_FakeResult]) -> None:
        self.responses = list(responses)
        self.calls = 0

    async def exec(self, *_args: object, **_kwargs: object) -> _FakeResult:
        self.calls += 1
        return self.responses[min(self.calls - 1, len(self.responses) - 1)]


async def test_login_as_guest_returns_token_once_ready() -> None:
    session = _FakeSession([_FAIL_CURL, _FAIL_CURL, _SUCCESS_TOKEN])

    token = await _login_as_guest(session, container_url="http://127.0.0.1:48080")

    assert token == "guest-token"
    assert session.calls == 3


async def test_login_as_guest_aborts_at_wall_clock_deadline() -> None:
    # Always-failing session. The loop is bounded by boot_wait_s, not by a
    # fixed attempt count, so a tiny budget must produce far fewer than the
    # old 10 attempts while still raising.
    session = _FakeSession([_FAIL_CURL])
    started = time.monotonic()

    with pytest.raises(RuntimeError, match=r"failed after 0\.5s \(\d+ attempts\)") as exc_info:
        await _login_as_guest(session, container_url="http://127.0.0.1:48080", boot_wait_s=0.5)

    elapsed = time.monotonic() - started
    assert elapsed < 5.0, "wall-clock budget was not enforced"
    attempts = int(re.search(r"\((\d+) attempts\)", str(exc_info.value)).group(1))
    assert attempts < 10


def test_caido_boot_wait_s_env_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_CAIDO_BOOT_WAIT_S", "600")

    settings = RuntimeSettings()

    assert settings.caido_boot_wait_s == 600

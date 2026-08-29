"""Telemetry must never block the caller's thread.

`_send` dispatches the HTTP beacon to a daemon thread, so operator-facing
paths (strix view, scan start, the viewer's /api/event handler) return
immediately even when the TLS handshake hangs or is intercepted.
"""

import threading
import time
from typing import Self

import pytest

from strix.telemetry import posthog, scarf


class _Resp:
    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


@pytest.mark.parametrize("telemetry", [posthog, scarf])
def test_send_does_not_block_caller(telemetry, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(telemetry, "_is_enabled", lambda: True)

    started = threading.Event()
    done = threading.Event()
    caller_thread = threading.get_ident()
    seen: dict[str, int] = {}

    def _slow_post(*_args: object, **_kwargs: object) -> _Resp:
        seen["thread"] = threading.get_ident()
        started.set()
        time.sleep(1.0)  # simulate a hanging / MITM-intercepted TLS handshake
        done.set()
        return _Resp()

    monkeypatch.setattr(telemetry.requests, "post", _slow_post)

    start = time.perf_counter()
    dispatched = telemetry._send("viewer_opened", {"x": 1})
    elapsed = time.perf_counter() - start

    # Returns immediately (reporting "dispatched") even though the POST hangs 1s.
    assert dispatched is True
    assert elapsed < 0.5
    # The HTTP actually runs, on a background thread -- not the caller's.
    assert started.wait(2.0)
    assert seen["thread"] != caller_thread
    assert done.wait(2.0)


def test_burst_does_not_spawn_unbounded_threads(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(posthog, "_is_enabled", lambda: True)

    def _slow_post(*_args: object, **_kwargs: object) -> _Resp:
        time.sleep(0.5)  # keep the shared worker busy so the queue backs up
        return _Resp()

    monkeypatch.setattr(posthog.requests, "post", _slow_post)

    start = time.perf_counter()
    for i in range(200):
        posthog._send("viewer_cta_clicked", {"i": i})
    elapsed = time.perf_counter() - start

    # Enqueuing a large burst stays fast and non-blocking...
    assert elapsed < 1.0
    # ...and telemetry runs on exactly one shared worker thread, not one per event.
    sender_threads = [t for t in threading.enumerate() if t.name == "telemetry-sender"]
    assert len(sender_threads) == 1


@pytest.mark.parametrize("telemetry", [posthog, scarf])
def test_send_disabled_returns_false_without_dispatch(
    telemetry, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(telemetry, "_is_enabled", lambda: False)
    called: list[bool] = []
    monkeypatch.setattr(
        telemetry.requests, "post", lambda *_a, **_k: called.append(True)
    )

    assert telemetry._send("viewer_opened", {"x": 1}) is False
    time.sleep(0.1)
    assert called == []

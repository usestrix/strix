"""Telemetry must never block the caller (regression test for #672).

``ReportState.add_vulnerability_report`` runs synchronously inside an async
tool, so a blocking ``urlopen`` in ``scarf.finding`` / ``posthog.finding``
stalled the asyncio event loop — and every concurrent agent — for up to the
full 10s network timeout per finding. Delivery now runs on a background
worker; these tests pin that the emit call returns immediately while the
send still happens off-thread.
"""

from __future__ import annotations

import queue
import time
from typing import Any, Self

import pytest

from strix.telemetry import _common, posthog, scarf


class _FakeResponse:
    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> bool:
        return False


@pytest.fixture(autouse=True)
def _drain_queue() -> Any:
    # Keep tests independent: let the background worker finish before the next.
    yield
    _common.flush(timeout=5.0)


def _install_slow_urlopen(monkeypatch: pytest.MonkeyPatch, module: Any, delay: float) -> list[str]:
    """Patch ``module``'s urlopen to record calls after sleeping ``delay``."""
    calls: list[str] = []

    def _slow_urlopen(req: Any, timeout: float | None = None) -> _FakeResponse:  # noqa: ARG001
        time.sleep(delay)
        calls.append(req.full_url)
        return _FakeResponse()

    monkeypatch.setattr(module, "_is_enabled", lambda: True)
    monkeypatch.setattr(module.urllib.request, "urlopen", _slow_urlopen)
    return calls


@pytest.mark.parametrize("module", [scarf, posthog])
def test_finding_returns_without_waiting_for_network(
    monkeypatch: pytest.MonkeyPatch, module: Any
) -> None:
    calls = _install_slow_urlopen(monkeypatch, module, delay=1.0)

    start = time.perf_counter()
    module.finding("high")
    elapsed = time.perf_counter() - start

    # The 1s "network" call must not be on the caller's critical path.
    assert elapsed < 0.2, f"{module.__name__}.finding blocked the caller for {elapsed:.3f}s"

    _common.flush(timeout=5.0)
    assert calls, f"{module.__name__}.finding never delivered the event off-thread"


@pytest.mark.parametrize("module", [scarf, posthog])
def test_disabled_telemetry_sends_nothing(
    monkeypatch: pytest.MonkeyPatch, module: Any
) -> None:
    calls: list[str] = []

    def _urlopen(req: Any, timeout: float | None = None) -> _FakeResponse:  # noqa: ARG001
        calls.append(req.full_url)
        return _FakeResponse()

    monkeypatch.setattr(module, "_is_enabled", lambda: False)
    monkeypatch.setattr(module.urllib.request, "urlopen", _urlopen)

    module.finding("high")
    _common.flush(timeout=1.0)
    assert not calls


@pytest.mark.parametrize("module", [scarf, posthog])
def test_terminal_events_deliver_after_shutdown_flush(
    monkeypatch: pytest.MonkeyPatch, module: Any
) -> None:
    # end()/error() were synchronous before; they must still deliver once the
    # queue is drained (the atexit hook uses this same flush at shutdown).
    calls = _install_slow_urlopen(monkeypatch, module, delay=0.0)

    module.error("unhandled_exception")
    _common.flush(timeout=5.0)
    assert calls, f"{module.__name__}.error was lost instead of delivered on flush"


@pytest.mark.parametrize("module", [scarf, posthog])
def test_unserializable_property_does_not_raise_to_caller(
    monkeypatch: pytest.MonkeyPatch, module: Any
) -> None:
    # A property whose str()/JSON encoding blows up must be swallowed by the
    # guarded delivery closure, never propagate through the public call.
    class _Explosive:
        def __str__(self) -> str:
            raise RuntimeError("boom")

    monkeypatch.setattr(module, "_is_enabled", lambda: True)
    monkeypatch.setattr(
        module.urllib.request,
        "urlopen",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("should not reach network")),
    )

    # Must not raise even though the property can't be serialized/encoded.
    module._send("scan_ended", {**_common.base_props(), "bad": _Explosive()})
    _common.flush(timeout=2.0)


def test_dispatch_drops_when_queue_full(monkeypatch: pytest.MonkeyPatch) -> None:
    # A hung endpoint must not let the queue grow without bound or block enqueue.
    full_queue: queue.Queue[Any] = queue.Queue(maxsize=1)
    full_queue.put(lambda: None)  # occupy the only slot; nothing drains it here
    monkeypatch.setattr(_common, "_telemetry_queue", full_queue)
    monkeypatch.setattr(_common, "_ensure_worker", lambda: None)  # don't spawn a real worker

    start = time.perf_counter()
    _common.dispatch(lambda: None)  # must drop, not raise or block
    assert time.perf_counter() - start < 0.1

    # Slot still holds only the original task; the overflow task was dropped.
    assert full_queue.qsize() == 1
    full_queue.get_nowait()
    with pytest.raises(queue.Empty):
        full_queue.get_nowait()

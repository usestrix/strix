from __future__ import annotations

import atexit
import logging
import platform
import queue
import sys
import threading
import time
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4


if TYPE_CHECKING:
    from collections.abc import Callable


logger = logging.getLogger(__name__)

SESSION_ID: str = uuid4().hex[:16]

_FIRST_RUN_CACHED: bool | None = None


def get_version() -> str:
    try:
        return version("strix-agent")
    except PackageNotFoundError:
        logger.debug("strix-agent version lookup failed", exc_info=True)
        return "unknown"


def is_first_run() -> bool:
    global _FIRST_RUN_CACHED  # noqa: PLW0603
    if _FIRST_RUN_CACHED is not None:
        return _FIRST_RUN_CACHED
    marker = Path.home() / ".strix" / ".seen"
    if marker.exists():
        _FIRST_RUN_CACHED = False
        return False
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    except Exception:  # noqa: BLE001, S110
        pass  # nosec B110
    _FIRST_RUN_CACHED = True
    return True


def base_props() -> dict[str, Any]:
    return {
        "os": platform.system().lower(),
        "arch": platform.machine(),
        "python": f"{sys.version_info.major}.{sys.version_info.minor}",
        "strix_version": get_version(),
    }


# ---------------------------------------------------------------------------
# Background dispatch
# ---------------------------------------------------------------------------
#
# Telemetry is best-effort and fire-and-forget. The actual delivery does a
# blocking ``urllib.request.urlopen(..., timeout=10)``; running that inline
# stalls whatever thread emits the event. ``finding()`` is emitted from an
# async tool, so an inline send blocks the asyncio event loop — and therefore
# every concurrent agent — for up to the full network timeout per finding.
#
# Instead, delivery runs on a single dedicated daemon worker fed by a bounded
# queue. Enqueue is non-blocking and drops the event when the queue is full,
# so a slow or hung telemetry endpoint can neither block nor back-pressure the
# caller. The worker is a daemon thread, and an ``atexit`` hook flushes the
# queue with a bounded timeout at interpreter shutdown so terminal ``end`` /
# ``error`` events still get a chance to deliver — without letting a hung
# endpoint stall process exit.

_TELEMETRY_QUEUE_MAXSIZE = 256

# Bounded time we allow queued telemetry (typically the terminal end/error
# events) to drain at interpreter shutdown. Well under the old synchronous
# worst case, so shutdown can never hang on an unresponsive endpoint.
_SHUTDOWN_FLUSH_TIMEOUT = 3.0

_telemetry_queue: queue.Queue[Callable[[], None]] = queue.Queue(maxsize=_TELEMETRY_QUEUE_MAXSIZE)
_worker_thread: threading.Thread | None = None
_worker_lock = threading.Lock()


def _worker_loop() -> None:
    while True:
        task = _telemetry_queue.get()
        try:
            task()
        except Exception:  # noqa: BLE001
            logger.debug("telemetry task raised", exc_info=True)
        finally:
            _telemetry_queue.task_done()


def _ensure_worker() -> None:
    global _worker_thread  # noqa: PLW0603
    if _worker_thread is not None and _worker_thread.is_alive():
        return
    with _worker_lock:
        if _worker_thread is None or not _worker_thread.is_alive():
            _worker_thread = threading.Thread(
                target=_worker_loop, name="strix-telemetry", daemon=True
            )
            _worker_thread.start()


def dispatch(task: Callable[[], None]) -> None:
    """Queue a best-effort telemetry task on the background worker.

    Non-blocking: returns immediately and never raises. If the queue is full
    (endpoint slow/unreachable) the task is dropped rather than blocking the
    caller — telemetry must never stall the event loop or delay a scan.
    """
    _ensure_worker()
    try:
        _telemetry_queue.put_nowait(task)
    except queue.Full:
        logger.debug("telemetry queue full; dropping event")


def flush(timeout: float = 5.0) -> None:
    """Best-effort wait for queued telemetry to drain (bounded by ``timeout``).

    Used by tests and by clean-shutdown paths that want emitted events to have
    a chance to deliver. Never blocks longer than ``timeout`` seconds.
    """
    deadline = time.monotonic() + timeout
    while _telemetry_queue.unfinished_tasks and time.monotonic() < deadline:
        time.sleep(0.01)


def _flush_on_exit() -> None:
    # Give queued terminal events (end/error) a bounded chance to deliver
    # before the daemon worker is torn down at interpreter shutdown.
    flush(timeout=_SHUTDOWN_FLUSH_TIMEOUT)


atexit.register(_flush_on_exit)

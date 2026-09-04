from __future__ import annotations

import logging
import platform
import queue
import sys
import threading
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4


if TYPE_CHECKING:
    from collections.abc import Callable


logger = logging.getLogger(__name__)

SESSION_ID: str = uuid4().hex[:16]

# (connect, read) seconds. Telemetry is a beacon, never something a user waits
# on, and these calls sit on the shutdown path: an endpoint that is blackholed by
# a firewall stalls in connect, so the cap has to be short enough that quitting
# still feels immediate.
SEND_TIMEOUT: tuple[float, float] = (2.0, 3.0)

_FIRST_RUN_CACHED: bool | None = None

# One daemon worker drains this queue, so the number of telemetry threads and
# in-flight sockets stays fixed no matter how fast events arrive. The queue is
# bounded: the viewer's /api/event endpoint is request-triggered, so an
# unbounded per-event thread would let a burst against a slow endpoint pile up
# threads until the process is starved. When the queue is full we drop the
# event -- telemetry is best-effort.
_SEND_QUEUE_MAXSIZE = 256
_send_queue: queue.Queue[Callable[[], None]] = queue.Queue(maxsize=_SEND_QUEUE_MAXSIZE)
_worker_lock = threading.Lock()
_worker_started = False


def _worker() -> None:
    while True:
        func = _send_queue.get()
        try:
            func()
        except Exception:  # noqa: BLE001
            logger.debug("telemetry send failed", exc_info=True)
        finally:
            _send_queue.task_done()


def _ensure_worker() -> None:
    global _worker_started  # noqa: PLW0603
    if _worker_started:
        return
    with _worker_lock:
        if _worker_started:
            return
        threading.Thread(target=_worker, name="telemetry-sender", daemon=True).start()
        _worker_started = True


def dispatch(func: Callable[[], None]) -> None:
    """Queue a best-effort telemetry send to run off the caller's thread.

    Telemetry is a beacon: operator-facing paths (``strix view``, scan start,
    the viewer's ``/api/event`` handler) must never block on it. The send runs
    on a single shared daemon worker, so a slow or MITM-intercepted TLS
    handshake can't stall the UI and can't spawn an unbounded number of threads
    when events arrive in bursts. The per-send ``SEND_TIMEOUT`` still bounds
    each request. Sends still in the queue when the process exits are dropped,
    which is acceptable for telemetry.
    """
    try:
        _ensure_worker()
        _send_queue.put_nowait(func)
    except queue.Full:
        logger.debug("telemetry queue full; dropping event")
    except Exception:  # noqa: BLE001
        logger.debug("telemetry dispatch failed", exc_info=True)


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

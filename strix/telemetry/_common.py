from __future__ import annotations

import logging
import platform
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


def dispatch(func: Callable[[], None]) -> None:
    """Run a best-effort telemetry send off the caller's thread.

    Telemetry is a beacon: operator-facing paths (``strix view``, scan start,
    the viewer's ``/api/event`` handler) must never block on it. A daemon
    thread keeps a slow or MITM-intercepted TLS handshake from stalling the UI,
    and won't hold the process open at exit -- the beacon is simply dropped if
    the process exits first, which is acceptable for telemetry. The per-send
    ``SEND_TIMEOUT`` still bounds each request.
    """
    try:
        threading.Thread(target=func, daemon=True).start()
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

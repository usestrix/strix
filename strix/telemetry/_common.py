from __future__ import annotations

import logging
import platform
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, cast
from uuid import uuid4


logger = logging.getLogger(__name__)

SESSION_ID: str = uuid4().hex[:16]

# (connect, read) seconds. Telemetry is a beacon, never something a user waits
# on, and these calls sit on the shutdown path: an endpoint that is blackholed by
# a firewall stalls in connect, so the cap has to be short enough that quitting
# still feels immediate.
SEND_TIMEOUT: tuple[float, float] = (2.0, 3.0)

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


# Coarse stage of the current run, attached to ``error`` beacons so a failure
# can be placed without a message or trace. Process-local, like the rest of the
# CLI telemetry: one process runs one scan.
_scan_phase = "startup"


def set_scan_phase(phase: str) -> None:
    global _scan_phase  # noqa: PLW0603
    _scan_phase = phase


def get_scan_phase() -> str:
    return _scan_phase


def _exception_name(exc: BaseException) -> str:
    cls = type(exc)
    package = cls.__module__.split(".")[0]
    return cls.__name__ if package == "builtins" else f"{package}.{cls.__name__}"


def _unwrap_group(exc: BaseException) -> BaseException:
    if not isinstance(exc, BaseExceptionGroup):
        return exc
    group = cast("BaseExceptionGroup[BaseException]", exc)
    return group.exceptions[0] if group.exceptions else group


def exception_props(exc: BaseException) -> dict[str, str]:
    """Class names only. Messages, arguments, and tracebacks never leave the machine."""
    exc = _unwrap_group(exc)
    props = {"exception_type": _exception_name(exc)}
    cause = exc.__cause__
    if cause is None and not exc.__suppress_context__:
        cause = exc.__context__
    if cause is not None:
        props["exception_cause"] = _exception_name(cause)
    return props

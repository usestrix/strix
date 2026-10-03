"""Make SIGTERM finalize the run instead of killing it abruptly.

A host "background time limit", a ``docker stop``, or an orchestrator shutting the
session down sends **SIGTERM**, whose default action terminates the process
immediately — skipping ``run_strix_scan``'s ``finally``. That is what leaked the
sandbox container and left ``run.json`` stuck at ``status: running`` after the 2h
cap killed a deep run. Routing SIGTERM through Python's KeyboardInterrupt handler
sends it into the run's existing interrupt path instead, which settles a resumable
state, snapshots agents for ``--resume``, closes sessions, and tears down the
sandbox.

Best-effort and self-disabling: a no-op off the main thread or where SIGTERM cannot
be installed (e.g. Windows), so it never breaks a run. A SIGKILL is still
uncatchable — this only helps the common, catchable SIGTERM shutdown.
"""

from __future__ import annotations

import contextlib
import logging
import signal
import threading
from typing import Any


logger = logging.getLogger(__name__)

# Sentinel returned when nothing was installed (so restore is a no-op).
_NOT_INSTALLED: Any = object()


def install_sigterm_as_interrupt() -> Any:
    """Route SIGTERM to Python's KeyboardInterrupt handler for the current process.

    Returns a token to pass to :func:`restore_sigterm`. Returns the not-installed
    sentinel (restore becomes a no-op) when the handler cannot be registered — off
    the main thread, or on a platform where SIGTERM is unavailable/uninstallable.
    """
    if threading.current_thread() is not threading.main_thread():
        return _NOT_INSTALLED
    if not hasattr(signal, "SIGTERM"):
        return _NOT_INSTALLED
    try:
        previous = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGTERM, signal.default_int_handler)
    except (ValueError, OSError, RuntimeError):
        return _NOT_INSTALLED
    logger.debug("SIGTERM routed to the run's interrupt path (clean teardown on shutdown)")
    return previous


def restore_sigterm(token: Any) -> None:
    """Restore the SIGTERM handler saved by :func:`install_sigterm_as_interrupt`."""
    if token is _NOT_INSTALLED:
        return
    with contextlib.suppress(ValueError, OSError, RuntimeError):
        signal.signal(signal.SIGTERM, token)

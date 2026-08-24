"""Background pre-import of the heavy scan dependencies.

The scan engine's import graph (the agents SDK, OpenAI client, LiteLLM, the
Caido SDK, the Docker SDK) costs seconds to import cold, but none of it is
needed until a scan actually starts. Importing it on a daemon thread at CLI
entry overlaps that cost with the I/O-bound startup work that always precedes
a scan (argument parsing, Docker checks, image pull, TUI setup), so by the
time the scan begins the modules are already in ``sys.modules``. Any thread
that needs one of them before the warm-up finishes just blocks on the normal
import lock, so behaviour is unchanged either way.
"""

from __future__ import annotations

import importlib
import logging
import threading


logger = logging.getLogger(__name__)

WARMUP_MODULES = (
    "strix.core.runner",
    "litellm",
    "caido_sdk_client",
    "docker",
)

_lock = threading.Lock()
_thread: threading.Thread | None = None


def _warm(modules: tuple[str, ...]) -> None:
    for name in modules:
        try:
            importlib.import_module(name)
        except Exception:  # noqa: BLE001 - a failed warm-up must never fail the run.
            logger.debug("Import warm-up for %r failed", name, exc_info=True)


def start_import_warmup(modules: tuple[str, ...] = WARMUP_MODULES) -> threading.Thread:
    """Start importing the heavy scan dependencies in the background, once.

    ``modules`` lets embedders that never touch some backends (e.g. a cloud
    runtime that has no local Docker) warm a narrower set.
    """
    global _thread  # noqa: PLW0603
    with _lock:
        if _thread is not None:
            return _thread
        _thread = threading.Thread(
            target=_warm, args=(modules,), name="strix-import-warmup", daemon=True
        )
        _thread.start()
        return _thread

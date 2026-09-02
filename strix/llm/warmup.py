"""Background pre-import of the heavy scan dependencies.

The scan engine's import graph (the agents SDK, OpenAI client, LiteLLM, the
Caido SDK, the Docker SDK) costs seconds to import cold, but none of it is
needed until a scan actually starts. Importing it on a daemon thread at CLI
entry overlaps that cost with the I/O-bound startup work that always precedes
a scan (argument parsing, Docker checks, image pull, TUI setup), so by the
time the scan begins the modules are already in ``sys.modules``.

The one rule: no other thread may import from the warmed graph while the
warm-up thread is still running. CPython's per-module import locks do not make
that safe. When two threads walk a package graph with internal import cycles
(the agents SDK has them), each ends up waiting for a lock the other holds,
and the import system breaks the cycle by failing one of the two imports
outright. The failed package is dropped from ``sys.modules`` while the other
thread is still inside it, which surfaces as ``KeyError: 'agents.models'`` or
``ImportError: cannot import name ... from partially initialized module``.
Callers must therefore :func:`wait_for_import_warmup` before the first import
from the warmed graph on any other thread; once the warm-up is done the call
returns immediately.
"""

from __future__ import annotations

import importlib
import logging
import sys
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


def _purge_orphaned_modules(before: frozenset[str]) -> None:
    """Remove submodules stranded by an import attempt that just failed.

    When a package import fails partway (for example CPython's import-lock
    deadlock avoidance breaking a cross-thread cycle), the failed package is
    removed from ``sys.modules`` but submodules it already finished stay
    behind. A later import of one of those submodules then short-circuits on
    the cached entry without re-importing its parent, and re-entering the
    parent from inside a submodule crashes with "partially initialized
    module". Dropping the orphans (cached submodules whose ancestor package is
    gone) restores a clean slate, and touches nothing another thread imported
    successfully.
    """
    added = set(sys.modules) - before
    for name in added:
        parent = name.rpartition(".")[0]
        while parent:
            if parent not in sys.modules:
                sys.modules.pop(name, None)
                logger.debug("Import warm-up purged orphaned module %r", name)
                break
            parent = parent.rpartition(".")[0]


def _warm(modules: tuple[str, ...]) -> None:
    for name in modules:
        before = frozenset(sys.modules)
        try:
            importlib.import_module(name)
        except Exception:  # noqa: BLE001 - a failed warm-up must never fail the run.
            logger.debug("Import warm-up for %r failed", name, exc_info=True)
            _purge_orphaned_modules(before)


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


def wait_for_import_warmup() -> None:
    """Block until the warm-up thread has finished; a no-op if none was started.

    Call this before the first import from the warmed graph on the calling
    thread. If the warm-up already finished this returns at once. If it is
    still running, the caller would otherwise have to import the same modules
    itself (or race the warm-up thread for them, see the module docstring), so
    waiting here costs nothing.
    """
    with _lock:
        thread = _thread
    if thread is None or thread is threading.current_thread():
        return
    thread.join()

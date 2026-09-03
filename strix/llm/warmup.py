"""Background pre-import of the heavy scan dependencies.

The scan engine's import graph (the agents SDK, OpenAI client, LiteLLM, the
Caido SDK, the Docker SDK) costs seconds to import cold, but none of it is
needed until a scan actually starts. Importing it on a daemon thread at CLI
entry overlaps that cost with the I/O-bound startup work that always precedes
a scan (argument parsing, Docker checks, image pull, TUI setup), so by the
time the scan begins the modules are already in ``sys.modules``.

CPython's per-module import locks do **not** make a second thread importing
from that graph safe. The agents SDK has internal import cycles; when the
warm-up thread and the main thread walk them at once, deadlock avoidance
fails one import and drops a half-built package from ``sys.modules``. The
main thread then crashes with ``KeyError: 'agents.models'`` (issue #1248) or
``ImportError: cannot import name ... from partially initialized module``.

Call :func:`wait_for_agents_models` before the first ``agents.models`` import
on any other thread. That wait is released once the runner (which loads
``agents.models``) has finished — not when the whole warm-up thread joins —
so LiteLLM / Caido / Docker continue overlapping later scan work.
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

# ``strix.core.runner`` transitively imports the agents SDK, including
# ``agents.models``. Waiters for that subpackage are released after these
# modules finish (or fail); later WARMUP_MODULES keep running.
_AGENTS_GRAPH_MODULES = frozenset({"strix.core.runner"})

_lock = threading.Lock()
_thread: threading.Thread | None = None
_agents_models_ready = threading.Event()


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


def _import_one(name: str) -> None:
    before = frozenset(sys.modules)
    try:
        importlib.import_module(name)
    except Exception:  # noqa: BLE001 - a failed warm-up must never fail the run.
        logger.debug("Import warm-up for %r failed", name, exc_info=True)
        _purge_orphaned_modules(before)


def _warm(modules: tuple[str, ...]) -> None:
    pending_graph = set(_AGENTS_GRAPH_MODULES.intersection(modules))
    try:
        for name in modules:
            _import_one(name)
            if name in pending_graph:
                pending_graph.discard(name)
                if not pending_graph:
                    # agents.models is fully loaded (or the attempt failed).
                    # Do not join the rest of this thread — see #1248.
                    _agents_models_ready.set()
    finally:
        # Always release waiters: a failed or runner-less warm-up must not
        # deadlock the main thread (e.g. missing optional deps, no API key
        # needed here — this path is import-only).
        _agents_models_ready.set()


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


def wait_for_agents_models() -> None:
    """Block until ``agents.models`` is fully imported, without joining warm-up.

    The import warm-up daemon loads ``agents.models`` transitively via
    ``strix.core.runner``. ``warm_up_llm`` used to import
    ``agents.models.interface`` on the main thread at the same time, which
    races CPython into ``KeyError: 'agents.models'`` (issue #1248).

    This waits on :data:`_agents_models_ready`, set as soon as that
    subpackage's loader (the runner) has finished or failed. It does **not**
    ``join()`` the warm-up thread, so LiteLLM / Caido / Docker keep importing
    in the background.

    No-op if warm-up was never started, so embedders and tests cannot
    deadlock. Safe to call from the warm-up thread itself.
    """
    with _lock:
        thread = _thread
    if thread is None or thread is threading.current_thread():
        return
    _agents_models_ready.wait()

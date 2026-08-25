"""Pre-import of the heavy scan dependencies.

The scan engine's import graph (the agents SDK, OpenAI client, LiteLLM, the
Caido SDK, the Docker SDK) costs seconds to import cold, but none of it is
needed until a scan actually starts. We import it here, once, at the start of
the scan bootstrap so the cost is paid up front rather than on first use deep
in the run.

This used to run on a background daemon thread to overlap the import cost with
the I/O-bound startup work that precedes a scan. That is unsound: the warm-up
imports ``strix.core.runner``, which pulls in the agents SDK, whose package
graph has internal circular imports. CPython resolves circular imports by
returning a *partially initialized* module to break the cycle, and that partial
state is observable from other threads. When the warm-up thread and the main
thread (``warm_up_llm`` imports ``agents.model_settings`` /
``agents.models.interface``) import that graph concurrently, they intermittently
observe each other's partial ``agents`` package and crash with
``KeyError: 'agents'`` or "cannot import name ... from partially initialized
module 'agents.agent_output'". This reproduces reliably on some hosts (e.g.
WSL2). The per-module import lock does not prevent it precisely because the
import system deliberately hands out partial modules mid-cycle.

Warm-up only runs on the scan path, which eagerly imports all of these modules
anyway, so importing synchronously here adds no net work - it just removes the
racy overlap. See https://github.com/usestrix/strix (import-warmup race).
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
_warmed: bool = False


def _warm(modules: tuple[str, ...]) -> None:
    for name in modules:
        try:
            importlib.import_module(name)
        except Exception:  # noqa: BLE001 - a failed warm-up must never fail the run.
            logger.debug("Import warm-up for %r failed", name, exc_info=True)


def start_import_warmup(modules: tuple[str, ...] = WARMUP_MODULES) -> None:
    """Import the heavy scan dependencies once, synchronously.

    Runs on the calling thread rather than a background daemon: importing the
    agents-SDK-bearing graph concurrently with the main thread races on the
    SDK's internal circular imports (see module docstring). ``modules`` lets
    embedders that never touch some backends (e.g. a cloud runtime that has no
    local Docker) warm a narrower set.
    """
    global _warmed  # noqa: PLW0603
    with _lock:
        if _warmed:
            return
        _warm(modules)
        _warmed = True

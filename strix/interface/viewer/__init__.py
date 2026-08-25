"""Local web viewer for Strix runs.

Serves a prebuilt single-page app that renders a run (live or finished) read
directly from the run's on-disk files. No cloud dependency, no file picker.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from strix.interface.viewer.server import serve


def __getattr__(name: str) -> Any:
    """Load the public server entry point without creating a package import cycle."""
    if name == "serve":
        return getattr(import_module("strix.interface.viewer.server"), name)
    raise AttributeError(name)


__all__ = ["serve"]

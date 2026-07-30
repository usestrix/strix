"""Backend bridge for external TUI clients."""

from strix.interface.tui_backend.controller import TuiController
from strix.interface.tui_backend.server import TuiBackendServer


__all__ = ["TuiBackendServer", "TuiController"]

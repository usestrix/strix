"""Backend bridge for external TUI clients."""

from strix.interface.tui.backend.controller import TuiController
from strix.interface.tui.backend.server import TuiBackendServer


__all__ = ["TuiBackendServer", "TuiController"]

"""Launch the interactive terminal interface."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    import argparse


logger = logging.getLogger(__name__)


class InteractiveSetupUnavailableError(RuntimeError):
    """Raised when the interactive TUI cannot be launched."""


async def run_tui(args: argparse.Namespace) -> None:
    """Run the Bubble Tea TUI."""
    from strix.interface.go_tui import (
        GoTuiPreActivationError,
        run_go_tui,
    )

    try:
        await run_go_tui(args)
    except GoTuiPreActivationError as exc:
        raise InteractiveSetupUnavailableError(
            "The interactive interface requires the Go TUI. "
            "Install an official platform wheel, set STRIX_TUI_BINARY, or run a source "
            "checkout with Go 1.24+."
        ) from exc


__all__ = [
    "InteractiveSetupUnavailableError",
    "run_tui",
]

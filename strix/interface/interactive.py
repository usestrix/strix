"""Select and launch an interactive terminal interface."""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    import argparse


logger = logging.getLogger(__name__)
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})


class InteractiveSetupUnavailableError(RuntimeError):
    """Compatibility error retained for callers of the interactive entry point."""


def _textual_tui_selected() -> bool:
    return os.environ.get("STRIX_TEXTUAL_TUI", "").strip().lower() in _TRUE_VALUES


def textual_tui_requested() -> bool:
    """Return whether the user explicitly selected the legacy Textual UI."""
    return _textual_tui_selected()


async def run_tui(args: argparse.Namespace) -> None:
    """Run Bubble Tea by default, with a Textual opt-out and safe fallback."""
    if _textual_tui_selected():
        if getattr(args, "needs_setup", False):
            raise InteractiveSetupUnavailableError(
                "The legacy Textual TUI requires a configured model and an explicit target."
            )
        from strix.interface.tui import run_tui as run_textual_tui  # noqa: PLC0415

        await run_textual_tui(args)
        return

    from strix.interface.go_tui import (  # noqa: PLC0415
        GoTuiPreActivationError,
        run_go_tui,
    )

    try:
        await run_go_tui(args)
    except GoTuiPreActivationError as exc:
        if getattr(args, "needs_setup", False):
            raise InteractiveSetupUnavailableError(
                "Interactive provider/target setup requires the Go TUI. "
                "Install an official platform wheel, set STRIX_TUI_BINARY, or run a source "
                "checkout with Go 1.24+."
            ) from exc
        logger.warning("Go TUI unavailable before activation; using Textual: %s", exc)
        from strix.interface.tui import run_tui as run_textual_tui  # noqa: PLC0415

        await run_textual_tui(args)


__all__ = [
    "InteractiveSetupUnavailableError",
    "run_tui",
    "textual_tui_requested",
]

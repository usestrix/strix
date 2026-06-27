"""Small Rich helpers shared by the subscription bring-up path."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, NoReturn

from rich.panel import Panel
from rich.text import Text


if TYPE_CHECKING:
    from rich.console import Console


def fail(console: Console, title: str, detail: str) -> NoReturn:
    """Print a red error panel and exit the process with status 1."""
    body = Text()
    body.append(f"{title}\n\n", style="bold red")
    body.append(detail, style="white")
    panel = Panel(
        body,
        title="[bold white]STRIX",
        title_align="left",
        border_style="red",
        padding=(1, 2),
    )
    console.print("\n")
    console.print(panel)
    console.print()
    sys.exit(1)


def notice(console: Console, message: str) -> None:
    """Print a dim, single-line informational notice."""
    console.print(f"[dim]{message}[/]")

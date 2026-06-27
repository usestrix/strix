"""Pre-flight subscription auth checks, run before the proxy starts."""

from __future__ import annotations

from typing import TYPE_CHECKING

from strix.subscription._ui import fail
from strix.subscription.claude.auth import BorrowKeyError as ClaudeBorrowKeyError
from strix.subscription.claude.auth import borrow_claude_key
from strix.subscription.codex.auth import BorrowKeyError as CodexBorrowKeyError
from strix.subscription.codex.auth import borrow_codex_key


if TYPE_CHECKING:
    from rich.console import Console


def claude_preflight(console: Console) -> None:
    """Ensure a Claude Code subscription token is usable before the proxy starts."""
    try:
        borrow_claude_key()
    except ClaudeBorrowKeyError as exc:
        fail(
            console,
            "Claude subscription auth failed",
            f"{exc}\n\nLog in with the `claude` CLI, or set CLAUDE_CODE_OAUTH_TOKEN.",
        )


def codex_preflight(console: Console) -> None:
    """Ensure a ChatGPT Codex subscription token is usable before the proxy starts."""
    try:
        borrow_codex_key()
    except CodexBorrowKeyError as exc:
        fail(
            console,
            "Codex subscription auth failed",
            f"{exc}\n\nLog in with the `codex` CLI and pick the ChatGPT option.",
        )

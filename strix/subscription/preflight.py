"""Pre-flight subscription auth checks, run before the proxy starts."""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import TYPE_CHECKING

from strix.subscription._ui import fail
from strix.subscription.claude.auth import BorrowKeyError as ClaudeBorrowKeyError
from strix.subscription.claude.auth import borrow_claude_key
from strix.subscription.codex.auth import BorrowKeyError as CodexBorrowKeyError
from strix.subscription.codex.auth import borrow_codex_key


if TYPE_CHECKING:
    from rich.console import Console


_CLAUDE_WAKE_TIMEOUT_SECONDS = 60


def claude_preflight(console: Console) -> None:
    """Ensure a Claude Code subscription token is usable before the proxy starts."""
    if not _has_claude_env_token() and shutil.which("claude") is not None:
        _wake_claude_cli(console)
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


def _has_claude_env_token() -> bool:
    token = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN")
    return bool(token and token.strip())


def _wake_claude_cli(console: Console) -> None:
    """Nudge the Claude CLI so it refreshes its on-disk token if needed."""
    try:
        result = subprocess.run(
            ["claude", "-p", "just print 'working'"],
            capture_output=True,
            text=True,
            timeout=_CLAUDE_WAKE_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        return
    except subprocess.TimeoutExpired:
        fail(
            console,
            "Claude CLI preflight timed out",
            f"`claude` did not respond within {_CLAUDE_WAKE_TIMEOUT_SECONDS}s.",
        )
    if result.returncode != 0:
        fail(
            console,
            "Claude CLI preflight failed",
            f"`claude` exited with code {result.returncode}.",
        )

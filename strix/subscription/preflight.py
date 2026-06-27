"""Pre-flight subscription auth checks, run before the proxy starts."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from strix.subscription._ui import fail
from strix.subscription.claude.auth import BorrowKeyError as ClaudeBorrowKeyError
from strix.subscription.claude.auth import borrow_claude_key
from strix.subscription.codex.auth import BorrowKeyError as CodexBorrowKeyError
from strix.subscription.codex.auth import borrow_codex_key


if TYPE_CHECKING:
    from rich.console import Console


logger = logging.getLogger(__name__)

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
    status = _claude_token_expiry_status()
    if status:
        logger.info("%s", status)


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


def _claude_token_expiry_status() -> str | None:
    expires_at_ms = _read_claude_expires_at()
    if expires_at_ms is None:
        return None
    expiry = datetime.fromtimestamp(expires_at_ms / 1000, tz=UTC).astimezone()
    remaining = max(0, int((expiry - datetime.now(tz=UTC)).total_seconds()))
    return f"Claude token expires in {_format_duration(remaining)} at {expiry:%Y-%m-%d %H:%M:%S}"


def _read_claude_expires_at() -> int | None:
    config_dir = Path(os.environ.get("CLAUDE_CONFIG_DIR", "~/.claude")).expanduser()
    try:
        data = json.loads((config_dir / ".credentials.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    oauth = data.get("claudeAiOauth")
    if not isinstance(oauth, dict):
        return None
    expires_at = oauth.get("expiresAt")
    return expires_at if isinstance(expires_at, int) else None


def _format_duration(total_seconds: int) -> str:
    minutes, _ = divmod(total_seconds, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)

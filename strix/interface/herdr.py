"""Herdr terminal workspace manager integration.

Reports agent lifecycle state (working, idle, blocked) and resume commands
to Herdr when running inside a Herdr pane.

Spec: https://herdr.dev/tui/docs/add-herdr-support/
"""

from __future__ import annotations

import itertools
import logging
import os
import subprocess
import time
from typing import TYPE_CHECKING, Literal


if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger(__name__)

AgentState = Literal["idle", "working", "blocked"]


def _env_active() -> bool:
    return (
        os.environ.get("HERDR_ENV") == "1"
        and bool(os.environ.get("HERDR_BIN_PATH"))
        and bool(os.environ.get("HERDR_PANE_ID"))
    )


_SOURCE = "strix:agent"
_AGENT_LABEL = "strix"

_seq_counter = itertools.count(int(time.time() * 1000))


def _next_seq() -> int:
    return next(_seq_counter)


def is_active() -> bool:
    """Return True if running inside an active Herdr pane."""
    return _env_active()


def report_state(
    state: AgentState,
    *,
    message: str | None = None,
    session_id: str | None = None,
    resume_argv: Sequence[str] | None = None,
) -> bool:
    """Report agent lifecycle state to Herdr.

    Args:
        state: One of 'working', 'idle', or 'blocked'.
        message: Optional human-readable message explaining the state.
        session_id: Unique identifier for the current scan run.
        resume_argv: Command and arguments to reopen this scan run.

    Returns:
        True if the report was accepted by Herdr (exit code 0), False otherwise.
    """
    if not is_active():
        return False

    bin_path = os.environ.get("HERDR_BIN_PATH")
    pane_id = os.environ.get("HERDR_PANE_ID")
    if not bin_path or not pane_id:
        return False

    cmd = [
        bin_path,
        "pane",
        "report-agent",
        pane_id,
        "--source",
        _SOURCE,
        "--agent",
        _AGENT_LABEL,
        "--state",
        state,
        "--seq",
        str(_next_seq()),
    ]

    if message:
        cmd.extend(["--message", message])
    if session_id:
        cmd.extend(["--agent-session-id", session_id])
    if resume_argv:
        cmd.append("--")
        cmd.extend(resume_argv)

    try:
        result = subprocess.run(  # noqa: S603
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2.0,
            check=False,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        logger.debug("Failed to report state to Herdr: %s", exc)
        return False
    else:
        return result.returncode == 0


def release_agent() -> bool:
    """Release agent state in Herdr when Strix exits."""
    if not is_active():
        return False

    bin_path = os.environ.get("HERDR_BIN_PATH")
    pane_id = os.environ.get("HERDR_PANE_ID")
    if not bin_path or not pane_id:
        return False

    cmd = [
        bin_path,
        "pane",
        "release-agent",
        pane_id,
        "--source",
        _SOURCE,
        "--agent",
        _AGENT_LABEL,
        "--seq",
        str(_next_seq()),
    ]

    try:
        result = subprocess.run(  # noqa: S603
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2.0,
            check=False,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        logger.debug("Failed to release agent from Herdr: %s", exc)
        return False
    else:
        return result.returncode == 0

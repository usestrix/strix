"""Safe rendering of untrusted text in a terminal."""

from __future__ import annotations

import re


_TERMINAL_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def has_terminal_control(value: object) -> bool:
    """Return whether text contains bytes that can alter terminal state/protocols."""
    return _TERMINAL_CONTROL.search(str(value)) is not None


def sanitize_terminal_text(value: object) -> str:
    """Make C0/C1 control bytes visible so they cannot operate a terminal."""
    return _TERMINAL_CONTROL.sub(
        lambda match: f"\\x{ord(match.group()):02x}",
        str(value),
    )

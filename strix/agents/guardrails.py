"""Destructive-command guardrails for the shell tool.

Strix agents run arbitrary commands against live targets. LLMs are
non-deterministic: a model may attempt a destructive action (DROP TABLE,
rm -rf /, ...) even when instructed to stay non-destructive. This module
implements a small, predictable safety layer on top of exec_command that
refuses clearly destructive commands unless the operator opts out with
STRIX_ALLOW_DESTRUCTIVE=1.
"""

from __future__ import annotations

import re

# SQL statements that are almost always destructive in a pentest context.
_SQL_DESTRUCTIVE = re.compile(
    r"\b(DROP\s+(TABLE|DATABASE|SCHEMA|VIEW|INDEX|TRIGGER|FUNCTION|PROCEDURE)"
    r"|TRUNCATE\s+(TABLE\s+)?\w+"
    r"|DELETE\s+FROM\s+\w+\s*;?\s*$"
    r"|ALTER\s+(TABLE|DATABASE|SCHEMA)\s+\w+\s+(DROP|DELETE|TRUNCATE))",
    re.IGNORECASE,
)

# Shell patterns that are destructive regardless of arguments.
_SHELL_DESTRUCTIVE = re.compile(
    r"\brm\s+(-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*)\s+(/|/\*|~\s*/\*)"
    r"|\bmkfs(\.\w+)?\b"
    r"|\bdd\b[^|;]*\bof=/dev/"
    r"|:\(\)\s*\{\s*:\|\:&\s*\}\s*;:"
    r"|\bshutdown\b|\breboot\b|\bpoweroff\b"
    r"|\bgit\s+push\s+.*\s--force",
    re.IGNORECASE,
)


def check_destructive(cmd: str) -> str | None:
    """Return a human-readable reason if *cmd* is destructive, else None.

    The check is intentionally conservative: it only flags commands whose
    destructive intent is unambiguous. It is a safety net, not a policy
    engine - operators who want full control can set
    STRIX_ALLOW_DESTRUCTIVE=1.
    """
    if not cmd:
        return None
    if _SQL_DESTRUCTIVE.search(cmd):
        return "SQL statement may modify or destroy data (DROP/TRUNCATE/DELETE)"
    if _SHELL_DESTRUCTIVE.search(cmd):
        return "shell command may destroy data or affect the host (rm -rf /, mkfs, dd to /dev/, force push)"
    return None

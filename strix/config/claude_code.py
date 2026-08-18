"""Claude Code subscription backend — provider metadata and CLI probing.

Strix runs its agents on a Claude Pro/Max subscription by shelling out to the
user's installed Claude Code binary in non-interactive mode (``claude -p``).
Claude Code owns auth, token refresh, and the wire protocol; this module only
locates the binary, reports its version and sign-in state, and parses the
``claude-code/<model>`` STRIX_LLM prefix. There is deliberately no OAuth here —
that is the whole point of Option B (see ``.artifacts/DESIGN.md``).
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess  # we invoke a trusted, user-installed CLI, never a shell
from functools import lru_cache
from typing import TYPE_CHECKING, Any, cast


if TYPE_CHECKING:
    from strix.config.settings import ReasoningEffort


logger = logging.getLogger(__name__)

PROVIDER = "claude-code"
SUBSCRIPTION_PREFIX = "claude-code/"

# The stream-json result schema this backend relies on (structured_output,
# api_error_status) has been stable since Claude Code 2.0.
MIN_CLAUDE_VERSION = (2, 0, 0)

_PROBE_TIMEOUT_S = 8


class ClaudeCodeError(Exception):
    """A Claude Code subprocess failed in a way Strix must surface to the user."""


def claude_code_model(model_name: str | None) -> str | None:
    """The model slug behind a ``claude-code/<model>`` STRIX_LLM, or None.

    Mirrors :func:`strix.config.codex.subscription_model` exactly: strip,
    case-insensitive prefix match, empty slug returns None.
    """
    name = (model_name or "").strip()
    if not name.lower().startswith(SUBSCRIPTION_PREFIX):
        return None
    return name[len(SUBSCRIPTION_PREFIX) :] or None


def auth_mode(model_name: str | None) -> str:
    """``"subscription"`` for a ``claude-code/...`` model, else ``"api_key"``."""
    return "subscription" if claude_code_model(model_name) else "api_key"


def binary_path() -> str | None:
    """Absolute path to the ``claude`` binary on PATH, or None."""
    return shutil.which("claude")


def _run_claude(args: list[str]) -> subprocess.CompletedProcess[str]:
    binary = binary_path()
    if binary is None:
        raise ClaudeCodeError("the `claude` CLI is not on PATH")
    return subprocess.run(  # noqa: S603  # trusted binary, fixed argv, no shell
        [binary, *args],
        capture_output=True,
        text=True,
        timeout=_PROBE_TIMEOUT_S,
        check=False,
    )


@lru_cache(maxsize=1)
def _raw_version() -> str | None:
    try:
        result = _run_claude(["--version"])
    except (ClaudeCodeError, OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def version() -> str | None:
    """The ``claude --version`` string (e.g. ``"2.1.234 (Claude Code)"``), or None."""
    return _raw_version()


def _parse_version(raw: str | None) -> tuple[int, int, int] | None:
    if not raw:
        return None
    token = raw.strip().split()[0]
    parts = token.split(".")
    try:
        nums = tuple(int(p) for p in parts[:3])
    except ValueError:
        return None
    padded = (*nums, 0, 0)[:3]
    return (padded[0], padded[1], padded[2])


def meets_min_version() -> bool:
    """True if the installed ``claude`` is at least :data:`MIN_CLAUDE_VERSION`."""
    parsed = _parse_version(version())
    return parsed is not None and parsed >= MIN_CLAUDE_VERSION


def is_available() -> bool:
    """True if the ``claude`` binary is present and new enough to drive."""
    return binary_path() is not None and meets_min_version()


def session_state() -> str:
    """One of ``"subscription"``, ``"api_key"``, ``"signed_out"``, ``"unknown"``.

    Parses ``claude auth status`` JSON. ``"unknown"`` means the probe itself
    failed (binary missing, timeout, unparseable output) — the caller decides
    whether that is fatal.
    """
    try:
        result = _run_claude(["auth", "status"])
    except (ClaudeCodeError, OSError, subprocess.SubprocessError):
        return "unknown"
    payload = _parse_status_json(result.stdout)
    if payload is None:
        return "unknown"
    if not payload.get("loggedIn"):
        return "signed_out"
    method = str(payload.get("authMethod") or "").lower()
    provider = str(payload.get("apiProvider") or "").lower()
    if method == "claude.ai" or (provider == "firstparty" and payload.get("subscriptionType")):
        return "subscription"
    return "api_key"


def _parse_status_json(stdout: str) -> dict[str, Any] | None:
    text = stdout.strip()
    if not text:
        return None
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        # Some builds wrap the JSON in log lines; grab the first {...} block.
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            return None
        try:
            payload = json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return None
    return cast("dict[str, Any]", payload) if isinstance(payload, dict) else None


def is_authenticated() -> bool:
    """True if Claude Code reports any signed-in session (subscription or key)."""
    return session_state() in {"subscription", "api_key"}


def reasoning_flags(effort: ReasoningEffort | None) -> list[str]:
    """Map ``STRIX_REASONING_EFFORT`` to ``claude`` CLI flags.

    Claude Code exposes ``--effort {low,medium,high,xhigh,max}``. Strix's
    ``none``/``minimal`` collapse to ``low`` (the CLI has no lower rung); an
    unset effort returns no flag so the CLI keeps its own default.
    """
    if effort is None or effort == "none":
        return []
    mapped = {"minimal": "low"}.get(effort, effort)
    return ["--effort", mapped]

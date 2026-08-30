"""Claude Code subscription backend, provider metadata and CLI probing.

Strix runs its agents on a Claude Pro/Max subscription by shelling out to the
user's installed Claude Code binary in non-interactive mode (``claude -p``).
Claude Code owns auth, token refresh, and the wire protocol; this module only
locates the binary, reports its version and sign-in state, and parses the
``claude-code/<model>`` STRIX_LLM prefix. There is deliberately no OAuth here:
not lifting the token out of the user's credentials file is the whole point.
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

# Everything this backend drives has to exist in the installed CLI, and 2.0 is far
# too low a bar. Checked against the published npm bundles:
#
#   2.0.0    no --json-schema, no --effort, no --no-session-persistence,
#            no --disable-slash-commands, no api_error_status
#   2.0.45   --json-schema appears
#   2.0.60   --disable-slash-commands appears
#   2.0.77   --no-session-persistence appears
#   2.1.100  api_error_status still absent (last release shipping a readable
#            cli.js bundle; later ones ship a downloaded binary)
#   2.1.220  verified end to end on Windows, 2.1.239 on Linux
#
# api_error_status is what the retry policy classifies a 429/529 on, so a CLI
# without it degrades every rate limit into an unclassified error. The floor is
# therefore the lowest release actually verified to carry the whole contract;
# it is conservative by construction, since the exact release that added
# api_error_status is not visible in the published artifacts.
MIN_CLAUDE_VERSION = (2, 1, 220)

_PROBE_TIMEOUT_S = 8


class ClaudeCodeError(Exception):
    """A Claude Code subprocess failed in a way Strix must surface to the user.

    ``retryable`` is False only when an identical second attempt cannot succeed,
    which in practice means the CLI is not installed. A turn that timed out,
    crashed, or produced no result event may well clear, so those stay on the
    normal retry path.
    """

    def __init__(self, message: str, *, retryable: bool = True) -> None:
        super().__init__(message)
        self.retryable = retryable


def is_permanent_error(exc: BaseException) -> bool:
    """Whether ``exc`` is a Claude Code failure no retry can clear, cause chain included.

    Such an error carries no status code, so without this it lands in the
    statusless-retry fallback and burns five attempts and roughly three minutes of
    backoff per turn, per agent, on a missing binary. The chain is walked because
    the SDK may wrap what the transport raised.
    """
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        if isinstance(current, ClaudeCodeError) and not current.retryable:
            return True
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return False


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
        raise ClaudeCodeError("the `claude` CLI is not on PATH", retryable=False)
    return subprocess.run(  # noqa: S603  # trusted binary, fixed argv, no shell
        [binary, *args],
        capture_output=True,
        text=True,
        # Pinned, because text=True otherwise decodes with the host locale codec:
        # the CLI emits UTF-8, and a console on a non-UTF-8 code page (cp1252,
        # cp932) would raise UnicodeDecodeError straight out of a probe that is
        # only supposed to answer a question.
        encoding="utf-8",
        errors="replace",
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


def version_state() -> str:
    """``"ok"``, ``"too_old"``, or ``"unknown"`` when the probe itself failed.

    Preflight needs the three apart: "update your CLI" is the wrong thing to
    tell someone whose binary did not run, or whose version string this cannot
    read, and both of those reach here as a missing version.
    """
    parsed = _parse_version(version())
    if parsed is None:
        return "unknown"
    return "ok" if parsed >= MIN_CLAUDE_VERSION else "too_old"


def meets_min_version() -> bool:
    """True if the installed ``claude`` is at least :data:`MIN_CLAUDE_VERSION`."""
    return version_state() == "ok"


def is_available() -> bool:
    """True if the ``claude`` binary is present and new enough to drive."""
    return binary_path() is not None and meets_min_version()


@lru_cache(maxsize=1)
def _status_payload() -> dict[str, Any] | None:
    """``claude auth status --json``, or None when the probe failed.

    Cached: the CLI's sign-in state does not change within a scan process, and
    several call sites (preflight, the auth CLI, the cost resolver) ask about it
    per run.
    """
    try:
        result = _run_claude(["auth", "status", "--json"])
    except (ClaudeCodeError, OSError, subprocess.SubprocessError):
        return None
    return _parse_status_json(result.stdout)


def api_key_source() -> str | None:
    """Where Claude Code took an API key from, when one is overriding the sign-in.

    ``"ANTHROPIC_API_KEY"`` for the environment variable, or the name of another
    source the CLI reports. None when the session is not on a key.
    """
    payload = _status_payload()
    source = payload.get("apiKeySource") if payload else None
    return str(source) if source else None


def session_state() -> str:
    """One of ``"subscription"``, ``"api_key"``, ``"signed_out"``, ``"unknown"``.

    Derived from ``claude auth status --json``. ``"unknown"`` means the probe
    itself failed (binary missing, timeout, unparseable output); the caller
    decides whether that is fatal.
    """
    payload = _status_payload()
    if payload is None:
        return "unknown"
    if not payload.get("loggedIn"):
        return "signed_out"
    if payload.get("apiKeySource"):
        # An ANTHROPIC_API_KEY in the environment (or an apiKeyHelper) takes
        # over inference while ``authMethod`` still reads "claude.ai" and only
        # ``apiKeySource`` gives it away. Strix inherits its own environment
        # into the child, so this is the common case of someone who has ever
        # used the Anthropic API. Calling it a subscription would zero a real
        # bill and leave the budget guard nothing to stop.
        return "api_key"
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
    ``none`` and ``minimal`` collapse to ``low`` (the CLI has no lower rung); an
    *unset* effort (``None``) returns no flag so the CLI keeps its own default.
    """
    if effort is None:
        return []
    mapped = {"none": "low", "minimal": "low"}.get(effort, effort)
    return ["--effort", mapped]

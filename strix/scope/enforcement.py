"""Runtime scope enforcement.

Holds the active :class:`ScopePolicy` for the run and turns tool arguments into
allow/deny decisions. The policy is loaded once at run start (by
``strix.strix2_ext``); tools and the MCP boundary call :func:`enforce_arguments`
(or :func:`enforce_target`) before acting.

Compatibility stance (Phase 1): enforcement is **active only when a scope policy
is loaded**. With no ``scope.yaml`` present, upstream web/MCP behavior is
unchanged (allow) — the fail-closed "refuse without scope" requirement applies to
the new intrusive domains (network/cloud), enforced inside those tools when they
land in Phase 3. The intrusive gate (``allow_intrusive`` / ``--allow-intrusive``)
is always honored when a policy is loaded.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from typing import TYPE_CHECKING, Any

from strix.scope.loader import load_scope_policy


if TYPE_CHECKING:
    from strix.scope.schema import ScopeDecision, ScopePolicy


logger = logging.getLogger(__name__)

_ALLOW_INTRUSIVE_ENV = "STRIX_ALLOW_INTRUSIVE"

_active_policy: ScopePolicy | None = None

# High-confidence target patterns only, so a scope check never rejects a legit
# MCP call over an ambiguous string. Bare hostnames are intentionally excluded
# here (too many false positives); domain tools check those against their known
# target argument directly.
_URL_RE = re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s\"'<>]+", re.IGNORECASE)
_ARN_RE = re.compile(r"\barn:aws:[^\s\"'<>]+", re.IGNORECASE)
_ACCOUNT_RE = re.compile(r"\b\d{12}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def get_active_policy() -> ScopePolicy | None:
    return _active_policy


def set_active_policy(policy: ScopePolicy | None) -> None:
    global _active_policy  # noqa: PLW0603
    _active_policy = policy


def _intrusive_override() -> bool:
    return os.environ.get(_ALLOW_INTRUSIVE_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def load_active_policy(
    *,
    path: str | None = None,
    search_from: str | None = None,
    allow_intrusive: bool | None = None,
) -> ScopePolicy | None:
    """Load ``scope.yaml`` and set it as the active policy for the run.

    ``allow_intrusive`` (or the ``STRIX_ALLOW_INTRUSIVE`` env var, set by the
    ``--allow-intrusive`` flag) overrides the file's value when True. Returns the
    policy, or ``None`` when no scope file is present.
    """
    policy = load_scope_policy(path, search_from=search_from)
    if policy is not None:
        override = allow_intrusive if allow_intrusive is not None else _intrusive_override()
        if override and not policy.allow_intrusive:
            policy = policy.model_copy(update={"allow_intrusive": True})
        logger.info("Scope enforcement active (allow_intrusive=%s)", policy.allow_intrusive)
    else:
        logger.info("No scope.yaml loaded; scope enforcement inactive for this run")
    set_active_policy(policy)
    return policy


def _looks_like_host(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
    except ValueError:
        return False
    return True


def extract_targets(value: Any) -> list[str]:
    """Pull high-confidence targets (URLs, ARNs, IPv4s, 12-digit account ids) from
    arbitrary tool arguments, de-duplicated in first-seen order."""
    found: list[str] = []
    seen: set[str] = set()

    def add(token: str) -> None:
        if token and token not in seen:
            seen.add(token)
            found.append(token)

    def walk(node: Any) -> None:
        if isinstance(node, str):
            for regex in (_URL_RE, _ARN_RE):
                for match in regex.findall(node):
                    add(match.rstrip(".,);'\""))
            for match in _IPV4_RE.findall(node):
                if _looks_like_host(match):
                    add(match)
            for match in _ACCOUNT_RE.findall(node):
                add(match)
        elif isinstance(node, dict):
            for item in node.values():
                walk(item)
        elif isinstance(node, (list, tuple)):
            for item in node:
                walk(item)

    walk(value)
    return found


def enforce_target(target: str, *, intrusive: bool = False) -> ScopeDecision | None:
    """Return a denial decision for an out-of-scope target, or ``None`` to allow.

    ``None`` when no policy is loaded (enforcement inactive) or the target is in
    scope. A truthy allow decision also returns ``None`` — callers only act on a
    returned (denial) decision.
    """
    policy = _active_policy
    if policy is None:
        return None
    decision = policy.evaluate(target, intrusive=intrusive)
    return None if decision.allowed else decision


def enforce_arguments(arguments: Any, *, intrusive: bool = False) -> ScopeDecision | None:
    """Check every high-confidence target found in ``arguments`` against the policy.

    Returns the first denial decision, or ``None`` when enforcement is inactive,
    no target could be extracted, or every extracted target is in scope. Extraction
    is conservative so a legit call over an ambiguous argument is never rejected;
    authoritative per-target checks belong in the domain wrappers.
    """
    if _active_policy is None:
        return None
    for target in extract_targets(arguments):
        decision = enforce_target(target, intrusive=intrusive)
        if decision is not None:
            return decision
    return None


# Network-reaching CLIs shipped in the sandbox image. A shell command that invokes
# one of these is scope-checked at the exec boundary (defense-in-depth). ``nc`` is
# intentionally excluded as too short/ambiguous to word-match safely; ``ncat`` is in.
_NETWORK_TOOL_RE = re.compile(
    r"\b(?:nmap|ncat|naabu|masscan|httpx|nuclei|curl|wget|subfinder|katana|gospider"
    r"|ffuf|sqlmap|wpscan|dirsearch|wafw00f|arjun|interactsh-client|dnsx|whatweb"
    r"|nikto|amass|sslscan|testssl)\b"
)


def enforce_shell_command(command: str) -> ScopeDecision | None:
    """Deny a sandbox shell command that reaches an out-of-scope host.

    Defense-in-depth at the ``exec_command`` boundary, mirroring the ``call_mcp``
    check. It is a **no-op** when no scope policy is loaded (so upstream behavior is
    unchanged and non-scope runs are never blocked) or when the command does not
    invoke a known network-reaching CLI. When it does, the command string is scanned
    for high-confidence targets (URLs / IPs / ARNs) and the first out-of-scope one is
    denied. Extraction is conservative — bare hostnames are not matched — so a legit
    command is not rejected over an ambiguous argument; the authoritative per-target
    check still lives in the domain tools.
    """
    if _active_policy is None:
        return None
    if not _NETWORK_TOOL_RE.search(command or ""):
        return None
    return enforce_arguments(command)

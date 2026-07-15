"""``retract_vulnerability_report`` — the inverse of create, for resumed scans.

On ``--resume`` the agent rehydrates every prior finding. When a later push
FIXES one, the agent must be able to DROP it, or rehydration is append-only and
the fixed finding re-emits into every subsequent SARIF forever — an alert that
can never auto-resolve (fail-CLOSED). This tool closes that gap.

GROUNDEDNESS GUARD (the load-bearing safety property): the tool does not blindly
trust the agent's "it's fixed" claim. Before retracting, it re-verifies against
the current tree via an injected ``read_target_file`` — recovering the finding's
fix-site (sink) locations and checking whether the vulnerable code is STILL
present. If a sink is still there verbatim, the retraction is REFUSED (a
confident-but-wrong agent must not be able to silently drop a real finding =
fail-open). Missing/deleted locations allow the retract (don't fabricate a block
from absent data).

The reader is injected rather than hard-wired: the target lives inside the
sandbox in v1, so the concrete sandbox-backed reader is supplied by the caller
(the agent factory, which holds the session). When no reader is available the
tool FAILS SAFE — it refuses to retract rather than allowing an unverified drop
(a retract we can't ground is more dangerous than a finding that survives).

Only exposed to the agent on resumed runs (see factory gating) — a fresh scan
can't need it and shouldn't be handed a findings-drop tool.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)

# read_target_file(repo_relative_path) -> awaitable file contents, or None if
# absent/unreadable. Injected by the caller (holds the sandbox session), so the
# concrete reader can `session.exec("cat", ...)` against the live /workspace
# tree. None = no reader wired → the guard fails safe (refuse).
ReadTargetFileFn = Callable[[str], Awaitable["str | None"]]

# Single-element list rather than a module global + ``global`` statement, so the
# reader can be swapped in place without PLW0603.
_reader: list[ReadTargetFileFn | None] = [None]


def set_target_file_reader(reader: ReadTargetFileFn | None) -> None:
    """Wire the sandbox-backed target-file reader (called at agent build time on
    resume). Passing None disables grounded retraction (fail-safe refuse)."""
    _reader[0] = reader


def _sink_locations(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Fix-site (sink) locations to re-verify: only those carrying a
    ``fix_before`` (the vulnerable line to change). A plain context ``snippet``
    frequently survives a genuine fix unchanged, so matching on it would
    false-refuse a real fix (real-canary lesson from the 0.8 impl)."""
    return [
        loc for loc in (report.get("code_locations") or [])
        if isinstance(loc, dict) and loc.get("fix_before") and loc.get("file")
    ]


async def _guard(report: dict[str, Any]) -> tuple[bool, str]:
    """Return (allow, detail). allow=False → REFUSE the retract.

    - no reader wired → REFUSE (fail-safe: can't ground → don't drop).
    - no fix_before sinks → ALLOW (nothing verifiable; don't fabricate a block).
    - any sink's fix_before still present verbatim → REFUSE.
    - otherwise → ALLOW.
    """
    reader = _reader[0]
    if reader is None:
        return False, "no target-file reader wired — refusing ungrounded retract"
    sinks = _sink_locations(report)
    if not sinks:
        return True, "no fix-site (fix_before) locations to verify — allowing"
    for loc in sinks:
        try:
            content = await reader(str(loc["file"]))
        except Exception:  # noqa: BLE001 — reader failure ≠ proof of absence
            return False, f"could not read {loc['file']} to verify — refusing"
        if content is None:
            continue  # file gone → this sink can't be present
        needle = str(loc["fix_before"]).strip()
        if needle and needle in content:
            return False, (f"vulnerable code still present at {loc['file']}: "
                           f"{needle[:80]!r}")
    return True, "vulnerable code no longer present at any verified sink"


@function_tool(timeout=120, strict_mode=False)
async def retract_vulnerability_report(
    ctx: RunContextWrapper,
    report_id: str,
    reason: str,
) -> dict[str, Any]:
    """Retract a finding you have RE-VERIFIED as fixed in the current code.

    Use ONLY when a prior finding (rehydrated on resume) has been genuinely
    fixed since it was reported. Cite what changed and where in ``reason``. The
    retraction is re-verified against the current tree; if the vulnerable code
    is still present, it is refused.

    Args:
        report_id: the finding id to retract (e.g. ``vuln-0003``).
        reason: code-grounded justification — what was fixed, and where.
    """
    reason = (reason or "").strip()
    if not reason:
        return {"success": False,
                "error": "reason is required — cite what was fixed and where"}

    from strix.report.state import get_global_report_state
    state = get_global_report_state()
    if state is None:
        return {"success": False, "error": "no active report state"}

    report = next(
        (r for r in state.get_existing_vulnerabilities() if r.get("id") == report_id),
        None,
    )
    if report is None:
        return {"success": True, "retracted": False, "reason": "id not present"}

    allow, detail = await _guard(report)
    if not allow:
        logger.warning("retract REFUSED for %s: %s", report_id, detail)
        return {"success": False, "retracted": False, "refused": True,
                "error": f"retraction refused — {detail}"}

    try:
        result = state.retract_vulnerability_report(report_id, reason)
    except (ValueError, AttributeError) as e:
        return {"success": False, "error": f"retract failed: {e!s}"}
    logger.info("retract honoured for %s (guard: %s)", report_id, detail)
    result["guard"] = detail
    return result

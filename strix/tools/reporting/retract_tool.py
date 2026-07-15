"""``retract_vulnerability_report`` — the inverse of create, for resumed scans.

On ``--resume`` the agent rehydrates every prior finding. When a later push
FIXES one, the agent must be able to DROP it, or rehydration is append-only and
the fixed finding re-emits into every subsequent SARIF forever — an alert that
can never auto-resolve. This tool closes that gap.

TRUST MODEL — the agent decides, the guard only annotates. Strix trusts the LLM
to FIND vulnerabilities, so it trusts the LLM's judgement that one is FIXED. The
retraction therefore ALWAYS proceeds on the agent's cited reason; the guard
never vetoes it. What the guard adds is an audit signal: it re-reads the
finding's fix-site (``fix_before``) sinks against the current tree and records a
verdict on the result, so a drop is explainable and recoverable — not a
decision-maker that can stubbornly block a genuine fix it merely can't
re-locate (moved/renamed file, dependency finding with no sink, transient read
failure). Recorded on the result:

- ``grounded=True`` (``guard_verdict="gone"``): the sink was read and the
  vulnerable line is gone (or the file is confirmed absent). The fix is
  independently corroborated.
- ``grounded=False`` (``guard_verdict="inconclusive"``): couldn't corroborate —
  no reader wired, no ``fix_before`` sink on the finding, or the sink file
  couldn't be read. Retract still honoured on the agent's word.
- ``grounded=False`` (``guard_verdict="present"``): the ``fix_before`` line is
  STILL present verbatim, which contradicts the "fixed" claim — logged as a loud
  warning, but the agent may have legitimately re-reasoned (line now unreachable,
  guarded, or the fixed form contains the substring), so the retract is honoured
  and flagged rather than blocked.

A wrong retraction is self-correcting: findings are re-derived on every scan of
the code, so a mistakenly-dropped-but-still-live finding re-appears next run.
That recoverability is what makes trusting the agent safe here.

The reader is injected rather than hard-wired: the target lives inside the
sandbox in v1, so the concrete sandbox-backed reader is supplied by the caller
(the agent factory, which holds the session). Its contract: return file text if
read, ``None`` ONLY when the file is positively confirmed absent, and RAISE when
a read neither returns content nor confirms absence — so "couldn't read" is
scored ``inconclusive``, never mistaken for "confirmed gone".

Only exposed to the agent on resumed runs, and only when
``STRIX_RESUME_RETRACT`` is set (see factory gating) — a fresh scan can't need
it, and resume stays append-only by default.
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
    resume). Passing None disables source grounding — retracts still proceed on
    the agent's reason, scored ``inconclusive`` (ungrounded) rather than
    ``gone``."""
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


# Three-way guard verdict. The point is to separate "the agent is provably
# WRONG" (hard block) from "we can't independently confirm" (defer to the
# agent's judgement but flag it) — so the tool neither silently drops live
# findings NOR stubbornly refuses a genuine fix it just can't re-locate (moved
# file, no structured sink, transient read failure).
GUARD_PRESENT = "present"          # sink confirmed still in source -> hard REFUSE
GUARD_GONE = "gone"                # sink/file confirmed absent -> grounded ALLOW
GUARD_INCONCLUSIVE = "inconclusive"  # couldn't verify -> allow on agent's word, flagged


async def _guard(report: dict[str, Any]) -> tuple[str, str]:
    """Re-verify a retract against current source. Returns ``(verdict, detail)``.

    - ``GUARD_PRESENT``: a ``fix_before`` sink is still present verbatim — the
      "it's fixed" claim is provably false. Hard refuse.
    - ``GUARD_GONE``: every verifiable sink's file was read and the vulnerable
      line is gone (or the file is confirmed absent). Grounded — allow.
    - ``GUARD_INCONCLUSIVE``: nothing could be positively checked — no reader,
      no ``fix_before`` sink (older/dependency findings), or the file couldn't
      be read (moved/renamed/permission). NOT proof either way; the tool allows
      on the agent's cited reason but records it as ungrounded so a wrong drop
      is auditable and a later re-scan re-adds it.
    """
    reader = _reader[0]
    if reader is None:
        return GUARD_INCONCLUSIVE, "no target-file reader wired — cannot ground the retract"
    sinks = _sink_locations(report)
    if not sinks:
        return GUARD_INCONCLUSIVE, "no fix_before sink on this finding — nothing to verify"

    verified_gone = False
    unread: list[str] = []
    for loc in sinks:
        try:
            result = await reader(str(loc["file"]))
        except Exception as exc:  # noqa: BLE001 — a failed read is not proof either way
            unread.append(f"{loc['file']} ({exc!r})")
            continue
        needle = str(loc["fix_before"]).strip()
        if result is None:
            verified_gone = True  # file confirmed absent → sink can't be present
            continue
        if needle and needle in result:
            return GUARD_PRESENT, (f"vulnerable code still present at {loc['file']}: "
                                   f"{needle[:80]!r}")
        verified_gone = True  # read the file, vulnerable line is gone

    if unread and not verified_gone:
        # Every sink was unreadable (e.g. the file moved) — can't confirm a fix,
        # but can't confirm it's still vulnerable either.
        return GUARD_INCONCLUSIVE, f"could not read any sink to verify: {'; '.join(unread)}"
    return GUARD_GONE, "vulnerable code no longer present at any readable sink"


async def _do_retract(report_id: str, reason: str) -> dict[str, Any]:
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

    # The guard NEVER overrides the agent: Strix trusts the LLM to find the
    # vulnerability, so it trusts the LLM's judgement that it's fixed. The guard
    # is an audit signal, not a veto — it records whether the drop could be
    # grounded in source and warns loudly when the agent's "fixed" claim looks
    # contradicted, but the retract always proceeds on the agent's cited reason.
    # A wrong drop re-appears on the next scan of the same code (findings are
    # re-derived every run), so this is recoverable, not silent data loss.
    verdict, detail = await _guard(report)
    grounded = verdict == GUARD_GONE
    if verdict == GUARD_PRESENT:
        logger.warning(
            "retract for %s: guard says vulnerable sink still present (%s), but "
            "honouring agent reason: %s",
            report_id, detail, reason,
        )
    elif not grounded:
        logger.info("retract for %s ungrounded (%s) — honouring agent reason", report_id, detail)

    try:
        result = state.retract_vulnerability_report(report_id, reason)
    except (ValueError, AttributeError) as e:
        return {"success": False, "error": f"retract failed: {e!s}"}
    logger.info("retract honoured for %s (grounded=%s, guard: %s)", report_id, grounded, detail)
    result["guard"] = detail
    result["grounded"] = grounded
    result["guard_verdict"] = verdict
    return result


@function_tool(timeout=120, strict_mode=False)
async def retract_vulnerability_report(
    ctx: RunContextWrapper,
    report_id: str,
    reason: str,
) -> dict[str, Any]:
    """Retract a prior finding you have determined is FIXED in the current code.

    Use on a resumed scan when a finding rehydrated from a previous run is no
    longer valid — the vulnerable code has been fixed or removed since it was
    reported. It is dropped from the cumulative report and SARIF so the resolved
    finding stops re-appearing. Cite what changed and where in ``reason``.

    Args:
        report_id: the finding id to retract (e.g. ``vuln-0003``).
        reason: what was fixed, and where.
    """
    return await _do_retract(report_id, reason)

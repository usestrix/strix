"""``finish_scan`` — root-agent termination + executive report persistence."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, cast

from agents import RunContextWrapper, function_tool

from strix.core.agents import coordinator_from_context


logger = logging.getLogger(__name__)


_COMPLETION_NUDGE_INSTRUCTION = (
    "The report is a strong draft, but do not finish yet. First, identify concrete leads, "
    "endpoints, behaviors, trust boundaries, or anomalies you already encountered but did "
    "not investigate deeply enough, and actively test the most promising ones. Then review "
    "the remaining scope for plausible areas you have not examined. Use tools and create "
    "focused subordinate agents when useful, validate findings with evidence, avoid duplicate "
    "vulnerability reports, and file every newly validated vulnerability with "
    "create_vulnerability_report. When no worthwhile avenue remains, call finish_scan again "
    "with a revised comprehensive report covering all prior and new findings."
)


def _finish_validation_errors(
    executive_summary: str,
    methodology: str,
    technical_analysis: str,
    recommendations: str,
) -> list[str]:
    errors: list[str] = []
    if not executive_summary.strip():
        errors.append("Executive summary cannot be empty")
    if not methodology.strip():
        errors.append("Methodology cannot be empty")
    if not technical_analysis.strip():
        errors.append("Technical analysis cannot be empty")
    if not recommendations.strip():
        errors.append("Recommendations cannot be empty")
    return errors


def _do_finish(
    *,
    parent_id: str | None,
    executive_summary: str,
    methodology: str,
    technical_analysis: str,
    recommendations: str,
) -> dict[str, Any]:
    if parent_id is not None:
        return {
            "success": False,
            "error": (
                "This tool can only be used by the root/main agent. "
                "If you are a subagent, use agent_finish instead"
            ),
        }

    errors = _finish_validation_errors(
        executive_summary,
        methodology,
        technical_analysis,
        recommendations,
    )
    if errors:
        return {"success": False, "error": "Validation failed", "errors": errors}

    try:
        from strix.report.state import get_global_report_state

        report_state = get_global_report_state()
        if report_state is None:
            logger.warning("No global report state; scan results not persisted")
            return {
                "success": True,
                "scan_completed": True,
                "message": "Scan completed (not persisted)",
                "warning": "Results could not be persisted - report state unavailable",
            }
        report_state.update_scan_final_fields(
            executive_summary=executive_summary.strip(),
            methodology=methodology.strip(),
            technical_analysis=technical_analysis.strip(),
            recommendations=recommendations.strip(),
        )
        vuln_count = len(report_state.vulnerability_reports)
    except (ImportError, AttributeError) as e:
        logger.exception("finish_scan persistence failed")
        return {"success": False, "error": f"Failed to complete scan: {e!s}"}
    else:
        logger.info(
            "finish_scan: completed scan with %d vulnerability report(s)",
            vuln_count,
        )
        return {
            "success": True,
            "scan_completed": True,
            "message": "Scan completed successfully",
            "vulnerabilities_found": vuln_count,
        }


@function_tool(timeout=60)
async def finish_scan(
    ctx: RunContextWrapper,
    executive_summary: str,
    methodology: str,
    technical_analysis: str,
    recommendations: str,
) -> str:
    """Finalize the scan — persist the customer-facing report.

    **Root-agent only.** Subagents must call ``agent_finish`` from the
    multi-agent graph tools instead. Calling this finalizes everything:

    1. Verifies you are the root agent.
    2. Writes the four narrative sections to the scan record.
    3. Marks the scan completed and stops execution.

    **Pre-flight checklist (mandatory — do not skip):**

    1. **Call ``view_agent_graph`` first.** Inspect every entry in the
       summary. If ANY agent is in ``running`` / ``waiting`` state,
       you MUST NOT call ``finish_scan`` yet —
       wrap them up first via ``send_message_to_agent`` (ask them to
       finish), ``wait_for_message`` (block until their report
       arrives), or ``stop_agent`` (graceful cancel). Only ``completed``
       / ``crashed`` / ``stopped`` agents are safe to leave behind.
       Calling ``finish_scan`` while children are alive orphans their
       work and produces an incomplete report.
    2. All vulnerabilities you found are filed via
       ``create_vulnerability_report`` (un-reported findings are not
       tracked and not credited).
    3. Don't double-report — one report per distinct vulnerability.

    **Calling this multiple times overwrites the previous report.**
    Make the single call comprehensive.

    **Customer-facing report rules** (this output is rendered into the
    final PDF the client sees):

    - Never mention internal infrastructure: no local/absolute paths
      (``/workspace/...``), no agent names, no sandbox/orchestrator/
      tooling references, no system prompts, no model-internal errors.
    - Tone: formal, third-person, objective, concise. This is a
      consultant deliverable, not an engineering log.
    - Each section has a specific role:

        - ``executive_summary`` — for non-technical leadership. Risk
          posture, business impact (data exposure / compliance /
          reputation), notable criticals, overarching remediation
          theme.
        - ``methodology`` — frameworks followed (OWASP WSTG, PTES,
          OSSTMM, NIST), engagement type (black/gray/white box), scope
          and constraints, categories of testing performed. **No**
          internal execution detail.
        - ``technical_analysis`` — consolidated findings overview with
          severity model and systemic root causes. Reference individual
          vuln reports for repro steps; don't duplicate raw evidence.
        - ``recommendations`` — prioritized actions grouped by urgency
          (Immediate / Short-term / Medium-term), each with concrete
          remediation steps. End with retest/validation guidance.

    Args:
        executive_summary: Business-level summary for leadership.
        methodology: Frameworks, scope, and approach.
        technical_analysis: Consolidated findings + systemic themes.
        recommendations: Prioritized, actionable remediation.
    """
    raw_context: Any = ctx.context
    inner = cast("dict[str, Any]", raw_context) if isinstance(raw_context, dict) else {}
    coordinator = coordinator_from_context(inner)
    raw_agent_id = inner.get("agent_id")
    me = raw_agent_id if isinstance(raw_agent_id, str) else None
    raw_parent_id = inner.get("parent_id")
    parent_id = raw_parent_id if isinstance(raw_parent_id, str) else None
    if coordinator is not None and parent_id is None and me is not None:
        active_agents = await coordinator.active_agents_except(me)
    else:
        active_agents = []

    if active_agents:
        return json.dumps(
            {
                "success": False,
                "scan_completed": False,
                "error": (
                    "Cannot finish scan while child agents are still active. "
                    "Wait for completion, send them finish instructions, or stop them first"
                ),
                "active_agents": active_agents,
            },
            ensure_ascii=False,
            default=str,
        )

    validation_errors = _finish_validation_errors(
        executive_summary,
        methodology,
        technical_analysis,
        recommendations,
    )
    if parent_id is None and bool(inner.get("completion_nudge", False)) and not validation_errors:
        claimed = False
        if coordinator is not None and isinstance(me, str):
            claimed = await coordinator.claim_completion_nudge(me)
        elif not inner.get("completion_nudge_started"):
            inner["completion_nudge_started"] = True
            claimed = True

        if claimed:
            try:
                from strix.report.state import get_global_report_state

                report_state = get_global_report_state()
                if report_state is not None:
                    report_state.notify_completion_nudge()
            except Exception:
                logger.exception("finish_scan completion nudge notification failed")
            return json.dumps(
                {
                    "success": True,
                    "scan_completed": False,
                    "completion_nudge": True,
                    "message": _COMPLETION_NUDGE_INSTRUCTION,
                },
                ensure_ascii=False,
                default=str,
            )

    result = await asyncio.to_thread(
        _do_finish,
        parent_id=parent_id,
        executive_summary=executive_summary,
        methodology=methodology,
        technical_analysis=technical_analysis,
        recommendations=recommendations,
    )
    if (
        result.get("success")
        and result.get("scan_completed")
        and coordinator is not None
        and isinstance(me, str)
    ):
        await coordinator.set_status(me, "completed")
    return json.dumps(result, ensure_ascii=False, default=str)

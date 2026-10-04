"""Candidate tools: file, list, promote, and dismiss leads.

These are the low-bar tier of the two-tier finding model
(``docs/strix2/04-validator-semantics.md``). A candidate is a lead whose impact is
NOT yet demonstrated — a scanner hit, an open port, a config that merely looks
wrong. It never counts as a finding. When impact is demonstrated it is promoted to
a validated finding (filed with ``create_vulnerability_report`` as usual); when
ruled out it is dismissed with a reason.

This module intentionally does not use ``from __future__ import annotations`` so the
SDK can resolve the ``RunContextWrapper`` context-parameter annotation at tool
registration (``get_type_hints`` runs at registration time).
"""

import json
import logging
from typing import Any, get_args

from agents import RunContextWrapper, function_tool

from strix.candidates.schema import CandidateDomain
from strix.candidates.store import CandidateStore, get_candidate_store, set_candidate_store
from strix.report.state import get_global_report_state


logger = logging.getLogger(__name__)

_VALID_DOMAINS = list(get_args(CandidateDomain))


def _store() -> CandidateStore:
    store = get_candidate_store()
    if store is None:  # no run bootstrap (e.g. a stray call); degrade to in-memory
        store = CandidateStore()
        set_candidate_store(store)
    return store


def _caller_identity(ctx: RunContextWrapper) -> tuple[str | None, str | None]:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    raw_agent_id = inner.get("agent_id")
    agent_id = raw_agent_id if isinstance(raw_agent_id, str) else None
    agent_name = None
    coordinator = inner.get("coordinator")
    if agent_id is not None and coordinator is not None:
        names = getattr(coordinator, "names", {})
        if isinstance(names, dict):
            raw = names.get(agent_id)
            agent_name = raw if isinstance(raw, str) else None
    return agent_id, agent_name


def _existing_validated() -> list[dict[str, Any]]:
    state = get_global_report_state()
    if state is None:
        return []
    try:
        return list(state.get_existing_vulnerabilities())
    except Exception:  # noqa: BLE001 - dedup is best-effort; never block filing a lead
        return []


@function_tool(timeout=30)
async def create_candidate(
    ctx: RunContextWrapper,
    title: str,
    target: str,
    domain: str,
    source: str,
    rationale: str,
) -> str:
    """File a **candidate** (a lead) — a potential issue whose impact is NOT yet proven.

    Use this for scanner/recon/static output that is worth tracking but is not a
    finding: an open port or service banner, a config that *looks* public or
    over-permissive, a version-based CVE guess, a static scanner hit. Candidates
    are deduped, persisted, and shown in a separate "Leads" section — they never
    count as findings and never appear in the finding count.

    When you actually demonstrate impact (per the per-domain bar), file the proof
    with ``create_vulnerability_report`` and then call ``promote_candidate`` to link
    the two. When you rule a lead out, call ``dismiss_candidate`` with the reason.

    Do NOT file a candidate for something you have already validated — file that as
    a vulnerability report. Do NOT re-file a lead already on the list.

    Args:
        title: Short, specific lead title (e.g. "Port 3306/MySQL open on 10.0.0.5").
        target: The affected asset (URL, host, IP, bucket, account, package@version).
        domain: One of ``web``, ``api``, ``network``, ``cloud``, ``infra``,
            ``dependency``, ``other``.
        source: What produced this lead (e.g. ``nmap``, ``prowler``, ``trivy``,
            ``reasoning``).
        rationale: Why it might matter AND what is not yet proven — the specific
            impact you would need to demonstrate to promote it.
    """
    domain_normalized = (domain or "").strip().lower()
    if domain_normalized not in _VALID_DOMAINS:
        return json.dumps(
            {
                "success": False,
                "error": f"invalid domain {domain!r}; must be one of {_VALID_DOMAINS}",
            },
            ensure_ascii=False,
        )

    agent_id, agent_name = _caller_identity(ctx)
    result = _store().add(
        title=title,
        target=target,
        domain=domain_normalized,
        source=source,
        rationale=rationale,
        agent_id=agent_id,
        agent_name=agent_name,
        existing_validated=_existing_validated(),
    )
    result["success"] = result.get("status") == "created"
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def list_candidates(ctx: RunContextWrapper, status: str | None = None) -> str:
    """List candidate leads filed so far, newest last.

    Args:
        status: Optional filter — ``open`` (default view of what still needs
            validation or dismissal), ``promoted``, or ``dismissed``. Omit for all.
    """
    del ctx
    status_filter = (status or "").strip().lower() or None
    if status_filter is not None and status_filter not in ("open", "promoted", "dismissed"):
        return json.dumps(
            {"success": False, "error": "status must be open, promoted, or dismissed"},
            ensure_ascii=False,
        )
    candidates = _store().all_candidates(status_filter)  # type: ignore[arg-type]
    return json.dumps(
        {
            "success": True,
            "count": len(candidates),
            "candidates": [c.model_dump() for c in candidates],
        },
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def promote_candidate(
    ctx: RunContextWrapper,
    candidate_id: str,
    vuln_report_id: str,
    note: str = "",
) -> str:
    """Mark a candidate promoted to a validated finding you have already filed.

    Call this AFTER you file the demonstrated impact with
    ``create_vulnerability_report`` — pass the candidate's id and the resulting
    ``vuln-NNNN`` id so the lead links to its finding and stops showing as an open
    lead.

    Args:
        candidate_id: The ``cand-NNNN`` id from ``list_candidates``.
        vuln_report_id: The ``vuln-NNNN`` report that now carries the proof.
        note: Optional one-line note on what demonstrated the impact.
    """
    del ctx
    updated = _store().promote(candidate_id, vuln_report_id, note)
    if updated is None:
        return json.dumps(
            {"success": False, "error": f"no candidate with id {candidate_id!r}"},
            ensure_ascii=False,
        )
    return json.dumps(
        {"success": True, "candidate": updated.model_dump()}, ensure_ascii=False, default=str
    )


@function_tool(timeout=30)
async def dismiss_candidate(ctx: RunContextWrapper, candidate_id: str, reason: str) -> str:
    """Rule a candidate out — it is not exploitable, or turned out benign.

    The lead is kept for the coverage/recall record (so the scan shows what was
    seen and checked), but it no longer shows as an open lead and never becomes a
    finding.

    Args:
        candidate_id: The ``cand-NNNN`` id from ``list_candidates``.
        reason: What you checked that rules this lead out.
    """
    del ctx
    if not (reason or "").strip():
        return json.dumps(
            {"success": False, "error": "reason cannot be empty - state what rules the lead out"},
            ensure_ascii=False,
        )
    updated = _store().dismiss(candidate_id, reason)
    if updated is None:
        return json.dumps(
            {"success": False, "error": f"no candidate with id {candidate_id!r}"},
            ensure_ascii=False,
        )
    return json.dumps(
        {"success": True, "candidate": updated.model_dump()}, ensure_ascii=False, default=str
    )

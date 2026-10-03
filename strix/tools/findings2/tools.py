"""Finding-annotation tools: attach optional ATT&CK/CIS/domain metadata to a finding.

These enrich a **validated** finding you have already filed with
``create_vulnerability_report`` — they never file, gate, or change a finding. Use
``annotate_finding`` after filing (and, for a promoted candidate, after
``promote_candidate``) to record the MITRE ATT&CK techniques, CIS controls, the
finding's domain, and a short pointer to the captured domain evidence, per the
validator semantics (§6). CVSS + CWE remain the finding's required rating.

This module omits ``from __future__ import annotations`` so the SDK resolves the
``RunContextWrapper`` context annotation at tool registration.
"""

import json
from typing import Any, get_args

from agents import RunContextWrapper, function_tool

from strix.candidates.schema import CandidateDomain
from strix.findings2.schema import invalid_mitre_ids, parse_ids
from strix.findings2.store import (
    FindingAnnotationStore,
    get_annotation_store,
    set_annotation_store,
)
from strix.report.state import get_global_report_state


_VALID_DOMAINS = list(get_args(CandidateDomain))


def _store() -> FindingAnnotationStore:
    store = get_annotation_store()
    if store is None:  # no run bootstrap (e.g. a stray call); degrade to in-memory
        store = FindingAnnotationStore()
        set_annotation_store(store)
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


def _finding_exists(vuln_report_id: str) -> bool:
    state = get_global_report_state()
    if state is None:
        return False
    try:
        return any(r.get("id") == vuln_report_id for r in state.get_existing_vulnerabilities())
    except Exception:  # noqa: BLE001 - existence check is best-effort, never blocks annotating
        return False


@function_tool(timeout=30)
async def annotate_finding(
    ctx: RunContextWrapper,
    vuln_report_id: str,
    domain: str = "",
    mitre_attack: str = "",
    cis_benchmark: str = "",
    notes: str = "",
) -> str:
    """Attach optional ATT&CK / CIS / domain metadata to a validated finding.

    Call this AFTER filing the finding with ``create_vulnerability_report``. It does
    not file or change the finding — it records optional framework mapping and a
    pointer to the captured domain evidence. Repeated calls merge (tags accumulate).

    Args:
        vuln_report_id: The ``vuln-NNNN`` id of the already-filed finding.
        domain: The finding's domain — one of ``web``, ``api``, ``network``,
            ``cloud``, ``infra``, ``dependency``, ``other``. Optional.
        mitre_attack: MITRE ATT&CK technique ids, comma/space separated
            (e.g. ``T1530, T1078.001``). Optional.
        cis_benchmark: CIS benchmark control ids, comma/space separated
            (e.g. ``CIS AWS 2.1.5``). Optional.
        notes: Short pointer to the captured domain evidence (e.g. the principal +
            denying policy, the command transcript, the runtime repro). Optional.
    """
    report_id = (vuln_report_id or "").strip()
    if not report_id:
        return json.dumps({"success": False, "error": "vuln_report_id is required"})

    domain_normalized = (domain or "").strip().lower() or None
    if domain_normalized is not None and domain_normalized not in _VALID_DOMAINS:
        return json.dumps(
            {
                "success": False,
                "error": f"invalid domain {domain!r}; must be one of {_VALID_DOMAINS}",
            },
            ensure_ascii=False,
        )

    mitre_ids = [technique.upper() for technique in parse_ids(mitre_attack)]
    bad = invalid_mitre_ids(mitre_ids)
    if bad:
        return json.dumps(
            {
                "success": False,
                "error": f"invalid MITRE ATT&CK ids {bad}; expected e.g. T1530 or T1078.001",
            },
            ensure_ascii=False,
        )
    cis_ids = parse_ids(cis_benchmark)

    agent_id, agent_name = _caller_identity(ctx)
    annotation = _store().upsert(
        vuln_report_id=report_id,
        domain=domain_normalized,  # type: ignore[arg-type]  # validated above
        mitre_attack=mitre_ids,
        cis_benchmark=cis_ids,
        notes=notes,
        agent_id=agent_id,
        agent_name=agent_name,
    )
    result: dict[str, Any] = {
        "success": True,
        "annotation": annotation.model_dump(),
        "known_finding": _finding_exists(report_id),
    }
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def list_finding_annotations(ctx: RunContextWrapper) -> str:
    """List the framework/domain annotations recorded for findings this run."""
    del ctx
    annotations = _store().all_annotations()
    return json.dumps(
        {
            "success": True,
            "count": len(annotations),
            "annotations": [a.model_dump() for a in annotations],
        },
        ensure_ascii=False,
        default=str,
    )

"""Identity-aware agent tools.

These tools operate on the per-target identity store and expose the auth-matrix
action to the agent runtime. All credential material returned to agents is
redacted; raw values live only inside the SQLite store.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agents import RunContextWrapper, function_tool

from strix.core.diff import diff
from strix.core.identity import IdentityStore, redact_identity
from strix.core.identity.capture import capture_from_login, capture_from_proxy
from strix.core.identity.models import Freshness, Identity
from strix.core.identity.replay import LADDER_ROLES, replay_ladder
from strix.core.identity.store import identity_store_path
from strix.core.paths import run_dir_for
from strix.report.state import get_global_report_state
from strix.tools.reporting.tool import _do_create


if TYPE_CHECKING:
    from strix.core.diff.models import Candidate, DiffResult


logger = logging.getLogger(__name__)


_CVSS_IDOR: dict[str, str] = {
    "attack_vector": "N",
    "attack_complexity": "L",
    "privileges_required": "L",
    "user_interaction": "N",
    "scope": "U",
    "confidentiality": "H",
    "integrity": "L",
    "availability": "N",
}

_CVSS_BFLA: dict[str, str] = {
    "attack_vector": "N",
    "attack_complexity": "L",
    "privileges_required": "L",
    "user_interaction": "N",
    "scope": "U",
    "confidentiality": "H",
    "integrity": "H",
    "availability": "N",
}

_CVSS_EXPIRED_AUTHORIZED: dict[str, str] = {
    "attack_vector": "N",
    "attack_complexity": "L",
    "privileges_required": "N",
    "user_interaction": "N",
    "scope": "U",
    "confidentiality": "H",
    "integrity": "H",
    "availability": "N",
}


_CWE_MAP = {
    "IDOR": "CWE-639",
    "BFLA": "CWE-862",
    "expired_authorized": "CWE-287",
}


_TITLE_MAP = {
    "IDOR": "Insecure Direct Object Reference (IDOR)",
    "BFLA": "Broken Function-Level Authorization",
    "expired_authorized": "Expired Session Still Authorized",
}


def _run_dir(ctx: RunContextWrapper) -> Path:
    """Resolve the run directory from agent context or the global report state."""
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    run_dir_value = inner.get("run_dir")
    if isinstance(run_dir_value, str) and run_dir_value:
        return Path(run_dir_value)

    report_state = get_global_report_state()
    if report_state is not None and report_state.run_name:
        return run_dir_for(report_state.run_name)

    raise RuntimeError("No run_dir provided in context and no global report state available")


def _get_store(run_dir: Path) -> IdentityStore:
    return IdentityStore(identity_store_path(run_dir))


def _make_ladder_identity(target_key: str, role: str) -> Identity:
    """Return a deliberately unauthorized identity for missing ladder roles."""
    return Identity(
        target_key=target_key,
        role=role,
        cookies={},
        tokens={},
        headers={},
        provenance="reserved",
        freshness=Freshness(captured_at="", status="expired"),
        is_reserved_expired=False,
    )


def _redacted_http_exchange(ladder_result: dict[str, Any]) -> dict[str, Any]:
    """Return a redacted view of every replay result in the ladder."""
    rows = [
        {
            "identity": cell.get("identity"),
            "success": cell.get("success"),
            "status": cell.get("status"),
            "error": cell.get("error"),
            "response": cell.get("response"),
        }
        for cell in ladder_result.get("results", [])
    ]
    return {"replay_results": rows}


def _build_labeled_responses(ladder_result: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert a ladder result into the LabeledResponse shape the diff engine expects."""
    labeled: list[dict[str, Any]] = []
    for cell in ladder_result.get("results", []):
        response = cell.get("response") or {}
        labeled.append(
            {
                "label": cell.get("identity", "unknown"),
                "response": {
                    "status_code": response.get("status_code", 0),
                    "headers": response.get("headers", []),
                    "body": (response.get("body") or b"").decode("utf-8", errors="replace"),
                },
            }
        )
    return labeled


async def _report_for_candidate(
    candidate: Candidate,
    target_key: str,
    request_id: str,
    ladder_result: dict[str, Any],
    diff_result: DiffResult,
) -> dict[str, Any]:
    """File a vulnerability report for a single auth-matrix candidate."""
    kind = candidate.kind
    cvss_breakdown = {
        "IDOR": _CVSS_IDOR,
        "BFLA": _CVSS_BFLA,
        "expired_authorized": _CVSS_EXPIRED_AUTHORIZED,
    }.get(kind, _CVSS_IDOR)

    delta = next((d for d in diff_result.deltas if d.pair == candidate.pair), None)
    artifacts: list[dict[str, Any]] = [
        {
            "artifact_type": "semantic_delta",
            "mime_type": "application/json",
            "summary": f"Semantic delta for pair {candidate.pair}",
            "data": delta.model_dump() if delta is not None else None,
        },
        {
            "artifact_type": "http_exchange",
            "mime_type": "application/json",
            "summary": f"Redacted replay ladder for request {request_id}",
            "data": _redacted_http_exchange(ladder_result),
        },
    ]

    label_a, label_b = candidate.pair
    title = f"{_TITLE_MAP.get(kind, kind)} on {target_key}"
    description = (
        f"Auth-matrix replay across roles {label_a} and {label_b} produced a "
        f"{kind} candidate: {candidate.rationale}"
    )
    impact = (
        "An attacker may access or manipulate resources outside their intended "
        "authorization scope, leading to confidentiality or integrity impact."
    )
    technical_analysis = (
        f"Candidate pair: {candidate.pair}. Evidence class: {candidate.evidence_class}. "
        f"Rationale: {candidate.rationale}. "
        f"Semantic delta: {delta.model_dump() if delta else 'none'}."
    )
    poc_description = (
        f"Replay request {request_id} as {label_a} and {label_b} via the auth-matrix "
        "ladder and compare the responses."
    )
    poc_script_code = (
        "# Auth-matrix replay results are captured in the attached http_exchange artifact."
    )
    remediation_steps = (
        "Verify authorization checks on the affected endpoint for every role in the matrix. "
        "Ensure object-level and function-level access controls are enforced server-side."
    )

    return await _do_create(
        title=title,
        description=description,
        impact=impact,
        target=target_key,
        technical_analysis=technical_analysis,
        poc_description=poc_description,
        poc_script_code=poc_script_code,
        remediation_steps=remediation_steps,
        cvss_breakdown=cvss_breakdown,
        endpoint=request_id,
        method="REPLAY",
        cve=None,
        cwe=_CWE_MAP.get(kind),
        code_locations=None,
        evidence_class=candidate.evidence_class,
        artifacts=artifacts,
    )


async def _run_auth_matrix(
    request_id: str,
    target_key: str,
    run_dir: Path,
) -> dict[str, Any]:
    """Core auth-matrix logic, separated from the tool decorator for testability."""
    store = _get_store(run_dir)
    try:
        identities = {i.role: i for i in store.list_identities(target_key)}
    finally:
        store.close()

    ladder_identities = [
        identities.get(role) or _make_ladder_identity(target_key, role) for role in LADDER_ROLES
    ]

    ladder_result = await replay_ladder(request_id, ladder_identities)
    labeled_responses = _build_labeled_responses(ladder_result)
    diff_result = diff(labeled_responses)

    reports: list[dict[str, Any]] = []
    for candidate in diff_result.candidates:
        report = await _report_for_candidate(
            candidate, target_key, request_id, ladder_result, diff_result
        )
        reports.append(report)

    matrix = {
        "identities": [redact_identity(i) for i in ladder_identities],
        "results": ladder_result.get("results", []),
        "pairwise_deltas": [d.model_dump() for d in diff_result.deltas],
    }

    return {
        "success": all(r.get("success") for r in reports) if reports else True,
        "request_id": request_id,
        "target_key": target_key,
        "matrix": matrix,
        "candidates": [c.model_dump() for c in diff_result.candidates],
        "reports": reports,
        "finding_count": len(reports),
    }


@function_tool(timeout=60, strict_mode=False)
async def identity_store_upsert(
    ctx: RunContextWrapper,
    target_key: str,
    role: str,
    source: str,
    *,
    method: str = "GET",
    url: str = "",
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    body: str = "",
) -> str:
    """Capture or update an identity for a target from proxy traffic or a login flow.

    Args:
        target_key: Canonical target key (host[:port] or repo id).
        role: Identity label (e.g. ``user``, ``admin``).
        source: Either ``proxy`` or ``login``.
        method: HTTP method when source is ``proxy``.
        url: Full URL when source is ``proxy``.
        headers: Auth-bearing headers when source is ``proxy`` or ``login``.
        cookies: Cookie values when source is ``login``.
        body: Optional request body when source is ``proxy``.
    """
    run_dir = _run_dir(ctx)
    headers = headers or {}

    if source == "proxy":
        identity = capture_from_proxy(
            target_key, role, method=method, url=url, headers=headers, body=body
        )
    elif source == "login":
        identity = capture_from_login(
            target_key, role, response_headers=headers, response_cookies=cookies or {}
        )
    else:
        return json.dumps({"success": False, "error": f"Unknown source: {source}"})

    store = _get_store(run_dir)
    try:
        store.upsert_identity(identity)
        redacted = redact_identity(identity)
    finally:
        store.close()

    return json.dumps({"success": True, "identity": redacted}, default=str)


@function_tool(timeout=30, strict_mode=False)
async def identity_store_list(
    ctx: RunContextWrapper,
    target_key: str,
) -> str:
    """List all identities (with credentials redacted) for a target."""
    run_dir = _run_dir(ctx)
    store = _get_store(run_dir)
    try:
        identities = store.list_identities(target_key)
        redacted = [redact_identity(i) for i in identities]
    finally:
        store.close()

    return json.dumps({"success": True, "identities": redacted}, default=str)


@function_tool(timeout=180, strict_mode=False)
async def auth_matrix(
    ctx: RunContextWrapper,
    request_id: str,
    target_key: str,
) -> str:
    """Replay a request across every identity for a target, diff the results, and file findings.

    The matrix covers the anonymous → user → admin → expired ladder. Any
    promoted candidates are filed as vulnerability reports with
    ``evidence_class="diff"`` and the attached SemanticDelta + redacted
    http_exchange artifacts. Empty diff → no finding reports.
    """
    run_dir = _run_dir(ctx)
    result = await _run_auth_matrix(request_id, target_key, run_dir)
    return json.dumps(result, default=str)

"""Typed terminal verdict for the independent finding verifier."""

from __future__ import annotations

import json
from typing import Any, Literal, TypeGuard

from agents import RunContextWrapper, function_tool


VerificationStatus = Literal["confirmed", "unverified", "not_applicable"]
VerificationConfidence = Literal["high", "medium", "low"]

_CVSS_VALID = {
    "attack_vector": {"N", "A", "L", "P"},
    "attack_complexity": {"L", "H"},
    "privileges_required": {"N", "L", "H"},
    "user_interaction": {"N", "R"},
    "scope": {"U", "C"},
    "confidentiality": {"N", "L", "H"},
    "integrity": {"N", "L", "H"},
    "availability": {"N", "L", "H"},
}


def _is_any_list(value: object) -> TypeGuard[list[Any]]:
    return isinstance(value, list)


def _validate_cvss(breakdown: dict[str, str] | None) -> list[str]:
    if not isinstance(breakdown, dict):
        return ["a complete revised_cvss_breakdown is required for an unverified finding"]
    return [
        f"invalid revised_cvss_breakdown {name}: {breakdown.get(name)!r}"
        for name, valid in _CVSS_VALID.items()
        if breakdown.get(name) not in valid
    ]


def _do_submit(  # noqa: PLR0912
    *,
    status: VerificationStatus,
    confidence: VerificationConfidence,
    reason: str,
    evidence: str,
    poc_description: str | None,
    poc_script_code: str | None,
    revised_impact: str | None,
    revised_cvss_breakdown: dict[str, str] | None,
    cvss_reasoning: str | None,
    finding_class: str,
    poc_required: bool,
    action_count: int,
) -> dict[str, Any]:
    errors: list[str] = []
    if not reason.strip():
        errors.append("reason cannot be empty")
    if not evidence.strip():
        errors.append("evidence cannot be empty")

    if status == "confirmed":
        if action_count <= 0:
            errors.append("confirmed requires at least one executed shell or HTTP replay action")
        if not str(poc_description or "").strip():
            errors.append("confirmed requires independent PoC reproduction steps")
        if not str(poc_script_code or "").strip():
            errors.append("confirmed requires independently tested PoC code")
        if revised_cvss_breakdown is not None:
            errors.extend(_validate_cvss(revised_cvss_breakdown))
            if not str(revised_impact or "").strip():
                errors.append("confirmed rescoring requires a revised impact statement")
            if not str(cvss_reasoning or "").strip():
                errors.append("confirmed rescoring requires CVSS review reasoning")
    elif status == "unverified":
        if action_count <= 0:
            errors.append("unverified requires at least one executed shell or HTTP replay action")
        if confidence == "high":
            errors.append("an unverified finding cannot retain high confidence")
        if not str(revised_impact or "").strip():
            errors.append("unverified requires a revised impact statement")
        if not str(cvss_reasoning or "").strip():
            errors.append("unverified requires CVSS review reasoning")
        errors.extend(_validate_cvss(revised_cvss_breakdown))
    elif finding_class != "dependency_cve":
        errors.append("not_applicable is only valid for dependency CVE findings")
    elif poc_required:
        errors.append("this dependency reaches an affected API and requires a PoC attempt")
    elif revised_cvss_breakdown is not None:
        errors.append("not_applicable retains the existing contextual CVSS score")

    if errors:
        return {"success": False, "verification_completed": False, "errors": errors}

    return {
        "success": True,
        "verification_completed": True,
        "status": status,
        "confidence": confidence,
        "reason": reason.strip()[:4000],
        "evidence": evidence.strip()[:8000],
        "poc_description": str(poc_description or "").strip()[:8000] or None,
        "poc_script_code": str(poc_script_code or "").strip()[:32000] or None,
        "revised_impact": str(revised_impact or "").strip()[:8000] or None,
        "revised_cvss_breakdown": revised_cvss_breakdown,
        "cvss_reasoning": str(cvss_reasoning or "").strip()[:4000] or None,
    }


@function_tool(strict_mode=False)
async def submit_verification_verdict(
    ctx: RunContextWrapper[dict[str, Any]],
    status: VerificationStatus,
    confidence: VerificationConfidence,
    reason: str,
    evidence: str,
    poc_description: str | None = None,
    poc_script_code: str | None = None,
    revised_impact: str | None = None,
    revised_cvss_breakdown: dict[str, str] | None = None,
    cvss_reasoning: str | None = None,
) -> str:
    """Submit the final independent verification result and stop.

    ``confirmed`` requires an independently executed PoC and concrete evidence.
    Use ``unverified`` after a real attempt cannot prove the claimed impact; review
    all CVSS metrics using only the evidence that remains. Use ``not_applicable``
    only for a dependency CVE whose vulnerable behavior cannot reasonably be
    exercised in this target; the existing advisory/contextual rating is retained.
    """
    inner = ctx.context
    raw_actions = inner.get("verification_actions")
    actions = raw_actions if _is_any_list(raw_actions) else []
    action_count = len(actions)
    result = _do_submit(
        status=status,
        confidence=confidence,
        reason=reason,
        evidence=evidence,
        poc_description=poc_description,
        poc_script_code=poc_script_code,
        revised_impact=revised_impact,
        revised_cvss_breakdown=revised_cvss_breakdown,
        cvss_reasoning=cvss_reasoning,
        finding_class=str(inner.get("verification_finding_class") or "dynamic"),
        poc_required=bool(inner.get("verification_poc_required", False)),
        action_count=action_count,
    )
    if result.get("success"):
        inner["validated_verification_verdict"] = dict(result)
    return json.dumps(result, ensure_ascii=False, default=str)

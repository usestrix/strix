"""Tests for restored report fields, SCA tool, and report formatting guidance."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from strix.report.dedupe import (
    _check_dependency_duplicate,
    _prepare_report_for_comparison,
    check_duplicate,
)
from strix.report.state import ReportState, set_global_report_state
from strix.tools.finish.tool import finish_scan
from strix.tools.reporting.tool import (
    _do_create,
    _do_create_dependency,
    _do_update,
    create_dependency_report,
    create_vulnerability_report,
    update_vulnerability_report,
)


if TYPE_CHECKING:
    from pathlib import Path


_CVSS = {
    "attack_vector": "N",
    "attack_complexity": "L",
    "privileges_required": "N",
    "user_interaction": "N",
    "scope": "U",
    "confidentiality": "H",
    "integrity": "H",
    "availability": "H",
}


_DEP_CONTEXT = {
    "attack_vector": "N",
    "attack_complexity": "L",
    "privileges_required": "N",
    "user_interaction": "N",
    "scope": "U",
    "confidentiality": "N",
    "integrity": "N",
    "availability": "H",
}

_DEP_CONTEXT_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"

_DEP_EVIDENCE = "src/render.ts:14 imports the package."

_DEP_REASONING = "Only scripts/import.py reaches the sink, so the impact is availability only."


@pytest.fixture
def report_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ReportState:
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="test-run")
    set_global_report_state(state)
    return state


def test_record_mcp_connection_status_persists_and_dedupes(
    report_state: ReportState, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The roster lands on the run record so run.json carries it for the viewer,
    and an unchanged re-write is a no-op (it does not re-save)."""
    roster = [{"name": "local_fs", "provider": None, "tool_count": 3, "dead": False}]
    report_state.record_mcp_connection_status(roster)
    assert report_state.run_record["mcp_connection_status"] == roster

    saves = 0
    original_save = report_state.save_run_data

    def _counting_save(*args: Any, **kwargs: Any) -> None:
        nonlocal saves
        saves += 1
        original_save(*args, **kwargs)

    monkeypatch.setattr(report_state, "save_run_data", _counting_save)
    report_state.record_mcp_connection_status(roster)
    assert saves == 0, "an identical roster must not trigger another save"

    report_state.record_mcp_connection_status(
        [{"name": "local_fs", "provider": None, "tool_count": 3, "dead": True}]
    )
    assert saves == 1
    assert report_state.run_record["mcp_connection_status"][0]["dead"] is True


async def test_create_report_persists_new_fields(report_state: ReportState) -> None:
    result = await _do_create(
        title="Reflected XSS in search",
        description="q reflects unencoded input.",
        impact="Session theft.",
        target="https://app.example.com",
        technical_analysis="Input interpolated into HTML.",
        poc_description="1. open /search?q=<payload>",
        poc_script_code="GET /search?q=<script>alert(1)</script>",
        remediation_steps="Context-encode output.",
        evidence="Response echoes the payload verbatim.",
        assumptions="Assumes a victim opens a crafted link.",
        counterevidence="No output encoding or CSP observed on this response.",
        confidence="HIGH",
        severity_change_conditions="A strict CSP would lower the severity.",
        fix_effort="LOW",
        cvss_breakdown=_CVSS,
        endpoint="/search",
        method="GET",
        cve=None,
        cwe="CWE-79",
        code_locations=None,
        fix_pr_body="## Fix\nEncode output.",
    )
    assert result["success"] is True
    report = report_state.vulnerability_reports[0]
    assert report["evidence"] == "Response echoes the payload verbatim."
    assert report["assumptions"] == "Assumes a victim opens a crafted link."
    assert report["fix_effort"] == "low"
    assert report["fix_pr_body"] == "## Fix\nEncode output."
    assert report["finding_class"] == "dynamic"
    assert report["counterevidence"] == "No output encoding or CSP observed on this response."
    assert report["confidence"] == "high"
    assert report["severity_change_conditions"] == "A strict CSP would lower the severity."


async def test_create_report_requires_evidence_and_assumptions(
    report_state: ReportState,
) -> None:
    result = await _do_create(
        title="X",
        description="d",
        impact="i",
        target="t",
        technical_analysis="ta",
        poc_description="p",
        poc_script_code="c",
        remediation_steps="r",
        evidence="   ",
        assumptions="",
        counterevidence="none found",
        confidence="high",
        severity_change_conditions="n/a",
        fix_effort="low",
        cvss_breakdown=_CVSS,
        endpoint=None,
        method=None,
        cve=None,
        cwe=None,
        code_locations=None,
    )
    assert result["success"] is False
    joined = " ".join(result["errors"])
    assert "Evidence" in joined
    assert "Assumptions" in joined
    assert not report_state.vulnerability_reports


async def test_create_report_rejects_invalid_fix_effort(report_state: ReportState) -> None:
    result = await _do_create(
        title="X",
        description="d",
        impact="i",
        target="t",
        technical_analysis="ta",
        poc_description="p",
        poc_script_code="c",
        remediation_steps="r",
        evidence="e",
        assumptions="a",
        counterevidence="none found",
        confidence="high",
        severity_change_conditions="n/a",
        fix_effort="enormous",
        cvss_breakdown=_CVSS,
        endpoint=None,
        method=None,
        cve=None,
        cwe=None,
        code_locations=None,
    )
    assert result["success"] is False
    assert any("fix_effort" in e for e in result["errors"])
    assert not report_state.vulnerability_reports


async def _create_with(report_state: ReportState, **overrides: object) -> dict[str, Any]:
    kwargs: dict[str, object] = {
        "title": "X",
        "description": "d",
        "impact": "i",
        "target": "t",
        "technical_analysis": "ta",
        "poc_description": "p",
        "poc_script_code": "c",
        "remediation_steps": "r",
        "evidence": "e",
        "assumptions": "a",
        "counterevidence": "No guard found on this path.",
        "confidence": "high",
        "severity_change_conditions": "Proof of internet exposure would raise it.",
        "fix_effort": "low",
        "cvss_breakdown": _CVSS,
        "endpoint": None,
        "method": None,
        "cve": None,
        "cwe": None,
        "code_locations": None,
    }
    kwargs.update(overrides)
    assert report_state is not None
    return await _do_create(**kwargs)  # type: ignore[arg-type]


async def test_create_report_requires_counterevidence(report_state: ReportState) -> None:
    result = await _create_with(report_state, counterevidence="   ")
    assert result["success"] is False
    assert any("Counterevidence" in e for e in result["errors"])
    assert not report_state.vulnerability_reports


async def test_create_report_requires_severity_change_conditions(
    report_state: ReportState,
) -> None:
    result = await _create_with(report_state, severity_change_conditions="")
    assert result["success"] is False
    assert any("severity_change_conditions" in e for e in result["errors"])
    assert not report_state.vulnerability_reports


async def test_create_report_rejects_invalid_confidence(report_state: ReportState) -> None:
    result = await _create_with(report_state, confidence="pretty sure")
    assert result["success"] is False
    assert any("confidence" in e for e in result["errors"])
    assert not report_state.vulnerability_reports


async def test_create_report_requires_rationale_when_confidence_not_high(
    report_state: ReportState,
) -> None:
    result = await _create_with(report_state, confidence="medium")
    assert result["success"] is False
    assert any("confidence_rationale" in e for e in result["errors"])
    assert not report_state.vulnerability_reports


async def test_create_report_accepts_medium_confidence_with_rationale(
    report_state: ReportState,
) -> None:
    result = await _create_with(
        report_state,
        confidence="medium",
        confidence_rationale="Static-only trace; could not stand up the service.",
    )
    assert result["success"] is True
    report = report_state.vulnerability_reports[0]
    assert report["confidence"] == "medium"
    assert report["confidence_rationale"] == "Static-only trace; could not stand up the service."


async def test_dependency_report_sets_class_and_metadata(report_state: ReportState) -> None:
    result = await _do_create_dependency(
        title="CVE-2021-23337 in lodash 4.17.20",
        description="Command injection via template.",
        target="repo/package.json",
        cve="CVE-2021-23337",
        package_name="lodash",
        installed_version="4.17.20",
        impact="Arbitrary command execution.",
        remediation_steps="Upgrade to 4.17.21.",
        assumptions="Assumes the template sink is reachable.",
        package_ecosystem="npm",
        manifest_path="package-lock.json",
        fixed_version="4.17.21",
        cwe="CWE-94",
        advisory_cvss=7.2,
        technical_analysis=None,
        fix_effort="trivial",
        reachability="imported",
        reachability_evidence=_DEP_EVIDENCE,
        contextual_cvss_breakdown=_DEP_CONTEXT,
        contextual_cvss_reasoning=_DEP_REASONING,
    )
    assert result["success"] is True
    report = report_state.vulnerability_reports[0]
    assert report["finding_class"] == "dependency_cve"
    assert report["cve"] == "CVE-2021-23337"
    assert report["severity"] == "high"
    assert report["evidence"].startswith(
        "**Advisory evidence:** `CVE-2021-23337` applies to `lodash` "
        "at installed version `4.17.20`. The advisory is fixed in `4.17.21`."
    )
    assert report["dependency_metadata"] == {
        "package_name": "lodash",
        "installed_version": "4.17.20",
        "advisory_cvss": 7.2,
        "package_ecosystem": "npm",
        "manifest_path": "package-lock.json",
        "fixed_version": "4.17.21",
        "reachability": "imported",
        "reachability_evidence": _DEP_EVIDENCE,
        "contextual_cvss_breakdown": _DEP_CONTEXT,
        "contextual_cvss_score": pytest.approx(7.5, abs=0.05),
        "contextual_cvss_vector": _DEP_CONTEXT_VECTOR,
        "contextual_cvss_reasoning": _DEP_REASONING,
    }


async def test_dependency_report_records_transitive_chain(report_state: ReportState) -> None:
    result = await _do_create_dependency(
        title="CVE-2022-24999 in qs 6.10.2",
        description="Prototype pollution in qs parsing.",
        target="repo/package.json",
        cve="CVE-2022-24999",
        package_name="qs",
        installed_version="6.10.2",
        impact="Denial of service via crafted query strings.",
        remediation_steps="Upgrade express to 4.18.2, which resolves qs 6.11.0.",
        assumptions="qs parses all incoming query strings by default.",
        package_ecosystem="npm",
        manifest_path="package-lock.json",
        fixed_version="6.10.3",
        cwe="CWE-1321",
        advisory_cvss=7.5,
        technical_analysis=None,
        fix_effort="trivial",
        introduced_by="express@4.18.1",
        dependency_path="express@4.18.1 > body-parser@1.20.0 > qs@6.10.2",
        reachability="imported",
        reachability_evidence=_DEP_EVIDENCE,
        contextual_cvss_breakdown=_DEP_CONTEXT,
        contextual_cvss_reasoning=_DEP_REASONING,
    )
    assert result["success"] is True
    report = report_state.vulnerability_reports[0]
    assert report["dependency_metadata"]["introduced_by"] == "express@4.18.1"
    assert (
        report["dependency_metadata"]["dependency_path"]
        == "express@4.18.1 > body-parser@1.20.0 > qs@6.10.2"
    )
    assert (
        "**Transitive dependency:** introduced by the direct dependency `express@4.18.1`."
        in report["evidence"]
    )
    assert (
        "**Dependency chain:** `express@4.18.1 > body-parser@1.20.0 > qs@6.10.2`"
        in report["evidence"]
    )


async def test_dependency_report_omits_blank_chain_fields(report_state: ReportState) -> None:
    result = await _do_create_dependency(
        title="CVE-2024-0001 in sample 1.0.0",
        description="Published advisory affects the pinned version.",
        target="repo/package.json",
        cve="CVE-2024-0001",
        package_name="sample",
        installed_version="1.0.0",
        impact="Impact.",
        remediation_steps="Upgrade.",
        assumptions="Assumptions.",
        package_ecosystem="npm",
        manifest_path="package-lock.json",
        fixed_version=None,
        cwe=None,
        advisory_cvss=5.0,
        technical_analysis=None,
        fix_effort="trivial",
        introduced_by="  ",
        dependency_path=None,
        reachability="imported",
        reachability_evidence=_DEP_EVIDENCE,
        contextual_cvss_breakdown=_DEP_CONTEXT,
        contextual_cvss_reasoning=_DEP_REASONING,
    )
    assert result["success"] is True
    report = report_state.vulnerability_reports[0]
    assert "introduced_by" not in report["dependency_metadata"]
    assert "dependency_path" not in report["dependency_metadata"]


async def test_dependency_report_with_no_contextual_impact_is_info(
    report_state: ReportState,
) -> None:
    result = await _do_create_dependency(
        title="CVE-2024-0001 in sample 1.0.0",
        description="Published advisory affects the pinned version.",
        target="repo/package.json",
        cve="CVE-2024-0001",
        package_name="sample",
        installed_version="1.0.0",
        impact="Low-impact dependency advisory.",
        remediation_steps="Upgrade to 1.0.1.",
        assumptions="Assumes the package is included in deployed builds.",
        package_ecosystem="npm",
        manifest_path="package-lock.json",
        fixed_version="1.0.1",
        cwe=None,
        advisory_cvss=0.0,
        technical_analysis=None,
        fix_effort="low",
        reachability="not_imported",
        reachability_evidence="No file imports the package.",
        contextual_cvss_breakdown={**_DEP_CONTEXT, "availability": "N"},
        contextual_cvss_reasoning="No application code imports the package.",
    )

    assert result["success"] is True
    assert result["severity"] == "info"
    report = report_state.vulnerability_reports[0]
    assert report["severity"] == "info"
    assert report["cvss"] == 0.0


async def test_dependency_report_records_reachability(report_state: ReportState) -> None:
    result = await _do_create_dependency(
        title="CVE-2021-23337 in lodash 4.17.20",
        description="Command injection via template.",
        target="repo/package.json",
        cve="CVE-2021-23337",
        package_name="lodash",
        installed_version="4.17.20",
        impact="Command injection where template is used.",
        remediation_steps="Upgrade to 4.17.21.",
        assumptions="Assumes the template sink is reachable.",
        package_ecosystem="npm",
        manifest_path="package-lock.json",
        fixed_version="4.17.21",
        cwe=None,
        advisory_cvss=7.2,
        technical_analysis=None,
        fix_effort="low",
        reachability="vulnerable_symbol_used",
        reachability_evidence="src/render.ts:14 calls `_.template()`.",
        contextual_cvss_breakdown=_DEP_CONTEXT,
        contextual_cvss_reasoning=_DEP_REASONING,
    )

    assert result["success"] is True
    report = report_state.vulnerability_reports[0]
    assert report["dependency_metadata"]["reachability"] == "vulnerable_symbol_used"
    assert (
        report["dependency_metadata"]["reachability_evidence"]
        == "src/render.ts:14 calls `_.template()`."
    )
    assert "**Usage analysis:**" in report["evidence"]
    assert "not a proof of exploitability or of safety" in report["evidence"]
    # The level must never influence the rating — that comes from the contextual
    # breakdown, or from advisory_cvss when no breakdown applies.
    assert report["severity"] == "high"


async def test_dependency_report_rejects_reachability_without_evidence(
    report_state: ReportState,
) -> None:
    result = await _do_create_dependency(
        title="CVE-2024-0001 in sample 1.0.0",
        description="Published advisory affects the pinned version.",
        target="repo/package.json",
        cve="CVE-2024-0001",
        package_name="sample",
        installed_version="1.0.0",
        impact="Impact.",
        remediation_steps="Upgrade.",
        assumptions="Assumptions.",
        package_ecosystem="npm",
        manifest_path="package-lock.json",
        fixed_version="1.0.1",
        cwe=None,
        advisory_cvss=5.0,
        technical_analysis=None,
        fix_effort="low",
        reachability="not_imported",
    )

    assert result["success"] is False
    assert any("reachability_evidence is required" in e for e in result["errors"])
    assert not report_state.vulnerability_reports


async def test_dependency_report_rejects_unknown_reachability_level(
    report_state: ReportState,
) -> None:
    result = await _do_create_dependency(
        title="CVE-2024-0001 in sample 1.0.0",
        description="Published advisory affects the pinned version.",
        target="repo/package.json",
        cve="CVE-2024-0001",
        package_name="sample",
        installed_version="1.0.0",
        impact="Impact.",
        remediation_steps="Upgrade.",
        assumptions="Assumptions.",
        package_ecosystem="npm",
        manifest_path="package-lock.json",
        fixed_version="1.0.1",
        cwe=None,
        advisory_cvss=5.0,
        technical_analysis=None,
        fix_effort="low",
        reachability="not_exploitable",
        reachability_evidence="vibes",
    )

    assert result["success"] is False
    assert any("Invalid reachability" in e for e in result["errors"])
    assert not report_state.vulnerability_reports


async def test_dependency_report_records_unknown_reachability(report_state: ReportState) -> None:
    result = await _do_create_dependency(
        title="CVE-2024-0001 in sample 1.0.0",
        description="Published advisory affects the pinned version.",
        target="repo/package.json",
        cve="CVE-2024-0001",
        package_name="sample",
        installed_version="1.0.0",
        impact="Impact.",
        remediation_steps="Upgrade.",
        assumptions="Analysis was inconclusive.",
        package_ecosystem="npm",
        manifest_path="package-lock.json",
        fixed_version="1.0.1",
        cwe=None,
        advisory_cvss=5.0,
        technical_analysis=None,
        fix_effort="low",
        reachability_evidence="Grep for the package found no import.",
        contextual_cvss_breakdown=_DEP_CONTEXT,
        contextual_cvss_reasoning=_DEP_REASONING,
    )

    assert result["success"] is True, result
    metadata = report_state.vulnerability_reports[0]["dependency_metadata"]
    assert metadata["reachability"] == "unknown"
    assert metadata["reachability_evidence"] == "Grep for the package found no import."


async def test_dependency_report_requires_advisory_cvss(report_state: ReportState) -> None:
    result = await _do_create_dependency(
        title="CVE-2024-0001 in sample 1.0.0",
        description="Published advisory affects the pinned version.",
        target="repo/package.json",
        cve="CVE-2024-0001",
        package_name="sample",
        installed_version="1.0.0",
        impact="Some impact.",
        remediation_steps="Upgrade to 1.0.1.",
        assumptions="Assumes the package ships in deployed builds.",
        package_ecosystem="npm",
        manifest_path="package-lock.json",
        fixed_version="1.0.1",
        cwe=None,
        advisory_cvss=None,
        technical_analysis=None,
        fix_effort="low",
    )

    assert result["success"] is False
    assert any("advisory_cvss is required" in e for e in result["errors"])
    assert not report_state.vulnerability_reports


async def test_dependency_report_dedupe_candidate_includes_dependency_metadata(
    report_state: ReportState,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    async def fake_check_duplicate(
        candidate: dict[str, object],
        existing: list[dict[str, object]],
    ) -> dict[str, object]:
        captured["candidate"] = candidate
        captured["existing"] = existing
        return {"is_duplicate": False}

    monkeypatch.setattr("strix.report.dedupe.check_duplicate", fake_check_duplicate)
    report_state.vulnerability_reports.append(
        {
            "id": "vuln-0001",
            "title": "CVE-2024-0001 in other 1.0.0",
            "severity": "low",
            "timestamp": "2026-01-01 00:00:00 UTC",
            "description": "Existing dependency finding.",
            "target": "repo/package.json",
            "cve": "CVE-2024-0001",
            "dependency_metadata": {
                "package_name": "other",
                "installed_version": "1.0.0",
                "package_ecosystem": "npm",
            },
        }
    )

    result = await _do_create_dependency(
        title="CVE-2024-0001 in sample 1.0.0",
        description="Published advisory affects the pinned version.",
        target="repo/package.json",
        cve="CVE-2024-0001",
        package_name="sample",
        installed_version="1.0.0",
        impact="Low-impact dependency advisory.",
        remediation_steps="Upgrade to 1.0.1.",
        assumptions="Assumes the package is included in deployed builds.",
        package_ecosystem="npm",
        manifest_path="package-lock.json",
        fixed_version="1.0.1",
        cwe=None,
        advisory_cvss=0.0,
        technical_analysis=None,
        fix_effort="low",
        reachability="imported",
        reachability_evidence=_DEP_EVIDENCE,
        contextual_cvss_breakdown=_DEP_CONTEXT,
        contextual_cvss_reasoning=_DEP_REASONING,
    )

    assert result["success"] is True
    assert captured["candidate"] == {
        "title": "CVE-2024-0001 in sample 1.0.0",
        "description": "Published advisory affects the pinned version.",
        "target": "repo/package.json",
        "cve": "CVE-2024-0001",
        "dependency_metadata": {
            "package_name": "sample",
            "installed_version": "1.0.0",
            "advisory_cvss": 0.0,
            "package_ecosystem": "npm",
            "manifest_path": "package-lock.json",
            "fixed_version": "1.0.1",
            "reachability": "imported",
            "reachability_evidence": _DEP_EVIDENCE,
            "contextual_cvss_breakdown": _DEP_CONTEXT,
            "contextual_cvss_score": pytest.approx(7.5, abs=0.05),
            "contextual_cvss_vector": _DEP_CONTEXT_VECTOR,
            "contextual_cvss_reasoning": _DEP_REASONING,
        },
        "technical_analysis": None,
    }


async def test_dependency_report_rejects_bad_cve(report_state: ReportState) -> None:
    result = await _do_create_dependency(
        title="bad",
        description="d",
        target="t",
        cve="not-a-cve",
        package_name="pkg",
        installed_version="1.0.0",
        impact="i",
        remediation_steps="r",
        assumptions="a",
        package_ecosystem="npm",
        manifest_path="package-lock.json",
        fixed_version=None,
        cwe=None,
        advisory_cvss=None,
        technical_analysis=None,
        fix_effort="low",
    )
    assert result["success"] is False
    assert not report_state.vulnerability_reports


async def test_dependency_report_requires_ecosystem(report_state: ReportState) -> None:
    result = await _do_create_dependency(
        title="CVE-2024-0001 in sample 1.0.0",
        description="Published advisory affects the pinned version.",
        target="repo/package.json",
        cve="CVE-2024-0001",
        package_name="sample",
        installed_version="1.0.0",
        impact="Low-impact dependency advisory.",
        remediation_steps="Upgrade to 1.0.1.",
        assumptions="Assumes the package is included in deployed builds.",
        package_ecosystem="",
        manifest_path="package-lock.json",
        fixed_version="1.0.1",
        cwe=None,
        advisory_cvss=0.0,
        technical_analysis=None,
        fix_effort="low",
    )

    assert result["success"] is False
    assert any("package_ecosystem" in error for error in result["errors"])
    assert not report_state.vulnerability_reports


async def test_dependency_report_requires_manifest_path(report_state: ReportState) -> None:
    result = await _do_create_dependency(
        title="CVE-2024-0001 in sample 1.0.0",
        description="Published advisory affects the pinned version.",
        target="repo/package.json",
        cve="CVE-2024-0001",
        package_name="sample",
        installed_version="1.0.0",
        impact="Low-impact dependency advisory.",
        remediation_steps="Upgrade to 1.0.1.",
        assumptions="Assumes the package is included in deployed builds.",
        package_ecosystem="npm",
        manifest_path=None,
        fixed_version="1.0.1",
        cwe=None,
        advisory_cvss=5.0,
        technical_analysis=None,
        fix_effort="low",
    )

    assert result["success"] is False
    assert any("manifest_path is required" in error for error in result["errors"])
    assert not report_state.vulnerability_reports


@pytest.mark.parametrize(
    "bad_path",
    ["/etc/passwd", "..\\pom.xml", "services/../pom.xml", "./package.json", "C:/repo/pom.xml"],
)
async def test_dependency_report_rejects_unsafe_manifest_path(
    report_state: ReportState, bad_path: str
) -> None:
    result = await _do_create_dependency(
        title="CVE-2024-0001 in sample 1.0.0",
        description="Published advisory affects the pinned version.",
        target="repo/package.json",
        cve="CVE-2024-0001",
        package_name="sample",
        installed_version="1.0.0",
        impact="Low-impact dependency advisory.",
        remediation_steps="Upgrade to 1.0.1.",
        assumptions="Assumes the package is included in deployed builds.",
        package_ecosystem="npm",
        manifest_path=bad_path,
        fixed_version="1.0.1",
        cwe=None,
        advisory_cvss=5.0,
        technical_analysis=None,
        fix_effort="low",
    )

    assert result["success"] is False
    assert any("manifest_path" in error for error in result["errors"])
    assert not report_state.vulnerability_reports


def test_dedupe_comparison_preserves_cve_identity() -> None:
    cleaned = _prepare_report_for_comparison(
        {
            "title": "CVE-2021-23337 in lodash",
            "description": "Pinned vulnerable dependency.",
            "target": "repo/package.json",
            "cve": "CVE-2021-23337",
            "dependency_metadata": {"package_name": "lodash"},
        }
    )

    assert cleaned["cve"] == "CVE-2021-23337"
    assert cleaned["dependency_metadata"] == {"package_name": "lodash"}


async def test_dependency_dedupe_uses_cve_package_identity() -> None:
    existing = [
        {
            "id": "vuln-0001",
            "title": "CVE-2024-0001 in other",
            "cve": "CVE-2024-0001",
            "dependency_metadata": {
                "package_name": "other",
                "installed_version": "1.0.0",
                "package_ecosystem": "npm",
            },
        }
    ]
    candidate = {
        "title": "CVE-2024-0001 in sample",
        "description": "Similar advisory prose.",
        "target": "repo/package.json",
        "cve": "CVE-2024-0001",
        "dependency_metadata": {
            "package_name": "sample",
            "installed_version": "1.0.0",
            "package_ecosystem": "npm",
        },
    }

    result = await check_duplicate(candidate, existing)

    assert result["is_duplicate"] is False
    assert result["confidence"] == 1.0


async def test_dependency_dedupe_rejects_same_cve_package_identity() -> None:
    existing = [
        {
            "id": "vuln-0001",
            "title": "CVE-2024-0001 in sample",
            "cve": "CVE-2024-0001",
            "dependency_metadata": {
                "package_name": "sample",
                "installed_version": "1.0.0",
                "package_ecosystem": "npm",
            },
        }
    ]
    candidate = {
        "title": "CVE-2024-0001 in sample with different prose",
        "description": "Different prose for the same dependency identity.",
        "target": "repo/package.json",
        "cve": "CVE-2024-0001",
        "dependency_metadata": {
            "package_name": "sample",
            "installed_version": "1.0.1",
            "package_ecosystem": "npm",
        },
    }

    result = await check_duplicate(candidate, existing)

    assert result["is_duplicate"] is True
    assert result["duplicate_id"] == "vuln-0001"
    assert result["confidence"] == 1.0


async def test_dependency_dedupe_keeps_findings_from_distinct_manifests() -> None:
    existing = [
        {
            "id": "vuln-0001",
            "title": "CVE-2024-0001 in sample",
            "cve": "CVE-2024-0001",
            "dependency_metadata": {
                "package_name": "sample",
                "installed_version": "1.0.0",
                "package_ecosystem": "npm",
                "manifest_path": "services/api/package-lock.json",
            },
        }
    ]
    candidate = {
        "title": "CVE-2024-0001 in sample (web)",
        "description": "Same advisory observed in a second workspace.",
        "target": "repo/package.json",
        "cve": "CVE-2024-0001",
        "dependency_metadata": {
            "package_name": "sample",
            "installed_version": "1.0.0",
            "package_ecosystem": "npm",
            "manifest_path": "services/web/package-lock.json",
        },
    }

    result = await check_duplicate(candidate, existing)

    assert result["is_duplicate"] is False
    assert result["confidence"] == 1.0


async def test_dependency_dedupe_rejects_same_manifest_identity() -> None:
    existing = [
        {
            "id": "vuln-0001",
            "title": "CVE-2024-0001 in sample",
            "cve": "CVE-2024-0001",
            "dependency_metadata": {
                "package_name": "sample",
                "installed_version": "1.0.0",
                "package_ecosystem": "npm",
                "manifest_path": "services/api/package-lock.json",
            },
        }
    ]
    candidate = {
        "title": "CVE-2024-0001 in sample re-reported",
        "description": "Same advisory, same manifest.",
        "target": "repo/package.json",
        "cve": "CVE-2024-0001",
        "dependency_metadata": {
            "package_name": "sample",
            "installed_version": "1.0.0",
            "package_ecosystem": "npm",
            "manifest_path": "services/api/package-lock.json",
        },
    }

    result = await check_duplicate(candidate, existing)

    assert result["is_duplicate"] is True
    assert result["duplicate_id"] == "vuln-0001"


async def test_dependency_dedupe_detects_legacy_same_cve_package() -> None:
    existing = [
        {
            "id": "vuln-0001",
            "title": "CVE-2024-0001 in npm sample package",
            "description": "Legacy dependency finding without structured metadata.",
            "cve": "CVE-2024-0001",
        }
    ]
    candidate = {
        "title": "CVE-2024-0001 in sample",
        "description": "Different prose for the same dependency identity.",
        "target": "repo/package.json",
        "cve": "CVE-2024-0001",
        "dependency_metadata": {
            "package_name": "sample",
            "installed_version": "1.0.1",
            "package_ecosystem": "npm",
        },
    }

    result = await check_duplicate(candidate, existing)

    assert result["is_duplicate"] is True
    assert result["duplicate_id"] == "vuln-0001"
    assert result["confidence"] == 1.0


def test_dependency_dedupe_defers_unclear_legacy_same_cve() -> None:
    existing = [
        {
            "id": "vuln-0001",
            "title": "CVE-2024-0001 dependency finding",
            "description": "Legacy dependency finding without package identity.",
            "cve": "CVE-2024-0001",
        }
    ]
    candidate = {
        "title": "CVE-2024-0001 in sample",
        "description": "Candidate dependency finding.",
        "target": "repo/package.json",
        "cve": "CVE-2024-0001",
        "dependency_metadata": {
            "package_name": "sample",
            "installed_version": "1.0.1",
            "package_ecosystem": "npm",
        },
    }

    assert _check_dependency_duplicate(candidate, existing) is None


def test_dependency_dedupe_defers_legacy_package_substring_match() -> None:
    existing = [
        {
            "id": "vuln-0001",
            "title": "CVE-2024-0001 in sample-package",
            "description": "Legacy dependency finding for a different package.",
            "cve": "CVE-2024-0001",
        }
    ]
    candidate = {
        "title": "CVE-2024-0001 in sample",
        "description": "Candidate dependency finding.",
        "target": "repo/package.json",
        "cve": "CVE-2024-0001",
        "dependency_metadata": {
            "package_name": "sample",
            "installed_version": "1.0.1",
            "package_ecosystem": "npm",
        },
    }

    assert _check_dependency_duplicate(candidate, existing) is None


def test_dependency_dedupe_defers_legacy_ecosystem_mismatch() -> None:
    existing = [
        {
            "id": "vuln-0001",
            "title": "CVE-2024-0001 in npm sample",
            "description": "Legacy dependency finding for a different ecosystem.",
            "cve": "CVE-2024-0001",
        }
    ]
    candidate = {
        "title": "CVE-2024-0001 in sample",
        "description": "Candidate dependency finding.",
        "target": "repo/requirements.txt",
        "cve": "CVE-2024-0001",
        "dependency_metadata": {
            "package_name": "sample",
            "installed_version": "1.0.1",
            "package_ecosystem": "pypi",
        },
    }

    assert _check_dependency_duplicate(candidate, existing) is None


def test_dependency_dedupe_matches_structured_missing_ecosystem() -> None:
    existing = [
        {
            "id": "vuln-0001",
            "title": "CVE-2024-0001 in sample",
            "cve": "CVE-2024-0001",
            "dependency_metadata": {
                "package_name": "sample",
                "installed_version": "1.0.0",
            },
        }
    ]
    candidate = {
        "title": "CVE-2024-0001 in sample",
        "description": "Candidate dependency finding.",
        "target": "repo/package.json",
        "cve": "CVE-2024-0001",
        "dependency_metadata": {
            "package_name": "sample",
            "installed_version": "1.0.1",
            "package_ecosystem": "npm",
        },
    }

    result = _check_dependency_duplicate(candidate, existing)

    assert result is not None
    assert result["is_duplicate"] is True
    assert result["duplicate_id"] == "vuln-0001"


def test_tool_descriptions_include_formatting_guidance() -> None:
    vuln_desc = create_vulnerability_report.description
    assert "markdown" in vuln_desc.lower()
    assert "fenced code" in vuln_desc.lower()

    finish_desc = finish_scan.description
    assert "markdown" in finish_desc.lower()
    assert "# Executive Summary" in finish_desc

    dep_desc = create_dependency_report.description
    assert "cve" in dep_desc.lower()
    assert "reachab" in dep_desc.lower()


def test_vuln_tool_exposes_new_params() -> None:
    props = create_vulnerability_report.params_json_schema["properties"]
    for field in ("evidence", "assumptions", "fix_effort", "fix_pr_body"):
        assert field in props

    dep_props = create_dependency_report.params_json_schema["properties"]
    for field in ("package_name", "installed_version", "cve", "advisory_cvss"):
        assert field in dep_props
    for field in ("reachability", "reachability_evidence", "manifest_path"):
        assert field in dep_props
    dep_required = create_dependency_report.params_json_schema["required"]
    assert "package_ecosystem" in dep_required
    assert "advisory_cvss" in dep_required


_FIX_LOCATION = {
    "file": "app/views.py",
    "start_line": 10,
    "end_line": 12,
    "fix_before": 'query = f"SELECT * FROM t WHERE id={uid}"',
    "fix_after": 'query = "SELECT * FROM t WHERE id=%s"',
}

_INFO_LOCATION = {
    "file": "app/views.py",
    "start_line": 10,
    "end_line": 12,
    "snippet": 'query = f"SELECT * FROM t WHERE id={uid}"',
}


async def test_fix_after_requires_verification(report_state: ReportState) -> None:
    result = await _create_with(report_state, code_locations=[_FIX_LOCATION])
    assert result["success"] is False
    assert any("fix_verification" in e for e in result["errors"])
    assert not report_state.vulnerability_reports


async def test_fix_after_with_verification_persists(report_state: ReportState) -> None:
    verification = (
        "Re-ran the PoC against the patched handler: the payload is now bound as a "
        "parameter and returns no extra rows. Checked the two sibling call sites of "
        "the same helper and the admin export path; both already parameterized. "
        "Legitimate numeric ids still resolve and the 404 path is unchanged. "
        "Ran the focused view tests and ruff."
    )
    result = await _create_with(
        report_state,
        code_locations=[_FIX_LOCATION],
        fix_verification=verification,
    )
    assert result["success"] is True
    assert report_state.vulnerability_reports[0]["fix_verification"] == verification


async def test_informational_location_needs_no_verification(report_state: ReportState) -> None:
    result = await _create_with(report_state, code_locations=[_INFO_LOCATION])
    assert result["success"] is True
    assert "fix_verification" not in report_state.vulnerability_reports[0]


def test_vuln_tool_exposes_fix_verification() -> None:
    assert "fix_verification" in create_vulnerability_report.params_json_schema["properties"]


def test_dep_tool_exposes_contextual_cvss_params() -> None:
    dep_props = create_dependency_report.params_json_schema["properties"]
    for field in (
        "contextual_cvss_breakdown",
        "contextual_cvss_reasoning",
    ):
        assert field in dep_props
    assert "source-to-sink" in dep_props["contextual_cvss_breakdown"]["description"].lower()
    assert "source-to-sink" in dep_props["reachability_evidence"]["description"].lower()
    assert "file:line" in dep_props["contextual_cvss_reasoning"]["description"].lower()


_CONTEXTUAL_BREAKDOWN = {
    "attack_vector": "L",
    "attack_complexity": "H",
    "privileges_required": "H",
    "user_interaction": "N",
    "scope": "U",
    "confidentiality": "L",
    "integrity": "L",
    "availability": "N",
}


@pytest.mark.asyncio
async def test_dependency_report_computes_contextual_cvss(
    report_state: ReportState,
) -> None:
    result = await _do_create_dependency(
        title="CVE-2021-23337 in lodash 4.17.20",
        description="Command injection via template.",
        target="repo/package.json",
        cve="CVE-2021-23337",
        package_name="lodash",
        installed_version="4.17.20",
        impact="Arbitrary command execution.",
        remediation_steps="Upgrade to 4.17.21.",
        assumptions="Assumes the template sink is reachable.",
        package_ecosystem="npm",
        advisory_cvss=7.2,
        technical_analysis=None,
        fixed_version="4.17.21",
        cwe="CWE-94",
        fix_effort="trivial",
        manifest_path="package-lock.json",
        reachability="vulnerable_symbol_used",
        reachability_evidence="scripts/import.py:88 calls `_.template()`.",
        contextual_cvss_breakdown=_CONTEXTUAL_BREAKDOWN,
        contextual_cvss_reasoning="Only scripts/import.py reaches the sink.",
    )
    assert result["success"] is True, result
    report = report_state.vulnerability_reports[0]
    metadata = report["dependency_metadata"]
    assert metadata["advisory_cvss"] == 7.2
    assert metadata["contextual_cvss_breakdown"] == _CONTEXTUAL_BREAKDOWN
    assert metadata["contextual_cvss_vector"] == ("CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:N")
    assert metadata["contextual_cvss_score"] == pytest.approx(3.0, abs=0.05)
    assert metadata["contextual_cvss_reasoning"] == "Only scripts/import.py reaches the sink."
    # The contextual rating determines the finding's score/severity, exactly
    # like a normal finding's cvss_breakdown.
    assert report["cvss"] == metadata["contextual_cvss_score"]
    assert report["severity"] == "low"


@pytest.mark.asyncio
async def test_dependency_report_requires_contextual_breakdown(
    report_state: ReportState,
) -> None:
    result = await _do_create_dependency(
        title="CVE-2021-23337 in lodash 4.17.20",
        description="Command injection via template.",
        target="repo/package.json",
        cve="CVE-2021-23337",
        package_name="lodash",
        installed_version="4.17.20",
        impact="Arbitrary command execution.",
        remediation_steps="Upgrade to 4.17.21.",
        assumptions="Assumes the template sink is reachable.",
        package_ecosystem="npm",
        advisory_cvss=7.2,
        technical_analysis=None,
        fixed_version="4.17.21",
        cwe="CWE-94",
        fix_effort="trivial",
        manifest_path="package-lock.json",
        reachability="imported",
        reachability_evidence=_DEP_EVIDENCE,
    )
    assert result["success"] is False
    assert any("contextual_cvss_breakdown is required" in error for error in result["errors"])
    assert report_state.vulnerability_reports == []


@pytest.mark.asyncio
async def test_dependency_report_rejects_incomplete_contextual_breakdown(
    report_state: ReportState,
) -> None:
    result = await _do_create_dependency(
        title="CVE-2021-23337 in lodash 4.17.20",
        description="Command injection via template.",
        target="repo/package.json",
        cve="CVE-2021-23337",
        package_name="lodash",
        installed_version="4.17.20",
        impact="Arbitrary command execution.",
        remediation_steps="Upgrade to 4.17.21.",
        assumptions="Assumes the template sink is reachable.",
        package_ecosystem="npm",
        advisory_cvss=7.2,
        technical_analysis=None,
        fixed_version="4.17.21",
        cwe="CWE-94",
        fix_effort="trivial",
        manifest_path="package-lock.json",
        contextual_cvss_breakdown={"attack_vector": "L", "attack_complexity": "Z"},
        contextual_cvss_reasoning="Only scripts/import.py reaches the sink.",
    )
    assert result["success"] is False
    assert any("attack_complexity" in error for error in result["errors"])
    assert any("privileges_required" in error for error in result["errors"])
    assert report_state.vulnerability_reports == []


@pytest.mark.asyncio
async def test_dependency_report_rejects_contextual_breakdown_without_reasoning(
    report_state: ReportState,
) -> None:
    result = await _do_create_dependency(
        title="CVE-2021-23337 in lodash 4.17.20",
        description="Command injection via template.",
        target="repo/package.json",
        cve="CVE-2021-23337",
        package_name="lodash",
        installed_version="4.17.20",
        impact="Arbitrary command execution.",
        remediation_steps="Upgrade to 4.17.21.",
        assumptions="Assumes the template sink is reachable.",
        package_ecosystem="npm",
        advisory_cvss=7.2,
        technical_analysis=None,
        fixed_version="4.17.21",
        cwe="CWE-94",
        fix_effort="trivial",
        manifest_path="package-lock.json",
        contextual_cvss_breakdown=_CONTEXTUAL_BREAKDOWN,
        contextual_cvss_reasoning="   ",
    )
    assert result["success"] is False
    assert any("contextual_cvss_reasoning is required" in error for error in result["errors"])
    assert report_state.vulnerability_reports == []


_CONFIRMED_KWARGS: dict[str, Any] = {
    "title": "Unauthenticated file write on /files/{id}",
    "description": "A multipart PATCH writes attacker content before the permission check.",
    "impact": "Any anonymous user overwrites stored files and serves attacker content.",
    "target": "https://cms.example.com",
    "technical_analysis": "disk.write runs before the authorization guard.",
    "poc_description": "1. PATCH /files/<uuid> with a multipart body as an anonymous user.",
    "poc_script_code": "PATCH /files/2f1c HTTP/1.1\n\n--x\nowned\n--x--",
    "remediation_steps": "Authorize before the write.",
    "evidence": "The stored file returns the injected payload after the 403 response.",
    "assumptions": "Assumes the uuid of one existing file is known.",
    "counterevidence": "The endpoint answers 403, yet the write already landed.",
    "confidence": "HIGH",
    "confidence_rationale": "The write was observed end to end against the live host.",
    "severity_change_conditions": "A guard before disk.write would remove the impact.",
    "fix_effort": "MEDIUM",
    "cvss_breakdown": _CVSS,
    "endpoint": "/files/{id}",
    "method": "PATCH",
    "cve": "CVE-2025-55746",
    "cwe": "CWE-863",
    "code_locations": None,
}


def _seed_weak_report(report_state: ReportState) -> None:
    """A version-based, unproven entry for the same issue, as an earlier agent files it."""
    report_state.vulnerability_reports.append(
        {
            "id": "vuln-0009",
            "title": "Directus 11.5.1 exposed on public host (in scope for CVE-2025-55746)",
            "severity": "medium",
            "timestamp": "2026-01-01 00:00:00 UTC",
            "description": "The banner reports a version affected by CVE-2025-55746.",
            "target": "https://cms.example.com",
            "confidence": "low",
            "evidence": "The version banner only.",
            "cvss": 5.3,
            "finding_class": "dynamic",
            "agent_id": "aaaa1111",
        }
    )
    report_state._saved_vuln_ids.add("vuln-0009")


async def test_duplicate_verdict_rejects_without_touching_the_existing_report(
    report_state: ReportState, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Deduplication only answers identity. A duplicate is rejected and points at the
    finding it matched; revising that finding is a separate, explicit operation."""
    _seed_weak_report(report_state)

    async def fake_check_duplicate(
        _candidate: dict[str, Any], _existing: list[dict[str, Any]]
    ) -> dict[str, Any]:
        return {
            "is_duplicate": True,
            "duplicate_id": "vuln-0009",
            "confidence": 0.9,
            "reason": "Same root cause on the same endpoint.",
        }

    monkeypatch.setattr("strix.report.dedupe.check_duplicate", fake_check_duplicate)

    result = await _do_create(**_CONFIRMED_KWARGS, agent_id="834f79fb", agent_name="Validation")

    assert result["success"] is False
    assert result["duplicate_of"] == "vuln-0009"
    assert "action" not in result
    assert len(report_state.vulnerability_reports) == 1
    report = report_state.vulnerability_reports[0]
    assert report["severity"] == "medium", "a duplicate verdict never edits the matched finding"
    assert "poc_script_code" not in report
    assert "update_history" not in report


def test_update_vulnerability_report_records_chained_impact(report_state: ReportState) -> None:
    """Attack chaining raises the impact of a finding already on file."""
    _seed_weak_report(report_state)

    updated = report_state.update_vulnerability_report(
        "vuln-0009",
        {
            "severity": "CRITICAL",
            "cvss": 9.8,
            "impact": "The overwritten file loads in an admin session and takes over the account.",
            "id": "vuln-9999",
            "finding_class": "static",
        },
        update_reason="A chained admin takeover follows the file write.",
    )

    assert updated is not None
    assert updated["id"] == "vuln-0009", "identity fields are not updatable"
    assert updated["finding_class"] == "dynamic"
    assert updated["severity"] == "critical"
    assert updated["updated_at"]
    assert report_state.update_vulnerability_report("vuln-0404", {"severity": "high"}) is None


def test_update_vulnerability_report_ignores_identical_content(report_state: ReportState) -> None:
    _seed_weak_report(report_state)
    assert report_state.update_vulnerability_report("vuln-0009", {"severity": "medium"}) is None
    assert "update_history" not in report_state.vulnerability_reports[0]


def test_update_drops_reasoning_left_behind_by_the_field_it_describes(
    report_state: ReportState,
) -> None:
    """A rating the update replaces must not keep the rationale for the old one."""
    _seed_weak_report(report_state)
    report = report_state.vulnerability_reports[0]
    report["confidence_rationale"] = "Nothing was executed; the version banner is the only signal."
    report["cvss_breakdown"] = {"attack_vector": "network", "user_interaction": "required"}
    report["severity_change_conditions"] = "Confirming the write would raise this."

    updated = report_state.update_vulnerability_report(
        "vuln-0009",
        {
            "confidence": "high",
            "severity": "critical",
            "cvss": 9.8,
            "severity_change_conditions": "A guard before the write would remove the impact.",
        },
    )

    assert updated is not None
    assert "confidence_rationale" not in updated, "the superseded rationale must not survive"
    assert "cvss_breakdown" not in updated
    assert updated["severity_change_conditions"].startswith("A guard"), (
        "a replacement the update supplies is kept, not dropped"
    )
    assert updated["update_history"][0]["dropped_fields"] == [
        "confidence_rationale",
        "cvss_breakdown",
    ]

    run_dir = report_state._run_dir
    assert run_dir is not None
    markdown = (run_dir / "vulnerabilities" / "vuln-0009.md").read_text(encoding="utf-8")
    assert "version banner is the only signal" not in markdown
    assert "Dropped as superseded: confidence_rationale, cvss_breakdown" in markdown


def test_agent_revises_its_own_report_without_a_duplicate_verdict(
    report_state: ReportState,
) -> None:
    """Editing a finding is its own operation: no dedupe verdict is involved."""
    _seed_weak_report(report_state)

    result = _do_update(
        report_id="vuln-0009",
        update_reason="An unauthenticated PATCH wrote the file, so the finding is confirmed.",
        fields={
            "poc_script_code": "PATCH /files/2f1c HTTP/1.1",
            "confidence": "HIGH",
            "confidence_rationale": "The write was replayed twice.",
            "cvss_breakdown": _CVSS,
            "severity_change_conditions": "A guard before the write would remove the impact.",
        },
        agent_id="834f79fb",
        agent_name="Directus CVE-2025-55746 Validation Agent",
    )

    assert result["success"] is True
    assert result["action"] == "updated"
    assert result["severity"] == "critical"
    assert result["cvss_score"] == pytest.approx(9.8)
    assert "cvss" in result["updated_fields"], "a new vector carries its own score"
    assert len(report_state.vulnerability_reports) == 1

    report = report_state.vulnerability_reports[0]
    assert report["id"] == "vuln-0009"
    assert report["confidence"] == "high"
    assert report["agent_id"] == "aaaa1111", "the original reporter stays on the finding"
    history = report["update_history"]
    assert history[0]["agent_name"] == "Directus CVE-2025-55746 Validation Agent"
    assert history[0]["reason"].startswith("An unauthenticated PATCH")

    run_dir = report_state._run_dir
    assert run_dir is not None
    markdown = (run_dir / "vulnerabilities" / "vuln-0009.md").read_text(encoding="utf-8")
    assert "PATCH /files/2f1c" in markdown


@pytest.mark.parametrize(
    ("report_id", "update_reason", "fields", "expected"),
    [
        ("  ", "reason", {"impact": "x"}, "report_id cannot be empty"),
        ("vuln-0009", "   ", {"impact": "x"}, "update_reason cannot be empty"),
        ("vuln-0009", "reason", {}, "No fields to update"),
        ("vuln-0404", "reason", {"impact": "x"}, "not found"),
    ],
)
def test_update_rejects_a_call_it_cannot_act_on(
    report_state: ReportState,
    report_id: str,
    update_reason: str,
    fields: dict[str, Any],
    expected: str,
) -> None:
    _seed_weak_report(report_state)

    result = _do_update(report_id=report_id, update_reason=update_reason, fields=fields)

    assert result["success"] is False
    assert expected in result["error"]
    assert "update_history" not in report_state.vulnerability_reports[0]


def test_update_reports_every_invalid_field_at_once(report_state: ReportState) -> None:
    _seed_weak_report(report_state)

    result = _do_update(
        report_id="vuln-0009",
        update_reason="Raising the rating.",
        fields={
            "confidence": "very high",
            "fix_effort": "weeks",
            "cvss_breakdown": {**_CVSS, "attack_vector": "X"},
            "cve": "CVE-BAD",
        },
    )

    assert result["success"] is False
    joined = " ".join(result["errors"])
    assert "confidence" in joined
    assert "fix_effort" in joined
    assert "attack_vector" in joined
    assert "CVE" in joined
    assert report_state.vulnerability_reports[0]["confidence"] == "low", "nothing was applied"


def test_update_wants_verification_for_a_fix_it_would_apply(
    report_state: ReportState,
) -> None:
    _seed_weak_report(report_state)

    result = _do_update(
        report_id="vuln-0009",
        update_reason="Adding the file the write lands in.",
        fields={
            "code_locations": [
                {
                    "file": "api/src/controllers/files.ts",
                    "start_line": 42,
                    "fix_before": "await storage.write(id, body)",
                    "fix_after": "await assertPermission(req); await storage.write(id, body)",
                }
            ]
        },
    )

    assert result["success"] is False
    assert any("fix_verification" in error for error in result["errors"])


def test_update_says_so_when_the_report_already_carries_it(
    report_state: ReportState,
) -> None:
    _seed_weak_report(report_state)

    result = _do_update(
        report_id="vuln-0009",
        update_reason="Restating the severity.",
        fields={"confidence": "low"},
    )

    assert result["success"] is False
    assert "already says this" in result["error"]
    assert result["report_id"] == "vuln-0009"


def test_update_tool_asks_for_the_report_and_the_reason() -> None:
    schema = update_vulnerability_report.params_json_schema
    assert set(schema["required"]) >= {"report_id", "update_reason"}
    assert "cvss_breakdown" in schema["properties"]
    assert "id" not in schema["properties"], "identity fields are not editable"
    description = update_vulnerability_report.description
    assert "not deduplication" in description


def test_update_keeps_an_exploit_out_of_a_dependency_finding(report_state: ReportState) -> None:
    """A dependency record is rated from its advisory, so a revision must not write a
    PoC and a dynamic rating onto it. The proof belongs in its own finding."""
    _seed_weak_report(report_state)
    dependency_report = report_state.vulnerability_reports[0]
    dependency_report["finding_class"] = "dependency_cve"
    dependency_report["dependency_metadata"] = {
        "package_name": "directus",
        "installed_version": "11.5.1",
    }

    result = _do_update(
        report_id="vuln-0009",
        update_reason="An unauthenticated PATCH wrote the file.",
        fields={
            "poc_script_code": "PATCH /files/2f1c HTTP/1.1",
            "endpoint": "/files/{uuid}",
            "cvss_breakdown": _CVSS,
        },
    )

    assert result["success"] is False
    assert "dependency_cve" in result["error"]
    assert set(result["rejected_fields"]) == {"endpoint", "poc_script_code"}
    assert dependency_report["severity"] == "medium"
    assert "poc_script_code" not in dependency_report
    assert "update_history" not in dependency_report


def _seed_dependency_report(report_state: ReportState) -> dict[str, Any]:
    _seed_weak_report(report_state)
    dependency_report = report_state.vulnerability_reports[0]
    dependency_report["finding_class"] = "dependency_cve"
    dependency_report["dependency_metadata"] = {
        "package_name": "directus",
        "installed_version": "11.5.1",
        "manifest_path": "package-lock.json",
        "advisory_cvss": 9.8,
        "contextual_cvss_breakdown": {**_CVSS, "confidentiality": "L"},
        "contextual_cvss_score": 5.3,
        "contextual_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "contextual_cvss_reasoning": "The vulnerable API is imported but never called.",
    }
    return dependency_report


def test_update_re_rates_a_dependency_finding_through_its_contextual_cvss(
    report_state: ReportState,
) -> None:
    """A dependency finding is rated in the context of the codebase. A revised
    breakdown replaces that contextual rating, with the reasoning a reader can
    check, and leaves the package identity alone."""
    dependency_report = _seed_dependency_report(report_state)

    result = _do_update(
        report_id="vuln-0009",
        update_reason="A call path from the upload handler to the vulnerable API was found.",
        fields={
            "cvss_breakdown": _CVSS,
            "contextual_cvss_reasoning": (
                "routes/upload.ts:88 reaches the affected parser with user input."
            ),
        },
    )

    assert result["success"] is True
    assert result["severity"] == "critical"
    assert dependency_report["severity"] == "critical"
    assert dependency_report["cvss"] == 9.8
    assert "cvss_breakdown" not in dependency_report
    assert "contextual_cvss_reasoning" not in dependency_report
    metadata = dependency_report["dependency_metadata"]
    assert metadata["package_name"] == "directus"
    assert metadata["installed_version"] == "11.5.1"
    assert metadata["manifest_path"] == "package-lock.json"
    assert metadata["advisory_cvss"] == 9.8
    assert metadata["contextual_cvss_breakdown"] == _CVSS
    assert metadata["contextual_cvss_score"] == 9.8
    assert metadata["contextual_cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert metadata["contextual_cvss_reasoning"].startswith("routes/upload.ts:88")
    assert dependency_report["finding_class"] == "dependency_cve"
    history = dependency_report["update_history"]
    assert history[-1]["previous_severity"] == "medium"
    assert set(history[-1]["fields"]) == {"cvss", "dependency_metadata", "severity"}


def test_update_wants_the_reasoning_behind_a_dependency_re_rating(
    report_state: ReportState,
) -> None:
    dependency_report = _seed_dependency_report(report_state)

    result = _do_update(
        report_id="vuln-0009",
        update_reason="The parser is reachable.",
        fields={"cvss_breakdown": _CVSS},
    )

    assert result["success"] is False
    assert any("contextual_cvss_reasoning" in error for error in result["errors"])
    assert dependency_report["severity"] == "medium"
    assert dependency_report["dependency_metadata"]["contextual_cvss_score"] == 5.3
    assert "update_history" not in dependency_report


def test_update_corrects_the_reasoning_behind_a_dependency_rating_alone(
    report_state: ReportState,
) -> None:
    """The rating on file stays; only its explanation is replaced."""
    dependency_report = _seed_dependency_report(report_state)

    result = _do_update(
        report_id="vuln-0009",
        update_reason="The reasoning named the wrong module.",
        fields={"contextual_cvss_reasoning": "lib/parser.ts imports it; no call site reaches it."},
    )

    assert result["success"] is True
    assert result["updated_fields"] == ["dependency_metadata"]
    assert dependency_report["severity"] == "medium"
    assert dependency_report["cvss"] == 5.3
    metadata = dependency_report["dependency_metadata"]
    assert metadata["contextual_cvss_breakdown"] == {**_CVSS, "confidentiality": "L"}
    assert metadata["contextual_cvss_score"] == 5.3
    assert metadata["contextual_cvss_reasoning"].startswith("lib/parser.ts")
    assert metadata["package_name"] == "directus"


def test_update_wants_a_rating_before_reasoning_about_one(
    report_state: ReportState,
) -> None:
    _seed_weak_report(report_state)
    dependency_report = report_state.vulnerability_reports[0]
    dependency_report["finding_class"] = "dependency_cve"
    dependency_report["dependency_metadata"] = {
        "package_name": "directus",
        "installed_version": "11.5.1",
    }

    result = _do_update(
        report_id="vuln-0009",
        update_reason="Explaining the rating.",
        fields={"contextual_cvss_reasoning": "Reachable."},
    )

    assert result["success"] is False
    assert any("cvss_breakdown is required" in error for error in result["errors"])
    assert "contextual_cvss_reasoning" not in dependency_report["dependency_metadata"]


def test_update_keeps_contextual_reasoning_off_a_dynamic_finding(
    report_state: ReportState,
) -> None:
    _seed_weak_report(report_state)

    result = _do_update(
        report_id="vuln-0009",
        update_reason="Re-rating.",
        fields={"cvss_breakdown": _CVSS, "contextual_cvss_reasoning": "Reachable."},
    )

    assert result["success"] is False
    assert result["rejected_fields"] == ["contextual_cvss_reasoning"]
    assert report_state.vulnerability_reports[0]["severity"] == "medium"


def test_update_reads_a_legacy_dependency_record_by_its_metadata(
    report_state: ReportState,
) -> None:
    """A dependency finding filed before finding_class was persisted still carries
    package metadata, so its class is read from that, not defaulted to dynamic."""
    _seed_weak_report(report_state)
    dependency_report = report_state.vulnerability_reports[0]
    dependency_report.pop("finding_class", None)
    dependency_report["dependency_metadata"] = {
        "package_name": "directus",
        "installed_version": "11.5.1",
    }

    result = _do_update(
        report_id="vuln-0009",
        update_reason="An unauthenticated PATCH wrote the file.",
        fields={"poc_script_code": "PATCH /files/2f1c HTTP/1.1", "cvss_breakdown": _CVSS},
    )

    assert result["success"] is False
    assert "dependency_cve" in result["error"]
    assert "poc_script_code" not in dependency_report


def test_update_still_corrects_the_prose_of_a_dependency_finding(
    report_state: ReportState,
) -> None:
    """Fields every class carries stay editable on a dependency record."""
    _seed_weak_report(report_state)
    dependency_report = report_state.vulnerability_reports[0]
    dependency_report["finding_class"] = "dependency_cve"

    result = _do_update(
        report_id="vuln-0009",
        update_reason="The advisory names a later fixed release than the report says.",
        fields={"remediation_steps": "Upgrade to 11.5.2 or later."},
    )

    assert result["success"] is True
    assert dependency_report["remediation_steps"] == "Upgrade to 11.5.2 or later."
    assert dependency_report["finding_class"] == "dependency_cve"


def test_update_refuses_code_locations_it_cannot_use(report_state: ReportState) -> None:
    """A location without a usable file and line is reported, not dropped in silence."""
    _seed_weak_report(report_state)

    result = _do_update(
        report_id="vuln-0009",
        update_reason="Naming the vulnerable handler.",
        fields={"code_locations": [{"label": "the file write"}]},
    )

    assert result["success"] is False
    assert any("start_line" in error for error in result["errors"])

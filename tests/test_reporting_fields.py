"""Tests for restored report fields, SCA tool, and report formatting guidance."""

from __future__ import annotations

from typing import TYPE_CHECKING

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
    create_dependency_report,
    create_vulnerability_report,
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

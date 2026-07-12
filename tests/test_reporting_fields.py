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
        fixed_version="4.17.21",
        cwe="CWE-94",
        advisory_cvss=7.2,
        technical_analysis=None,
        fix_effort="trivial",
    )
    assert result["success"] is True
    report = report_state.vulnerability_reports[0]
    assert report["finding_class"] == "dependency_cve"
    assert report["cve"] == "CVE-2021-23337"
    assert report["severity"] == "high"
    assert report["evidence"] == (
        "**Advisory evidence:** `CVE-2021-23337` applies to `lodash` "
        "at installed version `4.17.20`. The advisory is fixed in `4.17.21`."
    )
    assert report["dependency_metadata"] == {
        "package_name": "lodash",
        "installed_version": "4.17.20",
        "package_ecosystem": "npm",
        "fixed_version": "4.17.21",
    }


async def test_dependency_report_with_zero_cvss_remains_low_severity(
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
        fixed_version="1.0.1",
        cwe=None,
        advisory_cvss=0.0,
        technical_analysis=None,
        fix_effort="low",
    )

    assert result["success"] is True
    assert result["severity"] == "low"
    report = report_state.vulnerability_reports[0]
    assert report["severity"] == "low"
    assert report["cvss"] == 0.0


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
        fixed_version="1.0.1",
        cwe=None,
        advisory_cvss=0.0,
        technical_analysis=None,
        fix_effort="low",
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
            "package_ecosystem": "npm",
            "fixed_version": "1.0.1",
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
        fixed_version="1.0.1",
        cwe=None,
        advisory_cvss=0.0,
        technical_analysis=None,
        fix_effort="low",
    )

    assert result["success"] is False
    assert any("package_ecosystem" in error for error in result["errors"])
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
    dep_required = create_dependency_report.params_json_schema["required"]
    assert "package_ecosystem" in dep_required
    assert "advisory_cvss" in dep_required

"""CSPT ``finding_class`` separation: registry sourcing, SARIF, dedup.

Client-side path traversal shares CWE-22 with server-side path traversal /
LFI / RFI, so ``ruleId`` alone cannot tell them apart. These tests pin the
machine-readable separation that keeps them distinct in the report artifacts —
pure-Python, no browser or network, so they run in ordinary CI.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from strix.report.coverage import selectable_finding_classes
from strix.report.dedupe import _prepare_report_for_comparison
from strix.report.sarif import _class_fingerprint, _class_token, _primary_fingerprint
from strix.report.state import ReportState, set_global_report_state
from strix.tools.reporting.tool import _VALID_FINDING_CLASSES, _do_create, _do_update


if TYPE_CHECKING:
    from pathlib import Path


_SECURITY_MD = [{"physicalLocation": {"artifactLocation": {"uri": "SECURITY.md"}}}]

_CVSS = {
    "attack_vector": "N",
    "attack_complexity": "L",
    "privileges_required": "N",
    "user_interaction": "R",
    "scope": "U",
    "confidentiality": "H",
    "integrity": "H",
    "availability": "N",
}


@pytest.fixture
def report_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ReportState:
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="test-run")
    set_global_report_state(state)
    return state


async def _create(**overrides: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "title": "CSPT in invoice viewer steers the session to /api/admin/keys",
        "description": "The ?doc= value is joined into a fetch path without encoding.",
        "impact": "The victim's session calls an admin endpoint.",
        "target": "https://app.example.com",
        "technical_analysis": "app.js builds fetch('/api/invoices/' + doc).",
        "poc_description": "Open /invoice?doc=../admin/keys while signed in.",
        "poc_script_code": "GET /invoice?doc=..%2Fadmin%2Fkeys",
        "remediation_steps": "encodeURIComponent the segment and allowlist ids.",
        "evidence": "The browser requested /api/admin/keys with the session cookie.",
        "assumptions": "The victim is signed in.",
        "counterevidence": "No router normalization or encoding on this path.",
        "confidence": "high",
        "severity_change_conditions": "A CSRF token on the sink would lower it.",
        "fix_effort": "low",
        "cvss_breakdown": _CVSS,
        "endpoint": "/api/admin/keys",
        "method": "GET",
        "cve": None,
        "cwe": "CWE-22",
        "code_locations": None,
        "finding_class": "client_side_path_traversal",
    }
    kwargs.update(overrides)
    return await _do_create(**kwargs)


def test_class_token_prefers_structured_finding_class() -> None:
    """The structured field wins over the (LLM-authored) title keyword."""
    assert (
        _class_token(
            {"finding_class": "client_side_path_traversal", "title": "Path traversal in fetch"}
        )
        == "client_side_path_traversal"
    )
    # default 'dynamic' carries no signal, so fall back to the title keyword
    assert _class_token({"finding_class": "dynamic", "title": "Path traversal in download"}) == (
        "path traversal"
    )
    assert _class_token({"title": "Reflected XSS in q"}) == "xss"


def test_cspt_and_server_side_cwe22_get_distinct_primary_fingerprints() -> None:
    """The reviewer's repro: a locationless CSPT and a server-side traversal,
    both CWE-22 and both anchored to SECURITY.md, must not collapse onto one
    SARIF primary fingerprint."""
    cspt = {
        "title": "Path traversal via client fetch",
        "finding_class": "client_side_path_traversal",
    }
    server = {"title": "Path traversal in file download", "finding_class": "dynamic"}

    fp_cspt = _primary_fingerprint("CWE-22", cspt, _SECURITY_MD, is_synthetic=True)
    fp_server = _primary_fingerprint("CWE-22", server, _SECURITY_MD, is_synthetic=True)

    assert fp_cspt and fp_server
    assert fp_cspt != fp_server


def test_same_class_still_reconciles_to_one_fingerprint() -> None:
    """Two server-side CWE-22 findings of the same class still share a
    fingerprint — the separation is by class, not by prose."""
    server_a = {"title": "Path traversal in file download", "finding_class": "dynamic"}
    server_b = {"title": "Path traversal reading logs", "finding_class": "dynamic"}

    assert _primary_fingerprint(
        "CWE-22", server_a, _SECURITY_MD, is_synthetic=True
    ) == _primary_fingerprint("CWE-22", server_b, _SECURITY_MD, is_synthetic=True)


def test_valid_finding_classes_are_sourced_from_the_registry() -> None:
    """The selectable CSPT class comes from VULN_CLASSES, not a hand-maintained
    list in the reporting tool."""
    assert "client_side_path_traversal" in selectable_finding_classes()
    assert "client_side_path_traversal" in _VALID_FINDING_CLASSES
    assert {"dynamic", "dependency_cve"} <= _VALID_FINDING_CLASSES


def test_dependency_findings_keep_their_title_class_token() -> None:
    """``dependency_cve`` marks a report type, not a vulnerability class, and
    every dependency finding carries it. Two locationless CVEs under one CWE must
    keep the title-derived token they had before finding_class existed, so they
    stay separate alerts with unchanged fingerprints."""
    lodash = {"title": "CVE-2020-8203 in lodash 4.17.15", "finding_class": "dependency_cve"}
    minimist = {"title": "CVE-2021-44906 in minimist 1.2.5", "finding_class": "dependency_cve"}

    assert _class_token(lodash) == _class_token({"title": lodash["title"]})
    assert _primary_fingerprint(
        "CWE-1321", lodash, _SECURITY_MD, is_synthetic=True
    ) != _primary_fingerprint("CWE-1321", minimist, _SECURITY_MD, is_synthetic=True)
    assert _class_fingerprint("CWE-1321", lodash) != _class_fingerprint("CWE-1321", minimist)


async def test_create_accepts_a_cspt_finding_with_an_endpoint(report_state: ReportState) -> None:
    result = await _create()

    assert result["success"] is True, result
    stored = report_state.vulnerability_reports[0]
    assert stored["finding_class"] == "client_side_path_traversal"
    assert stored["endpoint"] == "/api/admin/keys"


async def test_create_reserves_dependency_cve_for_the_dependency_tool(
    report_state: ReportState,
) -> None:
    """A PoC-backed report filed as ``dependency_cve`` would carry no package
    metadata yet be gated and fingerprinted as a dependency finding."""
    result = await _create(finding_class="dependency_cve")

    assert result["success"] is False
    assert any("dependency_cve" in e for e in result["errors"])
    assert not report_state.vulnerability_reports


@pytest.mark.parametrize("nullish", ["none", "null", "", "  "])
async def test_create_treats_a_nullish_finding_class_as_dynamic(
    report_state: ReportState, nullish: str
) -> None:
    result = await _create(finding_class=nullish)

    assert result["success"] is True, result
    assert report_state.vulnerability_reports[0]["finding_class"] == "dynamic"


async def test_cspt_finding_takes_proof_revisions_like_a_dynamic_one(
    report_state: ReportState,
) -> None:
    """A CSPT finding is PoC-backed: correcting its endpoint (the discriminator),
    its PoC, or its rating must work, and must not route through the dependency
    re-rating path or attach dependency metadata."""
    assert (await _create())["success"] is True
    report_id = report_state.vulnerability_reports[0]["id"]

    result = _do_update(
        report_id=report_id,
        update_reason="The traversal reaches the key-rotation endpoint, not the listing.",
        fields={
            "endpoint": "/api/admin/keys/rotate",
            "method": "POST",
            "poc_script_code": "POST /invoice?doc=..%2Fadmin%2Fkeys%2Frotate",
            "cvss_breakdown": {**_CVSS, "availability": "H"},
        },
    )

    assert result["success"] is True, result
    stored = report_state.vulnerability_reports[0]
    assert stored["endpoint"] == "/api/admin/keys/rotate"
    assert stored["cvss_breakdown"]["availability"] == "H"
    assert stored["finding_class"] == "client_side_path_traversal"
    assert "dependency_metadata" not in stored


async def test_cspt_finding_rejects_dependency_only_revisions(report_state: ReportState) -> None:
    assert (await _create())["success"] is True
    report_id = report_state.vulnerability_reports[0]["id"]

    result = _do_update(
        report_id=report_id,
        update_reason="Add a contextual rating.",
        fields={"contextual_cvss_reasoning": "Only admins can reach it."},
    )

    assert result["success"] is False
    assert result["rejected_fields"] == ["contextual_cvss_reasoning"]


def test_dedupe_comparison_includes_finding_class() -> None:
    """Dedup sees finding_class, so two CWE-22 findings of different classes are
    not judged duplicates."""
    cleaned = _prepare_report_for_comparison(
        {"id": "1", "title": "x", "finding_class": "client_side_path_traversal"}
    )

    assert cleaned.get("finding_class") == "client_side_path_traversal"

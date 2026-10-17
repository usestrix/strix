"""CSPT ``finding_class`` separation: registry sourcing, SARIF, dedup.

Client-side path traversal shares CWE-22 with server-side path traversal /
LFI / RFI, so ``ruleId`` alone cannot tell them apart. These tests pin the
machine-readable separation that keeps them distinct in the report artifacts —
pure-Python, no browser or network, so they run in ordinary CI.
"""

from __future__ import annotations

from strix.report.coverage import selectable_finding_classes
from strix.report.dedupe import _prepare_report_for_comparison
from strix.report.sarif import _class_token, _primary_fingerprint


_SECURITY_MD = [{"physicalLocation": {"artifactLocation": {"uri": "SECURITY.md"}}}]


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
    from strix.tools.reporting.tool import _VALID_FINDING_CLASSES

    assert "client_side_path_traversal" in selectable_finding_classes()
    assert "client_side_path_traversal" in _VALID_FINDING_CLASSES
    assert {"dynamic", "dependency_cve"} <= _VALID_FINDING_CLASSES


def test_dedupe_comparison_includes_finding_class() -> None:
    """Dedup sees finding_class, so two CWE-22 findings of different classes are
    not judged duplicates."""
    cleaned = _prepare_report_for_comparison(
        {"id": "1", "title": "x", "finding_class": "client_side_path_traversal"}
    )

    assert cleaned.get("finding_class") == "client_side_path_traversal"

"""STRIDE-leg tagging in the SARIF emitter (strix.report.sarif).

Every finding's SARIF rule (and, by inheritance via ``ruleId``, its results)
carries one or more ``stride:<leg>`` tags derived from the finding's CWE, so the
GitHub code-scanning Security tab and ASPM dashboards can group/filter by
threat-model leg. Unmapped or no-CWE findings fall back to a default so coverage
reports have no gaps.
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.report.sarif import (
    _CWE_TO_STRIDE,
    _DEFAULT_STRIDE_LEGS,
    _stride_legs_for_cwe,
    build_sarif_report,
)


def _finding(**overrides: Any) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "id": "vuln-0001",
        "title": "Missing authentication on gRPC endpoint",
        "severity": "critical",
        "cwe": "CWE-306",
        "description": "The gRPC server registers no auth interceptor.",
    }
    finding.update(overrides)
    return finding


def _rule_tags(doc: dict[str, Any]) -> list[str]:
    return doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]


def test_stride_tags_on_rule_for_known_cwe() -> None:
    """CWE-306 (Missing Authentication) maps to S+E, alongside existing tags."""
    tags = _rule_tags(build_sarif_report([_finding(cwe="CWE-306")]))
    assert "stride:S" in tags
    assert "stride:E" in tags
    assert "security" in tags  # existing tags preserved
    assert "CWE-306" in tags


def test_stride_tags_attach_to_rule_not_duplicated_on_result() -> None:
    """STRIDE tags live on the RULE; results inherit them via ruleId (standard
    SARIF) rather than duplicating — the result carries the matching ruleId and
    its own strix.* properties, not a redundant tags copy."""
    doc = build_sarif_report([_finding(cwe="CWE-306")])
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    result = doc["runs"][0]["results"][0]
    assert result["ruleId"] == rule["id"]  # inherits via ruleId
    assert {"stride:S", "stride:E"} <= set(rule["properties"]["tags"])
    assert "tags" not in result["properties"]  # not duplicated


def test_stride_default_for_unmapped_cwe() -> None:
    tags = _rule_tags(build_sarif_report([_finding(cwe="CWE-99999")]))
    assert "stride:T" in tags and "stride:I" in tags


def test_stride_default_for_no_cwe() -> None:
    tags = _rule_tags(build_sarif_report([_finding(cwe=None)]))
    assert "stride:T" in tags and "stride:I" in tags


def test_stride_sql_injection_is_tampering_not_spoofing() -> None:
    tags = _rule_tags(build_sarif_report([_finding(cwe="CWE-89")]))
    assert "stride:T" in tags
    assert "stride:S" not in tags  # SQLi is tampering, not auth-shape


def test_stride_idor_is_elevation() -> None:
    tags = _rule_tags(build_sarif_report([_finding(cwe="CWE-639")]))
    assert "stride:E" in tags


def test_stride_cleartext_transmission_is_info_disclosure() -> None:
    tags = _rule_tags(build_sarif_report([_finding(cwe="CWE-319")]))
    assert "stride:I" in tags


def test_stride_hardcoded_credentials_is_spoofing() -> None:
    """CWE-798 (Hard-coded Credentials) is Spoofing (+ Info disclosure), not the
    generic default."""
    tags = _rule_tags(build_sarif_report([_finding(cwe="CWE-798")]))
    assert "stride:S" in tags
    assert set(_stride_legs_for_cwe("CWE-798")) != set(_DEFAULT_STRIDE_LEGS)


def test_stride_missing_authorization_is_elevation() -> None:
    """CWE-862 (Missing Authorization) is Elevation of privilege — sibling of
    863 Incorrect Authorization."""
    tags = _rule_tags(build_sarif_report([_finding(cwe="CWE-862")]))
    assert "stride:E" in tags
    assert "stride:T" not in tags  # not the default


@pytest.mark.parametrize("raw", ["CWE-306", "306", "cwe 306", "CWE306"])
def test_stride_cwe_normalisation_variants(raw: str) -> None:
    """CWE id variants all resolve to the same legs (S+E for 306)."""
    tags = _rule_tags(build_sarif_report([_finding(cwe=raw)]))
    assert "stride:S" in tags and "stride:E" in tags


def test_every_leg_letter_is_valid() -> None:
    """Sanity: the mapping only emits the six canonical STRIDE letters."""
    valid = {"S", "T", "R", "I", "D", "E"}
    for legs in _CWE_TO_STRIDE.values():
        assert set(legs) <= valid, f"invalid STRIDE leg in {legs}"
    assert set(_DEFAULT_STRIDE_LEGS) <= valid

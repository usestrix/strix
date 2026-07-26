"""Tests for the read-only list_reports / get_report tools."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from strix.report.state import ReportState, set_global_report_state
from strix.tools.reporting.tool import (
    _do_get_report,
    _do_list_reports,
    get_report,
    list_reports,
)


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def report_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ReportState:
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="test-run")
    set_global_report_state(state)
    return state


def _seed(state: ReportState) -> None:
    state.add_vulnerability_report(
        title="Reflected XSS in search",
        severity="medium",
        description="q reflects unencoded input.",
        target="https://app.example.com",
        endpoint="/search",
        method="GET",
        cwe="CWE-79",
        cvss=6.1,
        agent_name="XSS Agent",
    )
    state.add_vulnerability_report(
        title="SQL Injection in login",
        severity="critical",
        description="Login parameter is injectable.",
        target="https://app.example.com",
        endpoint="/api/login",
        cwe="CWE-89",
        cvss=9.8,
        agent_name="SQLi Agent",
    )
    state.add_vulnerability_report(
        title="CVE-2021-23337 in lodash 4.17.20",
        severity="high",
        description="Command injection via template.",
        target="repo/package.json",
        cve="CVE-2021-23337",
        cvss=7.2,
        finding_class="dependency_cve",
    )


@pytest.mark.usefixtures("report_state")
def test_list_reports_empty() -> None:
    result = _do_list_reports(
        severity=None, finding_class=None, target=None, search=None, include_details=False
    )
    assert result["success"] is True
    assert result["reports"] == []
    assert result["total_count"] == 0
    assert result["severity_counts"] == {}


def test_list_reports_metadata_first_and_sorted(report_state: ReportState) -> None:
    _seed(report_state)
    result = _do_list_reports(
        severity=None, finding_class=None, target=None, search=None, include_details=False
    )
    assert result["success"] is True
    assert result["total_count"] == 3
    # sorted by severity: critical, high, medium
    titles = [r["title"] for r in result["reports"]]
    assert titles == [
        "SQL Injection in login",
        "CVE-2021-23337 in lodash 4.17.20",
        "Reflected XSS in search",
    ]
    assert result["severity_counts"] == {"critical": 1, "high": 1, "medium": 1}
    # compact entries carry a preview, never full-body fields
    first = result["reports"][0]
    assert "description_preview" in first
    assert "poc_script_code" not in first
    assert "evidence" not in first


def test_list_reports_filter_severity(report_state: ReportState) -> None:
    _seed(report_state)
    result = _do_list_reports(
        severity="critical", finding_class=None, target=None, search=None, include_details=False
    )
    assert result["filtered_count"] == 1
    assert result["reports"][0]["title"] == "SQL Injection in login"
    # severity_counts reflect ALL reports, not the filtered subset
    assert result["total_count"] == 3


def test_list_reports_filter_finding_class(report_state: ReportState) -> None:
    _seed(report_state)
    result = _do_list_reports(
        severity=None,
        finding_class="dependency_cve",
        target=None,
        search=None,
        include_details=False,
    )
    assert result["filtered_count"] == 1
    assert result["reports"][0]["cve"] == "CVE-2021-23337"


def test_list_reports_filter_target_and_search(report_state: ReportState) -> None:
    _seed(report_state)
    by_target = _do_list_reports(
        severity=None, finding_class=None, target="/api/login", search=None, include_details=False
    )
    assert [r["title"] for r in by_target["reports"]] == ["SQL Injection in login"]

    by_search = _do_list_reports(
        severity=None, finding_class=None, target=None, search="lodash", include_details=False
    )
    assert [r["cve"] for r in by_search["reports"]] == ["CVE-2021-23337"]


def test_list_reports_include_details(report_state: ReportState) -> None:
    _seed(report_state)
    result = _do_list_reports(
        severity="medium", finding_class=None, target=None, search=None, include_details=True
    )
    entry = result["reports"][0]
    assert entry["description"] == "q reflects unencoded input."
    assert "description_preview" not in entry


@pytest.mark.usefixtures("report_state")
def test_list_reports_rejects_invalid_filters() -> None:
    result = _do_list_reports(
        severity="spicy", finding_class="bogus", target=None, search=None, include_details=False
    )
    assert result["success"] is False
    joined = " ".join(result["errors"])
    assert "severity" in joined
    assert "finding_class" in joined


def test_get_report_success(report_state: ReportState) -> None:
    _seed(report_state)
    result = _do_get_report("vuln-0002")
    assert result["success"] is True
    assert result["report"]["title"] == "SQL Injection in login"
    assert result["report"]["cwe"] == "CWE-89"


def test_get_report_not_found(report_state: ReportState) -> None:
    _seed(report_state)
    result = _do_get_report("vuln-9999")
    assert result["success"] is False
    assert result["report"] is None


@pytest.mark.usefixtures("report_state")
def test_get_report_empty_id() -> None:
    result = _do_get_report("   ")
    assert result["success"] is False


def test_read_tools_are_read_only_and_stateless(report_state: ReportState) -> None:
    _seed(report_state)
    before = list(report_state.vulnerability_reports)
    _do_list_reports(
        severity=None, finding_class=None, target=None, search=None, include_details=True
    )
    _do_get_report("vuln-0001")
    assert report_state.vulnerability_reports == before


def test_tool_descriptions_mention_read_only() -> None:
    assert "read-only" in list_reports.description.lower()
    assert "get_report" in list_reports.description
    assert "read-only" in get_report.description.lower()

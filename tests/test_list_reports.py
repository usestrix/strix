"""Tests for the read-only list_reports / get_report tools."""

from __future__ import annotations

import json
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


def test_add_vulnerability_report_strips_control_chars_from_title(
    report_state: ReportState,
) -> None:
    # A title quotes text from the scanned target, so it can carry newlines or
    # tabs that break the markdown heading, the CSV cell and the TUI list.
    report_id = report_state.add_vulnerability_report(
        title="\tXSS in\r\n search\x00 form ",
        severity="medium",
        target="https://app.example.com",
    )
    report = next(r for r in report_state.vulnerability_reports if r["id"] == report_id)
    assert report["title"] == "XSS in search form"


def test_hydrate_from_run_dir_strips_control_chars_from_title(
    report_state: ReportState,
) -> None:
    # A run started before titles were normalized can hold control characters on
    # disk, and resume re-exports those titles to the CSV, the SARIF and the TUI.
    (report_state.get_run_dir() / "vulnerabilities.json").write_text(
        json.dumps(
            [
                {
                    "id": "vuln-0001",
                    "title": "XSS in\r\n search\tform",
                    "severity": "medium",
                    "timestamp": "2026-01-01 00:00:00 UTC",
                }
            ]
        ),
        encoding="utf-8",
    )

    md_path = report_state.get_run_dir() / "vulnerabilities" / "vuln-0001.md"
    md_path.parent.mkdir(exist_ok=True)
    md_path.write_text("# XSS in\r\n search\tform\n", encoding="utf-8")

    report_state.hydrate_from_run_dir()
    report_state.save_run_data()

    assert report_state.vulnerability_reports[0]["title"] == "XSS in search form"
    # The markdown on disk holds the raw heading, so resume must rewrite it.
    assert md_path.read_text(encoding="utf-8").startswith("# XSS in search form\n")


def test_hydrate_names_the_class_a_legacy_record_always_had(
    report_state: ReportState,
) -> None:
    # A run started before the class was persisted still holds the package metadata
    # of a dependency finding, and resume must not read it as a dynamic one.
    (report_state.get_run_dir() / "vulnerabilities.json").write_text(
        json.dumps(
            [
                {
                    "id": "vuln-0001",
                    "title": "Directus 11.5.1 is affected by CVE-2025-55746",
                    "severity": "medium",
                    "timestamp": "2026-01-01 00:00:00 UTC",
                    "dependency_metadata": {
                        "package_name": "directus",
                        "installed_version": "11.5.1",
                    },
                },
                {
                    "id": "vuln-0002",
                    "title": "Reflected XSS in search",
                    "severity": "medium",
                    "timestamp": "2026-01-01 00:00:00 UTC",
                },
            ]
        ),
        encoding="utf-8",
    )

    report_state.hydrate_from_run_dir()

    assert report_state.vulnerability_reports[0]["finding_class"] == "dependency_cve"
    assert report_state.vulnerability_reports[1]["finding_class"] == "dynamic"


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


def test_list_reports_flags_callers_own_reports(report_state: ReportState) -> None:
    report_state.add_vulnerability_report(
        title="Mine", severity="high", target="t", agent_id="agent-1", agent_name="Agent One"
    )
    report_state.add_vulnerability_report(
        title="Theirs", severity="low", target="t", agent_id="agent-2", agent_name="Agent Two"
    )
    result = _do_list_reports(
        severity=None,
        finding_class=None,
        target=None,
        search=None,
        include_details=False,
        caller_agent_id="agent-1",
    )
    by_title = {r["title"]: r for r in result["reports"]}
    assert by_title["Mine"].get("by_you") is True
    assert by_title["Mine"]["agent_name"] == "Agent One"
    assert "by_you" not in by_title["Theirs"]
    assert by_title["Theirs"]["agent_name"] == "Agent Two"


def test_list_reports_no_caller_marks_nothing(report_state: ReportState) -> None:
    report_state.add_vulnerability_report(
        title="Mine", severity="high", target="t", agent_id="agent-1", agent_name="Agent One"
    )
    result = _do_list_reports(
        severity=None, finding_class=None, target=None, search=None, include_details=False
    )
    assert "by_you" not in result["reports"][0]


def test_get_report_flags_caller_ownership(report_state: ReportState) -> None:
    report_state.add_vulnerability_report(
        title="Mine", severity="high", target="t", agent_id="agent-1", agent_name="Agent One"
    )
    mine = _do_get_report("vuln-0001", caller_agent_id="agent-1")
    assert mine["report"].get("by_you") is True
    theirs = _do_get_report("vuln-0001", caller_agent_id="agent-9")
    assert "by_you" not in theirs["report"]


def test_list_reports_docstring_scopes_to_orchestrator() -> None:
    desc = list_reports.description.lower()
    assert "orchestrator" in desc or "root agent" in desc


@pytest.mark.parametrize("sev", ["CRITICAL", "Critical", "critical"])
def test_list_reports_severity_filter_case_insensitive(report_state: ReportState, sev: str) -> None:
    _seed(report_state)
    result = _do_list_reports(
        severity=sev, finding_class=None, target=None, search=None, include_details=False
    )
    assert [r["title"] for r in result["reports"]] == ["SQL Injection in login"]


def test_list_reports_finding_class_filter_case_insensitive(report_state: ReportState) -> None:
    _seed(report_state)
    result = _do_list_reports(
        severity=None,
        finding_class="Dependency_CVE",
        target=None,
        search=None,
        include_details=False,
    )
    assert result["filtered_count"] == 1


def test_list_reports_target_filter_matches_domain_and_is_case_insensitive(
    report_state: ReportState,
) -> None:
    _seed(report_state)
    # substring of the `target` field (not the endpoint), mixed case
    result = _do_list_reports(
        severity=None,
        finding_class=None,
        target="APP.EXAMPLE.COM",
        search=None,
        include_details=False,
    )
    assert {r["title"] for r in result["reports"]} == {
        "Reflected XSS in search",
        "SQL Injection in login",
    }


def test_list_reports_search_matches_title_case_insensitive(report_state: ReportState) -> None:
    _seed(report_state)
    result = _do_list_reports(
        severity=None, finding_class=None, target=None, search="INJECTION", include_details=False
    )
    # matches title "SQL Injection in login" and description "Command injection..."
    assert {r["title"] for r in result["reports"]} == {
        "SQL Injection in login",
        "CVE-2021-23337 in lodash 4.17.20",
    }


def test_list_reports_filters_compose(report_state: ReportState) -> None:
    _seed(report_state)
    result = _do_list_reports(
        severity="high",
        finding_class="dependency_cve",
        target="package.json",
        search="lodash",
        include_details=False,
    )
    assert [r["cve"] for r in result["reports"]] == ["CVE-2021-23337"]


def test_list_reports_no_match_returns_empty_success(report_state: ReportState) -> None:
    _seed(report_state)
    result = _do_list_reports(
        severity=None,
        finding_class=None,
        target=None,
        search="nonexistent-xyz",
        include_details=False,
    )
    assert result["success"] is True
    assert result["filtered_count"] == 0
    assert result["reports"] == []
    # counts still reflect all reports
    assert result["total_count"] == 3


def test_list_reports_description_preview_truncated(report_state: ReportState) -> None:
    long_desc = "A" * 400
    report_state.add_vulnerability_report(
        title="Long", severity="low", description=long_desc, target="t"
    )
    result = _do_list_reports(
        severity=None, finding_class=None, target=None, search=None, include_details=False
    )
    preview = result["reports"][0]["description_preview"]
    assert preview.endswith("...")
    assert len(preview) <= 284  # 280 chars + "..."


def test_list_reports_severity_counts_ordered_with_none_bucket(
    report_state: ReportState,
) -> None:
    report_state.add_vulnerability_report(title="A", severity="low", target="t")
    report_state.add_vulnerability_report(title="B", severity="critical", target="t")
    report_state.add_vulnerability_report(title="C", severity="", target="t")
    result = _do_list_reports(
        severity=None, finding_class=None, target=None, search=None, include_details=False
    )
    # ordered critical -> ... -> none
    assert list(result["severity_counts"].keys()) == ["critical", "low", "none"]


@pytest.mark.usefixtures("report_state")
def test_list_reports_no_state_returns_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("strix.report.state.get_global_report_state", lambda: None)
    result = _do_list_reports(
        severity=None, finding_class=None, target=None, search=None, include_details=False
    )
    assert result["success"] is True
    assert result["reports"] == []
    assert "warning" in result


@pytest.mark.usefixtures("report_state")
def test_get_report_no_state_returns_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("strix.report.state.get_global_report_state", lambda: None)
    result = _do_get_report("vuln-0001")
    assert result["success"] is False
    assert result["report"] is None


@pytest.mark.parametrize("nullish", ["null", "none", "NULL", " None ", "undefined", "nil"])
def test_list_reports_ignores_nullish_filter_strings(
    report_state: ReportState, nullish: str
) -> None:
    _seed(report_state)
    unfiltered = _do_list_reports(
        severity=None, finding_class=None, target=None, search=None, include_details=False
    )
    assert unfiltered["filtered_count"] == 3

    assert (
        _do_list_reports(
            severity=nullish,
            finding_class=nullish,
            target=nullish,
            search=nullish,
            include_details=False,
        )
        == unfiltered
    )

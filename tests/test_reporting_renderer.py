"""A rejected vulnerability report must render as rejected, not as a filed one."""

from __future__ import annotations

from typing import Any

from rich.text import Text

from strix.interface.tui.renderers.reporting_renderer import (
    CreateDependencyReportRenderer,
    CreateVulnerabilityReportRenderer,
)


def _args() -> dict[str, Any]:
    return {
        "title": "SQL injection in /api/login",
        "severity": "critical",
        "description": "The username parameter reaches the query unsanitized.",
        "impact": "Full database read access.",
        "target": "https://app.example.com",
        "poc_script_code": 'curl -d "user=\' OR 1=1--" https://app.example.com/api/login',
        "remediation_steps": "Use parameterized queries.",
    }


def _plain(static: object) -> str:
    content = static.content  # type: ignore[attr-defined]
    return content.plain if isinstance(content, Text) else str(content)


def test_duplicate_rejection_is_rendered_as_not_created() -> None:
    result = {
        "success": False,
        "error": "Potential duplicate of 'SQLi in login' (id=8f2ab1c0...) — do not re-report",
        "duplicate_of": "8f2ab1c0",
    }
    widget = CreateVulnerabilityReportRenderer.render(
        {"args": _args(), "result": result, "status": "failed"},
    )
    text = _plain(widget)

    assert "Not created" in text
    assert "Potential duplicate" in text
    assert "Use parameterized queries." not in text, "args rendered as if the report was filed"
    assert "status-failed" in widget.classes


def test_validation_failure_lists_every_error() -> None:
    result = {
        "success": False,
        "error": "Validation failed",
        "errors": ["Invalid attack_vector: X", "Invalid cwe: CWE-abc"],
    }
    text = _plain(
        CreateVulnerabilityReportRenderer.render(
            {"args": _args(), "result": result, "status": "failed"},
        ),
    )

    assert "Invalid attack_vector: X; Invalid cwe: CWE-abc" in text


def test_unpersisted_report_is_flagged_as_not_persisted() -> None:
    result = {
        "success": True,
        "warning": "Report could not be persisted - report state unavailable",
    }
    widget = CreateVulnerabilityReportRenderer.render(
        {"args": _args(), "result": result, "status": "completed"},
    )
    text = _plain(widget)

    assert "Not persisted" in text
    assert "report state unavailable" in text
    assert "status-failed" in widget.classes


def test_successful_report_still_renders_the_full_body() -> None:
    result = {"success": True, "severity": "critical", "cvss_score": 9.8}
    widget = CreateVulnerabilityReportRenderer.render(
        {"args": _args(), "result": result, "status": "completed"},
    )
    text = _plain(widget)

    assert "SQL injection in /api/login" in text
    assert "Use parameterized queries." in text
    assert "status-completed" in widget.classes


def test_in_flight_report_still_renders_the_pending_state() -> None:
    widget = CreateVulnerabilityReportRenderer.render(
        {"args": _args(), "result": None, "status": "running"},
    )

    assert "SQL injection in /api/login" in _plain(widget)


def test_dependency_rejection_rendering_is_unchanged() -> None:
    # The dependency renderer already handled these payloads; it now shares the
    # vulnerability renderer's helper, so pin its output.
    result = {"success": False, "error": "Validation failed", "errors": ["bad cvss"]}
    widget = CreateDependencyReportRenderer.render(
        {"args": {"title": "lodash CVE"}, "result": result, "status": "failed"},
    )
    text = _plain(widget)

    assert "📦 Dependency (SCA) Report" in text
    assert "Title: lodash CVE" in text
    assert "✗ Not created: bad cvss" in text
    assert "status-failed" in widget.classes

"""Tests for the self-contained HTML findings report renderer."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from strix.report.html_report import render_html_report
from strix.report.writer import write_html_report


if TYPE_CHECKING:
    from pathlib import Path


def _run_record() -> dict[str, Any]:
    return {
        "run_name": "demo_ab12",
        "targets_info": [{"type": "web_application", "original": "https://example.com"}],
        "start_time": "2026-07-22T00:00:00Z",
    }


def _finding(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "vuln-1",
        "title": "SQL Injection in login",
        "severity": "critical",
        "timestamp": "2026-07-22T00:01:00Z",
        "cvss": 9.8,
        "description": "User input concatenated into a SQL query.",
        "impact": "Full database read.",
        "poc_script_code": "' OR '1'='1",
        "remediation_steps": "Use parameterized queries.",
        "code_locations": [{"file": "app/auth.py", "start_line": 42, "snippet": "query = ..."}],
    }
    base.update(overrides)
    return base


def test_report_is_a_full_html_document() -> None:
    html = render_html_report(_run_record(), [_finding()])
    assert html.startswith("<!doctype html>")
    assert '<html lang="en">' in html
    assert "</html>" in html
    # Self-contained: inline style, no external asset references.
    assert "<style>" in html
    assert "http://" not in html.split("<footer>")[0].replace("https://example.com", "")
    assert "src=" not in html
    assert "<link" not in html


def test_report_renders_findings_and_summary() -> None:
    html = render_html_report(_run_record(), [_finding()])
    assert "SQL Injection in login" in html
    assert "CRITICAL" in html
    assert "CVSS 9.8" in html
    assert "Total findings: 1" in html
    assert "Remediation" in html
    assert "app/auth.py" in html


def test_report_escapes_malicious_finding_content() -> None:
    # Bug/abuse guard (FR4/SEC1): attacker-influenced content must be escaped.
    payload = "<script>alert(1)</script>"
    html = render_html_report(
        _run_record(),
        [_finding(title=payload, poc_script_code=payload, description=payload)],
    )
    # The raw executable tag must NOT appear; only its escaped form.
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_report_empty_state() -> None:
    html = render_html_report(_run_record(), [])
    assert "No exploitable vulnerabilities detected." in html
    assert html.startswith("<!doctype html>")
    assert "<article" not in html  # no finding cards


def test_report_orders_by_severity() -> None:
    reports = [
        _finding(id="a", title="low one", severity="low", timestamp="2026-07-22T00:00:00Z"),
        _finding(id="b", title="crit one", severity="critical", timestamp="2026-07-22T00:00:01Z"),
    ]
    html = render_html_report(_run_record(), reports)
    assert html.index("crit one") < html.index("low one")


def test_report_omits_absent_fields() -> None:
    minimal = {"id": "x", "title": "Minimal", "severity": "low", "timestamp": "t"}
    html = render_html_report(_run_record(), [minimal])
    assert "Minimal" in html
    assert "Remediation" not in html
    assert "Proof of Concept" not in html


def test_write_html_report_creates_file(tmp_path: Path) -> None:
    write_html_report(tmp_path, _run_record(), [_finding()])
    out = tmp_path / "report.html"
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert content.startswith("<!doctype html>")
    assert "SQL Injection in login" in content

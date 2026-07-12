"""Tests for XSS submit-only false-positive rejection in reporting."""

from __future__ import annotations

from strix.tools.reporting.tool import _looks_like_xss_submit_only_false_positive


def test_rejects_submit_success_as_stored_xss() -> None:
    err = _looks_like_xss_submit_only_false_positive(
        title="Stored XSS in contact form",
        description="The form accepts raw HTML without sanitization.",
        technical_analysis=(
            "The vulnerability was confirmed by successfully submitting a request "
            "with <img src=x onerror=alert(1)> payloads. The server responded with "
            "HTTP 200 and a success message: Request sent."
        ),
        poc_description="POST the payload to the form and receive success.",
        cwe="CWE-79",
    )
    assert err is not None
    assert "not confirmed" in err.lower()


def test_allows_xss_with_sink_observation() -> None:
    err = _looks_like_xss_submit_only_false_positive(
        title="Stored XSS in admin request detail",
        description="Payload executes when admin opens the request.",
        technical_analysis=(
            "Submitted payload via contact form (HTTP 200). Opened the admin "
            "request detail page; page source contained the payload unescaped "
            "and agent-browser confirmed script execution via onerror."
        ),
        poc_description=(
            "1. Submit payload. 2. Open /admin/requests/123. "
            "3. Observed payload appeared unescaped and script execution."
        ),
        cwe="CWE-79",
    )
    assert err is None


def test_non_xss_findings_unaffected() -> None:
    err = _looks_like_xss_submit_only_false_positive(
        title="SQL Injection in login",
        description="Auth bypass via SQLi.",
        technical_analysis="Server responded with HTTP 200 and dumped rows.",
        poc_description="Successfully submitted ' OR 1=1--",
        cwe="CWE-89",
    )
    assert err is None

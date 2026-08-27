"""Tests for building and encrypting the viewer PDF report."""

from __future__ import annotations

import json
from io import BytesIO
from typing import TYPE_CHECKING

import pytest
from pypdf import PdfReader
from pypdf.errors import WrongPasswordError

from strix.interface.viewer.report_pdf import (
    build_encrypted_report,
    encrypt_pdf,
    generate_password,
    generate_report_pdf,
)


if TYPE_CHECKING:
    from pathlib import Path


def _make_run(base: Path, name: str = "sample") -> Path:
    run_dir = base / "strix_runs" / name
    run_dir.mkdir(parents=True)
    record = {
        "run_name": name,
        "targets_info": [{"original": "https://example.com"}],
        "scan_mode": "deep",
        "status": "completed",
        "start_time": "2026-01-01T00:00:00Z",
        "end_time": "2026-01-01T01:02:03Z",
        "scan_results": {
            "executive_summary": "Summary with an ampersand & an <angle> bracket.",
            "recommendations": "Patch things.",
        },
    }
    (run_dir / "run.json").write_text(json.dumps(record), encoding="utf-8")
    vulns = [
        {
            "title": "SQL Injection",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "description": "User input reaches the query.",
            "impact": "Full database read.",
            "technical_analysis": "Details here.",
            "poc_description": "Send a crafted parameter.",
            "poc_script_code": "print('exploit')",
            "evidence": "HTTP 500 with SQL error.",
            "counterevidence": "The control request returned one public row.",
            "confidence_rationale": "Independent reproduction was limited to one account.",
            "verification": {
                "status": "unverified",
                "reason": "Database-wide read access was not reproduced.",
                "evidence": "The independent payload returned one account.",
                "rescored": True,
                "original_cvss": 9.8,
                "original_severity": "critical",
                "final_cvss": 5.3,
                "final_severity": "medium",
                "cvss_reasoning": "Only limited confidentiality impact remains supported.",
            },
            "remediation_steps": ["Use parameterized queries", "Validate input"],
            "target": "https://example.com",
            "endpoint": "/login",
            "method": "POST",
        },
        {"title": "Informational note", "severity": "info"},
    ]
    (run_dir / "vulnerabilities.json").write_text(json.dumps(vulns), encoding="utf-8")
    return run_dir


def test_generate_report_pdf_has_pdf_header(tmp_path: Path) -> None:
    run_dir = _make_run(tmp_path)
    pdf = generate_report_pdf(run_dir)
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 1000


def test_generate_report_pdf_includes_verification_status(tmp_path: Path) -> None:
    run_dir = _make_run(tmp_path)
    reader = PdfReader(BytesIO(generate_report_pdf(run_dir)))
    text = "\n".join(page.extract_text() or "" for page in reader.pages)
    assert "INDEPENDENT VERIFICATION" in text
    assert "Database-wide read access was not reproduced" in text
    assert "9.8 (CRITICAL) to 5.3 (MEDIUM)" in text


def test_generate_password_is_long_and_random() -> None:
    first = generate_password()
    second = generate_password()
    assert len(first) >= 20
    assert first != second


def test_encrypt_pdf_roundtrip(tmp_path: Path) -> None:
    run_dir = _make_run(tmp_path)
    pdf = generate_report_pdf(run_dir)
    password = generate_password()
    encrypted = encrypt_pdf(pdf, password)

    reader = PdfReader(BytesIO(encrypted))
    assert reader.is_encrypted
    assert reader.decrypt(password)
    # A correct password unlocks the pages.
    assert len(reader.pages) >= 1


def test_wrong_password_is_rejected(tmp_path: Path) -> None:
    run_dir = _make_run(tmp_path)
    encrypted = encrypt_pdf(generate_report_pdf(run_dir), "correct-horse-battery")
    with pytest.raises(WrongPasswordError):
        PdfReader(BytesIO(encrypted), password="not-the-password")  # nosec B106


def test_build_encrypted_report(tmp_path: Path) -> None:
    run_dir = _make_run(tmp_path, name="run-42")
    pdf_bytes, password, filename = build_encrypted_report(run_dir)

    assert filename == "strix-report-run-42.pdf"
    assert len(password) >= 20
    reader = PdfReader(BytesIO(pdf_bytes))
    assert reader.is_encrypted
    assert reader.decrypt(password)

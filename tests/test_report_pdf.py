"""Tests for building and encrypting the viewer PDF report."""

from __future__ import annotations

import json
from io import BytesIO
from itertools import product
from typing import TYPE_CHECKING

import pytest
from pypdf import PdfReader
from pypdf.errors import WrongPasswordError
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import Paragraph

from strix.interface.viewer.report_pdf import (
    _duration,
    _inline_md,
    _normalize_severity,
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
            "remediation_steps": ["Use parameterized queries", "Validate input"],
            "target": "https://example.com",
            "endpoint": "/login",
            "method": "POST",
        },
        {"title": "Informational note", "severity": "info"},
    ]
    (run_dir / "vulnerabilities.json").write_text(json.dumps(vulns), encoding="utf-8")
    return run_dir


def _pdf_text(pdf: bytes) -> str:
    return "\n".join(page.extract_text() or "" for page in PdfReader(BytesIO(pdf)).pages)


def test_generate_report_pdf_has_pdf_header(tmp_path: Path) -> None:
    run_dir = _make_run(tmp_path)
    pdf = generate_report_pdf(run_dir)
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 1000


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


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("**bold**", "<b>bold</b>"),
        ("__bold__", "<b>bold</b>"),
        ("*italic*", "<i>italic</i>"),
        ("***both***", "<i><b>both</b></i>"),
        ("**bold with *italic* inside**", "<b>bold with <i>italic</i> inside</b>"),
        ("*outer **bold** inner*", "<i>outer <b>bold</b> inner</i>"),
        (r"\*literal\*", "*literal*"),
        ("******", "******"),
        ("`a * < &`", '<font face="Courier" color="#b31d28">a * &lt; &amp;</font>'),
        (
            "![alt](https://example.invalid/image.png)",
            "![alt](https://example.invalid/image.png)",
        ),
        ("<https://example.invalid>", "&lt;https://example.invalid&gt;"),
    ],
)
def test_inline_md_emits_only_safe_balanced_markup(text: str, expected: str) -> None:
    markup = _inline_md(text)
    assert markup == expected
    Paragraph(markup, ParagraphStyle("test"))


@pytest.mark.parametrize(
    "text",
    [
        "*a **b* c**",
        "**a *b** c*",
        "*outer **inner* end**",
        "__a *b__ c*",
        "***__***__",
        "__***__***",
        "<b><i></b></i>",
        "<font size='999'>x</font>",
        "<img src='/definitely/missing.png'/>",
        "\x000\x00 `code` \x0099\x00",
        "\ud800",
    ],
)
def test_inline_md_survives_malformed_external_text(text: str) -> None:
    markup = _inline_md(text)
    assert "\x00" not in markup
    assert "\ud800" not in markup
    Paragraph(markup, ParagraphStyle("test"))


def test_inline_md_generated_corpus_never_breaks_reportlab() -> None:
    style = ParagraphStyle("test")
    for length in range(1, 6):
        for chars in product("*_`a ", repeat=length):
            Paragraph(_inline_md("".join(chars)), style)


def test_generate_report_pdf_survives_hostile_run_fields(tmp_path: Path) -> None:
    run_dir = _make_run(tmp_path)
    hostile = "****** <b><i></b></i> <img src='/definitely/missing.png'/> \x000\x00 \ud800"
    record = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    record.update(
        {
            "run_name": hostile,
            "targets_info": [{"original": hostile}],
            "scan_mode": hostile,
            "status": hostile,
            "start_time": hostile,
            "end_time": hostile,
            "scan_results": {
                "executive_summary": hostile,
                "methodology": hostile,
                "technical_analysis": hostile,
                "recommendations": hostile,
            },
        }
    )
    (run_dir / "run.json").write_text(json.dumps(record), encoding="utf-8")

    text = _pdf_text(generate_report_pdf(run_dir))
    assert "******" in text
    assert "<b><i></b></i>" in text
    assert "<img src='/definitely/missing.png'/>" in text


def test_generate_report_pdf_survives_hostile_finding_fields(tmp_path: Path) -> None:
    run_dir = _make_run(tmp_path)
    hostile = "****** <b><i></b></i> <img src='/definitely/missing.png'/> \x000\x00 \ud800"
    vulnerability = {
        "title": hostile,
        "severity": hostile,
        "cvss": hostile,
        "description": hostile,
        "impact": hostile,
        "technical_analysis": hostile,
        "poc_description": hostile,
        "poc_script_code": hostile,
        "evidence": hostile,
        "remediation_steps": [hostile],
        "target": hostile,
        "endpoint": hostile,
        "method": hostile,
    }
    (run_dir / "vulnerabilities.json").write_text(json.dumps([vulnerability]), encoding="utf-8")

    text = _pdf_text(generate_report_pdf(run_dir))
    assert "******" in text
    assert "<b><i></b></i>" in text
    assert "<img src='/definitely/missing.png'/>" in text
    assert text.count("LOW") == 2  # severity grid label plus canonicalized finding badge


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("CRITICAL", "critical"),
        (" info ", "info"),
        ("informational", "info"),
        ("<b><i></b></i>", "low"),
        ({"severity": "critical"}, "low"),
        (None, "low"),
    ],
)
def test_normalize_severity_restricts_badge_markup(value: object, expected: str) -> None:
    assert _normalize_severity(value) == expected


def test_duration_rejects_mixed_timezone_awareness() -> None:
    assert _duration("2026-01-01T00:00:00", "2026-01-01T01:00:00Z") == "n/a"

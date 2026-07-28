"""Build and encrypt a branded PDF report for a run.

The layout mirrors the Strix cloud pentest report (cover page, executive
severity grid, per-finding detail with colored severity badges) but is rendered
entirely locally with reportlab, so it ships without a browser or heavy system
deps and keeps the report on the user's machine.

The PDF carries FULL finding detail, including proof-of-concept scripts, so it
is encrypted end to end with AES-256. The password is generated locally with a
CSPRNG, shown only to the local browser, and never leaves the machine except in
the user's own hands. Strix cannot read the delivered report.
"""

from __future__ import annotations

import html
import re
import secrets
from datetime import datetime
from io import BytesIO
from typing import TYPE_CHECKING, Any

from pypdf import PdfReader, PdfWriter
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.platypus import (
    Flowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from strix.interface.viewer.transcript import (
    primary_target,
    read_run_summary,
    read_vulnerabilities,
    severity_counts,
)


if TYPE_CHECKING:
    from pathlib import Path


# Palette lifted from the cloud report theme (styles/base.ts, docx/theme.ts).
_INK = colors.HexColor("#000000")
_TEXT = colors.HexColor("#1a1a1a")
_MUTED = colors.HexColor("#666666")
_FAINT = colors.HexColor("#999999")
_BORDER = colors.HexColor("#e5e5e5")
_LIGHT_BG = colors.HexColor("#f7f7f7")

_SEVERITY_ORDER = ("critical", "high", "medium", "low")
_SEVERITY_COLORS = {
    "critical": colors.HexColor("#dc2626"),
    "high": colors.HexColor("#ea580c"),
    "medium": colors.HexColor("#ca8a04"),
    "low": colors.HexColor("#2563eb"),
}

# Helvetica stands in for Geist: a clean sans with no font file to ship.
_SANS = "Helvetica"
_SANS_BOLD = "Helvetica-Bold"
_MONO = "Courier"

_PAGE_W, _PAGE_H = A4


def _esc(value: Any) -> str:
    """Escape a value for reportlab's Paragraph markup."""
    return html.escape(str(value)).replace("\n", "<br/>")


class _NumberedCanvas(pdfcanvas.Canvas):  # type: ignore[misc]  # reportlab base is untyped
    """Two-pass canvas that prints 'Page X of Y' on every page after the cover."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._saved_states: list[dict[str, Any]] = []

    def showPage(self) -> None:  # noqa: N802 - reportlab API
        self._saved_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        total = len(self._saved_states)
        for index, state in enumerate(self._saved_states):
            self.__dict__.update(state)
            if index > 0:  # skip the cover page
                self._draw_footer(index + 1, total)
            super().showPage()
        super().save()

    def _draw_footer(self, page: int, total: int) -> None:
        self.setFont(_SANS, 8)
        self.setFillColor(_FAINT)
        self.drawCentredString(_PAGE_W / 2, 14 * mm, f"Page {page} of {total}")


class _LogoMark(Flowable):  # type: ignore[misc]  # reportlab base is untyped
    """The rounded-square Strix mark drawn inline (no raster asset to ship)."""

    def __init__(self, size: float = 30) -> None:
        super().__init__()
        self.size = size
        self.width = size
        self.height = size

    def draw(self) -> None:
        c = self.canv
        s = self.size
        c.setFillColor(_INK)
        c.roundRect(0, 0, s, s, s * 0.28, fill=1, stroke=0)
        c.setFillColor(colors.white)
        c.setFont(_SANS_BOLD, s * 0.56)
        c.drawCentredString(s / 2, s * 0.27, "S")


def _styles() -> dict[str, ParagraphStyle]:
    styles: dict[str, ParagraphStyle] = {}
    styles["wordmark"] = ParagraphStyle(
        "Wordmark", fontName=_SANS_BOLD, fontSize=17, leading=20, textColor=_INK
    )
    styles["badge_label"] = ParagraphStyle(
        "BadgeLabel", fontName=_SANS_BOLD, fontSize=9, leading=12, textColor=_MUTED
    )
    styles["cover_title"] = ParagraphStyle(
        "CoverTitle", fontName=_SANS_BOLD, fontSize=34, leading=38, textColor=_INK
    )
    styles["cover_org"] = ParagraphStyle(
        "CoverOrg", fontName=_SANS, fontSize=13, leading=18, textColor=_MUTED
    )
    styles["meta_label"] = ParagraphStyle(
        "MetaLabel", fontName=_SANS_BOLD, fontSize=8, leading=12, textColor=_MUTED
    )
    styles["meta_value"] = ParagraphStyle(
        "MetaValue", fontName=_SANS, fontSize=10.5, leading=14, textColor=_TEXT
    )
    styles["section"] = ParagraphStyle(
        "Section", fontName=_SANS_BOLD, fontSize=18, leading=22, textColor=_INK, spaceAfter=6
    )
    styles["finding"] = ParagraphStyle(
        "Finding", fontName=_SANS_BOLD, fontSize=13, leading=17, textColor=_INK, spaceBefore=6
    )
    styles["field_label"] = ParagraphStyle(
        "FieldLabel",
        fontName=_SANS_BOLD,
        fontSize=8.5,
        leading=12,
        textColor=_MUTED,
        spaceBefore=10,
        spaceAfter=2,
    )
    styles["body"] = ParagraphStyle(
        "Body", fontName=_SANS, fontSize=10, leading=15, textColor=_TEXT, spaceAfter=8
    )
    styles["md_heading"] = ParagraphStyle(
        "MdHeading",
        fontName=_SANS_BOLD,
        fontSize=11,
        leading=15,
        textColor=_INK,
        spaceBefore=10,
        spaceAfter=4,
    )
    styles["bullet"] = ParagraphStyle(
        "Bullet",
        fontName=_SANS,
        fontSize=10,
        leading=15,
        textColor=_TEXT,
        leftIndent=16,
        firstLineIndent=-11,
        spaceAfter=3,
    )
    styles["meta_inline"] = ParagraphStyle(
        "MetaInline", fontName=_SANS, fontSize=9, leading=13, textColor=_MUTED, spaceBefore=4
    )
    # spaceBefore/spaceAfter must exceed borderPadding: reportlab does not reserve
    # a bordered paragraph's top padding, so too small a gap lets the background
    # box bleed up over the field label above it.
    styles["code"] = ParagraphStyle(
        "Code",
        fontName=_MONO,
        fontSize=8,
        leading=11,
        textColor=_TEXT,
        backColor=_LIGHT_BG,
        borderColor=_BORDER,
        borderWidth=0.5,
        borderPadding=8,
        spaceBefore=12,
        spaceAfter=12,
    )
    styles["count"] = ParagraphStyle(
        "Count", fontName=_SANS_BOLD, fontSize=30, leading=32, alignment=TA_CENTER
    )
    styles["count_label"] = ParagraphStyle(
        "CountLabel",
        fontName=_SANS_BOLD,
        fontSize=8,
        leading=12,
        textColor=_MUTED,
        alignment=TA_CENTER,
        spaceBefore=4,
    )
    styles["badge"] = ParagraphStyle(
        "Badge",
        fontName=_SANS_BOLD,
        fontSize=9,
        leading=11,
        textColor=colors.white,
        alignment=TA_CENTER,
    )
    styles["confidential"] = ParagraphStyle(
        "Confidential",
        fontName=_SANS_BOLD,
        fontSize=9,
        leading=12,
        textColor=colors.white,
        alignment=TA_CENTER,
    )
    return styles


def _parse_time(raw: Any) -> datetime | None:
    if not isinstance(raw, str) or not raw:
        return None
    text = raw.strip().replace(" UTC", "Z").replace(" ", "T")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _fmt_time(raw: Any) -> str:
    parsed = _parse_time(raw)
    return parsed.strftime("%Y-%m-%d %H:%M UTC") if parsed else "n/a"


def _duration(start: Any, end: Any) -> str:
    start_dt = _parse_time(start)
    end_dt = _parse_time(end)
    if not start_dt or not end_dt:
        return "n/a"
    seconds = int((end_dt - start_dt).total_seconds())
    if seconds < 0:
        return "n/a"
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def _severity_badge(styles: dict[str, ParagraphStyle], severity: str) -> Table:
    """A colored pill matching .severity-badge in the cloud report."""
    color = _SEVERITY_COLORS.get(severity, _MUTED)
    cell = Paragraph(severity.upper(), styles["badge"])
    table = Table([[cell]], colWidths=[len(severity) * 6.5 + 20])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), color),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    table.hAlign = "LEFT"
    return table


def _severity_grid(styles: dict[str, ParagraphStyle], counts: dict[str, int]) -> Table:
    """The four-card severity grid from the executive summary."""
    cells: list[list[Flowable]] = []
    for name in _SEVERITY_ORDER:
        color = _SEVERITY_COLORS[name]
        count_style = ParagraphStyle(f"Count{name}", parent=styles["count"], textColor=color)
        cells.append(
            [
                Paragraph(str(counts.get(name, 0)), count_style),
                Paragraph(name.upper(), styles["count_label"]),
            ]
        )
    col = (_PAGE_W - 40 * mm) / 4
    table = Table([cells], colWidths=[col] * 4)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 16),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 16),
        ("GRID", (0, 0), (-1, -1), 0.5, _BORDER),
    ]
    for index, name in enumerate(_SEVERITY_ORDER):
        style.append(("LINEABOVE", (index, 0), (index, 0), 3, _SEVERITY_COLORS[name]))
    table.setStyle(TableStyle(style))
    return table


def _section(styles: dict[str, ParagraphStyle], title: str) -> Table:
    """Section title with the underline rule from h2.section-title."""
    table = Table([[Paragraph(_esc(title), styles["section"])]], colWidths=[_PAGE_W - 40 * mm])
    table.setStyle(
        TableStyle(
            [
                ("LINEBELOW", (0, 0), (-1, -1), 1, _BORDER),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    return table


def _cover(
    styles: dict[str, ParagraphStyle], record: dict[str, Any], run_name: str
) -> list[Flowable]:
    header = Table(
        [[_LogoMark(30), Paragraph("Strix", styles["wordmark"])]],
        colWidths=[38, _PAGE_W - 40 * mm - 38],
    )
    header.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )

    target = primary_target(record) or "Target"
    meta_rows = [
        ("TARGET", primary_target(record) or "unknown target"),
        ("RUN", run_name),
        ("SCAN MODE", str(record.get("scan_mode") or "n/a")),
        ("STATUS", str(record.get("status") or "n/a")),
        ("STARTED", _fmt_time(record.get("start_time"))),
        ("COMPLETED", _fmt_time(record.get("end_time"))),
        ("DURATION", _duration(record.get("start_time"), record.get("end_time"))),
    ]
    meta_table = Table(
        [
            [Paragraph(label, styles["meta_label"]), Paragraph(_esc(value), styles["meta_value"])]
            for label, value in meta_rows
        ],
        colWidths=[38 * mm, _PAGE_W - 40 * mm - 38 * mm],
    )
    meta_table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LINEBELOW", (0, 0), (-1, -2), 0.5, _BORDER),
            ]
        )
    )

    confidential = Table([[Paragraph("CONFIDENTIAL", styles["confidential"])]], colWidths=[120])
    confidential.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), _INK),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    confidential.hAlign = "CENTER"

    return [
        header,
        Spacer(1, 150),
        Paragraph("PENETRATION TEST REPORT", styles["badge_label"]),
        Spacer(1, 20),
        Paragraph("Security Assessment", styles["cover_title"]),
        Paragraph(_esc(target), styles["cover_org"]),
        Spacer(1, 28),
        meta_table,
        Spacer(1, 90),
        confidential,
        PageBreak(),
    ]


def _inline_md(text: str) -> str:
    """Convert inline markdown (bold, italic, `code`) to reportlab markup.

    Code spans are stashed as placeholders before bold/italic run, so bold that
    wraps a code span (``**`x`**``) works and code contents are never mangled.
    """
    codes: list[str] = []

    def _stash(match: re.Match[str]) -> str:
        codes.append(match.group(1))
        return f"\x00{len(codes) - 1}\x00"

    seg = html.escape(re.sub(r"`([^`]+)`", _stash, text))
    seg = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", seg)
    seg = re.sub(r"__(.+?)__", r"<b>\1</b>", seg)
    seg = re.sub(r"\*(.+?)\*", r"<i>\1</i>", seg)

    def _restore(match: re.Match[str]) -> str:
        inner = html.escape(codes[int(match.group(1))])
        return f'<font face="{_MONO}" color="#b31d28">{inner}</font>'

    return re.sub(r"\x00(\d+)\x00", _restore, seg)


def _strip_leading_heading(md: str) -> str:
    """Drop a single leading markdown heading (each section adds its own title)."""
    lines = md.lstrip("\n").split("\n")
    if lines and re.match(r"^#{1,6}\s+", lines[0].strip()):
        return "\n".join(lines[1:]).lstrip("\n")
    return md


def _markdown_flowables(  # noqa: PLR0915 - cohesive block parser, splitting hurts clarity
    md: str, styles: dict[str, ParagraphStyle]
) -> list[Flowable]:
    """Render a markdown block (headings, lists, fenced code, prose) to flowables."""
    flow: list[Flowable] = []
    para: list[str] = []
    bullets: list[tuple[str, str]] = []

    def flush_para() -> None:
        if para:
            flow.append(Paragraph(_inline_md(" ".join(para)), styles["body"]))
            para.clear()

    def flush_bullets() -> None:
        for marker, item in bullets:
            flow.append(Paragraph(f"{marker}&nbsp;{_inline_md(item)}", styles["bullet"]))
        bullets.clear()

    lines = md.replace("\r\n", "\n").split("\n")
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if stripped.startswith("```"):
            flush_para()
            flush_bullets()
            i += 1
            code: list[str] = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code.append(lines[i])
                i += 1
            i += 1  # closing fence
            flow.append(Paragraph(_esc("\n".join(code)) or "&nbsp;", styles["code"]))
            continue
        if not stripped:
            flush_para()
            flush_bullets()
            i += 1
            continue
        heading = re.match(r"^(#{1,6})\s+(.*)$", stripped)
        if heading:
            flush_para()
            flush_bullets()
            flow.append(Paragraph(_inline_md(heading.group(2)), styles["md_heading"]))
            i += 1
            continue
        ordered = re.match(r"^(\d+)\.\s+(.*)$", stripped)
        unordered = re.match(r"^[-*+]\s+(.*)$", stripped)
        if ordered:
            flush_para()
            bullets.append((f"{ordered.group(1)}.", ordered.group(2)))
            i += 1
            continue
        if unordered:
            flush_para()
            bullets.append(("•", unordered.group(1)))
            i += 1
            continue
        flush_bullets()
        para.append(stripped)
        i += 1

    flush_para()
    flush_bullets()
    return flow


_FENCE_RE = re.compile(r"^```([^\n`]*)\n(.*?)\n?```$", re.DOTALL)


def _strip_code_fence(value: Any) -> Any:
    """Drop a wrapping markdown code fence so raw-code fields don't show the
    ``` ```lang ``` marker lines literally in the PDF."""
    if not isinstance(value, str):
        return value
    match = _FENCE_RE.match(value.strip())
    return match.group(2) if match else value


def _field_block(
    styles: dict[str, ParagraphStyle], label: str, value: Any, *, code: bool = False
) -> list[Flowable]:
    if value is None or (isinstance(value, str) and not value.strip()):
        return []
    flow: list[Flowable] = [Paragraph(label.upper(), styles["field_label"])]
    if code:
        flow.append(Paragraph(_esc(value), styles["code"]))
    else:
        flow.extend(_markdown_flowables(str(value), styles))
    return flow


def _finding_flowables(
    styles: dict[str, ParagraphStyle], index: int, vuln: dict[str, Any]
) -> list[Flowable]:
    title = vuln.get("title") or "Untitled finding"
    severity = str(vuln.get("severity") or "").lower().strip() or "low"

    meta_bits = []
    if vuln.get("cvss") is not None:
        meta_bits.append(f"<b>CVSS</b> {_esc(vuln.get('cvss'))}")
    meta_bits.extend(
        f"<b>{key.title()}</b> {_esc(vuln.get(key))}"
        for key in ("target", "endpoint", "method")
        if vuln.get(key)
    )

    header: list[Flowable] = [
        Paragraph(f"{index}. {_esc(title)}", styles["finding"]),
        Spacer(1, 4),
        _severity_badge(styles, severity),
    ]
    if meta_bits:
        header.append(Paragraph("&nbsp;&nbsp;".join(meta_bits), styles["meta_inline"]))

    story: list[Flowable] = [KeepTogether(header)]
    story.extend(_field_block(styles, "Description", vuln.get("description")))
    story.extend(_field_block(styles, "Impact", vuln.get("impact")))
    story.extend(_field_block(styles, "Technical analysis", vuln.get("technical_analysis")))
    story.extend(_field_block(styles, "Proof of concept", vuln.get("poc_description")))
    poc_script = _strip_code_fence(vuln.get("poc_script_code"))
    story.extend(_field_block(styles, "PoC script", poc_script, code=True))
    story.extend(_field_block(styles, "Evidence", vuln.get("evidence"), code=True))

    remediation = vuln.get("remediation_steps")
    if isinstance(remediation, list):
        remediation = "\n".join(str(step) for step in remediation)
    story.extend(_field_block(styles, "Remediation", remediation))

    story.append(Spacer(1, 22))
    return story


def _overview_flowables(
    styles: dict[str, ParagraphStyle], record: dict[str, Any], total: int, counts: dict[str, int]
) -> list[Flowable]:
    story: list[Flowable] = [
        _section(styles, "Executive Summary"),
        Spacer(1, 16),
        _severity_grid(styles, counts),
        Spacer(1, 10),
        Paragraph(f"<b>{total}</b> total findings across this assessment.", styles["body"]),
    ]
    scan_results = record.get("scan_results")
    if not isinstance(scan_results, dict):
        return story
    summary = scan_results.get("executive_summary")
    if isinstance(summary, str) and summary.strip():
        story.append(Spacer(1, 16))
        story.extend(_markdown_flowables(_strip_leading_heading(summary), styles))
    for label, key in (
        ("Methodology", "methodology"),
        ("Technical Analysis", "technical_analysis"),
        ("Recommendations", "recommendations"),
    ):
        value = scan_results.get(key)
        if isinstance(value, str) and value.strip():
            story.append(Spacer(1, 20))
            story.append(_section(styles, label))
            story.append(Spacer(1, 12))
            story.extend(_markdown_flowables(_strip_leading_heading(value), styles))
    return story


def generate_report_pdf(run_dir: Path) -> bytes:
    """Render a branded, full-detail PDF report for the run at ``run_dir``."""
    record = read_run_summary(run_dir)
    vulns = [v for v in read_vulnerabilities(run_dir) if isinstance(v, dict)]
    counts = severity_counts(vulns)
    run_name = str(record.get("run_name") or run_dir.name)

    styles = _styles()
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        title="Strix Security Report",
        author="Strix",
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=22 * mm,
        bottomMargin=24 * mm,
    )

    story: list[Flowable] = []
    story.extend(_cover(styles, record, run_name))
    story.extend(_overview_flowables(styles, record, len(vulns), counts))

    story.append(PageBreak())
    story.append(_section(styles, "Findings"))
    story.append(Spacer(1, 16))
    if vulns:
        for index, vuln in enumerate(vulns, start=1):
            story.extend(_finding_flowables(styles, index, vuln))
    else:
        story.append(Paragraph("No findings were recorded for this run.", styles["body"]))

    doc.build(story, canvasmaker=_NumberedCanvas)
    return buffer.getvalue()


def generate_password() -> str:
    """Return a >=20 character URL-safe password from a CSPRNG."""
    return secrets.token_urlsafe(16)


def encrypt_pdf(pdf_bytes: bytes, password: str) -> bytes:
    """Encrypt a PDF with AES-256 using ``password`` as the user password."""
    reader = PdfReader(BytesIO(pdf_bytes))
    writer = PdfWriter()
    writer.append(reader)
    writer.encrypt(user_password=password, algorithm="AES-256")
    out = BytesIO()
    writer.write(out)
    return out.getvalue()


def build_encrypted_report(run_dir: Path) -> tuple[bytes, str, str]:
    """Build, encrypt, and name the report. Returns (pdf_bytes, password, filename)."""
    record = read_run_summary(run_dir)
    run_name = str(record.get("run_name") or run_dir.name)
    pdf_bytes = generate_report_pdf(run_dir)
    password = generate_password()
    encrypted = encrypt_pdf(pdf_bytes, password)
    filename = f"strix-report-{run_name}.pdf"
    return encrypted, password, filename


__all__ = [
    "build_encrypted_report",
    "encrypt_pdf",
    "generate_password",
    "generate_report_pdf",
]

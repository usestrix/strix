"""Self-contained HTML findings report renderer.

Renders a Strix scan's findings (the same ``run_record`` + ``vulnerability_reports``
data used by :mod:`strix.report.writer`) into a single portable HTML document with
inlined CSS — no external assets, opens offline.

Named ``html_report`` (not ``html``) to avoid shadowing the stdlib :mod:`html`
module used here for escaping. All finding-derived content is escaped before
embedding, so attacker-influenced values (titles, PoC code, snippets) cannot
inject markup or script into the report.
"""

from __future__ import annotations

import html
from datetime import UTC, datetime
from typing import Any


# Mirrors ``strix.report.writer._SEVERITY_ORDER`` (kept local to avoid a cross-
# module import cycle; both derive from the same fixed severity vocabulary).
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Mirrors ``strix.interface.utils.get_severity_color`` for visual consistency.
_SEVERITY_COLOR = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#65a30d",
    "info": "#0284c7",
}
_DEFAULT_COLOR = "#6b7280"

_SEVERITIES = ("critical", "high", "medium", "low", "info")


def _esc(value: Any) -> str:
    """HTML-escape any value (attribute-safe). ``None`` becomes an empty string."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _severity_color(severity: str) -> str:
    return _SEVERITY_COLOR.get(severity.lower(), _DEFAULT_COLOR)


def _sort_key(report: dict[str, Any]) -> tuple[int, str]:
    severity = str(report.get("severity", "")).lower()
    return (_SEVERITY_ORDER.get(severity, 5), str(report.get("timestamp", "")))


def _target_label(run_record: dict[str, Any]) -> str:
    targets = run_record.get("targets_info") or []
    if isinstance(targets, list) and targets:
        first = targets[0] if isinstance(targets[0], dict) else {}
        original = first.get("original")
        if isinstance(original, str) and original:
            if len(targets) > 1:
                return f"{original} (+{len(targets) - 1} more)"
            return original
    return "unknown"


def _severity_counts(reports: list[dict[str, Any]]) -> dict[str, int]:
    counts = dict.fromkeys(_SEVERITIES, 0)
    for report in reports:
        severity = str(report.get("severity", "")).lower()
        if severity in counts:
            counts[severity] += 1
    return counts


def _render_summary(run_record: dict[str, Any], reports: list[dict[str, Any]]) -> str:
    run_name = _esc(run_record.get("run_name") or run_record.get("run_id") or "scan")
    generated = _esc(datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"))
    parts = [
        '<header class="report-header">',
        "<h1>Strix &middot; Security Penetration Test Report</h1>",
        f'<p class="meta">Target: {_esc(_target_label(run_record))} '
        f"&middot; Run: {run_name} &middot; Generated: {generated}</p>",
        "</header>",
        '<section class="summary" aria-label="Summary">',
    ]
    if reports:
        counts = _severity_counts(reports)
        chips = "".join(
            f'<li class="chip {sev}" style="border-color:{_severity_color(sev)}">'
            f'<span class="chip-label" style="color:{_severity_color(sev)}">'
            f'{sev.upper()}</span> <span class="chip-count">{counts[sev]}</span></li>'
            for sev in _SEVERITIES
        )
        parts.append(f'<ul class="severity-chips">{chips}</ul>')
        parts.append(f'<p class="total">Total findings: {len(reports)}</p>')
    else:
        parts.append(
            '<p class="empty">No exploitable vulnerabilities detected.</p>'
        )
    parts.append("</section>")
    return "".join(parts)


def _render_code_block(label: str, code: str) -> str:
    return (
        f"<h3>{_esc(label)}</h3>"
        f'<pre class="code"><code>{_esc(code)}</code></pre>'
    )


def _render_meta_row(report: dict[str, Any]) -> str:
    dep = report.get("dependency_metadata") or {}
    pairs: list[tuple[str, Any]] = [
        ("ID", report.get("id")),
        ("Target", report.get("target")),
        ("Package", dep.get("package_name") if isinstance(dep, dict) else None),
        ("Installed", dep.get("installed_version") if isinstance(dep, dict) else None),
        ("Fixed", dep.get("fixed_version") if isinstance(dep, dict) else None),
        ("Endpoint", report.get("endpoint")),
        ("Method", report.get("method")),
        ("CVE", report.get("cve")),
        ("CWE", report.get("cwe")),
    ]
    items = "".join(
        f"<dt>{_esc(label)}</dt><dd>{_esc(value)}</dd>" for label, value in pairs if value
    )
    return f'<dl class="finding-meta">{items}</dl>' if items else ""


def _render_finding(report: dict[str, Any]) -> str:
    severity = str(report.get("severity", "unknown")).lower()
    color = _severity_color(severity)
    title = _esc(report.get("title") or "Untitled Vulnerability")
    cvss = report.get("cvss")
    cvss_html = f'<span class="cvss">CVSS {_esc(cvss)}</span>' if cvss is not None else ""
    parts = [
        f'<article class="finding sev-{_esc(severity)}" id="vuln-{_esc(report.get("id"))}">',
        f'<h2><span class="badge" style="background:{color}">{_esc(severity.upper())}</span> '
        f"{title} {cvss_html}</h2>",
        _render_meta_row(report),
    ]
    for label, key in (
        ("Description", "description"),
        ("Impact", "impact"),
        ("Technical Analysis", "technical_analysis"),
    ):
        value = report.get(key)
        if value:
            parts.append(f"<section><h3>{label}</h3><p>{_esc(value)}</p></section>")

    if report.get("poc_description") or report.get("poc_script_code"):
        parts.append("<section>")
        if report.get("poc_description"):
            parts.append(f"<h3>Proof of Concept</h3><p>{_esc(report['poc_description'])}</p>")
        if report.get("poc_script_code"):
            parts.append(_render_code_block("PoC Script", str(report["poc_script_code"])))
        parts.append("</section>")

    code_locations = report.get("code_locations")
    if isinstance(code_locations, list) and code_locations:
        parts.append("<section><h3>Code Locations</h3>")
        for loc in code_locations:
            if not isinstance(loc, dict):
                continue
            file_ref = _esc(loc.get("file") or "unknown")
            line = loc.get("start_line")
            line_ref = f":{_esc(line)}" if line is not None else ""
            parts.append(f'<p class="loc"><code>{file_ref}{line_ref}</code></p>')
            snippet = loc.get("snippet")
            if snippet:
                parts.append(f'<pre class="code"><code>{_esc(snippet)}</code></pre>')
        parts.append("</section>")

    if report.get("remediation_steps"):
        parts.append(
            f"<section><h3>Remediation</h3><p>{_esc(report['remediation_steps'])}</p></section>"
        )
    parts.append("</article>")
    return "".join(parts)


_STYLE = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0; padding: 0 1rem 3rem;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  color: #1f2937; background: #f9fafb; line-height: 1.5; }
.report-header, .summary, .findings, footer { max-width: 960px; margin: 0 auto; }
.report-header { padding: 2rem 0 1rem; border-bottom: 2px solid #e5e7eb; }
h1 { font-size: 1.5rem; margin: 0; }
.meta { color: #6b7280; font-size: .9rem; margin: .4rem 0 0; }
.summary { padding: 1.25rem 0; }
.severity-chips { list-style: none; display: flex; flex-wrap: wrap; gap: .5rem;
  padding: 0; margin: 0 0 .75rem; }
.chip { border: 1px solid #e5e7eb; border-radius: 999px; padding: .25rem .75rem;
  font-size: .85rem; background: #fff; }
.chip-label { font-weight: 700; }
.total { font-weight: 600; margin: 0; }
.empty { font-size: 1.1rem; color: #15803d; }
.finding { background: #fff; border: 1px solid #e5e7eb; border-radius: 8px;
  padding: 1rem 1.25rem; margin: 1rem auto; }
.finding h2 { font-size: 1.15rem; display: flex; align-items: center; gap: .5rem;
  flex-wrap: wrap; margin: 0 0 .5rem; }
.badge { color: #fff; font-size: .72rem; font-weight: 700; padding: .15rem .5rem;
  border-radius: 4px; letter-spacing: .03em; }
.cvss { color: #6b7280; font-size: .85rem; font-weight: 600; margin-left: auto; }
.finding-meta { display: grid; grid-template-columns: max-content 1fr; gap: .1rem .75rem;
  font-size: .85rem; margin: .5rem 0; }
.finding-meta dt { color: #6b7280; }
.finding-meta dd { margin: 0; }
h3 { font-size: .95rem; margin: .75rem 0 .25rem; }
.code { background: #0f172a; color: #e2e8f0; padding: .75rem; border-radius: 6px;
  overflow-x: auto; font-size: .8rem; }
.loc code { background: #f1f5f9; padding: .1rem .3rem; border-radius: 4px; }
footer { color: #9ca3af; font-size: .8rem; text-align: center; padding-top: 2rem; }
@media print { body { background: #fff; } .finding { break-inside: avoid; } }
"""


def _document(body: str, title: str) -> str:
    return (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{_esc(title)}</title>\n"
        f"<style>{_STYLE}</style>\n"
        "</head>\n<body>\n"
        f"{body}\n"
        "</body>\n</html>\n"
    )


def render_html_report(
    run_record: dict[str, Any],
    vulnerability_reports: list[dict[str, Any]],
) -> str:
    """Return a complete, self-contained HTML document for the scan's findings."""
    reports = sorted(vulnerability_reports, key=_sort_key)
    body_parts = [_render_summary(run_record, reports)]
    if reports:
        findings = "".join(_render_finding(r) for r in reports)
        body_parts.append(f'<main class="findings">{findings}</main>')
    body_parts.append(
        "<footer>Strix &middot; generated locally &middot; open this file in a browser</footer>"
    )
    target = _target_label(run_record)
    return _document("".join(body_parts), f"Strix Report — {target}")

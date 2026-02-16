from functools import cache
from typing import Any, ClassVar

from pygments.lexers import PythonLexer
from pygments.styles import get_style_by_name
from rich.text import Text
from textual.widgets import Static

from strix.tools.reporting.reporting_actions import (
    parse_code_locations_xml,
    parse_cvss_xml,
)

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


@cache
def _get_style_colors() -> dict[Any, str]:
    style = get_style_by_name("native")
    return {token: f"#{style_def['color']}" for token, style_def in style if style_def["color"]}


FIELD_STYLE = "bold #4ade80"
DIM_STYLE = "dim"
FILE_STYLE = "bold #60a5fa"
LINE_STYLE = "#facc15"
LABEL_STYLE = "italic #a1a1aa"
CODE_STYLE = "#e2e8f0"
BEFORE_STYLE = "#ef4444"
AFTER_STYLE = "#22c55e"


@register_tool_renderer
class CreateVulnerabilityReportRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "create_vulnerability_report"
    css_classes: ClassVar[list[str]] = ["tool-call", "reporting-tool"]

    SEVERITY_COLORS: ClassVar[dict[str, str]] = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#d97706",
        "low": "#65a30d",
        "info": "#0284c7",
    }

    @classmethod
    def _get_token_color(cls, token_type: Any) -> str | None:
        colors = _get_style_colors()
        while token_type:
            if token_type in colors:
                return colors[token_type]
            token_type = token_type.parent
        return None

    @classmethod
    def _highlight_python(cls, code: str) -> Text:
        lexer = PythonLexer()
        text = Text()

        for token_type, token_value in lexer.get_tokens(code):
            if not token_value:
                continue
            color = cls._get_token_color(token_type)
            text.append(token_value, style=color)

        return text

    @classmethod
    def _get_cvss_color(cls, cvss_score: float) -> str:
        if cvss_score >= 9.0:
            return "#dc2626"
        if cvss_score >= 7.0:
            return "#ea580c"
        if cvss_score >= 4.0:
            return "#d97706"
        if cvss_score >= 0.1:
            return "#65a30d"
        return "#6b7280"

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:  # noqa: PLR0912, PLR0915
        args = tool_data.get("args", {})
        result = tool_data.get("result", {})

        title = args.get("title", "")
        description = args.get("description", "")
        impact = args.get("impact", "")
        target = args.get("target", "")
        technical_analysis = args.get("technical_analysis", "")
        poc_description = args.get("poc_description", "")
        poc_script_code = args.get("poc_script_code", "")
        remediation_steps = args.get("remediation_steps", "")

        cvss_breakdown_xml = args.get("cvss_breakdown", "")
        code_locations_xml = args.get("code_locations", "")

        endpoint = args.get("endpoint", "")
        method = args.get("method", "")
        cve = args.get("cve", "")
        cwe = args.get("cwe", "")

        severity = ""
        cvss_score = None
        if isinstance(result, dict):
            severity = result.get("severity", "")
            cvss_score = result.get("cvss_score")

        text = Text()
        text.append("🐞 ")
        text.append("Vulnerability Report", style="bold #ea580c")

        if title:
            text.append("\n\n")
            text.append("Title: ", style=FIELD_STYLE)
            text.append(title)

        if severity:
            text.append("\n\n")
            text.append("Severity: ", style=FIELD_STYLE)
            severity_color = cls.SEVERITY_COLORS.get(severity.lower(), "#6b7280")
            text.append(severity.upper(), style=f"bold {severity_color}")

        if cvss_score is not None:
            text.append("\n\n")
            text.append("CVSS Score: ", style=FIELD_STYLE)
            cvss_color = cls._get_cvss_color(cvss_score)
            text.append(str(cvss_score), style=f"bold {cvss_color}")

        if target:
            text.append("\n\n")
            text.append("Target: ", style=FIELD_STYLE)
            text.append(target)

        if endpoint:
            text.append("\n\n")
            text.append("Endpoint: ", style=FIELD_STYLE)
            text.append(endpoint)

        if method:
            text.append("\n\n")
            text.append("Method: ", style=FIELD_STYLE)
            text.append(method)

        if cve:
            text.append("\n\n")
            text.append("CVE: ", style=FIELD_STYLE)
            text.append(cve)

        if cwe:
            text.append("\n\n")
            text.append("CWE: ", style=FIELD_STYLE)
            text.append(cwe)

        parsed_cvss = parse_cvss_xml(cvss_breakdown_xml) if cvss_breakdown_xml else None
        if parsed_cvss:
            text.append("\n\n")
            cvss_parts = []
            for key, prefix in [
                ("attack_vector", "AV"),
                ("attack_complexity", "AC"),
                ("privileges_required", "PR"),
                ("user_interaction", "UI"),
                ("scope", "S"),
                ("confidentiality", "C"),
                ("integrity", "I"),
                ("availability", "A"),
            ]:
                val = parsed_cvss.get(key)
                if val:
                    cvss_parts.append(f"{prefix}:{val}")
            text.append("CVSS Vector: ", style=FIELD_STYLE)
            text.append("/".join(cvss_parts), style=DIM_STYLE)

        if description:
            text.append("\n\n")
            text.append("Description", style=FIELD_STYLE)
            text.append("\n")
            text.append(description)

        if impact:
            text.append("\n\n")
            text.append("Impact", style=FIELD_STYLE)
            text.append("\n")
            text.append(impact)

        if technical_analysis:
            text.append("\n\n")
            text.append("Technical Analysis", style=FIELD_STYLE)
            text.append("\n")
            text.append(technical_analysis)

        parsed_locations = (
            parse_code_locations_xml(code_locations_xml) if code_locations_xml else None
        )
        if parsed_locations:
            text.append("\n\n")
            text.append("Code Locations", style=FIELD_STYLE)
            for i, loc in enumerate(parsed_locations):
                text.append("\n\n")
                text.append(f"  Location {i + 1}: ", style=DIM_STYLE)
                text.append(loc.get("file", "unknown"), style=FILE_STYLE)
                start = loc.get("start_line")
                end = loc.get("end_line")
                if start is not None:
                    if end and end != start:
                        text.append(f":{start}-{end}", style=LINE_STYLE)
                    else:
                        text.append(f":{start}", style=LINE_STYLE)
                if loc.get("label"):
                    text.append(f"\n  {loc['label']}", style=LABEL_STYLE)
                if loc.get("snippet"):
                    text.append("\n  ")
                    text.append(loc["snippet"], style=CODE_STYLE)
                if loc.get("fix_before") or loc.get("fix_after"):
                    text.append("\n  ")
                    text.append("Fix:", style=DIM_STYLE)
                    if loc.get("fix_before"):
                        text.append("\n  ")
                        text.append("- ", style=BEFORE_STYLE)
                        text.append(loc["fix_before"], style=BEFORE_STYLE)
                    if loc.get("fix_after"):
                        text.append("\n  ")
                        text.append("+ ", style=AFTER_STYLE)
                        text.append(loc["fix_after"], style=AFTER_STYLE)

        if poc_description:
            text.append("\n\n")
            text.append("PoC Description", style=FIELD_STYLE)
            text.append("\n")
            text.append(poc_description)

        if poc_script_code:
            text.append("\n\n")
            text.append("PoC Code", style=FIELD_STYLE)
            text.append("\n")
            text.append_text(cls._highlight_python(poc_script_code))

        if remediation_steps:
            text.append("\n\n")
            text.append("Remediation", style=FIELD_STYLE)
            text.append("\n")
            text.append(remediation_steps)

        if not title:
            text.append("\n  ")
            text.append("Creating report...", style="dim")

        padded = Text()
        padded.append("\n\n")
        padded.append_text(text)
        padded.append("\n\n")

        css_classes = cls.get_css_classes("completed")
        return Static(padded, classes=css_classes)

from typing import Any, ClassVar

from rich.text import Text
from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


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
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})

        title = args.get("title", "")
        severity = args.get("severity", "")
        content = args.get("content", "")

        text = Text()
        text.append("🐞 ")
        text.append("Vulnerability Report", style="bold #ea580c")

        if title:
            text.append("\n  ")
            text.append(title, style="bold")

            if severity:
                severity_color = cls.SEVERITY_COLORS.get(severity.lower(), "#6b7280")
                text.append("\n  Severity: ")
                text.append(severity.upper(), style=severity_color)

            if content:
                text.append("\n  ")
                text.append(content, style="dim")
        else:
            text.append("\n  ")
            text.append("Creating report...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)

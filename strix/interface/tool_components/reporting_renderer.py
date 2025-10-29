from typing import Any, ClassVar

from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


@register_tool_renderer
class CreateVulnerabilityReportRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "create_vulnerability_report"
    css_classes: ClassVar[list[str]] = ["tool-call", "reporting-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})

        title = args.get("title", "")
        severity = args.get("severity", "")
        content = args.get("content", "")

        header = "🐞 [bold #ea580c]Vulnerability Report[/]"

        if title:
            content_parts = [f"{header}\n  [bold]{cls.escape_markup(title)}[/]"]

            if severity:
                severity_color = cls._get_severity_color(severity.lower())
                content_parts.append(
                    f"  [dim]Severity: [{severity_color}]"
                    f"{cls.escape_markup(severity.upper())}[/{severity_color}][/]"
                )

            if content:
                content_parts.append(f"  [dim]{cls.escape_markup(content)}[/]")

            content_text = "\n".join(content_parts)
        else:
            content_text = f"{header}\n  [dim]Creating report...[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)

    @classmethod
    def _get_severity_color(cls, severity: str) -> str:
        severity_colors = {
            "critical": "#dc2626",
            "high": "#ea580c",
            "medium": "#d97706",
            "low": "#65a30d",
            "info": "#0284c7",
        }
        return severity_colors.get(severity, "#6b7280")

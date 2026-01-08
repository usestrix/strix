from typing import Any, ClassVar

from rich.padding import Padding
from rich.text import Text
from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


FIELD_STYLE = "bold #4ade80"
BG_COLOR = "#141414"


@register_tool_renderer
class FinishScanRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "finish_scan"
    css_classes: ClassVar[list[str]] = ["tool-call", "finish-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})

        executive_summary = args.get("executive_summary", "")
        methodology = args.get("methodology", "")
        technical_analysis = args.get("technical_analysis", "")
        recommendations = args.get("recommendations", "")

        text = Text()
        text.append("🏁 ")
        text.append("Finishing Scan", style="bold #dc2626")

        if executive_summary:
            text.append("\n\n")
            text.append("Executive Summary", style=FIELD_STYLE)
            text.append("\n")
            text.append(executive_summary)

        if methodology:
            text.append("\n\n")
            text.append("Methodology", style=FIELD_STYLE)
            text.append("\n")
            text.append(methodology)

        if technical_analysis:
            text.append("\n\n")
            text.append("Technical Analysis", style=FIELD_STYLE)
            text.append("\n")
            text.append(technical_analysis)

        if recommendations:
            text.append("\n\n")
            text.append("Recommendations", style=FIELD_STYLE)
            text.append("\n")
            text.append(recommendations)

        if not (executive_summary or methodology or technical_analysis or recommendations):
            text.append("\n  ")
            text.append("Generating final report...", style="dim")

        padded = Padding(text, 2, style=f"on {BG_COLOR}")

        css_classes = cls.get_css_classes("completed")
        return Static(padded, classes=css_classes)

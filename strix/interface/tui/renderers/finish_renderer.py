from typing import Any, ClassVar, cast

from rich.text import Text
from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


FIELD_STYLE = "bold #4ade80"


@register_tool_renderer
class FinishScanRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "finish_scan"
    css_classes: ClassVar[list[str]] = ["tool-call", "finish-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        raw_result = tool_data.get("result")
        result = cast("dict[str, Any]", raw_result) if isinstance(raw_result, dict) else None
        text = Text()

        if result is None:
            text.append("◆ ", style="#eab308")
            text.append("Generating final report...", style="bold #eab308")
            render_status = "running"
        elif result.get("completion_nudge") is True:
            text.append("◆ ", style="#eab308")
            text.append("Completion nudged", style="bold #eab308")
            text.append("\n")
            text.append(
                "Testing continues while the agent investigates underexplored areas."
            )
            render_status = "completed"
        elif result.get("success") is False:
            text.append("◆ ", style="#ef4444")
            text.append("Final report not accepted", style="bold #ef4444")
            error = result.get("error")
            if error:
                text.append("\n")
                text.append(str(error))
            render_status = "error"
        elif result.get("scan_completed") is True:
            raw_args = tool_data.get("args", {})
            args = cast("dict[str, Any]", raw_args) if isinstance(raw_args, dict) else {}
            text.append("◆ ", style="#22c55e")
            text.append("Penetration test completed", style="bold #22c55e")

            fields = (
                ("Executive Summary", args.get("executive_summary", "")),
                ("Methodology", args.get("methodology", "")),
                ("Technical Analysis", args.get("technical_analysis", "")),
                ("Recommendations", args.get("recommendations", "")),
            )
            for heading, value in fields:
                if value:
                    text.append("\n\n")
                    text.append(heading, style=FIELD_STYLE)
                    text.append("\n")
                    text.append(str(value))
            render_status = "completed"
        else:
            text.append("◆ ", style="#eab308")
            text.append("Generating final report...", style="bold #eab308")
            render_status = "running"

        padded = Text()
        padded.append("\n\n")
        padded.append_text(text)
        padded.append("\n\n")

        return Static(padded, classes=cls.get_css_classes(render_status))

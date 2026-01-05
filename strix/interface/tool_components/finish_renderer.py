from typing import Any, ClassVar

from rich.text import Text
from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


@register_tool_renderer
class FinishScanRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "finish_scan"
    css_classes: ClassVar[list[str]] = ["tool-call", "finish-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})

        content = args.get("content", "")
        success = args.get("success", True)

        text = Text()
        text.append("🏁 ")

        if success:
            text.append("Finishing Scan", style="bold #dc2626")
        else:
            text.append("Scan Failed", style="bold #dc2626")

        text.append("\n  ")

        if content:
            text.append(content, style="bold")
        else:
            text.append("Generating final report...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)

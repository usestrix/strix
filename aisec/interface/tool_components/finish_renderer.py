from typing import Any, ClassVar

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

        header = (
            "🏁 [bold #dc2626]Finishing Scan[/]" if success else "🏁 [bold #dc2626]Scan Failed[/]"
        )

        if content:
            content_text = f"{header}\n  [bold]{cls.escape_markup(content)}[/]"
        else:
            content_text = f"{header}\n  [dim]Generating final report...[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)

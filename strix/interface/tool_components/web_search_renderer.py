from typing import Any, ClassVar

from rich.text import Text
from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


@register_tool_renderer
class WebSearchRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "web_search"
    css_classes: ClassVar[list[str]] = ["tool-call", "web-search-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        query = args.get("query", "")

        text = Text()
        text.append("🌐 ")
        text.append("Searching the web...", style="bold #60a5fa")

        if query:
            text.append("\n  ")
            text.append(query, style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)

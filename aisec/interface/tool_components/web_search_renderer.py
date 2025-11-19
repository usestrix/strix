from typing import Any, ClassVar

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

        header = "🌐 [bold #60a5fa]Searching the web...[/]"

        if query:
            query_display = query[:100] + "..." if len(query) > 100 else query
            content_text = f"{header}\n  [dim]{cls.escape_markup(query_display)}[/]"
        else:
            content_text = f"{header}"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)

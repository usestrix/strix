from typing import Any, ClassVar

from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


@register_tool_renderer
class ThinkRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "think"
    css_classes: ClassVar[list[str]] = ["tool-call", "thinking-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})

        thought = args.get("thought", "")

        header = "🧠 [bold #a855f7]Thinking[/]"

        if thought:
            thought_display = thought[:600] + "..." if len(thought) > 600 else thought
            content = f"{header}\n  [italic dim]{cls.escape_markup(thought_display)}[/]"
        else:
            content = f"{header}\n  [italic dim]Thinking...[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content, classes=css_classes)

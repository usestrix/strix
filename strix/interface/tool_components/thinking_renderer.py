from typing import Any, ClassVar

from rich.text import Text
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

        text = Text()
        text.append("🧠 ")
        text.append("Thinking", style="bold #a855f7")
        text.append("\n  ")

        if thought:
            text.append(thought, style="italic dim")
        else:
            text.append("Thinking...", style="italic dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)

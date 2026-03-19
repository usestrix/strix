from typing import Any, ClassVar

from rich.text import Text
from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


@register_tool_renderer
class UserMessageRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "user_message"
    css_classes: ClassVar[list[str]] = ["chat-message", "user-message"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        content = tool_data.get("content", "")

        if not content:
            return Static(Text(), classes=" ".join(cls.css_classes))

        styled_text = cls._format_user_message(content)

        return Static(styled_text, classes=" ".join(cls.css_classes))

    @classmethod
    def render_simple(cls, content: str) -> Text:
        if not content:
            return Text()

        return cls._format_user_message(content)

    @classmethod
    def _format_user_message(cls, content: str) -> Text:
        text = Text()

        text.append("▍", style="#3b82f6")
        text.append(" ")
        text.append("You:", style="bold")
        text.append("\n")

        lines = content.split("\n")
        for i, line in enumerate(lines):
            if i > 0:
                text.append("\n")
            text.append("▍", style="#3b82f6")
            text.append(" ")
            text.append(line)

        return text

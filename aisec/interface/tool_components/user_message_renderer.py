from typing import Any, ClassVar

from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


@register_tool_renderer
class UserMessageRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "user_message"
    css_classes: ClassVar[list[str]] = ["chat-message", "user-message"]

    @classmethod
    def render(cls, message_data: dict[str, Any]) -> Static:
        content = message_data.get("content", "")

        if not content:
            return Static("", classes=cls.css_classes)

        if len(content) > 300:
            content = content[:297] + "..."

        lines = content.split("\n")
        bordered_lines = [f"[#3b82f6]▍[/#3b82f6] {line}" for line in lines]
        bordered_content = "\n".join(bordered_lines)
        formatted_content = f"[#3b82f6]▍[/#3b82f6] [bold]You:[/]\n{bordered_content}"

        css_classes = " ".join(cls.css_classes)
        return Static(formatted_content, classes=css_classes)

    @classmethod
    def render_simple(cls, content: str) -> str:
        if not content:
            return ""

        if len(content) > 300:
            content = content[:297] + "..."

        lines = content.split("\n")
        bordered_lines = [f"[#3b82f6]▍[/#3b82f6] {line}" for line in lines]
        bordered_content = "\n".join(bordered_lines)
        return f"[#3b82f6]▍[/#3b82f6] [bold]You:[/]\n{bordered_content}"

from typing import Any, ClassVar

from rich.text import Text
from textual.widgets import Static

from .agent_message_renderer import AgentMessageRenderer
from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


@register_tool_renderer
class RespondToUserRenderer(BaseToolRenderer):
    """Render a reply as the agent's own prose, not as a tool call.

    ``respond_to_user`` carries the message the user is meant to read, so it
    gets the same markdown treatment as a plain assistant turn.
    """

    tool_name: ClassVar[str] = "respond_to_user"
    css_classes: ClassVar[list[str]] = ["tool-call", "respond-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        message = args.get("message", "")

        text = Text()
        if message:
            text.append_text(AgentMessageRenderer.render_simple(message))
            text.append("\n\n")
        text.append("○ ", style="#6b7280")
        text.append("waiting for your reply", style="dim")

        css_classes = cls.get_css_classes(tool_data.get("status", "unknown"))
        return Static(text, classes=css_classes)

import re
from typing import Any, ClassVar

from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


def markdown_to_rich(text: str) -> str:
    # Fenced code blocks: ```lang\n...\n``` or ```\n...\n```
    text = re.sub(
        r"```(?:\w*)\n(.*?)```",
        r"[dim]\1[/dim]",
        text,
        flags=re.DOTALL,
    )

    # Headers
    text = re.sub(r"^#### (.+)$", r"[bold]\1[/bold]", text, flags=re.MULTILINE)
    text = re.sub(r"^### (.+)$", r"[bold]\1[/bold]", text, flags=re.MULTILINE)
    text = re.sub(r"^## (.+)$", r"[bold]\1[/bold]", text, flags=re.MULTILINE)
    text = re.sub(r"^# (.+)$", r"[bold]\1[/bold]", text, flags=re.MULTILINE)

    # Links
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"[underline]\1[/underline] [dim](\2)[/dim]", text)

    # Bold
    text = re.sub(r"\*\*(.+?)\*\*", r"[bold]\1[/bold]", text)
    text = re.sub(r"__(.+?)__", r"[bold]\1[/bold]", text)

    # Italic
    text = re.sub(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", r"[italic]\1[/italic]", text)
    text = re.sub(r"(?<![_\w])_(?!_)(.+?)(?<!_)_(?![_\w])", r"[italic]\1[/italic]", text)

    # Inline code
    text = re.sub(r"`([^`]+)`", r"[bold dim]\1[/bold dim]", text)

    # Strikethrough
    return re.sub(r"~~(.+?)~~", r"[strike]\1[/strike]", text)


@register_tool_renderer
class AgentMessageRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "agent_message"
    css_classes: ClassVar[list[str]] = ["chat-message", "agent-message"]

    @classmethod
    def render(cls, message_data: dict[str, Any]) -> Static:
        content = message_data.get("content", "")

        if not content:
            return Static("", classes=cls.css_classes)

        formatted_content = cls._format_agent_message(content)

        css_classes = " ".join(cls.css_classes)
        return Static(formatted_content, classes=css_classes)

    @classmethod
    def render_simple(cls, content: str) -> str:
        if not content:
            return ""

        return cls._format_agent_message(content)

    @classmethod
    def _format_agent_message(cls, content: str) -> str:
        escaped_content = cls.escape_markup(content)
        return markdown_to_rich(escaped_content)

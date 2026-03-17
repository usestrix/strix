import re
from typing import Any, ClassVar

from rich.text import Text
from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


@register_tool_renderer
class UserMessageRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "user_message"
    css_classes: ClassVar[list[str]] = ["chat-message", "user-message"]
    _RUNTIME_SKILL_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"Loaded tool-specific CLI skills for:\s*(.+?)\.\s*Use these references",
        re.IGNORECASE | re.DOTALL,
    )

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
        runtime_label = cls._runtime_skill_label(content)
        if runtime_label:
            return cls._format_runtime_skill_context(runtime_label)

        text = Text()
        header = "Context:" if cls._is_context_message(content) else "You:"

        text.append("▍", style="#3b82f6")
        text.append(" ")
        text.append(header, style="bold")
        text.append("\n")

        lines = content.split("\n")
        for i, line in enumerate(lines):
            if i > 0:
                text.append("\n")
            text.append("▍", style="#3b82f6")
            text.append(" ")
            text.append(line)

        return text

    @classmethod
    def _format_runtime_skill_context(cls, skill_names: str) -> Text:
        text = Text()
        text.append(">_", style="dim")
        text.append(" ", style="dim")
        text.append(f"getting context for tool {skill_names}", style="dim")
        return text

    @classmethod
    def _runtime_skill_label(cls, content: str) -> str | None:
        stripped = content.lstrip()
        if not stripped.startswith("<runtime_tool_skill_context>"):
            return None

        match = cls._RUNTIME_SKILL_RE.search(stripped)
        if not match:
            return "unknown"

        skills = ", ".join(part.strip() for part in match.group(1).split(",") if part.strip())
        return skills or "unknown"

    @staticmethod
    def _is_context_message(content: str) -> bool:
        stripped = content.lstrip()
        return stripped.startswith("<runtime_tool_skill_context>") or stripped.startswith(
            "<inter_agent_message>"
        )

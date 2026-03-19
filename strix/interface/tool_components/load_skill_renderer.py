from typing import Any, ClassVar

from rich.text import Text
from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


@register_tool_renderer
class LoadSkillRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "load_skill"
    css_classes: ClassVar[list[str]] = ["tool-call", "load-skill-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        status = tool_data.get("status", "completed")

        requested = args.get("skills", "")

        text = Text()
        text.append("◇ ", style="#10b981")
        text.append("loading skill", style="dim")

        if requested:
            text.append(" ")
            text.append(requested, style="#10b981")
        elif not tool_data.get("result"):
            text.append("\n  ")
            text.append("Loading...", style="dim")

        return Static(text, classes=cls.get_css_classes(status))

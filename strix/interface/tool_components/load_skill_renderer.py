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
        result = tool_data.get("result")
        status = tool_data.get("status", "completed")

        requested = args.get("skills", "")
        if not requested and isinstance(result, dict):
            requested = ", ".join(result.get("requested_skills", []) or [])

        text = Text()
        text.append("◇ ", style="#10b981")
        text.append("load skill", style="dim")

        if requested:
            text.append(" ")
            text.append(requested, style="#10b981")

        if isinstance(result, dict):
            if result.get("success"):
                newly_loaded = result.get("newly_loaded_skills", []) or []
                already_loaded = result.get("already_loaded_skills", []) or []

                if newly_loaded:
                    text.append("\n  ")
                    text.append("loaded: ", style="dim")
                    text.append(", ".join(newly_loaded))

                if already_loaded:
                    text.append("\n  ")
                    text.append("already loaded: ", style="dim")
                    text.append(", ".join(already_loaded))
            else:
                error = str(result.get("error", "")).strip()
                if error:
                    text.append("\n  ")
                    text.append(error, style="#ef4444")
        elif not requested:
            text.append("\n  ")
            text.append("Loading...", style="dim")

        return Static(text, classes=cls.get_css_classes(status))

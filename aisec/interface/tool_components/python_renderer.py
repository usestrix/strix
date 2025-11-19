from typing import Any, ClassVar

from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


@register_tool_renderer
class PythonRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "python_action"
    css_classes: ClassVar[list[str]] = ["tool-call", "python-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})

        action = args.get("action", "")
        code = args.get("code", "")

        header = "</> [bold #3b82f6]Python[/]"

        if code and action in ["new_session", "execute"]:
            code_display = code[:600] + "..." if len(code) > 600 else code
            content_text = f"{header}\n  [italic white]{cls.escape_markup(code_display)}[/]"
        elif action == "close":
            content_text = f"{header}\n  [dim]Closing session...[/]"
        elif action == "list_sessions":
            content_text = f"{header}\n  [dim]Listing sessions...[/]"
        else:
            content_text = f"{header}\n  [dim]Running...[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)

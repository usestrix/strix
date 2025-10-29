from typing import Any, ClassVar

from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


@register_tool_renderer
class TerminalRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "terminal_execute"
    css_classes: ClassVar[list[str]] = ["tool-call", "terminal-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        status = tool_data.get("status", "unknown")
        result = tool_data.get("result", {})

        command = args.get("command", "")
        is_input = args.get("is_input", False)
        terminal_id = args.get("terminal_id", "default")
        timeout = args.get("timeout")

        content = cls._build_sleek_content(command, is_input, terminal_id, timeout, result)

        css_classes = cls.get_css_classes(status)
        return Static(content, classes=css_classes)

    @classmethod
    def _build_sleek_content(
        cls,
        command: str,
        is_input: bool,
        terminal_id: str,  # noqa: ARG003
        timeout: float | None,  # noqa: ARG003
        result: dict[str, Any],  # noqa: ARG003
    ) -> str:
        terminal_icon = ">_"

        if not command.strip():
            return f"{terminal_icon} [dim]getting logs...[/]"

        control_sequences = {
            "C-c",
            "C-d",
            "C-z",
            "C-a",
            "C-e",
            "C-k",
            "C-l",
            "C-u",
            "C-w",
            "C-r",
            "C-s",
            "C-t",
            "C-y",
            "^c",
            "^d",
            "^z",
            "^a",
            "^e",
            "^k",
            "^l",
            "^u",
            "^w",
            "^r",
            "^s",
            "^t",
            "^y",
        }
        special_keys = {
            "Enter",
            "Escape",
            "Space",
            "Tab",
            "BTab",
            "BSpace",
            "DC",
            "IC",
            "Up",
            "Down",
            "Left",
            "Right",
            "Home",
            "End",
            "PageUp",
            "PageDown",
            "PgUp",
            "PgDn",
            "PPage",
            "NPage",
            "F1",
            "F2",
            "F3",
            "F4",
            "F5",
            "F6",
            "F7",
            "F8",
            "F9",
            "F10",
            "F11",
            "F12",
        }

        is_special = (
            command in control_sequences
            or command in special_keys
            or command.startswith(("M-", "S-", "C-S-", "C-M-", "S-M-"))
        )

        if is_special:
            return f"{terminal_icon} [#ef4444]{cls.escape_markup(command)}[/]"

        if is_input:
            formatted_command = cls._format_command_display(command)
            return f"{terminal_icon} [#3b82f6]>>>[/] [#22c55e]{formatted_command}[/]"

        formatted_command = cls._format_command_display(command)
        return f"{terminal_icon} [#22c55e]$ {formatted_command}[/]"

    @classmethod
    def _format_command_display(cls, command: str) -> str:
        if not command:
            return ""

        if len(command) > 400:
            command = command[:397] + "..."

        return cls.escape_markup(command)

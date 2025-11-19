from abc import ABC, abstractmethod
from typing import Any, ClassVar, cast

from rich.markup import escape as rich_escape
from textual.widgets import Static


class BaseToolRenderer(ABC):
    tool_name: ClassVar[str] = ""

    css_classes: ClassVar[list[str]] = ["tool-call"]

    @classmethod
    @abstractmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        pass

    @classmethod
    def escape_markup(cls, text: str) -> str:
        return cast("str", rich_escape(text))

    @classmethod
    def format_args(cls, args: dict[str, Any], max_length: int = 500) -> str:
        if not args:
            return ""

        args_parts = []
        for k, v in args.items():
            str_v = str(v)
            if len(str_v) > max_length:
                str_v = str_v[: max_length - 3] + "..."
            args_parts.append(f"  [dim]{k}:[/] {cls.escape_markup(str_v)}")
        return "\n".join(args_parts)

    @classmethod
    def format_result(cls, result: Any, max_length: int = 1000) -> str:
        if result is None:
            return ""

        str_result = str(result).strip()
        if not str_result:
            return ""

        if len(str_result) > max_length:
            str_result = str_result[: max_length - 3] + "..."
        return cls.escape_markup(str_result)

    @classmethod
    def get_status_icon(cls, status: str) -> str:
        status_icons = {
            "running": "[#f59e0b]●[/#f59e0b] In progress...",
            "completed": "[#22c55e]✓[/#22c55e] Done",
            "failed": "[#dc2626]✗[/#dc2626] Failed",
            "error": "[#dc2626]✗[/#dc2626] Error",
        }
        return status_icons.get(status, "[dim]○[/dim] Unknown")

    @classmethod
    def get_css_classes(cls, status: str) -> str:
        base_classes = cls.css_classes.copy()
        base_classes.append(f"status-{status}")
        return " ".join(base_classes)

from abc import ABC, abstractmethod
from typing import Any, ClassVar

from rich.text import Text
from textual.widgets import Static


class BaseToolRenderer(ABC):
    tool_name: ClassVar[str] = ""
    css_classes: ClassVar[list[str]] = ["tool-call"]

    @classmethod
    @abstractmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        pass

    @classmethod
    def build_text(cls, tool_data: dict[str, Any]) -> Text:  # noqa: ARG003
        return Text()

    @classmethod
    def create_static(cls, content: Text, status: str) -> Static:
        css_classes = cls.get_css_classes(status)
        return Static(content, classes=css_classes)

    @classmethod
    def status_icon(cls, status: str) -> tuple[str, str]:
        icons = {
            "running": ("● In progress...", "#f59e0b"),
            "completed": ("✓ Done", "#22c55e"),
            "failed": ("✗ Failed", "#dc2626"),
            "error": ("✗ Error", "#dc2626"),
        }
        return icons.get(status, ("○ Unknown", "dim"))

    @classmethod
    def get_css_classes(cls, status: str) -> str:
        base_classes = cls.css_classes.copy()
        base_classes.append(f"status-{status}")
        return " ".join(base_classes)

    @classmethod
    def text_with_style(cls, content: str, style: str | None = None) -> Text:
        text = Text()
        text.append(content, style=style)
        return text

    @classmethod
    def text_icon_label(
        cls,
        icon: str,
        label: str,
        icon_style: str | None = None,
        label_style: str | None = None,
    ) -> Text:
        text = Text()
        text.append(icon, style=icon_style)
        text.append(" ")
        text.append(label, style=label_style)
        return text

    @classmethod
    def text_header(
        cls,
        icon: str,
        title: str,
        subtitle: str = "",
        title_style: str = "bold",
        subtitle_style: str = "dim",
    ) -> Text:
        text = Text()
        text.append(icon)
        text.append(" ")
        text.append(title, style=title_style)
        if subtitle:
            text.append(" ")
            text.append(subtitle, style=subtitle_style)
        return text

    @classmethod
    def text_key_value(
        cls,
        key: str,
        value: str,
        key_style: str = "dim",
        value_style: str | None = None,
        indent: int = 2,
    ) -> Text:
        text = Text()
        text.append(" " * indent)
        text.append(key, style=key_style)
        text.append(": ")
        text.append(value, style=value_style)
        return text

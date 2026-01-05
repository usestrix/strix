from typing import Any, ClassVar

from rich.text import Text
from textual.widgets import Static

from .base_renderer import BaseToolRenderer


class ToolTUIRegistry:
    _renderers: ClassVar[dict[str, type[BaseToolRenderer]]] = {}

    @classmethod
    def register(cls, renderer_class: type[BaseToolRenderer]) -> None:
        if not renderer_class.tool_name:
            raise ValueError(f"Renderer {renderer_class.__name__} must define tool_name")

        cls._renderers[renderer_class.tool_name] = renderer_class

    @classmethod
    def get_renderer(cls, tool_name: str) -> type[BaseToolRenderer] | None:
        return cls._renderers.get(tool_name)

    @classmethod
    def list_tools(cls) -> list[str]:
        return list(cls._renderers.keys())

    @classmethod
    def has_renderer(cls, tool_name: str) -> bool:
        return tool_name in cls._renderers


def register_tool_renderer(renderer_class: type[BaseToolRenderer]) -> type[BaseToolRenderer]:
    ToolTUIRegistry.register(renderer_class)
    return renderer_class


def get_tool_renderer(tool_name: str) -> type[BaseToolRenderer] | None:
    return ToolTUIRegistry.get_renderer(tool_name)


def render_tool_widget(tool_data: dict[str, Any]) -> Static:
    tool_name = tool_data.get("tool_name", "")
    renderer = get_tool_renderer(tool_name)

    if renderer:
        return renderer.render(tool_data)
    return _render_default_tool_widget(tool_data)


def _render_default_tool_widget(tool_data: dict[str, Any]) -> Static:
    tool_name = tool_data.get("tool_name", "Unknown Tool")
    args = tool_data.get("args", {})
    status = tool_data.get("status", "unknown")
    result = tool_data.get("result")

    text = Text()

    text.append("→ Using tool ", style="dim")
    text.append(tool_name, style="bold blue")
    text.append("\n")

    for k, v in list(args.items()):
        str_v = str(v)
        text.append("  ")
        text.append(k, style="dim")
        text.append(": ")
        text.append(str_v)
        text.append("\n")

    if status in ["completed", "failed", "error"] and result is not None:
        result_str = str(result)
        text.append("Result: ", style="bold")
        text.append(result_str)
    else:
        icon, color = BaseToolRenderer.status_icon(status)
        text.append(icon, style=color)

    css_classes = BaseToolRenderer.get_css_classes(status)
    return Static(text, classes=css_classes)

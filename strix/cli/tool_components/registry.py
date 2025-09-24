from typing import Any, ClassVar

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
    tool_name = BaseToolRenderer.escape_markup(tool_data.get("tool_name", "Unknown Tool"))
    args = tool_data.get("args", {})
    status = tool_data.get("status", "unknown")
    result = tool_data.get("result")

    status_text = BaseToolRenderer.get_status_icon(status)

    header = f"→ Using tool [bold blue]{BaseToolRenderer.escape_markup(tool_name)}[/]"
    content_parts = [header]

    args_str = BaseToolRenderer.format_args(args)
    if args_str:
        content_parts.append(args_str)

    if status in ["completed", "failed", "error"] and result is not None:
        result_str = BaseToolRenderer.format_result(result)
        if result_str:
            content_parts.append(f"[bold]Result:[/] {result_str}")
    else:
        content_parts.append(status_text)

    css_classes = BaseToolRenderer.get_css_classes(status)
    return Static("\n".join(content_parts), classes=css_classes)

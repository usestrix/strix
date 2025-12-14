from typing import Any, ClassVar

from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


STATUS_MARKERS = {
    "pending": "[ ]",
    "in_progress": "[~]",
    "done": "[•]",
}


def _truncate(text: str, length: int = 80) -> str:
    if len(text) <= length:
        return text
    return text[: length - 3] + "..."


def _format_todo_lines(
    cls: type[BaseToolRenderer], result: dict[str, Any], limit: int = 10
) -> list[str]:
    todos = result.get("todos")
    if not isinstance(todos, list) or not todos:
        return ["  [dim]No todos[/]"]

    lines: list[str] = []
    total = len(todos)

    for index, todo in enumerate(todos):
        if index >= limit:
            remaining = total - limit
            if remaining > 0:
                lines.append(f"  [dim]... +{remaining} more[/]")
            break

        status = todo.get("status", "pending")
        marker = STATUS_MARKERS.get(status, STATUS_MARKERS["pending"])

        title = todo.get("title", "").strip() or "(untitled)"
        title = cls.escape_markup(_truncate(title, 90))

        if status == "done":
            title_markup = f"[dim strike]{title}[/]"
        elif status == "in_progress":
            title_markup = f"[italic]{title}[/]"
        else:
            title_markup = title

        lines.append(f"  {marker} {title_markup}")

    return lines


@register_tool_renderer
class CreateTodoRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "create_todo"
    css_classes: ClassVar[list[str]] = ["tool-call", "todo-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        result = tool_data.get("result")
        header = "📋 [bold #a78bfa]Todo[/]"

        if result and isinstance(result, dict):
            if result.get("success"):
                lines = [header]
                lines.extend(_format_todo_lines(cls, result, limit=10))
                content_text = "\n".join(lines)
            else:
                error = result.get("error", "Failed to create todo")
                content_text = f"{header}\n  [#ef4444]{cls.escape_markup(error)}[/]"
        else:
            content_text = f"{header}\n  [dim]Creating...[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)


@register_tool_renderer
class ListTodosRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "list_todos"
    css_classes: ClassVar[list[str]] = ["tool-call", "todo-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        result = tool_data.get("result")
        header = "📋 [bold #a78bfa]Todos[/]"

        if result and isinstance(result, dict):
            if result.get("success"):
                lines = [header]
                lines.extend(_format_todo_lines(cls, result, limit=10))
                content_text = "\n".join(lines)
            else:
                error = result.get("error", "Unable to list todos")
                content_text = f"{header}\n  [#ef4444]{cls.escape_markup(error)}[/]"
        else:
            content_text = f"{header}\n  [dim]Loading...[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)


@register_tool_renderer
class UpdateTodoRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "update_todo"
    css_classes: ClassVar[list[str]] = ["tool-call", "todo-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        result = tool_data.get("result")
        header = "📋 [bold #a78bfa]Todo Updated[/]"

        if result and isinstance(result, dict):
            if result.get("success"):
                lines = [header]
                lines.extend(_format_todo_lines(cls, result, limit=10))
                content_text = "\n".join(lines)
            else:
                error = result.get("error", "Failed to update todo")
                content_text = f"{header}\n  [#ef4444]{cls.escape_markup(error)}[/]"
        else:
            content_text = f"{header}\n  [dim]Updating...[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)


@register_tool_renderer
class MarkTodoDoneRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "mark_todo_done"
    css_classes: ClassVar[list[str]] = ["tool-call", "todo-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        result = tool_data.get("result")
        header = "📋 [bold #a78bfa]Todo Completed[/]"

        if result and isinstance(result, dict):
            if result.get("success"):
                lines = [header]
                lines.extend(_format_todo_lines(cls, result, limit=10))
                content_text = "\n".join(lines)
            else:
                error = result.get("error", "Failed to mark todo done")
                content_text = f"{header}\n  [#ef4444]{cls.escape_markup(error)}[/]"
        else:
            content_text = f"{header}\n  [dim]Marking done...[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)


@register_tool_renderer
class MarkTodoPendingRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "mark_todo_pending"
    css_classes: ClassVar[list[str]] = ["tool-call", "todo-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        result = tool_data.get("result")
        header = "📋 [bold #f59e0b]Todo Reopened[/]"

        if result and isinstance(result, dict):
            if result.get("success"):
                lines = [header]
                lines.extend(_format_todo_lines(cls, result, limit=10))
                content_text = "\n".join(lines)
            else:
                error = result.get("error", "Failed to reopen todo")
                content_text = f"{header}\n  [#ef4444]{cls.escape_markup(error)}[/]"
        else:
            content_text = f"{header}\n  [dim]Reopening...[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)


@register_tool_renderer
class DeleteTodoRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "delete_todo"
    css_classes: ClassVar[list[str]] = ["tool-call", "todo-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        result = tool_data.get("result")
        header = "📋 [bold #94a3b8]Todo Removed[/]"

        if result and isinstance(result, dict):
            if result.get("success"):
                lines = [header]
                lines.extend(_format_todo_lines(cls, result, limit=10))
                content_text = "\n".join(lines)
            else:
                error = result.get("error", "Failed to remove todo")
                content_text = f"{header}\n  [#ef4444]{cls.escape_markup(error)}[/]"
        else:
            content_text = f"{header}\n  [dim]Removing...[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)

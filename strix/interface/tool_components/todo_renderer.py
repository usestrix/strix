from typing import Any, ClassVar

from rich.text import Text
from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


STATUS_MARKERS: dict[str, str] = {
    "pending": "[ ]",
    "in_progress": "[~]",
    "done": "[•]",
}


def _format_todo_lines(text: Text, result: dict[str, Any]) -> None:
    todos = result.get("todos")
    if not isinstance(todos, list) or not todos:
        text.append("\n  ")
        text.append("No todos", style="dim")
        return

    for todo in todos:
        status = todo.get("status", "pending")
        marker = STATUS_MARKERS.get(status, STATUS_MARKERS["pending"])

        title = todo.get("title", "").strip() or "(untitled)"

        text.append("\n  ")
        text.append(marker)
        text.append(" ")

        if status == "done":
            text.append(title, style="dim strike")
        elif status == "in_progress":
            text.append(title, style="italic")
        else:
            text.append(title)


@register_tool_renderer
class CreateTodoRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "create_todo"
    css_classes: ClassVar[list[str]] = ["tool-call", "todo-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        result = tool_data.get("result")

        text = Text()
        text.append("📋 ")
        text.append("Todo", style="bold #a78bfa")

        if result and isinstance(result, dict):
            if result.get("success"):
                _format_todo_lines(text, result)
            else:
                error = result.get("error", "Failed to create todo")
                text.append("\n  ")
                text.append(error, style="#ef4444")
        else:
            text.append("\n  ")
            text.append("Creating...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)


@register_tool_renderer
class ListTodosRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "list_todos"
    css_classes: ClassVar[list[str]] = ["tool-call", "todo-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        result = tool_data.get("result")

        text = Text()
        text.append("📋 ")
        text.append("Todos", style="bold #a78bfa")

        if result and isinstance(result, dict):
            if result.get("success"):
                _format_todo_lines(text, result)
            else:
                error = result.get("error", "Unable to list todos")
                text.append("\n  ")
                text.append(error, style="#ef4444")
        else:
            text.append("\n  ")
            text.append("Loading...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)


@register_tool_renderer
class UpdateTodoRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "update_todo"
    css_classes: ClassVar[list[str]] = ["tool-call", "todo-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        result = tool_data.get("result")

        text = Text()
        text.append("📋 ")
        text.append("Todo Updated", style="bold #a78bfa")

        if result and isinstance(result, dict):
            if result.get("success"):
                _format_todo_lines(text, result)
            else:
                error = result.get("error", "Failed to update todo")
                text.append("\n  ")
                text.append(error, style="#ef4444")
        else:
            text.append("\n  ")
            text.append("Updating...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)


@register_tool_renderer
class MarkTodoDoneRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "mark_todo_done"
    css_classes: ClassVar[list[str]] = ["tool-call", "todo-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        result = tool_data.get("result")

        text = Text()
        text.append("📋 ")
        text.append("Todo Completed", style="bold #a78bfa")

        if result and isinstance(result, dict):
            if result.get("success"):
                _format_todo_lines(text, result)
            else:
                error = result.get("error", "Failed to mark todo done")
                text.append("\n  ")
                text.append(error, style="#ef4444")
        else:
            text.append("\n  ")
            text.append("Marking done...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)


@register_tool_renderer
class MarkTodoPendingRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "mark_todo_pending"
    css_classes: ClassVar[list[str]] = ["tool-call", "todo-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        result = tool_data.get("result")

        text = Text()
        text.append("📋 ")
        text.append("Todo Reopened", style="bold #f59e0b")

        if result and isinstance(result, dict):
            if result.get("success"):
                _format_todo_lines(text, result)
            else:
                error = result.get("error", "Failed to reopen todo")
                text.append("\n  ")
                text.append(error, style="#ef4444")
        else:
            text.append("\n  ")
            text.append("Reopening...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)


@register_tool_renderer
class DeleteTodoRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "delete_todo"
    css_classes: ClassVar[list[str]] = ["tool-call", "todo-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        result = tool_data.get("result")

        text = Text()
        text.append("📋 ")
        text.append("Todo Removed", style="bold #94a3b8")

        if result and isinstance(result, dict):
            if result.get("success"):
                _format_todo_lines(text, result)
            else:
                error = result.get("error", "Failed to remove todo")
                text.append("\n  ")
                text.append(error, style="#ef4444")
        else:
            text.append("\n  ")
            text.append("Removing...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)

from typing import Any, ClassVar

from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


@register_tool_renderer
class StrReplaceEditorRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "str_replace_editor"
    css_classes: ClassVar[list[str]] = ["tool-call", "file-edit-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        result = tool_data.get("result")

        command = args.get("command", "")
        path = args.get("path", "")

        if command == "view":
            header = "📖 [bold #10b981]Reading file[/]"
        elif command == "str_replace":
            header = "✏️ [bold #10b981]Editing file[/]"
        elif command == "create":
            header = "📝 [bold #10b981]Creating file[/]"
        elif command == "insert":
            header = "✏️ [bold #10b981]Inserting text[/]"
        elif command == "undo_edit":
            header = "↩️ [bold #10b981]Undoing edit[/]"
        else:
            header = "📄 [bold #10b981]File operation[/]"

        if (result and isinstance(result, dict) and "content" in result) or path:
            path_display = path[-60:] if len(path) > 60 else path
            content_text = f"{header} [dim]{cls.escape_markup(path_display)}[/]"
        else:
            content_text = f"{header} [dim]Processing...[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)


@register_tool_renderer
class ListFilesRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "list_files"
    css_classes: ClassVar[list[str]] = ["tool-call", "file-edit-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})

        path = args.get("path", "")

        header = "📂 [bold #10b981]Listing files[/]"

        if path:
            path_display = path[-60:] if len(path) > 60 else path
            content_text = f"{header} [dim]{cls.escape_markup(path_display)}[/]"
        else:
            content_text = f"{header} [dim]Current directory[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)


@register_tool_renderer
class SearchFilesRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "search_files"
    css_classes: ClassVar[list[str]] = ["tool-call", "file-edit-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})

        path = args.get("path", "")
        regex = args.get("regex", "")

        header = "🔍 [bold purple]Searching files[/]"

        if path and regex:
            path_display = path[-30:] if len(path) > 30 else path
            regex_display = regex[:30] if len(regex) > 30 else regex
            content_text = (
                f"{header} [dim]{cls.escape_markup(path_display)} for "
                f"'{cls.escape_markup(regex_display)}'[/]"
            )
        elif path:
            path_display = path[-60:] if len(path) > 60 else path
            content_text = f"{header} [dim]{cls.escape_markup(path_display)}[/]"
        elif regex:
            regex_display = regex[:60] if len(regex) > 60 else regex
            content_text = f"{header} [dim]'{cls.escape_markup(regex_display)}'[/]"
        else:
            content_text = f"{header} [dim]Searching...[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)

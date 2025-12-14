from functools import cache
from typing import Any, ClassVar

from pygments.lexers import get_lexer_by_name, get_lexer_for_filename
from pygments.styles import get_style_by_name
from pygments.util import ClassNotFound
from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


@cache
def _get_style_colors() -> dict[Any, str]:
    style = get_style_by_name("native")
    return {token: f"#{style_def['color']}" for token, style_def in style if style_def["color"]}


def _get_lexer_for_file(path: str) -> Any:
    try:
        return get_lexer_for_filename(path)
    except ClassNotFound:
        return get_lexer_by_name("text")


@register_tool_renderer
class StrReplaceEditorRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "str_replace_editor"
    css_classes: ClassVar[list[str]] = ["tool-call", "file-edit-tool"]

    @classmethod
    def _get_token_color(cls, token_type: Any) -> str | None:
        colors = _get_style_colors()
        while token_type:
            if token_type in colors:
                return colors[token_type]
            token_type = token_type.parent
        return None

    @classmethod
    def _highlight_code(cls, code: str, path: str) -> str:
        lexer = _get_lexer_for_file(path)
        result_parts: list[str] = []

        for token_type, token_value in lexer.get_tokens(code):
            if not token_value:
                continue

            escaped_value = cls.escape_markup(token_value)
            color = cls._get_token_color(token_type)

            if color:
                result_parts.append(f"[{color}]{escaped_value}[/]")
            else:
                result_parts.append(escaped_value)

        return "".join(result_parts)

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        result = tool_data.get("result")

        command = args.get("command", "")
        path = args.get("path", "")
        old_str = args.get("old_str", "")
        new_str = args.get("new_str", "")
        file_text = args.get("file_text", "")

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

        path_display = path[-60:] if len(path) > 60 else path
        content_parts = [f"{header} [dim]{cls.escape_markup(path_display)}[/]"]

        if command == "str_replace" and (old_str or new_str):
            if old_str:
                old_display = old_str[:1000] + "..." if len(old_str) > 1000 else old_str
                highlighted_old = cls._highlight_code(old_display, path)
                old_lines = highlighted_old.split("\n")
                content_parts.extend(f"[#ef4444]-[/] {line}" for line in old_lines)
            if new_str:
                new_display = new_str[:1000] + "..." if len(new_str) > 1000 else new_str
                highlighted_new = cls._highlight_code(new_display, path)
                new_lines = highlighted_new.split("\n")
                content_parts.extend(f"[#22c55e]+[/] {line}" for line in new_lines)
        elif command == "create" and file_text:
            text_display = file_text[:1500] + "..." if len(file_text) > 1500 else file_text
            highlighted_text = cls._highlight_code(text_display, path)
            content_parts.append(highlighted_text)
        elif command == "insert" and new_str:
            new_display = new_str[:1000] + "..." if len(new_str) > 1000 else new_str
            highlighted_new = cls._highlight_code(new_display, path)
            new_lines = highlighted_new.split("\n")
            content_parts.extend(f"[#22c55e]+[/] {line}" for line in new_lines)
        elif not (result and isinstance(result, dict) and "content" in result) and not path:
            content_parts = [f"{header} [dim]Processing...[/]"]

        content_text = "\n".join(content_parts)
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

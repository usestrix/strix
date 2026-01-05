from functools import cache
from typing import Any, ClassVar

from pygments.lexers import get_lexer_by_name, get_lexer_for_filename
from pygments.styles import get_style_by_name
from pygments.util import ClassNotFound
from rich.text import Text
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
    def _highlight_code(cls, code: str, path: str) -> Text:
        lexer = _get_lexer_for_file(path)
        text = Text()

        for token_type, token_value in lexer.get_tokens(code):
            if not token_value:
                continue
            color = cls._get_token_color(token_type)
            text.append(token_value, style=color)

        return text

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        result = tool_data.get("result")

        command = args.get("command", "")
        path = args.get("path", "")
        old_str = args.get("old_str", "")
        new_str = args.get("new_str", "")
        file_text = args.get("file_text", "")

        text = Text()

        icons_and_labels = {
            "view": ("📖 ", "Reading file", "#10b981"),
            "str_replace": ("✏️ ", "Editing file", "#10b981"),
            "create": ("📝 ", "Creating file", "#10b981"),
            "insert": ("✏️ ", "Inserting text", "#10b981"),
            "undo_edit": ("↩️ ", "Undoing edit", "#10b981"),
        }

        icon, label, color = icons_and_labels.get(command, ("📄 ", "File operation", "#10b981"))
        text.append(icon)
        text.append(label, style=f"bold {color}")

        if path:
            path_display = path[-60:] if len(path) > 60 else path
            text.append(" ")
            text.append(path_display, style="dim")

        if command == "str_replace" and (old_str or new_str):
            if old_str:
                old_display = cls.truncate(old_str, 1000)
                highlighted_old = cls._highlight_code(old_display, path)
                for line in highlighted_old.plain.split("\n"):
                    text.append("\n")
                    text.append("-", style="#ef4444")
                    text.append(" ")
                    text.append(line)

            if new_str:
                new_display = cls.truncate(new_str, 1000)
                highlighted_new = cls._highlight_code(new_display, path)
                for line in highlighted_new.plain.split("\n"):
                    text.append("\n")
                    text.append("+", style="#22c55e")
                    text.append(" ")
                    text.append(line)

        elif command == "create" and file_text:
            text_display = cls.truncate(file_text, 1500)
            text.append("\n")
            text.append_text(cls._highlight_code(text_display, path))

        elif command == "insert" and new_str:
            new_display = cls.truncate(new_str, 1000)
            highlighted_new = cls._highlight_code(new_display, path)
            for line in highlighted_new.plain.split("\n"):
                text.append("\n")
                text.append("+", style="#22c55e")
                text.append(" ")
                text.append(line)

        elif not (result and isinstance(result, dict) and "content" in result) and not path:
            text.append(" ")
            text.append("Processing...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)


@register_tool_renderer
class ListFilesRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "list_files"
    css_classes: ClassVar[list[str]] = ["tool-call", "file-edit-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        path = args.get("path", "")

        text = Text()
        text.append("📂 ")
        text.append("Listing files", style="bold #10b981")
        text.append(" ")

        if path:
            path_display = path[-60:] if len(path) > 60 else path
            text.append(path_display, style="dim")
        else:
            text.append("Current directory", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)


@register_tool_renderer
class SearchFilesRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "search_files"
    css_classes: ClassVar[list[str]] = ["tool-call", "file-edit-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        path = args.get("path", "")
        regex = args.get("regex", "")

        text = Text()
        text.append("🔍 ")
        text.append("Searching files", style="bold purple")
        text.append(" ")

        if path and regex:
            path_display = path[-30:] if len(path) > 30 else path
            regex_display = regex[:30] if len(regex) > 30 else regex
            text.append(path_display, style="dim")
            text.append(" for '", style="dim")
            text.append(regex_display, style="dim")
            text.append("'", style="dim")
        elif path:
            path_display = path[-60:] if len(path) > 60 else path
            text.append(path_display, style="dim")
        elif regex:
            regex_display = regex[:60] if len(regex) > 60 else regex
            text.append("'", style="dim")
            text.append(regex_display, style="dim")
            text.append("'", style="dim")
        else:
            text.append("Searching...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)

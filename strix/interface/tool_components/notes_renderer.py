from typing import Any, ClassVar

from rich.text import Text
from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


@register_tool_renderer
class CreateNoteRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "create_note"
    css_classes: ClassVar[list[str]] = ["tool-call", "notes-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})

        title = args.get("title", "")
        content = args.get("content", "")
        category = args.get("category", "general")

        text = Text()
        text.append("📝 ")
        text.append("Note", style="bold #fbbf24")
        text.append(" ")
        text.append(f"({category})", style="dim")

        if title:
            text.append("\n  ")
            text.append(title.strip())

        if content:
            text.append("\n  ")
            text.append(content.strip(), style="dim")

        if not title and not content:
            text.append("\n  ")
            text.append("Capturing...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)


@register_tool_renderer
class DeleteNoteRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "delete_note"
    css_classes: ClassVar[list[str]] = ["tool-call", "notes-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:  # noqa: ARG003
        text = Text()
        text.append("📝 ")
        text.append("Note Removed", style="bold #94a3b8")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)


@register_tool_renderer
class UpdateNoteRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "update_note"
    css_classes: ClassVar[list[str]] = ["tool-call", "notes-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})

        title = args.get("title")
        content = args.get("content")

        text = Text()
        text.append("📝 ")
        text.append("Note Updated", style="bold #fbbf24")

        if title:
            text.append("\n  ")
            text.append(title)

        if content:
            text.append("\n  ")
            text.append(content.strip(), style="dim")

        if not title and not content:
            text.append("\n  ")
            text.append("Updating...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)


@register_tool_renderer
class ListNotesRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "list_notes"
    css_classes: ClassVar[list[str]] = ["tool-call", "notes-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        result = tool_data.get("result")

        text = Text()
        text.append("📝 ")
        text.append("Notes", style="bold #fbbf24")

        if isinstance(result, str) and result.strip():
            text.append("\n  ")
            text.append(result.strip(), style="dim")
        elif result and isinstance(result, dict) and result.get("success"):
            count = result.get("total_count", 0)
            notes = result.get("notes", []) or []

            if count == 0:
                text.append("\n  ")
                text.append("No notes", style="dim")
            else:
                for note in notes:
                    title = note.get("title", "").strip() or "(untitled)"
                    category = note.get("category", "general")
                    note_content = note.get("content", "").strip()

                    text.append("\n  - ")
                    text.append(title)
                    text.append(f" ({category})", style="dim")

                    if note_content:
                        text.append("\n    ")
                        text.append(note_content, style="dim")
        else:
            text.append("\n  ")
            text.append("Loading...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)

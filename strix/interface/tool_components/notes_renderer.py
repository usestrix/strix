from typing import Any, ClassVar

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

        header = "📝 [bold #fbbf24]Note[/]"

        if title:
            title_display = title[:100] + "..." if len(title) > 100 else title
            note_parts = [f"{header}\n  [bold]{cls.escape_markup(title_display)}[/]"]

            if content:
                content_display = content[:200] + "..." if len(content) > 200 else content
                note_parts.append(f"  [dim]{cls.escape_markup(content_display)}[/]")

            content_text = "\n".join(note_parts)
        else:
            content_text = f"{header}\n  [dim]Creating note...[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)


@register_tool_renderer
class DeleteNoteRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "delete_note"
    css_classes: ClassVar[list[str]] = ["tool-call", "notes-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:  # noqa: ARG003
        header = "🗑️ [bold #fbbf24]Delete Note[/]"
        content_text = f"{header}\n  [dim]Deleting...[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)


@register_tool_renderer
class UpdateNoteRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "update_note"
    css_classes: ClassVar[list[str]] = ["tool-call", "notes-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})

        title = args.get("title", "")
        content = args.get("content", "")

        header = "✏️ [bold #fbbf24]Update Note[/]"

        if title or content:
            note_parts = [header]

            if title:
                title_display = title[:100] + "..." if len(title) > 100 else title
                note_parts.append(f"  [bold]{cls.escape_markup(title_display)}[/]")

            if content:
                content_display = content[:200] + "..." if len(content) > 200 else content
                note_parts.append(f"  [dim]{cls.escape_markup(content_display)}[/]")

            content_text = "\n".join(note_parts)
        else:
            content_text = f"{header}\n  [dim]Updating...[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)


@register_tool_renderer
class ListNotesRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "list_notes"
    css_classes: ClassVar[list[str]] = ["tool-call", "notes-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        result = tool_data.get("result")

        header = "📋 [bold #fbbf24]Listing notes[/]"

        if result and isinstance(result, dict) and "notes" in result:
            notes = result["notes"]
            if isinstance(notes, list):
                count = len(notes)
                content_text = f"{header}\n  [dim]{count} notes found[/]"
            else:
                content_text = f"{header}\n  [dim]No notes found[/]"
        else:
            content_text = f"{header}\n  [dim]Listing notes...[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)

from typing import Any, ClassVar

from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


def _truncate(text: str, length: int = 800) -> str:
    if len(text) <= length:
        return text
    return text[: length - 3] + "..."


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

        header = f"📝 [bold #fbbf24]Note[/] [dim]({category})[/]"

        lines = [header]
        if title:
            title_display = _truncate(title.strip(), 300)
            lines.append(f"  {cls.escape_markup(title_display)}")

        if content:
            content_display = _truncate(content.strip(), 800)
            lines.append(f"  [dim]{cls.escape_markup(content_display)}[/]")

        if len(lines) == 1:
            lines.append("  [dim]Capturing...[/]")

        css_classes = cls.get_css_classes("completed")
        return Static("\n".join(lines), classes=css_classes)


@register_tool_renderer
class DeleteNoteRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "delete_note"
    css_classes: ClassVar[list[str]] = ["tool-call", "notes-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:  # noqa: ARG003
        header = "📝 [bold #94a3b8]Note Removed[/]"
        content_text = header

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)


@register_tool_renderer
class UpdateNoteRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "update_note"
    css_classes: ClassVar[list[str]] = ["tool-call", "notes-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})

        title = args.get("title")
        content = args.get("content")

        header = "📝 [bold #fbbf24]Note Updated[/]"
        lines = [header]

        if title:
            lines.append(f"  {cls.escape_markup(_truncate(title, 300))}")

        if content:
            content_display = _truncate(content.strip(), 800)
            lines.append(f"  [dim]{cls.escape_markup(content_display)}[/]")

        if len(lines) == 1:
            lines.append("  [dim]Updating...[/]")

        css_classes = cls.get_css_classes("completed")
        return Static("\n".join(lines), classes=css_classes)


@register_tool_renderer
class ListNotesRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "list_notes"
    css_classes: ClassVar[list[str]] = ["tool-call", "notes-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        result = tool_data.get("result")

        header = "📝 [bold #fbbf24]Notes[/]"

        if result and isinstance(result, dict) and result.get("success"):
            count = result.get("total_count", 0)
            notes = result.get("notes", []) or []
            lines = [header]

            if count == 0:
                lines.append("  [dim]No notes[/]")
            else:
                for note in notes[:5]:
                    title = note.get("title", "").strip() or "(untitled)"
                    category = note.get("category", "general")
                    content = note.get("content", "").strip()

                    lines.append(
                        f"  - {cls.escape_markup(_truncate(title, 300))} [dim]({category})[/]"
                    )
                    if content:
                        content_preview = _truncate(content, 400)
                        lines.append(f"    [dim]{cls.escape_markup(content_preview)}[/]")

                remaining = max(count - 5, 0)
                if remaining:
                    lines.append(f"  [dim]... +{remaining} more[/]")
            content_text = "\n".join(lines)
        else:
            content_text = f"{header}\n  [dim]Loading...[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)

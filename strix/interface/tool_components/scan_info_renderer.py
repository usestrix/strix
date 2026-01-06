from typing import Any, ClassVar

from rich.text import Text
from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


@register_tool_renderer
class ScanStartInfoRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "scan_start_info"
    css_classes: ClassVar[list[str]] = ["tool-call", "scan-info-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        status = tool_data.get("status", "unknown")
        targets = args.get("targets", [])

        text = Text()
        text.append("🚀 Starting penetration test")

        if len(targets) == 1:
            text.append(" on ")
            text.append(cls._get_target_display(targets[0]))
        elif len(targets) > 1:
            text.append(f" on {len(targets)} targets")
            for target_info in targets:
                text.append("\n   • ")
                text.append(cls._get_target_display(target_info))

        css_classes = cls.get_css_classes(status)
        return Static(text, classes=css_classes)

    @classmethod
    def _get_target_display(cls, target_info: dict[str, Any]) -> str:
        original = target_info.get("original")
        if original:
            return str(original)
        return "unknown target"


@register_tool_renderer
class SubagentStartInfoRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "subagent_start_info"
    css_classes: ClassVar[list[str]] = ["tool-call", "subagent-info-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        status = tool_data.get("status", "unknown")

        name = str(args.get("name", "Unknown Agent"))
        task = str(args.get("task", ""))

        text = Text()
        text.append("◈ ", style="#a78bfa")
        text.append("subagent ", style="dim")
        text.append(name, style="bold #a78bfa")

        if task:
            text.append("\n  ")
            text.append(task, style="dim")

        css_classes = cls.get_css_classes(status)
        return Static(text, classes=css_classes)

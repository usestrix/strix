from typing import Any, ClassVar

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

        if len(targets) == 1:
            target_display = cls._build_single_target_display(targets[0])
            content = f"🚀 Starting penetration test on {target_display}"
        elif len(targets) > 1:
            content = f"🚀 Starting penetration test on {len(targets)} targets"
            for target_info in targets:
                target_display = cls._build_single_target_display(target_info)
                content += f"\n   • {target_display}"
        else:
            content = "🚀 Starting penetration test"

        css_classes = cls.get_css_classes(status)
        return Static(content, classes=css_classes)

    @classmethod
    def _build_single_target_display(cls, target_info: dict[str, Any]) -> str:
        original = target_info.get("original")
        if original:
            return cls.escape_markup(str(original))

        return "unknown target"


@register_tool_renderer
class SubagentStartInfoRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "subagent_start_info"
    css_classes: ClassVar[list[str]] = ["tool-call", "subagent-info-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        status = tool_data.get("status", "unknown")

        name = args.get("name", "Unknown Agent")
        task = args.get("task", "")

        name = cls.escape_markup(str(name))
        content = f"🤖 Spawned subagent {name}"
        if task:
            task = cls.escape_markup(str(task))
            content += f"\n    Task: {task}"

        css_classes = cls.get_css_classes(status)
        return Static(content, classes=css_classes)

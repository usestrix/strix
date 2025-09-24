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

        target = args.get("target", {})

        target_display = cls._build_target_display(target)

        content = f"🚀 Starting scan on {target_display}"

        css_classes = cls.get_css_classes(status)
        return Static(content, classes=css_classes)

    @classmethod
    def _build_target_display(cls, target: dict[str, Any]) -> str:
        if target_url := target.get("target_url"):
            return cls.escape_markup(str(target_url))
        if target_repo := target.get("target_repo"):
            return cls.escape_markup(str(target_repo))
        if target_path := target.get("target_path"):
            return cls.escape_markup(str(target_path))
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

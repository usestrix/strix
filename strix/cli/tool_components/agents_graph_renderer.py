from typing import Any, ClassVar

from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


@register_tool_renderer
class ViewAgentGraphRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "view_agent_graph"
    css_classes: ClassVar[list[str]] = ["tool-call", "agents-graph-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:  # noqa: ARG003
        content_text = "🕸️ [bold #fbbf24]Viewing agents graph[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)


@register_tool_renderer
class CreateAgentRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "create_agent"
    css_classes: ClassVar[list[str]] = ["tool-call", "agents-graph-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})

        task = args.get("task", "")
        name = args.get("name", "Agent")

        header = f"🤖 [bold #fbbf24]Creating {cls.escape_markup(name)}[/]"

        if task:
            task_display = task[:400] + "..." if len(task) > 400 else task
            content_text = f"{header}\n  [dim]{cls.escape_markup(task_display)}[/]"
        else:
            content_text = f"{header}\n  [dim]Spawning agent...[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)


@register_tool_renderer
class SendMessageToAgentRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "send_message_to_agent"
    css_classes: ClassVar[list[str]] = ["tool-call", "agents-graph-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})

        message = args.get("message", "")

        header = "💬 [bold #fbbf24]Sending message[/]"

        if message:
            message_display = message[:400] + "..." if len(message) > 400 else message
            content_text = f"{header}\n  [dim]{cls.escape_markup(message_display)}[/]"
        else:
            content_text = f"{header}\n  [dim]Sending...[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)


@register_tool_renderer
class AgentFinishRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "agent_finish"
    css_classes: ClassVar[list[str]] = ["tool-call", "agents-graph-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})

        result_summary = args.get("result_summary", "")
        findings = args.get("findings", [])
        success = args.get("success", True)

        header = (
            "🏁 [bold #fbbf24]Agent completed[/]" if success else "🏁 [bold #fbbf24]Agent failed[/]"
        )

        if result_summary:
            content_parts = [f"{header}\n  [bold]{cls.escape_markup(result_summary)}[/]"]

            if findings and isinstance(findings, list):
                finding_lines = [f"• {finding}" for finding in findings]
                content_parts.append(
                    f"  [dim]{chr(10).join([cls.escape_markup(line) for line in finding_lines])}[/]"
                )

            content_text = "\n".join(content_parts)
        else:
            content_text = f"{header}\n  [dim]Completing task...[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)


@register_tool_renderer
class WaitForMessageRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "wait_for_message"
    css_classes: ClassVar[list[str]] = ["tool-call", "agents-graph-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})

        reason = args.get("reason", "Waiting for messages from other agents or user input")

        header = "⏸️ [bold #fbbf24]Waiting for messages[/]"

        if reason:
            reason_display = reason[:400] + "..." if len(reason) > 400 else reason
            content_text = f"{header}\n  [dim]{cls.escape_markup(reason_display)}[/]"
        else:
            content_text = f"{header}\n  [dim]Agent paused until message received...[/]"

        css_classes = cls.get_css_classes("completed")
        return Static(content_text, classes=css_classes)

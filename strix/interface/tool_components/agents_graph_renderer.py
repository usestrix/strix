from typing import Any, ClassVar

from rich.text import Text
from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


@register_tool_renderer
class ViewAgentGraphRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "view_agent_graph"
    css_classes: ClassVar[list[str]] = ["tool-call", "agents-graph-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:  # noqa: ARG003
        text = Text()
        text.append("🕸️ ")
        text.append("Viewing agents graph", style="bold #fbbf24")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)


@register_tool_renderer
class CreateAgentRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "create_agent"
    css_classes: ClassVar[list[str]] = ["tool-call", "agents-graph-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})

        task = args.get("task", "")
        name = args.get("name", "Agent")

        text = Text()
        text.append("🤖 ")
        text.append(f"Creating {name}", style="bold #fbbf24")

        if task:
            text.append("\n  ")
            text.append(task, style="dim")
        else:
            text.append("\n  ")
            text.append("Spawning agent...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)


@register_tool_renderer
class SendMessageToAgentRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "send_message_to_agent"
    css_classes: ClassVar[list[str]] = ["tool-call", "agents-graph-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})

        message = args.get("message", "")

        text = Text()
        text.append("💬 ")
        text.append("Sending message", style="bold #fbbf24")

        if message:
            text.append("\n  ")
            text.append(message, style="dim")
        else:
            text.append("\n  ")
            text.append("Sending...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)


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

        text = Text()
        text.append("🏁 ")

        if success:
            text.append("Agent completed", style="bold #fbbf24")
        else:
            text.append("Agent failed", style="bold #fbbf24")

        if result_summary:
            text.append("\n  ")
            text.append(result_summary, style="bold")

            if findings and isinstance(findings, list):
                for finding in findings:
                    text.append("\n  • ")
                    text.append(str(finding), style="dim")
        else:
            text.append("\n  ")
            text.append("Completing task...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)


@register_tool_renderer
class WaitForMessageRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "wait_for_message"
    css_classes: ClassVar[list[str]] = ["tool-call", "agents-graph-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})

        reason = args.get("reason", "Waiting for messages from other agents or user input")

        text = Text()
        text.append("⏸️ ")
        text.append("Waiting for messages", style="bold #fbbf24")

        if reason:
            text.append("\n  ")
            text.append(reason, style="dim")
        else:
            text.append("\n  ")
            text.append("Agent paused until message received...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)

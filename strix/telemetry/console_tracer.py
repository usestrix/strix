"""Console tracer for human-readable verbose output."""

from datetime import datetime
from typing import Any

from rich.console import Console
from rich.text import Text


class ConsoleTracer:
    """Outputs human-readable trace events to console in real-time."""

    def __init__(self, console: Console | None = None):
        self.console = console or Console()

    def _timestamp(self) -> str:
        """Get current timestamp in HH:MM:SS format."""
        return datetime.now().strftime("%H:%M:%S")

    def _print_event(self, text: Text) -> None:
        """Print an event with timestamp prefix."""
        output = Text()
        output.append(f"[{self._timestamp()}] ", style="dim")
        output.append_text(text)
        self.console.print(output)

    def log_trace_start(self, run_id: str, target: str | None = None) -> None:
        """Log trace start event."""
        text = Text()
        text.append("▶ ", style="bold #22c55e")
        text.append("Trace started", style="bold #22c55e")
        if run_id:
            text.append(f" ({run_id})", style="dim")
        self._print_event(text)

    def log_trace_end(self, run_id: str) -> None:
        """Log trace end event."""
        text = Text()
        text.append("■ ", style="bold #6b7280")
        text.append("Trace ended", style="#6b7280")
        self._print_event(text)

    def log_llm_request(
        self,
        model: str,
        message_count: int,
        agent_id: str | None = None,
    ) -> None:
        """Log LLM request event."""
        text = Text()
        text.append("🤖 ", style="")
        text.append("LLM Request", style="bold #60a5fa")
        text.append(" → ", style="dim")
        text.append(model, style="#60a5fa")
        text.append(f" ({message_count} messages)", style="dim")
        if agent_id:
            text.append(f" [{agent_id[:12]}]", style="dim italic")
        self._print_event(text)

    def log_llm_response(
        self,
        model: str,
        tokens: dict[str, int] | None = None,
        agent_id: str | None = None,
    ) -> None:
        """Log LLM response event."""
        text = Text()
        text.append("✓ ", style="#22c55e")
        text.append("LLM Response", style="#22c55e")
        if tokens:
            input_tokens = tokens.get("input", 0)
            output_tokens = tokens.get("output", 0)
            text.append(f" ({input_tokens}→{output_tokens} tokens)", style="dim")
        self._print_event(text)

    def log_llm_error(self, error: str, model: str | None = None) -> None:
        """Log LLM error event."""
        text = Text()
        text.append("✗ ", style="#ef4444")
        text.append("LLM Error", style="bold #ef4444")
        text.append(f": {error[:100]}", style="#ef4444")
        self._print_event(text)

    def log_tool_call(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
        agent_id: str | None = None,
    ) -> None:
        """Log tool call event."""
        text = Text()

        # Use different icons/styles based on tool type
        if tool_name == "terminal_execute":
            text.append(">_ ", style="dim")
            command = (args or {}).get("command", "")
            is_input = (args or {}).get("is_input", False)
            if is_input:
                text.append(">>> ", style="#3b82f6")
            else:
                text.append("$ ", style="#22c55e")
            # Truncate long commands
            if len(command) > 100:
                command = command[:97] + "..."
            text.append(command, style="bold")

        elif tool_name == "think":
            text.append("🧠 ", style="")
            text.append("Thinking", style="bold #a855f7")
            thought = (args or {}).get("thought", "")
            if thought:
                # Truncate long thoughts
                if len(thought) > 80:
                    thought = thought[:77] + "..."
                text.append(f": {thought}", style="italic dim")

        elif tool_name == "create_agent":
            text.append("◈ ", style="#a78bfa")
            text.append("spawning ", style="dim")
            name = (args or {}).get("name", "Agent")
            text.append(name, style="bold #a78bfa")
            task = (args or {}).get("task", "")
            if task:
                text.append("\n           ")
                if len(task) > 80:
                    task = task[:77] + "..."
                text.append(task, style="dim")

        elif tool_name == "send_message_to_agent":
            text.append("→ ", style="#60a5fa")
            agent_target = (args or {}).get("agent_id", "")
            if agent_target:
                text.append(f"to {agent_target[:12]}", style="dim")
            message = (args or {}).get("message", "")
            if message:
                text.append("\n           ")
                if len(message) > 80:
                    message = message[:77] + "..."
                text.append(message, style="dim")

        elif tool_name == "wait_for_message":
            text.append("○ ", style="#6b7280")
            text.append("waiting", style="dim")
            reason = (args or {}).get("reason", "")
            if reason:
                text.append(f": {reason[:60]}", style="dim italic")

        elif tool_name == "agent_finish":
            success = (args or {}).get("success", True)
            if success:
                text.append("◆ ", style="#22c55e")
                text.append("Agent completed", style="bold #22c55e")
            else:
                text.append("◆ ", style="#ef4444")
                text.append("Agent failed", style="bold #ef4444")
            summary = (args or {}).get("result_summary", "")
            if summary:
                text.append("\n           ")
                if len(summary) > 80:
                    summary = summary[:77] + "..."
                text.append(summary, style="bold")

        elif tool_name == "browser_action":
            text.append("🌐 ", style="")
            action = (args or {}).get("action", "browse")
            text.append(f"Browser: {action}", style="bold #f59e0b")
            url = (args or {}).get("url", "")
            if url:
                if len(url) > 60:
                    url = url[:57] + "..."
                text.append(f" → {url}", style="dim")

        elif tool_name == "send_request":
            text.append("📡 ", style="")
            method = (args or {}).get("method", "GET")
            url = (args or {}).get("url", "")
            text.append(f"{method}", style="bold #f59e0b")
            if url:
                if len(url) > 60:
                    url = url[:57] + "..."
                text.append(f" {url}", style="dim")

        elif tool_name == "file_edit":
            text.append("📝 ", style="")
            text.append("Edit file", style="bold #22d3ee")
            path = (args or {}).get("path", "")
            if path:
                text.append(f": {path}", style="dim")

        elif tool_name == "web_search":
            text.append("🔍 ", style="")
            text.append("Web search", style="bold #a855f7")
            query = (args or {}).get("query", "")
            if query:
                if len(query) > 60:
                    query = query[:57] + "..."
                text.append(f": {query}", style="dim italic")

        else:
            # Generic tool format
            text.append("⚡ ", style="dim")
            text.append(tool_name, style="bold")
            if args:
                # Show first arg value as preview
                for key, value in args.items():
                    if isinstance(value, str) and value:
                        preview = value[:40] + "..." if len(value) > 40 else value
                        text.append(f" ({key}={preview})", style="dim")
                        break

        self._print_event(text)

    def log_tool_result(
        self,
        tool_name: str,
        result: Any,
        error: str | None = None,
        agent_id: str | None = None,
    ) -> None:
        """Log tool result event."""
        # Only log errors or significant results
        if error:
            text = Text()
            text.append("  ✗ ", style="#ef4444")
            text.append("Error: ", style="#ef4444")
            if len(error) > 80:
                error = error[:77] + "..."
            text.append(error, style="dim #ef4444")
            self._print_event(text)
        elif tool_name == "terminal_execute" and result:
            # Show terminal output preview
            content = ""
            if isinstance(result, dict):
                content = result.get("content", "")
            elif isinstance(result, str):
                content = result
            if content:
                lines = content.strip().split("\n")
                if lines:
                    text = Text()
                    # Show first few lines of output
                    for i, line in enumerate(lines[:3]):
                        if len(line) > 80:
                            line = line[:77] + "..."
                        text.append(f"           {line}\n", style="dim")
                    if len(lines) > 3:
                        text.append(f"           ... ({len(lines) - 3} more lines)", style="dim italic")
                    self.console.print(text)

    def log_agent_created(
        self,
        agent_id: str,
        agent_name: str,
        task: str | None = None,
    ) -> None:
        """Log agent created event."""
        text = Text()
        text.append("● ", style="#a78bfa")
        text.append("Agent created: ", style="dim")
        text.append(agent_name, style="bold #a78bfa")
        text.append(f" [{agent_id[:12]}]", style="dim italic")
        self._print_event(text)

    def log_agent_completed(
        self,
        agent_id: str,
        agent_name: str,
        success: bool = True,
    ) -> None:
        """Log agent completed event."""
        text = Text()
        if success:
            text.append("● ", style="#22c55e")
            text.append("Agent finished: ", style="dim")
            text.append(agent_name, style="#22c55e")
        else:
            text.append("● ", style="#ef4444")
            text.append("Agent failed: ", style="dim")
            text.append(agent_name, style="#ef4444")
        self._print_event(text)

    def log_state_change(
        self,
        agent_id: str,
        state: str,
        details: str | None = None,
    ) -> None:
        """Log agent state change event."""
        # Only log significant state changes
        if state in ("waiting", "error", "completed"):
            text = Text()
            text.append("◇ ", style="dim")
            text.append(f"State: {state}", style="dim")
            if details:
                text.append(f" - {details[:50]}", style="dim italic")
            self._print_event(text)

    def log_message(
        self,
        from_agent: str,
        to_agent: str | None = None,
        content: str | None = None,
    ) -> None:
        """Log inter-agent message event."""
        text = Text()
        text.append("💬 ", style="")
        text.append(f"{from_agent[:12]}", style="bold")
        if to_agent:
            text.append(" → ", style="dim")
            text.append(f"{to_agent[:12]}", style="bold")
        if content:
            text.append("\n           ")
            if len(content) > 80:
                content = content[:77] + "..."
            text.append(content, style="dim")
        self._print_event(text)

    def log_vulnerability_found(
        self,
        vuln_id: str,
        title: str,
        severity: str | None = None,
    ) -> None:
        """Log vulnerability found event."""
        text = Text()
        text.append("🚨 ", style="")
        text.append("VULNERABILITY", style="bold #ef4444")
        text.append(f" [{vuln_id}]", style="#ef4444")
        if severity:
            severity_colors = {
                "critical": "#dc2626",
                "high": "#ef4444",
                "medium": "#f59e0b",
                "low": "#22c55e",
                "info": "#6b7280",
            }
            color = severity_colors.get(severity.lower(), "#6b7280")
            text.append(f" ({severity})", style=f"bold {color}")
        text.append(f"\n           {title}", style="bold")
        self._print_event(text)

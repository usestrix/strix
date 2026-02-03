"""
Live Tracer Module - Real-time JSONL audit trail for pentesting runs.

Streams structured events to disk as they happen, capturing:
- LLM requests and responses
- Tool calls and results
- Agent lifecycle events
- State changes

Enable via --trace flag or STRIX_TRACE=1 environment variable.
Use --trace-verbose for human-readable console output.
"""

import json
import logging
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from strix.telemetry.console_tracer import ConsoleTracer
from strix.telemetry.redactor import SecretRedactor


if TYPE_CHECKING:
    from io import TextIOWrapper


logger = logging.getLogger(__name__)

_global_live_tracer: "LiveTracer | None" = None


def get_live_tracer() -> "LiveTracer | None":
    """Get the global live tracer instance."""
    return _global_live_tracer


def set_live_tracer(tracer: "LiveTracer | None") -> None:
    """Set the global live tracer instance."""
    global _global_live_tracer  # noqa: PLW0603
    _global_live_tracer = tracer


class LiveTracer:
    """
    Real-time JSONL tracer that streams events to disk.
    
    Each event is a JSON object written as a single line with:
    - timestamp: ISO 8601 timestamp
    - trace_id: Unique ID for the entire run
    - event_id: Unique ID for each event
    - sequence: Monotonically increasing sequence number
    - event_type: Type of event
    - agent_id: Which agent this event belongs to (if applicable)
    - data: Event-specific payload
    """

    def __init__(
        self,
        output_path: Path | str | None = None,
        run_name: str | None = None,
        redact_secrets: bool = False,
        verbose: bool = False,
    ):
        self.trace_id = f"trace-{uuid4().hex[:12]}"
        self.run_name = run_name or self.trace_id
        self.start_time = datetime.now(UTC).isoformat()
        self.redact_secrets = redact_secrets
        self.verbose = verbose
        
        self._sequence = 0
        self._sequence_lock = threading.Lock()
        self._file_lock = threading.Lock()
        self._file: "TextIOWrapper | None" = None
        self._closed = False
        
        # Initialize redactor
        self._redactor = SecretRedactor() if redact_secrets else None
        
        # Initialize console tracer for verbose output
        self._console_tracer = ConsoleTracer() if verbose else None
        
        # Determine output path
        if output_path:
            self._output_path = Path(output_path)
        else:
            runs_dir = Path.cwd() / "strix_runs"
            runs_dir.mkdir(exist_ok=True)
            run_dir = runs_dir / self.run_name
            run_dir.mkdir(exist_ok=True)
            self._output_path = run_dir / "trace.jsonl"
        
        # Open file for append
        self._open_file()
        
        # Write trace start event
        self._emit_event(
            event_type="trace_start",
            data={
                "run_name": self.run_name,
                "redact_secrets": self.redact_secrets,
            },
        )
        
        # Console output
        if self._console_tracer:
            self._console_tracer.log_trace_start(self.run_name)

    def _open_file(self) -> None:
        """Open the trace file for writing."""
        try:
            self._output_path.parent.mkdir(parents=True, exist_ok=True)
            self._file = self._output_path.open("a", encoding="utf-8")
            logger.info(f"Live trace output: {self._output_path}")
        except OSError as e:
            logger.error(f"Failed to open trace file: {e}")
            raise

    def _get_next_sequence(self) -> int:
        """Get the next sequence number (thread-safe)."""
        with self._sequence_lock:
            self._sequence += 1
            return self._sequence

    def _emit_event(
        self,
        event_type: str,
        data: dict[str, Any] | None = None,
        agent_id: str | None = None,
    ) -> str:
        """
        Emit an event to the trace file.
        
        Returns the event_id.
        """
        if self._closed or self._file is None:
            return ""
        
        event_id = f"evt-{uuid4().hex[:8]}"
        sequence = self._get_next_sequence()
        
        event = {
            "timestamp": datetime.now(UTC).isoformat(),
            "trace_id": self.trace_id,
            "event_id": event_id,
            "sequence": sequence,
            "event_type": event_type,
        }
        
        if agent_id:
            event["agent_id"] = agent_id
        
        if data:
            # Apply redaction if enabled
            if self._redactor:
                data = self._redactor.redact(data)
            event["data"] = data
        
        try:
            with self._file_lock:
                if self._file and not self._closed:
                    self._file.write(json.dumps(event, default=str) + "\n")
                    self._file.flush()
        except OSError as e:
            logger.error(f"Failed to write trace event: {e}")
        
        return event_id

    # -------------------------------------------------------------------------
    # LLM Events
    # -------------------------------------------------------------------------
    
    def log_llm_request(
        self,
        agent_id: str | None,
        model: str,
        messages: list[dict[str, Any]],
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Log an LLM request being sent."""
        data: dict[str, Any] = {
            "model": model,
            "message_count": len(messages),
            "messages": self._summarize_messages(messages),
        }
        if metadata:
            data["metadata"] = metadata
        
        # Console output
        if self._console_tracer:
            self._console_tracer.log_llm_request(model, len(messages), agent_id)
        
        return self._emit_event(
            event_type="llm_request",
            agent_id=agent_id,
            data=data,
        )

    def log_llm_response(
        self,
        agent_id: str | None,
        content: str,
        usage: dict[str, Any] | None = None,
        tool_invocations: list[dict[str, Any]] | None = None,
        thinking_blocks: list[dict[str, Any]] | None = None,
        duration_ms: float | None = None,
        model: str | None = None,
    ) -> str:
        """Log an LLM response received."""
        data: dict[str, Any] = {
            "content_length": len(content) if content else 0,
            "content_preview": (content[:500] + "...") if content and len(content) > 500 else content,
        }
        
        if usage:
            data["usage"] = usage
        if tool_invocations:
            data["tool_invocations"] = tool_invocations
        if thinking_blocks:
            data["has_thinking"] = True
            data["thinking_count"] = len(thinking_blocks)
        if duration_ms is not None:
            data["duration_ms"] = round(duration_ms, 2)
        
        # Console output
        if self._console_tracer:
            tokens = None
            if usage:
                tokens = {
                    "input": usage.get("prompt_tokens", 0),
                    "output": usage.get("completion_tokens", 0),
                }
            self._console_tracer.log_llm_response(model or "unknown", tokens, agent_id)
        
        return self._emit_event(
            event_type="llm_response",
            agent_id=agent_id,
            data=data,
        )

    def log_llm_error(
        self,
        agent_id: str | None,
        error_type: str,
        error_message: str,
        retryable: bool = False,
        model: str | None = None,
    ) -> str:
        """Log an LLM error."""
        # Console output
        if self._console_tracer:
            self._console_tracer.log_llm_error(error_message, model)
        
        return self._emit_event(
            event_type="llm_error",
            agent_id=agent_id,
            data={
                "error_type": error_type,
                "error_message": error_message,
                "retryable": retryable,
            },
        )

    # -------------------------------------------------------------------------
    # Tool Events
    # -------------------------------------------------------------------------
    
    def log_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        args: dict[str, Any],
        execution_id: int | None = None,
    ) -> str:
        """Log a tool being called."""
        # Console output
        if self._console_tracer:
            self._console_tracer.log_tool_call(tool_name, args, agent_id)
        
        return self._emit_event(
            event_type="tool_call",
            agent_id=agent_id,
            data={
                "tool_name": tool_name,
                "args": args,
                "execution_id": execution_id,
            },
        )

    def log_tool_result(
        self,
        agent_id: str,
        tool_name: str,
        status: str,
        result: Any,
        execution_id: int | None = None,
        duration_ms: float | None = None,
        error: str | None = None,
    ) -> str:
        """Log a tool execution result."""
        # Summarize large results
        result_summary = self._summarize_result(result)
        
        data: dict[str, Any] = {
            "tool_name": tool_name,
            "status": status,
            "result": result_summary,
            "execution_id": execution_id,
        }
        if duration_ms is not None:
            data["duration_ms"] = round(duration_ms, 2)
        
        # Console output
        if self._console_tracer:
            self._console_tracer.log_tool_result(tool_name, result, error, agent_id)
        
        return self._emit_event(
            event_type="tool_result",
            agent_id=agent_id,
            data=data,
        )

    # -------------------------------------------------------------------------
    # Agent Events
    # -------------------------------------------------------------------------
    
    def log_agent_created(
        self,
        agent_id: str,
        agent_name: str,
        task: str,
        parent_id: str | None = None,
        agent_type: str | None = None,
    ) -> str:
        """Log an agent being created."""
        # Console output
        if self._console_tracer:
            self._console_tracer.log_agent_created(agent_id, agent_name, task)
        
        return self._emit_event(
            event_type="agent_created",
            agent_id=agent_id,
            data={
                "agent_name": agent_name,
                "task": task,
                "parent_id": parent_id,
                "agent_type": agent_type,
            },
        )

    def log_agent_completed(
        self,
        agent_id: str,
        status: str,
        result: dict[str, Any] | None = None,
        error_message: str | None = None,
        agent_name: str | None = None,
    ) -> str:
        """Log an agent completing its task."""
        data: dict[str, Any] = {"status": status}
        if result:
            data["result"] = self._summarize_result(result)
        if error_message:
            data["error_message"] = error_message
        
        # Console output
        if self._console_tracer:
            success = status in ("completed", "success")
            self._console_tracer.log_agent_completed(
                agent_id, agent_name or "Agent", success
            )
        
        return self._emit_event(
            event_type="agent_completed",
            agent_id=agent_id,
            data=data,
        )

    def log_agent_state_change(
        self,
        agent_id: str,
        field: str,
        old_value: Any,
        new_value: Any,
    ) -> str:
        """Log a significant state change in an agent."""
        # Console output
        if self._console_tracer:
            self._console_tracer.log_state_change(
                agent_id, str(new_value), str(field)
            )
        
        return self._emit_event(
            event_type="state_change",
            agent_id=agent_id,
            data={
                "field": field,
                "old_value": str(old_value) if old_value is not None else None,
                "new_value": str(new_value) if new_value is not None else None,
            },
        )

    # -------------------------------------------------------------------------
    # Message Events
    # -------------------------------------------------------------------------
    
    def log_message(
        self,
        agent_id: str | None,
        role: str,
        content: str,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Log a chat message."""
        data: dict[str, Any] = {
            "role": role,
            "content_length": len(content) if content else 0,
            "content_preview": (content[:1000] + "...") if content and len(content) > 1000 else content,
        }
        if metadata:
            data["metadata"] = metadata
        
        return self._emit_event(
            event_type="message",
            agent_id=agent_id,
            data=data,
        )

    # -------------------------------------------------------------------------
    # Vulnerability Events
    # -------------------------------------------------------------------------
    
    def log_vulnerability_found(
        self,
        agent_id: str | None,
        vuln_id: str,
        title: str,
        severity: str,
        target: str | None = None,
    ) -> str:
        """Log a vulnerability being discovered."""
        # Console output
        if self._console_tracer:
            self._console_tracer.log_vulnerability_found(vuln_id, title, severity)
        
        return self._emit_event(
            event_type="vulnerability_found",
            agent_id=agent_id,
            data={
                "vuln_id": vuln_id,
                "title": title,
                "severity": severity,
                "target": target,
            },
        )

    # -------------------------------------------------------------------------
    # Helper Methods
    # -------------------------------------------------------------------------
    
    def _summarize_messages(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Create a summary of messages for logging."""
        summaries = []
        for msg in messages:
            role = msg.get("role", "unknown")
            content = msg.get("content", "")
            
            if isinstance(content, str):
                content_len = len(content)
                preview = (content[:200] + "...") if len(content) > 200 else content
            elif isinstance(content, list):
                # Handle multi-part content (text + images)
                content_len = sum(
                    len(p.get("text", "")) if isinstance(p, dict) else 0
                    for p in content
                )
                preview = f"[{len(content)} parts]"
            else:
                content_len = 0
                preview = str(content)[:200]
            
            summaries.append({
                "role": role,
                "content_length": content_len,
                "preview": preview,
            })
        
        return summaries

    def _summarize_result(self, result: Any) -> Any:
        """Summarize a result for logging (truncate large values)."""
        if result is None:
            return None
        
        if isinstance(result, str):
            if len(result) > 2000:
                return result[:1000] + f"\n... [truncated {len(result) - 2000} chars] ...\n" + result[-1000:]
            return result
        
        if isinstance(result, dict):
            # Remove screenshot data if present
            result = dict(result)
            if "screenshot" in result:
                result["screenshot"] = "[screenshot data removed]"
            
            # Truncate large string values
            for key, value in result.items():
                if isinstance(value, str) and len(value) > 500:
                    result[key] = value[:250] + f"... [truncated {len(value) - 500} chars] ..." + value[-250:]
            
            return result
        
        if isinstance(result, list) and len(result) > 50:
            return result[:25] + [f"... [{len(result) - 50} items truncated] ..."] + result[-25:]
        
        return result

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------
    
    def close(self) -> None:
        """Close the trace file."""
        if self._closed:
            return
        
        # Console output
        if self._console_tracer:
            self._console_tracer.log_trace_end(self.run_name)
        
        # Write trace end event
        self._emit_event(
            event_type="trace_end",
            data={
                "total_events": self._sequence,
                "end_time": datetime.now(UTC).isoformat(),
            },
        )
        
        self._closed = True
        
        with self._file_lock:
            if self._file:
                try:
                    self._file.close()
                except OSError:
                    pass
                self._file = None
        
        logger.info(f"Live trace completed: {self._output_path} ({self._sequence} events)")

    @property
    def output_path(self) -> Path:
        """Get the trace output path."""
        return self._output_path

    def __enter__(self) -> "LiveTracer":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

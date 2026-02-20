"""Tests for the LiveTracer module."""

import json
import tempfile
from pathlib import Path

import pytest

from strix.telemetry.live_tracer import LiveTracer, get_live_tracer, set_live_tracer


class TestLiveTracer:
    """Tests for LiveTracer class."""

    def test_initialization_creates_file(self, tmp_path: Path) -> None:
        """Test that LiveTracer creates a trace file on initialization."""
        trace_path = tmp_path / "trace.jsonl"
        tracer = LiveTracer(output_path=trace_path, run_name="test-run")

        assert trace_path.exists()
        tracer.close()

    def test_trace_start_event(self, tmp_path: Path) -> None:
        """Test that trace_start event is written on initialization."""
        trace_path = tmp_path / "trace.jsonl"
        tracer = LiveTracer(output_path=trace_path, run_name="test-run")
        tracer.close()

        with trace_path.open() as f:
            lines = f.readlines()

        assert len(lines) >= 2  # At least trace_start and trace_end

        # Check trace_start event
        start_event = json.loads(lines[0])
        assert start_event["event_type"] == "trace_start"
        assert start_event["data"]["run_name"] == "test-run"
        assert "trace_id" in start_event
        assert "timestamp" in start_event
        assert "event_id" in start_event
        assert start_event["sequence"] == 1

    def test_trace_end_event(self, tmp_path: Path) -> None:
        """Test that trace_end event is written on close."""
        trace_path = tmp_path / "trace.jsonl"
        tracer = LiveTracer(output_path=trace_path, run_name="test-run")
        tracer.close()

        with trace_path.open() as f:
            lines = f.readlines()

        # Check trace_end event (last line)
        end_event = json.loads(lines[-1])
        assert end_event["event_type"] == "trace_end"
        assert "total_events" in end_event["data"]

    def test_log_llm_request(self, tmp_path: Path) -> None:
        """Test logging an LLM request."""
        trace_path = tmp_path / "trace.jsonl"
        tracer = LiveTracer(output_path=trace_path)

        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Hello!"},
        ]

        event_id = tracer.log_llm_request(
            agent_id="agent_123",
            model="test-model",
            messages=messages,
            metadata={"test": True},
        )
        tracer.close()

        assert event_id.startswith("evt-")

        with trace_path.open() as f:
            lines = f.readlines()

        # Find the llm_request event
        llm_event = None
        for line in lines:
            event = json.loads(line)
            if event["event_type"] == "llm_request":
                llm_event = event
                break

        assert llm_event is not None
        assert llm_event["agent_id"] == "agent_123"
        assert llm_event["data"]["model"] == "test-model"
        assert llm_event["data"]["message_count"] == 2

    def test_log_llm_response(self, tmp_path: Path) -> None:
        """Test logging an LLM response."""
        trace_path = tmp_path / "trace.jsonl"
        tracer = LiveTracer(output_path=trace_path)

        event_id = tracer.log_llm_response(
            agent_id="agent_123",
            content="Hello! How can I help you?",
            usage={"input_tokens": 100, "output_tokens": 50},
            duration_ms=1234.56,
        )
        tracer.close()

        assert event_id.startswith("evt-")

        with trace_path.open() as f:
            lines = f.readlines()

        # Find the llm_response event
        response_event = None
        for line in lines:
            event = json.loads(line)
            if event["event_type"] == "llm_response":
                response_event = event
                break

        assert response_event is not None
        assert response_event["agent_id"] == "agent_123"
        assert response_event["data"]["content_length"] == 26
        assert response_event["data"]["duration_ms"] == 1234.56

    def test_log_tool_call(self, tmp_path: Path) -> None:
        """Test logging a tool call."""
        trace_path = tmp_path / "trace.jsonl"
        tracer = LiveTracer(output_path=trace_path)

        tracer.log_tool_call(
            agent_id="agent_123",
            tool_name="terminal",
            args={"command": "ls -la"},
            execution_id=42,
        )
        tracer.close()

        with trace_path.open() as f:
            lines = f.readlines()

        tool_event = None
        for line in lines:
            event = json.loads(line)
            if event["event_type"] == "tool_call":
                tool_event = event
                break

        assert tool_event is not None
        assert tool_event["data"]["tool_name"] == "terminal"
        assert tool_event["data"]["args"]["command"] == "ls -la"
        assert tool_event["data"]["execution_id"] == 42

    def test_log_tool_result(self, tmp_path: Path) -> None:
        """Test logging a tool result."""
        trace_path = tmp_path / "trace.jsonl"
        tracer = LiveTracer(output_path=trace_path)

        tracer.log_tool_result(
            agent_id="agent_123",
            tool_name="terminal",
            status="completed",
            result={"output": "file1.txt\nfile2.txt"},
            execution_id=42,
            duration_ms=100.5,
        )
        tracer.close()

        with trace_path.open() as f:
            lines = f.readlines()

        result_event = None
        for line in lines:
            event = json.loads(line)
            if event["event_type"] == "tool_result":
                result_event = event
                break

        assert result_event is not None
        assert result_event["data"]["tool_name"] == "terminal"
        assert result_event["data"]["status"] == "completed"
        assert result_event["data"]["duration_ms"] == 100.5

    def test_log_agent_created(self, tmp_path: Path) -> None:
        """Test logging agent creation."""
        trace_path = tmp_path / "trace.jsonl"
        tracer = LiveTracer(output_path=trace_path)

        tracer.log_agent_created(
            agent_id="agent_123",
            agent_name="Root Agent",
            task="Perform security scan",
            parent_id=None,
            agent_type="StrixAgent",
        )
        tracer.close()

        with trace_path.open() as f:
            lines = f.readlines()

        agent_event = None
        for line in lines:
            event = json.loads(line)
            if event["event_type"] == "agent_created":
                agent_event = event
                break

        assert agent_event is not None
        assert agent_event["agent_id"] == "agent_123"
        assert agent_event["data"]["agent_name"] == "Root Agent"
        assert agent_event["data"]["task"] == "Perform security scan"
        assert agent_event["data"]["agent_type"] == "StrixAgent"

    def test_log_agent_completed(self, tmp_path: Path) -> None:
        """Test logging agent completion."""
        trace_path = tmp_path / "trace.jsonl"
        tracer = LiveTracer(output_path=trace_path)

        tracer.log_agent_completed(
            agent_id="agent_123",
            status="completed",
            result={"success": True, "findings": 5},
        )
        tracer.close()

        with trace_path.open() as f:
            lines = f.readlines()

        completed_event = None
        for line in lines:
            event = json.loads(line)
            if event["event_type"] == "agent_completed":
                completed_event = event
                break

        assert completed_event is not None
        assert completed_event["data"]["status"] == "completed"
        assert completed_event["data"]["result"]["success"] is True

    def test_log_state_change(self, tmp_path: Path) -> None:
        """Test logging state changes."""
        trace_path = tmp_path / "trace.jsonl"
        tracer = LiveTracer(output_path=trace_path)

        tracer.log_agent_state_change(
            agent_id="agent_123",
            field="iteration",
            old_value=5,
            new_value=6,
        )
        tracer.close()

        with trace_path.open() as f:
            lines = f.readlines()

        state_event = None
        for line in lines:
            event = json.loads(line)
            if event["event_type"] == "state_change":
                state_event = event
                break

        assert state_event is not None
        assert state_event["data"]["field"] == "iteration"
        assert state_event["data"]["old_value"] == "5"
        assert state_event["data"]["new_value"] == "6"

    def test_log_vulnerability_found(self, tmp_path: Path) -> None:
        """Test logging vulnerability discovery."""
        trace_path = tmp_path / "trace.jsonl"
        tracer = LiveTracer(output_path=trace_path)

        tracer.log_vulnerability_found(
            agent_id="agent_123",
            vuln_id="vuln-0001",
            title="SQL Injection",
            severity="high",
            target="https://example.com/api",
        )
        tracer.close()

        with trace_path.open() as f:
            lines = f.readlines()

        vuln_event = None
        for line in lines:
            event = json.loads(line)
            if event["event_type"] == "vulnerability_found":
                vuln_event = event
                break

        assert vuln_event is not None
        assert vuln_event["data"]["vuln_id"] == "vuln-0001"
        assert vuln_event["data"]["title"] == "SQL Injection"
        assert vuln_event["data"]["severity"] == "high"

    def test_sequence_numbers_increment(self, tmp_path: Path) -> None:
        """Test that sequence numbers increment monotonically."""
        trace_path = tmp_path / "trace.jsonl"
        tracer = LiveTracer(output_path=trace_path)

        # Generate multiple events
        for i in range(5):
            tracer.log_message(
                agent_id="agent_123",
                role="user",
                content=f"Message {i}",
            )
        tracer.close()

        with trace_path.open() as f:
            lines = f.readlines()

        sequences = [json.loads(line)["sequence"] for line in lines]
        assert sequences == sorted(sequences)  # Must be monotonically increasing
        assert len(set(sequences)) == len(sequences)  # All unique

    def test_context_manager(self, tmp_path: Path) -> None:
        """Test LiveTracer as context manager."""
        trace_path = tmp_path / "trace.jsonl"

        with LiveTracer(output_path=trace_path) as tracer:
            tracer.log_message(
                agent_id="agent_123",
                role="user",
                content="Test message",
            )

        # File should be properly closed after context exits
        with trace_path.open() as f:
            lines = f.readlines()

        assert len(lines) >= 3  # trace_start, message, trace_end

    def test_output_path_property(self, tmp_path: Path) -> None:
        """Test that output_path property returns correct path."""
        trace_path = tmp_path / "custom" / "trace.jsonl"
        tracer = LiveTracer(output_path=trace_path)

        assert tracer.output_path == trace_path
        tracer.close()

    def test_global_tracer_functions(self, tmp_path: Path) -> None:
        """Test get_live_tracer and set_live_tracer functions."""
        # Initially should be None
        original = get_live_tracer()

        trace_path = tmp_path / "trace.jsonl"
        tracer = LiveTracer(output_path=trace_path)

        set_live_tracer(tracer)
        assert get_live_tracer() is tracer

        # Clean up
        set_live_tracer(original)
        tracer.close()

    def test_large_content_truncation(self, tmp_path: Path) -> None:
        """Test that large content is properly truncated."""
        trace_path = tmp_path / "trace.jsonl"
        tracer = LiveTracer(output_path=trace_path)

        large_content = "x" * 10000  # 10KB of content

        tracer.log_llm_response(
            agent_id="agent_123",
            content=large_content,
        )
        tracer.close()

        with trace_path.open() as f:
            lines = f.readlines()

        response_event = None
        for line in lines:
            event = json.loads(line)
            if event["event_type"] == "llm_response":
                response_event = event
                break

        assert response_event is not None
        # Content preview should be truncated
        assert len(response_event["data"]["content_preview"]) < len(large_content)
        assert "..." in response_event["data"]["content_preview"]
        # But content_length should report actual size
        assert response_event["data"]["content_length"] == 10000


class TestLiveTracerWithRedaction:
    """Tests for LiveTracer with secret redaction enabled."""

    def test_redaction_enabled(self, tmp_path: Path) -> None:
        """Test that redaction is applied when enabled."""
        trace_path = tmp_path / "trace.jsonl"
        tracer = LiveTracer(output_path=trace_path, redact_secrets=True)

        tracer.log_tool_call(
            agent_id="agent_123",
            tool_name="http_request",
            args={
                "url": "https://api.example.com",
                "headers": {"Authorization": "Bearer sk-secret-key-12345"},
                "api_key": "sk-openai-secret-key-abcdef",
            },
        )
        tracer.close()

        with trace_path.open() as f:
            lines = f.readlines()

        tool_event = None
        for line in lines:
            event = json.loads(line)
            if event["event_type"] == "tool_call":
                tool_event = event
                break

        assert tool_event is not None
        # API key should be redacted
        assert tool_event["data"]["args"]["api_key"] == "[REDACTED]"

    def test_redaction_disabled(self, tmp_path: Path) -> None:
        """Test that redaction is not applied when disabled."""
        trace_path = tmp_path / "trace.jsonl"
        tracer = LiveTracer(output_path=trace_path, redact_secrets=False)

        test_value = "not-really-secret"
        tracer.log_tool_call(
            agent_id="agent_123",
            tool_name="test_tool",
            args={"url": test_value},
        )
        tracer.close()

        with trace_path.open() as f:
            lines = f.readlines()

        tool_event = None
        for line in lines:
            event = json.loads(line)
            if event["event_type"] == "tool_call":
                tool_event = event
                break

        assert tool_event is not None
        assert tool_event["data"]["args"]["url"] == test_value

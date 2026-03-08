import json
import os
import time
from pathlib import Path
from typing import Any, ClassVar

import pytest
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

from strix.telemetry import tracer as tracer_module
from strix.telemetry.tracer import Tracer, set_global_tracer


def _load_events(events_path: Path) -> list[dict[str, Any]]:
    lines = events_path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line]


@pytest.fixture(autouse=True)
def _reset_tracer_globals(monkeypatch) -> None:
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    monkeypatch.delenv("STRIX_EVENTS_RETENTION_DAYS", raising=False)
    monkeypatch.delenv("TRACELOOP_BASE_URL", raising=False)
    monkeypatch.delenv("TRACELOOP_API_KEY", raising=False)
    monkeypatch.delenv("TRACELOOP_HEADERS", raising=False)


def test_tracer_local_mode_writes_jsonl_with_correlation(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)

    tracer = Tracer("local-observability")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": ["https://example.com"], "user_instructions": "focus auth"})
    tracer.log_agent_creation("agent-1", "Root Agent", "scan auth")
    tracer.log_chat_message("starting scan", "user", "agent-1")
    execution_id = tracer.log_tool_execution_start(
        "agent-1",
        "send_request",
        {"url": "https://example.com/login"},
    )
    tracer.update_tool_execution(execution_id, "completed", {"status_code": 200, "body": "ok"})

    events_path = tmp_path / "strix_runs" / "local-observability" / "events.jsonl"
    assert events_path.exists()

    events = _load_events(events_path)
    assert any(event["event_type"] == "tool.execution.updated" for event in events)
    assert any(event["event_type"] == "traffic.intercepted" for event in events)

    for event in events:
        assert event["run_id"] == "local-observability"
        assert event["trace_id"]
        assert event["span_id"]


def test_tracer_redacts_sensitive_payloads(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)

    tracer = Tracer("redaction-run")
    set_global_tracer(tracer)
    execution_id = tracer.log_tool_execution_start(
        "agent-1",
        "send_request",
        {
            "url": "https://example.com",
            "api_key": "sk-secret-token-value",
            "authorization": "Bearer super-secret-token",
        },
    )
    tracer.update_tool_execution(
        execution_id,
        "error",
        {"error": "request failed with token sk-secret-token-value"},
    )

    events_path = tmp_path / "strix_runs" / "redaction-run" / "events.jsonl"
    events = _load_events(events_path)
    serialized = json.dumps(events)

    assert "sk-secret-token-value" not in serialized
    assert "super-secret-token" not in serialized
    assert "[REDACTED]" in serialized


def test_tracer_remote_mode_configures_traceloop_export(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)

    class FakeTraceloop:
        init_calls: ClassVar[list[dict[str, Any]]] = []

        @staticmethod
        def init(**kwargs: Any) -> None:
            FakeTraceloop.init_calls.append(kwargs)

        @staticmethod
        def set_association_properties(properties: dict[str, Any]) -> None:  # noqa: ARG004
            return None

    monkeypatch.setattr(tracer_module, "Traceloop", FakeTraceloop)
    monkeypatch.setenv("TRACELOOP_BASE_URL", "https://otel.example.com")
    monkeypatch.setenv("TRACELOOP_API_KEY", "test-api-key")
    monkeypatch.setenv("TRACELOOP_HEADERS", '{"x-custom":"header"}')

    tracer = Tracer("remote-observability")
    set_global_tracer(tracer)
    tracer.log_chat_message("hello", "user", "agent-1")

    assert tracer._remote_export_enabled is True
    assert FakeTraceloop.init_calls
    init_kwargs = FakeTraceloop.init_calls[-1]
    assert init_kwargs["api_endpoint"] == "https://otel.example.com"
    assert init_kwargs["api_key"] == "test-api-key"
    assert init_kwargs["headers"] == {"x-custom": "header"}
    assert isinstance(init_kwargs["processor"], SimpleSpanProcessor)

    events_path = tmp_path / "strix_runs" / "remote-observability" / "events.jsonl"
    events = _load_events(events_path)
    run_started = next(event for event in events if event["event_type"] == "run.started")
    assert run_started["payload"]["remote_export_enabled"] is True


def test_tracer_local_mode_avoids_traceloop_remote_endpoint(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)

    class FakeTraceloop:
        init_calls: ClassVar[list[dict[str, Any]]] = []

        @staticmethod
        def init(**kwargs: Any) -> None:
            FakeTraceloop.init_calls.append(kwargs)

        @staticmethod
        def set_association_properties(properties: dict[str, Any]) -> None:  # noqa: ARG004
            return None

    monkeypatch.setattr(tracer_module, "Traceloop", FakeTraceloop)

    tracer = Tracer("local-traceloop")
    set_global_tracer(tracer)
    tracer.log_chat_message("hello", "user", "agent-1")

    assert FakeTraceloop.init_calls
    init_kwargs = FakeTraceloop.init_calls[-1]
    assert "api_endpoint" not in init_kwargs
    assert "api_key" not in init_kwargs
    assert "headers" not in init_kwargs
    assert isinstance(init_kwargs["processor"], SimpleSpanProcessor)
    assert tracer._remote_export_enabled is False


def test_run_completed_event_emitted_once(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)

    tracer = Tracer("single-complete")
    set_global_tracer(tracer)
    tracer.save_run_data(mark_complete=True)
    tracer.save_run_data(mark_complete=True)

    events_path = tmp_path / "strix_runs" / "single-complete" / "events.jsonl"
    events = _load_events(events_path)
    run_completed = [event for event in events if event["event_type"] == "run.completed"]
    assert len(run_completed) == 1


def test_streaming_updates_are_throttled(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_STREAMING_EVENT_MIN_LENGTH_DELTA", 50)
    monkeypatch.setattr(tracer_module, "_STREAMING_EVENT_MIN_INTERVAL_SECONDS", 1000.0)
    monkeypatch.setattr(tracer_module.time, "monotonic", lambda: 1.0)

    tracer = Tracer("throttled-stream")
    set_global_tracer(tracer)

    tracer.update_streaming_content("agent-1", "a" * 10)
    tracer.update_streaming_content("agent-1", "a" * 20)
    tracer.update_streaming_content("agent-1", "a" * 30)
    tracer.update_streaming_content("agent-1", "a" * 70)

    events_path = tmp_path / "strix_runs" / "throttled-stream" / "events.jsonl"
    events = _load_events(events_path)
    stream_updates = [event for event in events if event["event_type"] == "agent.streaming.updated"]
    assert len(stream_updates) == 2


def test_events_with_agent_id_include_agent_name(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)

    tracer = Tracer("agent-name-enrichment")
    set_global_tracer(tracer)
    tracer.log_agent_creation("agent-1", "Root Agent", "scan auth")
    tracer.log_chat_message("hello", "assistant", "agent-1")

    events_path = tmp_path / "strix_runs" / "agent-name-enrichment" / "events.jsonl"
    events = _load_events(events_path)
    chat_event = next(event for event in events if event["event_type"] == "chat.message")

    assert chat_event["actor"]["agent_id"] == "agent-1"
    assert chat_event["actor"]["agent_name"] == "Root Agent"


def test_run_metadata_is_only_on_run_lifecycle_events(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)

    tracer = Tracer("metadata-scope")
    set_global_tracer(tracer)
    tracer.log_chat_message("hello", "assistant", "agent-1")
    tracer.save_run_data(mark_complete=True)

    events_path = tmp_path / "strix_runs" / "metadata-scope" / "events.jsonl"
    events = _load_events(events_path)

    run_started = next(event for event in events if event["event_type"] == "run.started")
    run_completed = next(event for event in events if event["event_type"] == "run.completed")
    chat_event = next(event for event in events if event["event_type"] == "chat.message")

    assert "run_metadata" in run_started
    assert "run_metadata" in run_completed
    assert "run_metadata" not in chat_event


def test_default_events_retention_prunes_old_files(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)

    old_events = tmp_path / "strix_runs" / "old-run" / "events.jsonl"
    recent_events = tmp_path / "strix_runs" / "recent-run" / "events.jsonl"
    old_events.parent.mkdir(parents=True, exist_ok=True)
    recent_events.parent.mkdir(parents=True, exist_ok=True)
    old_events.write_text('{"event_type":"old"}\n', encoding="utf-8")
    recent_events.write_text('{"event_type":"recent"}\n', encoding="utf-8")

    now = time.time()
    thirty_one_days = 31 * 24 * 60 * 60
    five_days = 5 * 24 * 60 * 60
    old_ts = now - thirty_one_days
    recent_ts = now - five_days
    old_events.touch()
    recent_events.touch()
    os.utime(old_events, (old_ts, old_ts))
    os.utime(recent_events, (recent_ts, recent_ts))

    tracer = Tracer("retention-default")
    set_global_tracer(tracer)

    assert not old_events.exists()
    assert recent_events.exists()


def test_events_retention_can_be_disabled(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("STRIX_EVENTS_RETENTION_DAYS", "0")

    old_events = tmp_path / "strix_runs" / "old-run" / "events.jsonl"
    old_events.parent.mkdir(parents=True, exist_ok=True)
    old_events.write_text('{"event_type":"old"}\n', encoding="utf-8")
    old_ts = time.time() - (90 * 24 * 60 * 60)
    os.utime(old_events, (old_ts, old_ts))

    tracer = Tracer("retention-disabled")
    set_global_tracer(tracer)

    assert old_events.exists()

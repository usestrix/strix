import json
import sys
import types
from pathlib import Path
from typing import Any, ClassVar

import pytest
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExportResult

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer


def _load_events(events_path: Path) -> list[dict[str, Any]]:
    lines = events_path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line]


@pytest.fixture(autouse=True)
def _reset_tracer_globals(monkeypatch) -> None:
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
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
    assert not any(event["event_type"] == "traffic.intercepted" for event in events)

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
    assert "strix.run_id" not in init_kwargs["resource_attributes"]
    assert "strix.run_name" not in init_kwargs["resource_attributes"]

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


def test_otlp_fallback_includes_auth_and_custom_headers(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "Traceloop", None)
    monkeypatch.setenv("TRACELOOP_BASE_URL", "https://otel.example.com")
    monkeypatch.setenv("TRACELOOP_API_KEY", "test-api-key")
    monkeypatch.setenv("TRACELOOP_HEADERS", '{"x-custom":"header"}')

    captured: dict[str, Any] = {}

    class FakeOTLPSpanExporter:
        def __init__(self, endpoint: str, headers: dict[str, str] | None = None, **kwargs: Any):
            captured["endpoint"] = endpoint
            captured["headers"] = headers or {}
            captured["kwargs"] = kwargs

        def export(self, spans: Any) -> SpanExportResult:  # noqa: ARG002
            return SpanExportResult.SUCCESS

        def shutdown(self) -> None:
            return None

        def force_flush(self, timeout_millis: int = 30_000) -> bool:  # noqa: ARG002
            return True

    fake_module = types.ModuleType("opentelemetry.exporter.otlp.proto.http.trace_exporter")
    fake_module.OTLPSpanExporter = FakeOTLPSpanExporter
    monkeypatch.setitem(
        sys.modules,
        "opentelemetry.exporter.otlp.proto.http.trace_exporter",
        fake_module,
    )

    tracer = Tracer("otlp-fallback")
    set_global_tracer(tracer)

    assert tracer._remote_export_enabled is True
    assert captured["endpoint"] == "https://otel.example.com/v1/traces"
    assert captured["headers"]["Authorization"] == "Bearer test-api-key"
    assert captured["headers"]["x-custom"] == "header"


def test_traceloop_init_failure_does_not_mark_bootstrapped_on_provider_failure(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.chdir(tmp_path)

    class FakeTraceloop:
        @staticmethod
        def init(**kwargs: Any) -> None:  # noqa: ARG004
            raise RuntimeError("traceloop init failed")

        @staticmethod
        def set_association_properties(properties: dict[str, Any]) -> None:  # noqa: ARG004
            return None

    monkeypatch.setattr(tracer_module, "Traceloop", FakeTraceloop)

    def _raise_provider_error(provider: Any) -> None:
        raise RuntimeError("provider setup failed")

    monkeypatch.setattr(tracer_module.trace, "set_tracer_provider", _raise_provider_error)

    tracer = Tracer("bootstrap-failure")
    set_global_tracer(tracer)

    assert tracer_module._OTEL_BOOTSTRAPPED is False
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


def test_set_run_name_resets_cached_paths(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)

    tracer = Tracer()
    set_global_tracer(tracer)
    old_events_path = tracer.events_file_path

    tracer.set_run_name("renamed-run")
    tracer.log_chat_message("hello", "assistant", "agent-1")

    new_events_path = tracer.events_file_path
    assert new_events_path != old_events_path
    assert new_events_path == tmp_path / "strix_runs" / "renamed-run" / "events.jsonl"

    events = _load_events(new_events_path)
    assert any(event["event_type"] == "run.started" for event in events)
    assert any(event["event_type"] == "chat.message" for event in events)


def test_set_run_name_resets_run_completed_flag(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)

    tracer = Tracer()
    set_global_tracer(tracer)

    tracer.save_run_data(mark_complete=True)
    tracer.set_run_name("renamed-complete")
    tracer.save_run_data(mark_complete=True)

    events_path = tmp_path / "strix_runs" / "renamed-complete" / "events.jsonl"
    events = _load_events(events_path)
    run_completed = [event for event in events if event["event_type"] == "run.completed"]

    assert any(event["event_type"] == "run.started" for event in events)
    assert len(run_completed) == 1


def test_set_run_name_updates_traceloop_association_properties(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)

    class FakeTraceloop:
        associations: ClassVar[list[dict[str, Any]]] = []

        @staticmethod
        def init(**kwargs: Any) -> None:  # noqa: ARG004
            return None

        @staticmethod
        def set_association_properties(properties: dict[str, Any]) -> None:
            FakeTraceloop.associations.append(properties)

    monkeypatch.setattr(tracer_module, "Traceloop", FakeTraceloop)

    tracer = Tracer()
    set_global_tracer(tracer)
    tracer.set_run_name("renamed-run")

    assert FakeTraceloop.associations
    assert FakeTraceloop.associations[-1]["run_id"] == "renamed-run"
    assert FakeTraceloop.associations[-1]["run_name"] == "renamed-run"


def test_events_write_locks_are_scoped_by_events_file(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("STRIX_TELEMETRY", "0")

    tracer_one = Tracer("lock-run-a")
    tracer_two = Tracer("lock-run-b")

    lock_a_from_one = tracer_one._get_events_write_lock(tracer_one.events_file_path)
    lock_a_from_two = tracer_two._get_events_write_lock(tracer_one.events_file_path)
    lock_b = tracer_two._get_events_write_lock(tracer_two.events_file_path)

    assert lock_a_from_one is lock_a_from_two
    assert lock_a_from_one is not lock_b


def test_tracer_skips_jsonl_when_telemetry_disabled(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("STRIX_TELEMETRY", "0")

    tracer = Tracer("telemetry-disabled")
    set_global_tracer(tracer)
    tracer.log_chat_message("hello", "assistant", "agent-1")
    tracer.save_run_data(mark_complete=True)

    events_path = tmp_path / "strix_runs" / "telemetry-disabled" / "events.jsonl"
    assert not events_path.exists()


def test_tracer_otel_flag_overrides_global_telemetry(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.setenv("STRIX_OTEL_TELEMETRY", "1")

    tracer = Tracer("otel-enabled")
    set_global_tracer(tracer)
    tracer.log_chat_message("hello", "assistant", "agent-1")
    tracer.save_run_data(mark_complete=True)

    events_path = tmp_path / "strix_runs" / "otel-enabled" / "events.jsonl"
    assert events_path.exists()

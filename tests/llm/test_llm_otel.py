import threading

import litellm

from strix.llm import llm as llm_module
from strix.llm.config import LLMConfig
from strix.llm.llm import LLM
from strix.telemetry import tracer as tracer_module


def test_llm_adds_otel_callback_without_clobbering_existing(monkeypatch) -> None:
    monkeypatch.setattr(litellm, "callbacks", ["custom-callback"])

    llm = LLM(LLMConfig(model_name="openai/gpt-5"), agent_name=None)

    assert llm is not None
    assert "custom-callback" in litellm.callbacks
    assert "otel" in litellm.callbacks
    assert litellm.callbacks.count("otel") == 1


def test_llm_skips_otel_callback_when_telemetry_disabled(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.setattr(litellm, "callbacks", ["custom-callback"])

    llm = LLM(LLMConfig(model_name="openai/gpt-5"), agent_name=None)

    assert llm is not None
    assert "custom-callback" in litellm.callbacks
    assert "otel" not in litellm.callbacks


def test_llm_trace_metadata_contains_run_and_agent_context(monkeypatch) -> None:
    class FakeTracer:
        run_id = "run-1234"
        run_name = "test-run"

    monkeypatch.setattr(tracer_module, "get_global_tracer", lambda: FakeTracer())
    monkeypatch.setattr(litellm, "callbacks", [])

    llm = LLM(LLMConfig(model_name="openai/gpt-5"), agent_name="Root Agent")
    llm.set_agent_identity("Root Agent", "agent-1")

    metadata = llm._build_trace_metadata()

    assert metadata["strix_run_id"] == "run-1234"
    assert metadata["strix_run_name"] == "test-run"
    assert metadata["strix_agent_name"] == "Root Agent"
    assert metadata["strix_agent_id"] == "agent-1"


def test_llm_otel_callback_registration_is_thread_safe(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_TELEMETRY", "1")
    monkeypatch.setattr(litellm, "callbacks", [])

    threads = [
        threading.Thread(target=llm_module._ensure_litellm_otel_callback) for _ in range(20)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert litellm.callbacks.count("otel") == 1

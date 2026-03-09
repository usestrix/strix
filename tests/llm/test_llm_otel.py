import litellm

from strix.llm.config import LLMConfig
from strix.llm.llm import LLM
from strix.telemetry import tracer as tracer_module


def test_llm_does_not_modify_litellm_callbacks(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_TELEMETRY", "1")
    monkeypatch.setenv("STRIX_OTEL_TELEMETRY", "1")
    monkeypatch.setattr(litellm, "callbacks", ["custom-callback"])

    llm = LLM(LLMConfig(model_name="openai/gpt-5"), agent_name=None)

    assert llm is not None
    assert litellm.callbacks == ["custom-callback"]


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

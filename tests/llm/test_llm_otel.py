import litellm
import pytest

from strix.llm.config import LLMConfig
from strix.llm.llm import LLM


def test_llm_does_not_modify_litellm_callbacks(
    monkeypatch: pytest.MonkeyPatch,
    write_config,
) -> None:
    write_config({"telemetry": {"enabled": True, "otel_enabled": True}})
    monkeypatch.setattr(litellm, "callbacks", ["custom-callback"])

    llm = LLM(LLMConfig(model_name="openai/gpt-5.4"), agent_name=None)

    assert llm is not None
    assert litellm.callbacks == ["custom-callback"]

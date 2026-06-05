"""Integration tests for MiniMax provider.

These tests verify end-to-end MiniMax integration by making real API calls.
They require MINIMAX_API_KEY to be set in the environment.
"""

import os

import pytest

from strix.llm.config import LLMConfig
from strix.llm.llm import LLM


pytestmark = pytest.mark.skipif(
    not os.environ.get("MINIMAX_API_KEY"),
    reason="MINIMAX_API_KEY not set",
)


@pytest.fixture()
def minimax_llm(monkeypatch: pytest.MonkeyPatch) -> LLM:
    """Create an LLM instance configured for MiniMax."""
    monkeypatch.setenv("STRIX_LLM", "openai/MiniMax-M3")
    monkeypatch.setenv("LLM_API_KEY", os.environ.get("MINIMAX_API_KEY", ""))
    monkeypatch.setenv("LLM_API_BASE", "https://api.minimax.io/v1")
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    config = LLMConfig()
    return LLM(config, agent_name=None)


@pytest.mark.asyncio()
async def test_minimax_basic_completion(minimax_llm: LLM):
    """Test that MiniMax can complete a simple prompt."""
    messages = [{"role": "user", "content": "Reply with exactly: hello"}]
    responses = []
    async for response in minimax_llm.generate(messages):
        responses.append(response)

    assert len(responses) > 0
    final = responses[-1]
    assert final.content
    assert "hello" in final.content.lower()


@pytest.mark.asyncio()
async def test_minimax_streaming(minimax_llm: LLM):
    """Test that MiniMax streaming produces incremental responses."""
    messages = [{"role": "user", "content": "Count from 1 to 3, one number per line."}]
    responses = []
    async for response in minimax_llm.generate(messages):
        responses.append(response)

    # Streaming should produce multiple intermediate responses
    assert len(responses) >= 2
    final = responses[-1]
    assert "1" in final.content
    assert "2" in final.content
    assert "3" in final.content


@pytest.mark.asyncio()
async def test_minimax_config_auto_detection():
    """Test that MINIMAX_API_KEY auto-detection works end-to-end."""
    api_key = os.environ.get("MINIMAX_API_KEY", "")
    orig_llm_key = os.environ.pop("LLM_API_KEY", None)
    orig_llm_base = os.environ.pop("LLM_API_BASE", None)
    os.environ["STRIX_LLM"] = "openai/MiniMax-M3"

    try:
        config = LLMConfig()
        assert config.api_key == api_key
        assert config.api_base == "https://api.minimax.io/v1"
    finally:
        if orig_llm_key is not None:
            os.environ["LLM_API_KEY"] = orig_llm_key
        if orig_llm_base is not None:
            os.environ["LLM_API_BASE"] = orig_llm_base

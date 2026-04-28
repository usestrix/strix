"""Tests for LLM._prepare_messages trailing-assistant-message handling."""
from strix.llm.config import LLMConfig
from strix.llm.llm import LLM


def _make_llm(monkeypatch, model_name: str, interactive: bool) -> LLM:
    monkeypatch.setenv("STRIX_LLM", model_name)
    config = LLMConfig(model_name=model_name, interactive=interactive, enable_prompt_caching=False)
    return LLM(config, agent_name=None)


def _history_ending_with_assistant() -> list[dict]:
    return [
        {"role": "user", "content": "Scan this target."},
        {"role": "assistant", "content": "I found a vulnerability."},
    ]


def test_non_interactive_anthropic_adds_user_message(monkeypatch) -> None:
    """Non-interactive mode always appends a user message when history ends with assistant."""
    llm = _make_llm(monkeypatch, "claude-sonnet-4-6", interactive=False)
    history = _history_ending_with_assistant()
    messages = llm._prepare_messages(history)
    assert messages[-1]["role"] == "user"
    assert messages[-1]["content"] == "<meta>Continue the task.</meta>"


def test_interactive_anthropic_adds_user_message(monkeypatch) -> None:
    """Interactive mode with Anthropic model must also append a user message.

    Anthropic API rejects messages where the last entry has role 'assistant'
    (no assistant prefill support). This should hold regardless of interactive mode.
    """
    llm = _make_llm(monkeypatch, "claude-sonnet-4-6", interactive=True)
    history = _history_ending_with_assistant()
    messages = llm._prepare_messages(history)
    assert messages[-1]["role"] == "user"
    assert messages[-1]["content"] == "<meta>Continue the task.</meta>"


def test_interactive_non_anthropic_does_not_add_user_message(monkeypatch) -> None:
    """Interactive mode with a non-Anthropic model keeps the trailing assistant message.

    Non-Anthropic models may support assistant prefill; in interactive mode the
    caller (TUI) is responsible for appending the next user message.
    """
    llm = _make_llm(monkeypatch, "openai/gpt-5.4", interactive=True)
    history = _history_ending_with_assistant()
    messages = llm._prepare_messages(history)
    assert messages[-1]["role"] == "assistant"

from typing import Any

import pytest

from strix.llm import memory_compressor
from strix.llm.memory_compressor import MemoryCompressor


def _message(index: int) -> dict[str, str]:
    return {"role": "user", "content": f"message {index} " + ("x" * 200)}


def test_summarizer_disables_litellm_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class Message:
        content = "summary"

    class Choice:
        message = Message()

    class Response:
        choices = [Choice()]

    def fake_completion(**kwargs: Any) -> Response:
        captured.update(kwargs)
        return Response()

    monkeypatch.setattr(memory_compressor.litellm, "completion", fake_completion)
    monkeypatch.setattr(
        memory_compressor,
        "resolve_llm_config",
        lambda: ("openai/gpt-5.4", "test-key", None),
    )

    summary = memory_compressor._summarize_messages([_message(1)], "openai/gpt-5.4", 5)

    assert captured["num_retries"] == 0
    assert captured["timeout"] == 5
    assert "summary" in summary["content"]


def test_summarizer_uses_local_fallback_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_completion(**_: Any) -> None:
        raise TimeoutError("request timed out")

    monkeypatch.setattr(memory_compressor.litellm, "completion", fake_completion)
    monkeypatch.setattr(
        memory_compressor,
        "resolve_llm_config",
        lambda: ("openai/gpt-5.4", "test-key", None),
    )

    summary = memory_compressor._summarize_messages([_message(i) for i in range(20)], "m", 1)

    assert "fallback='true'" in summary["content"]
    assert "LLM summarization failed" in summary["content"]
    assert "message 0" in summary["content"]
    assert "message 19" in summary["content"]
    assert "middle message(s) omitted" in summary["content"]


def test_compress_history_falls_back_without_returning_raw_old_messages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(memory_compressor, "MAX_TOTAL_TOKENS", 10)
    monkeypatch.setattr(memory_compressor, "MIN_RECENT_MESSAGES", 2)
    monkeypatch.setattr(memory_compressor, "get_message_tokens", lambda *_: 100)
    monkeypatch.setattr(
        memory_compressor,
        "_summarize_messages",
        lambda messages, *_: {
            "role": "user",
            "content": (
                f"<context_summary fallback='true'>compressed {len(messages)} messages"
                "</context_summary>"
            ),
        },
    )
    monkeypatch.setenv("STRIX_LLM", "openai/gpt-5.4")

    messages = [_message(i) for i in range(8)]
    compressed = MemoryCompressor(timeout=1).compress_history(messages)

    assert any("compressed 6 messages" in msg["content"] for msg in compressed)
    assert compressed[-2:] == messages[-2:]

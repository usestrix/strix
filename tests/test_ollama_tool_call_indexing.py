"""Tests for the Ollama chat stream's tool-call indexing."""

from __future__ import annotations

from typing import Any

from litellm.types.utils import LlmProviders
from litellm.utils import ProviderConfigManager

from strix.config.models import _install_ollama_tool_call_indexing


def _stream_iterator() -> Any:
    _install_ollama_tool_call_indexing()
    # Resolve the config the way LiteLLM does, so the override is proven
    # reachable through provider resolution.
    config = ProviderConfigManager.get_provider_chat_config(
        model="glm-5.3:cloud", provider=LlmProviders.OLLAMA_CHAT
    )
    assert config is not None
    assert type(config).__name__ == "_StrixOllamaChatConfig"
    return config.get_model_response_iterator(streaming_response=iter([]), sync_stream=True)


def _tool_call(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    # Ollama's shape: the position is in function.index, and is 0 for every call.
    return {"id": f"call_{name}", "function": {"index": 0, "name": name, "arguments": arguments}}


def _chunk(*tool_calls: dict[str, Any], done: bool = False) -> dict[str, Any]:
    return {
        "model": "glm-5.3:cloud",
        "created_at": "2026-10-04T10:12:40Z",
        "message": {"role": "assistant", "content": "", "tool_calls": list(tool_calls)},
        "done": done,
    }


def _indexed(stream: Any) -> list[tuple[int, str]]:
    return [(call.index, call.function.name) for call in stream.choices[0].delta.tool_calls]


def test_parallel_tool_calls_in_one_chunk_get_distinct_indexes() -> None:
    iterator = _stream_iterator()

    stream = iterator.chunk_parser(
        _chunk(
            _tool_call("get_threat_model", {"target": "/workspace/src"}),
            _tool_call("list_notes", {"include_content": True}),
            _tool_call("exec_command", {"cmd": "ls -la /workspace/src"}),
        )
    )

    assert _indexed(stream) == [(0, "get_threat_model"), (1, "list_notes"), (2, "exec_command")]


def test_tool_calls_across_chunks_keep_counting() -> None:
    # Ollama's own shape for parallel calls; stock LiteLLM gives both index 0.
    iterator = _stream_iterator()

    first = iterator.chunk_parser(_chunk(_tool_call("list_notes", {"include_content": False})))
    second = iterator.chunk_parser(
        _chunk(_tool_call("exec_command", {"cmd": "ls -la /workspace"}), done=True)
    )

    assert _indexed(first) == [(0, "list_notes")]
    assert _indexed(second) == [(1, "exec_command")]


def test_each_stream_counts_from_zero() -> None:
    _stream_iterator().chunk_parser(_chunk(_tool_call("list_notes", {})))

    stream = _stream_iterator().chunk_parser(_chunk(_tool_call("exec_command", {"cmd": "id"})))

    assert _indexed(stream) == [(0, "exec_command")]

"""Bridge translation, exercised against recorded ``claude -p`` transcripts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import ClassVar

import pytest

from strix.config import claude_bridge


FIXTURES = Path(__file__).parent / "fixtures" / "claude_code"


def _decode(name: str) -> object:
    lines = (FIXTURES / name).read_text(encoding="utf-8").splitlines()
    return claude_bridge.decode_result(claude_bridge.parse_transcript(lines))


def test_decode_simple_text() -> None:
    response = _decode("simple_text.jsonl")
    assert len(response.output) == 1
    message = response.output[0]
    assert message.type == "message"
    assert message.content[0].text.startswith("Reconnaissance complete")
    assert response.usage.input_tokens == 1200
    assert response.usage.output_tokens == 45
    assert response.usage.total_tokens == 1245
    assert response.usage.input_tokens_details.cached_tokens == 29225
    assert response.usage.input_tokens_details.cache_write_tokens == 24303


def test_decode_tool_request() -> None:
    response = _decode("tool_request.jsonl")
    calls = [item for item in response.output if getattr(item, "type", None) == "function_call"]
    assert [c.name for c in calls] == ["shell", "browser"]
    assert json.loads(calls[0].arguments) == {"command": "nmap -sV 10.0.0.1"}
    # Every emitted call gets a stable id shared between id and call_id.
    assert calls[0].call_id == calls[0].id
    assert calls[0].call_id != calls[1].call_id


def test_decode_skips_non_json_lines() -> None:
    response = _decode("noisy.jsonl")
    assert response.output[0].content[0].text == "done"


def test_decode_rate_limit_raises_retryable() -> None:
    with pytest.raises(claude_bridge.ClaudeStreamError) as excinfo:
        _decode("error_ratelimit.jsonl")
    assert excinfo.value.status_code == 429


def test_missing_result_line_raises() -> None:
    with pytest.raises(claude_bridge.ClaudeStreamError):
        claude_bridge.parse_transcript(['{"type": "system", "subtype": "init"}'])


def test_error_status_inferred_from_message() -> None:
    result = {"is_error": True, "result": "API Error: Overloaded, please retry"}
    with pytest.raises(claude_bridge.ClaudeStreamError) as excinfo:
        claude_bridge.decode_result(result)
    assert excinfo.value.status_code == 529


def test_structured_output_falls_back_to_result_string() -> None:
    result = {
        "type": "result",
        "is_error": False,
        "result": '{"text": "hi", "tool_calls": []}',
        "usage": {"input_tokens": 5, "output_tokens": 1},
    }
    response = claude_bridge.decode_result(result)
    assert response.output[0].content[0].text == "hi"


def test_mcp_prefixed_tool_names_are_stripped() -> None:
    result = {
        "is_error": False,
        "structured_output": {
            "text": "",
            "tool_calls": [{"name": "mcp__strix__shell", "arguments": {"command": "ls"}}],
        },
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }
    response = claude_bridge.decode_result(result)
    calls = [i for i in response.output if getattr(i, "type", None) == "function_call"]
    assert calls[0].name == "shell"


class _FakeTool:
    name = "shell"
    description = "Run a shell command in the sandbox"
    params_json_schema: ClassVar[dict] = {
        "type": "object",
        "properties": {"command": {"type": "string"}},
    }


def test_build_prompt_includes_history_tools_and_task() -> None:
    prompt = claude_bridge.build_prompt(
        "You are a pentester.",
        [
            {"role": "user", "content": "scan the target"},
            {"type": "function_call", "name": "shell", "arguments": '{"command": "nmap x"}'},
            {"type": "function_call_output", "call_id": "c1", "output": "22/tcp open"},
        ],
        [_FakeTool()],
    )
    assert "You are a pentester." in prompt
    assert "shell" in prompt
    assert "scan the target" in prompt
    assert "nmap x" in prompt
    assert "22/tcp open" in prompt
    assert "tool_calls" in prompt  # the task instruction naming the reply shape


def test_build_prompt_string_input() -> None:
    prompt = claude_bridge.build_prompt(None, "just a string", [])
    assert "just a string" in prompt

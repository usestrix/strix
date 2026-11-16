"""Tests for what a child agent inherits from its parent."""

from __future__ import annotations

from strix.tools.agents_graph.tools import create_agent, inheritable_history


def test_inheritable_history_drops_reasoning_items() -> None:
    message = {"role": "user", "content": "scan the repo"}
    call = {"type": "function_call", "name": "read_file", "arguments": "{}"}
    reasoning = {
        "type": "reasoning",
        "provider_data": {"thinking_blocks": [{"type": "redacted_thinking", "data": "x" * 1000}]},
    }

    assert inheritable_history([message, reasoning, call, reasoning]) == [message, call]


def test_inheritable_history_handles_empty_input() -> None:
    assert inheritable_history(None) == []
    assert inheritable_history([]) == []


def test_create_agent_does_not_inherit_context_by_default() -> None:
    schema = create_agent.params_json_schema["properties"]["inherit_context"]

    assert schema["default"] is False
    assert "Default ``False``" in schema["description"]

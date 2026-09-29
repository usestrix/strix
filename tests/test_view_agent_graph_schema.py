"""Groq rejects a no-argument tool schema that lists ``required`` without properties.

``view_agent_graph`` takes only the run context, so its generated schema is an
empty object. Groq's validator fails that shape with ``required is present but
properties is missing`` and drops the whole request. The published schema must
omit that pair without turning strict validation off for tools that do take
arguments.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any, cast

import pytest
from agents.models.chatcmpl_converter import Converter
from agents.tool import FunctionTool
from agents.tool_context import ToolContext

from strix.agents.factory import build_strix_agent
from strix.core.agents import AgentCoordinator
from strix.tools.agents_graph.tools import (
    _groq_compatible_empty_object_schema,
    send_message_to_agent,
    view_agent_graph,
)


def test_view_agent_graph_schema_omits_empty_required_and_properties() -> None:
    schema = view_agent_graph.params_json_schema

    assert view_agent_graph.strict_json_schema is True
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert "required" not in schema
    assert "properties" not in schema


def test_published_chat_completions_schema_has_no_empty_required() -> None:
    """The schema Groq receives is the chat-completions function parameters."""
    parameters = Converter.tool_to_openai(view_agent_graph)["function"]["parameters"]

    assert parameters["type"] == "object"
    assert parameters["additionalProperties"] is False
    assert "required" not in parameters
    assert "properties" not in parameters
    assert Converter.tool_to_openai(view_agent_graph)["function"]["strict"] is True


def test_argument_tools_keep_required_properties() -> None:
    schema = send_message_to_agent.params_json_schema

    assert send_message_to_agent.strict_json_schema is True
    assert "target_agent_id" in schema["properties"]
    assert "target_agent_id" in schema["required"]
    assert "message" in schema["required"]


def test_groq_schema_fix_does_not_strip_declared_parameters() -> None:
    original = {
        "type": "object",
        "properties": {"target_agent_id": {"type": "string"}},
        "required": ["target_agent_id"],
        "additionalProperties": False,
    }

    assert _groq_compatible_empty_object_schema(original) == original
    # A required list with no properties is not the empty no-arg shape; leave
    # it alone rather than dropping a constraint this helper does not own.
    mismatched = {"type": "object", "required": ["target_agent_id"]}
    assert _groq_compatible_empty_object_schema(mismatched) is mismatched


def test_agent_copy_keeps_the_groq_compatible_schema() -> None:
    agent = build_strix_agent(is_root=True)
    tool = next(t for t in agent.tools if t.name == "view_agent_graph")
    assert isinstance(tool, FunctionTool)

    assert tool.strict_json_schema is True
    assert "required" not in tool.params_json_schema
    assert "properties" not in tool.params_json_schema
    # Disabling strict for another route copies the tool; that copy must not
    # reintroduce the rejected empty required/properties pair.
    copied = dataclasses.replace(tool, strict_json_schema=False)
    assert "required" not in copied.params_json_schema
    assert "properties" not in copied.params_json_schema


@pytest.mark.asyncio
async def test_view_agent_graph_still_returns_the_tree() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "Validator", parent_id="root")
    ctx = ToolContext(
        context={"coordinator": coordinator, "agent_id": "root"},
        tool_name=view_agent_graph.name,
        tool_call_id="call-1",
        tool_arguments="{}",
    )

    result = cast("dict[str, Any]", json.loads(await view_agent_graph.on_invoke_tool(ctx, "{}")))

    assert result["success"] is True
    assert "strix (root)" in result["graph_structure"]
    assert "Validator (child)" in result["graph_structure"]
    assert "← you" in result["graph_structure"]
    assert result["summary"]["total"] == 2

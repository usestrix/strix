"""Tests for scan-agent tool registration in factory."""

from __future__ import annotations

import pytest
from agents.tool import FunctionTool

from strix.agents import factory


def _tool(name: str) -> FunctionTool:
    return FunctionTool(
        name=name,
        description="test tool",
        params_json_schema={"type": "object", "properties": {}, "additionalProperties": False},
        on_invoke_tool=lambda _ctx, _inp: "ok",
    )


@pytest.fixture(autouse=True)
def _reset_registry() -> object:
    saved = list(factory._EXTRA_TOOLS)
    factory._EXTRA_TOOLS.clear()
    try:
        yield
    finally:
        factory._EXTRA_TOOLS[:] = saved


def test_register_agent_tools_is_deduped() -> None:
    tool = _tool("dup")
    factory.register_agent_tools(tool)
    factory.register_agent_tools(tool)
    assert factory.registered_agent_tools() == (tool,)


def test_registered_tools_appear_before_lifecycle_tool() -> None:
    tool = _tool("extra")
    factory.register_agent_tools(tool)

    root = factory.build_strix_agent(is_root=True)
    child = factory.build_strix_agent(is_root=False)

    root_names = [t.name for t in root.tools]
    child_names = [t.name for t in child.tools]

    assert root_names[-2:] == ["extra", "finish_scan"]
    assert child_names[-2:] == ["extra", "agent_finish"]


def test_per_call_extra_tools_stack_with_registry() -> None:
    factory.register_agent_tools(_tool("registered"))

    agent = factory.build_strix_agent(is_root=True, extra_tools=[_tool("per_call")])
    names = [t.name for t in agent.tools]

    assert "registered" in names
    assert "per_call" in names
    assert names[-1] == "finish_scan"


def test_register_agent_tools_rejects_duplicate_names() -> None:
    factory.register_agent_tools(_tool("same_name"))

    with pytest.raises(ValueError, match="same_name"):
        factory.register_agent_tools(_tool("same_name"))


def test_per_call_extra_tools_reject_duplicate_registered_names() -> None:
    factory.register_agent_tools(_tool("same_name"))

    with pytest.raises(ValueError, match="same_name"):
        factory.build_strix_agent(is_root=True, extra_tools=[_tool("same_name")])


def test_instructions_override_is_used_verbatim() -> None:
    custom = "You are a scan agent. Follow the provided scope."

    agent = factory.build_strix_agent(is_root=True, instructions_override=custom)

    assert agent.instructions == custom


def test_no_override_renders_builtin_prompt() -> None:
    agent = factory.build_strix_agent(is_root=True)

    assert isinstance(agent.instructions, str)
    assert agent.instructions != ""

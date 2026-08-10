"""Tests for scan-agent tool registration in factory."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from agents.tool import FunctionTool

from strix.agents import factory
from strix.config import loader


if TYPE_CHECKING:
    from collections.abc import Iterator

    from agents.tool_context import ToolContext


def _tool(name: str) -> FunctionTool:
    # A per-tool closure keeps two same-named tools unequal, which is what the
    # duplicate-name tests exercise.
    async def invoke(_ctx: ToolContext[Any], _input: str) -> str:
        return "ok"

    return FunctionTool(
        name=name,
        description="test tool",
        params_json_schema={"type": "object", "properties": {}, "additionalProperties": False},
        on_invoke_tool=invoke,
    )


@pytest.fixture(autouse=True)
def _reset_registry() -> object:
    saved = list(factory._EXTRA_TOOLS)
    factory._EXTRA_TOOLS.clear()
    try:
        yield
    finally:
        factory._EXTRA_TOOLS[:] = saved


@pytest.fixture
def _bedrock_claude_model(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Point STRIX_LLM at a Bedrock Claude route for the duration of a test."""
    monkeypatch.setenv("STRIX_LLM", "bedrock/anthropic.claude-4-6-sonnet")
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(loader, "_override", None)
    yield
    monkeypatch.setattr(loader, "_cached", None)


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


def test_respond_to_user_is_interactive_only() -> None:
    """Yielding to the user is meaningless when no user is attached."""
    interactive = factory.build_strix_agent(is_root=True, interactive=True)
    autonomous = factory.build_strix_agent(is_root=True, interactive=False)

    assert "respond_to_user" in [t.name for t in interactive.tools]
    assert "respond_to_user" not in [t.name for t in autonomous.tools]


def test_wait_for_agents_is_available_in_both_modes() -> None:
    for interactive in (True, False):
        agent = factory.build_strix_agent(is_root=True, interactive=interactive)
        assert "wait_for_agents" in [t.name for t in agent.tools]


def test_bedrock_claude_disables_strict_schema_past_the_tool_cap(
    _bedrock_claude_model: None,
) -> None:
    """Bedrock's Converse API 400s a request with >20 strict-schema tools.

    ``_BASE_TOOLS`` alone is already past 20, so every Bedrock Claude agent
    must drop strict mode on every tool, not just the ones past #20 (Bedrock
    rejects the whole request, not a subset of tools).
    """
    agent = factory.build_strix_agent(is_root=True)

    assert len(agent.tools) > 20
    function_tools = [t for t in agent.tools if isinstance(t, FunctionTool)]
    assert function_tools
    assert all(not t.strict_json_schema for t in function_tools)


def test_non_bedrock_model_keeps_default_strict_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_LLM", "anthropic/claude-4-6-sonnet")
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(loader, "_override", None)

    agent = factory.build_strix_agent(is_root=True)

    function_tools = [t for t in agent.tools if isinstance(t, FunctionTool)]
    assert any(t.strict_json_schema for t in function_tools)


def test_bedrock_claude_under_the_cap_keeps_strict_schema(
    monkeypatch: pytest.MonkeyPatch,
    _bedrock_claude_model: None,
) -> None:
    """A tool set at/under the cap should keep the SDK's strict-mode default."""
    monkeypatch.setattr(factory, "_BASE_TOOLS", (_tool("only_base"),))

    agent = factory.build_strix_agent(is_root=True)

    assert len(agent.tools) <= 20
    function_tools = [t for t in agent.tools if isinstance(t, FunctionTool)]
    assert any(t.strict_json_schema for t in function_tools)


def test_disabling_strict_schema_does_not_leak_across_builds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Bedrock build must not mutate the shared tool singletons.

    ``_BASE_TOOLS``/``_EXTRA_TOOLS`` entries are the same objects reused by
    every ``build_strix_agent`` call; if a Bedrock build flipped
    ``strict_json_schema`` in place, a later non-Bedrock build in the same
    process would incorrectly inherit non-strict tools.
    """
    originally_strict = {
        tool.name
        for tool in factory._BASE_TOOLS
        if isinstance(tool, FunctionTool) and tool.strict_json_schema
    }
    assert originally_strict, "expected at least one strict tool in _BASE_TOOLS to test against"

    monkeypatch.setenv("STRIX_LLM", "bedrock/anthropic.claude-4-6-sonnet")
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(loader, "_override", None)
    bedrock_agent = factory.build_strix_agent(is_root=True)
    bedrock_tools = [t for t in bedrock_agent.tools if isinstance(t, FunctionTool)]
    assert all(not t.strict_json_schema for t in bedrock_tools)

    monkeypatch.setenv("STRIX_LLM", "anthropic/claude-4-6-sonnet")
    monkeypatch.setattr(loader, "_cached", None)
    non_bedrock_agent = factory.build_strix_agent(is_root=True)
    non_bedrock_tools = {t.name: t for t in non_bedrock_agent.tools if isinstance(t, FunctionTool)}
    assert all(non_bedrock_tools[name].strict_json_schema for name in originally_strict)

    for shared in factory._BASE_TOOLS:
        if isinstance(shared, FunctionTool) and shared.name in originally_strict:
            assert shared.strict_json_schema, (
                f"{shared.name} singleton was mutated by the Bedrock build"
            )

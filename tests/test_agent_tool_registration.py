"""Tests for scan-agent tool registration in factory."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from agents.tool import FunctionTool

from strix.agents import factory


if TYPE_CHECKING:
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


def test_root_ends_with_the_given_finish_tool() -> None:
    root = factory.build_strix_agent(is_root=True, finish_tool=_tool("finish_pr_review"))

    root_names = [t.name for t in root.tools]

    assert root_names[-1] == "finish_pr_review"
    assert "finish_scan" not in root_names


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


def test_report_tool_replaces_create_vulnerability_report() -> None:
    for is_root in (True, False):
        agent = factory.build_strix_agent(is_root=is_root, report_tool=_tool("file_pr_finding"))
        names = [t.name for t in agent.tools]
        assert "file_pr_finding" in names
        assert "create_vulnerability_report" not in names
        assert isinstance(agent.instructions, str)
        assert "file_pr_finding" in agent.instructions
        assert "create_vulnerability_report" not in agent.instructions


def _descriptions(tools: list[Any]) -> list[str]:
    return [t.description for t in tools if isinstance(t, FunctionTool)]


def test_coverage_tools_can_be_turned_off() -> None:
    coverage = {"record_coverage", "update_coverage", "list_coverage"}
    for is_root in (True, False):
        on = factory.build_strix_agent(is_root=is_root, is_whitebox=True)
        off = factory.build_strix_agent(is_root=is_root, is_whitebox=True, coverage_tools=False)
        assert coverage <= {t.name for t in on.tools}
        assert not coverage & {t.name for t in off.tools}
        assert isinstance(on.instructions, str)
        assert isinstance(off.instructions, str)
        assert "- COVERAGE" in on.instructions
        assert "## Recording Closure" in on.instructions
        assert not any(name in off.instructions for name in coverage)
        on_descriptions = "\n".join(_descriptions(on.tools))
        off_descriptions = "\n".join(_descriptions(off.tools))
        if is_root:
            assert "Coverage reconciliation" in on_descriptions
            assert "Coverage reconciliation" not in off_descriptions
        assert not any(name in off_descriptions for name in coverage)

    diff_on = factory.build_strix_agent(is_root=True, is_diff_scoped=True)
    diff_off = factory.build_strix_agent(is_root=True, is_diff_scoped=True, coverage_tools=False)
    assert isinstance(diff_on.instructions, str)
    assert isinstance(diff_off.instructions, str)
    assert "Record coverage per changed component" in diff_on.instructions
    assert "`needs_follow_up` coverage" in diff_on.instructions
    assert "Record coverage per changed component" not in diff_off.instructions
    assert "`needs_follow_up` coverage" not in diff_off.instructions
    assert not any(name in diff_off.instructions for name in coverage)


def test_instructions_override_is_used_verbatim() -> None:
    custom = "You are a scan agent. Follow the provided scope."

    agent = factory.build_strix_agent(is_root=True, instructions_override=custom)

    assert agent.instructions == custom


def test_no_override_renders_builtin_prompt() -> None:
    agent = factory.build_strix_agent(is_root=True)

    assert isinstance(agent.instructions, str)
    assert agent.instructions != ""


def test_wait_for_user_is_interactive_only() -> None:
    """Yielding to the user is meaningless when no user is attached."""
    interactive = factory.build_strix_agent(is_root=True, interactive=True)
    autonomous = factory.build_strix_agent(is_root=True, interactive=False)

    assert "wait_for_user" in [t.name for t in interactive.tools]
    assert "wait_for_user" not in [t.name for t in autonomous.tools]


def test_wait_for_agents_is_available_in_both_modes() -> None:
    for interactive in (True, False):
        agent = factory.build_strix_agent(is_root=True, interactive=interactive)
        assert "wait_for_agents" in [t.name for t in agent.tools]


def test_strict_tool_schemas_can_be_disabled_per_route() -> None:
    """Claude routes cap strict tools; the toolset must be sendable without strict."""
    agent = factory.build_strix_agent(is_root=True, strict_tool_schemas=False)

    function_tools = [t for t in agent.tools if isinstance(t, FunctionTool)]
    assert function_tools
    assert not any(t.strict_json_schema for t in function_tools)


def test_disabling_strict_leaves_shared_tools_untouched() -> None:
    factory.build_strix_agent(is_root=True, strict_tool_schemas=False)
    agent = factory.build_strix_agent(is_root=True)

    assert any(t.strict_json_schema for t in agent.tools if isinstance(t, FunctionTool))


@pytest.mark.parametrize(
    ("tool_name", "output", "completed"),
    [
        ("finish_pr_review", '{"success": true, "review_completed": true}', True),
        ("finish_pr_review", '{"success": false, "error": "agents_still_active"}', False),
        ("finish_scan", '{"success": true, "scan_completed": true}', True),
        ("think", '{"success": true, "review_completed": true}', False),
    ],
)
def test_lifecycle_tool_completed(tool_name: str, output: str, completed: bool) -> None:
    assert factory._lifecycle_tool_completed(tool_name, output) is completed

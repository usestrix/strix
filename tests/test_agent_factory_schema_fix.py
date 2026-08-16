"""Tests for _ensure_properties_in_schema in the agent factory.

Regression test for issue #1088: Groq rejects tool schemas that have a
``required`` key without a corresponding ``properties`` key.  The fix
adds an empty ``properties: {}`` whenever ``required`` is present but
``properties`` is missing.
"""

from __future__ import annotations

from typing import Any

from agents.tool import FunctionTool

from strix.agents import factory


def _make_tool(schema: dict[str, Any]) -> FunctionTool:
    async def invoke(_ctx: Any, _raw_input: str) -> str:
        return "ok"

    return FunctionTool(
        name="test_tool",
        description="test",
        params_json_schema=schema,
        on_invoke_tool=invoke,
    )


class TestEnsurePropertiesInSchema:
    def test_adds_properties_when_required_present_but_missing(self) -> None:
        """Schema with 'required' but no 'properties' gets properties: {} added."""
        tool = _make_tool({"type": "object", "required": []})
        result = factory._ensure_properties_in_schema(tool)

        assert "properties" in result.params_json_schema
        assert result.params_json_schema["properties"] == {}
        assert result.params_json_schema["required"] == []

    def test_adds_properties_when_required_has_items(self) -> None:
        """Schema with non-empty required and no properties still gets fixed."""
        tool = _make_tool({"type": "object", "required": ["name", "value"]})
        result = factory._ensure_properties_in_schema(tool)

        assert "properties" in result.params_json_schema
        assert result.params_json_schema["properties"] == {}

    def test_preserves_existing_properties(self) -> None:
        """Schema that already has 'properties' is left unchanged."""
        schema = {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
            "additionalProperties": False,
        }
        tool = _make_tool(schema)
        result = factory._ensure_properties_in_schema(tool)

        assert result.params_json_schema == schema

    def test_noop_when_neither_required_nor_properties(self) -> None:
        """Schema with neither 'required' nor 'properties' is untouched."""
        schema = {"type": "object"}
        tool = _make_tool(schema)
        result = factory._ensure_properties_in_schema(tool)

        assert "properties" not in result.params_json_schema
        assert "required" not in result.params_json_schema

    def test_noop_when_properties_present_without_required(self) -> None:
        """Schema with 'properties' but no 'required' is not modified by the fix.

        Note: FunctionTool.__post_init__ applies ensure_strict_json_schema which
        may add 'required' and 'additionalProperties'.  Our fix only triggers when
        'required' is present and 'properties' is absent, so a schema that already
        has 'properties' is never touched by _ensure_properties_in_schema.
        """
        tool = _make_tool({"type": "object", "properties": {"opt": {"type": "string"}}})
        # FunctionTool.__post_init__ adds required + additionalProperties
        schema_before = dict(tool.params_json_schema)
        result = factory._ensure_properties_in_schema(tool)

        # The fix should NOT have modified the schema (properties already present)
        assert result.params_json_schema == schema_before

    def test_simulates_view_agent_graph_scenario(self) -> None:
        """Reproduce the exact scenario from issue #1088.

        view_agent_graph takes only ctx: RunContextWrapper, so its
        generated schema may end up with required: [] and no properties.
        """
        # This is what the schema might look like after SDK processing
        # on certain openai-agents / pydantic / litellm version combos
        broken_schema = {
            "type": "object",
            "required": [],
            "additionalProperties": False,
        }
        tool = _make_tool(broken_schema)
        result = factory._ensure_properties_in_schema(tool)

        # After fix: both 'required' and 'properties' are present
        schema = result.params_json_schema
        assert "properties" in schema
        assert "required" in schema
        assert schema["properties"] == {}
        assert schema["required"] == []
        assert schema["additionalProperties"] is False

    def test_other_keys_preserved(self) -> None:
        """All other schema keys are preserved when adding properties."""
        broken_schema = {
            "type": "object",
            "required": [],
            "additionalProperties": False,
            "title": "view_agent_graph_args",
        }
        tool = _make_tool(broken_schema)
        result = factory._ensure_properties_in_schema(tool)

        schema = result.params_json_schema
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False
        assert schema["title"] == "view_agent_graph_args"
        assert schema["properties"] == {}

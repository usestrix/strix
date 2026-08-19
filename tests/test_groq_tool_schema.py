"""Regression tests for issue #1088.

Groq provider: view_agent_graph tool schema (required without properties)
causes 400 BadRequestError, aborts scan.

Groq's strict JSON-schema validator rejects tool parameters that contain
a ``required`` key alongside an empty (or absent) ``properties`` object:

    GroqException - invalid JSON schema for tool view_agent_graph,
    tools[24].function.parameters: 'required' present but 'properties'
    is missing

The ``@function_tool`` decorator generates this shape for every zero-argument
tool (e.g. ``view_agent_graph``)::

    {"type": "object", "properties": {}, "required": [], "additionalProperties": false}

The fix: ``sanitize_tool_schema`` strips ``required``, ``properties``, and
``additionalProperties`` when all three are empty/false, leaving the
provider-agnostic ``{"type": "object"}`` form.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from agents import RunContextWrapper, function_tool
from agents.tool import FunctionTool

from strix.agents.tool_schema import sanitize_tool_schema


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_no_arg_tool() -> FunctionTool:
    """Simulate a @function_tool with no user-visible parameters."""

    @function_tool(timeout=30)
    async def view_agent_graph(ctx: RunContextWrapper) -> str:
        """Print the multi-agent tree."""
        return ""

    return view_agent_graph  # type: ignore[return-value]


def _make_tool_with_args() -> FunctionTool:
    """Simulate a @function_tool with real parameters."""

    @function_tool(timeout=30)
    async def send_message(ctx: RunContextWrapper, target_agent_id: str, message: str) -> str:
        """Send a message to another agent."""
        return ""

    return send_message  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Core regression: empty required/properties must be stripped
# ---------------------------------------------------------------------------


def test_sanitize_removes_empty_required_from_no_arg_tool() -> None:
    """Issue #1088: 'required: []' must be removed so Groq doesn't reject it."""
    tool = _make_no_arg_tool()

    # Confirm the decorator generates the problematic schema
    raw = tool.params_json_schema
    assert isinstance(raw.get("required"), list), (
        "Expected @function_tool to generate a 'required' key for a no-arg tool"
    )

    sanitize_tool_schema(tool)

    schema = tool.params_json_schema
    assert "required" not in schema, (
        "After sanitize_tool_schema, 'required' must be removed from a no-arg "
        "tool schema. Groq rejects schemas where 'required' is present alongside "
        "an empty/absent 'properties' (issue #1088)."
    )


def test_sanitize_removes_empty_properties_from_no_arg_tool() -> None:
    """Issue #1088: 'properties: {}' alongside empty required must be stripped."""
    tool = _make_no_arg_tool()
    sanitize_tool_schema(tool)

    schema = tool.params_json_schema
    # After sanitization the schema should be minimal: just {"type": "object"}
    assert schema.get("type") == "object"
    assert "properties" not in schema, (
        "Empty 'properties' should be stripped along with empty 'required'."
    )


def test_sanitize_removes_additionalproperties_from_no_arg_tool() -> None:
    """Groq may also choke on additionalProperties on an empty schema."""
    tool = _make_no_arg_tool()
    sanitize_tool_schema(tool)

    schema = tool.params_json_schema
    assert "additionalProperties" not in schema, (
        "Redundant 'additionalProperties: false' should be removed from a "
        "no-arg tool schema."
    )


def test_sanitize_resulting_schema_is_minimal_object() -> None:
    """After sanitization, view_agent_graph-style tools emit only {type: object}."""
    tool = _make_no_arg_tool()
    sanitize_tool_schema(tool)

    schema = tool.params_json_schema
    # Only 'type' (and optionally 'title') should remain.
    allowed_keys = {"type", "title"}
    unexpected = set(schema) - allowed_keys
    assert not unexpected, (
        f"Unexpected keys remain in sanitized no-arg tool schema: {unexpected}"
    )


# ---------------------------------------------------------------------------
# Safety: tools WITH parameters must not be modified
# ---------------------------------------------------------------------------


def test_sanitize_does_not_modify_tool_with_parameters() -> None:
    """sanitize_tool_schema must be a no-op for tools that have real params."""
    tool = _make_tool_with_args()
    original_schema = json.loads(json.dumps(tool.params_json_schema))  # deep copy

    sanitize_tool_schema(tool)

    assert tool.params_json_schema == original_schema, (
        "sanitize_tool_schema must not alter schemas that have actual parameters."
    )


def test_sanitize_is_idempotent() -> None:
    """Calling sanitize_tool_schema twice must produce the same result as once."""
    tool = _make_no_arg_tool()
    sanitize_tool_schema(tool)
    schema_after_first = json.loads(json.dumps(tool.params_json_schema))
    sanitize_tool_schema(tool)
    assert tool.params_json_schema == schema_after_first, (
        "sanitize_tool_schema must be idempotent."
    )


# ---------------------------------------------------------------------------
# Integration: the real view_agent_graph schema passes Groq validation rules
# ---------------------------------------------------------------------------


def test_view_agent_graph_schema_valid_for_groq() -> None:
    """Full integration: the real view_agent_graph schema must pass Groq's rules
    after being piped through sanitize_tool_schema.

    Groq's rule: a tool parameters object must NOT have 'required' present
    without non-empty 'properties'.
    """
    # Import the real tool (without docker/runtime deps)
    from agents import RunContextWrapper, function_tool  # noqa: F811 – re-import for clarity

    @function_tool(timeout=30)
    async def view_agent_graph(ctx: RunContextWrapper) -> str:  # type: ignore[no-redef]
        """Print the multi-agent tree."""
        return ""

    sanitize_tool_schema(view_agent_graph)  # type: ignore[arg-type]
    schema: dict[str, Any] = view_agent_graph.params_json_schema  # type: ignore[attr-defined]

    # Groq's rule: if 'required' is present, 'properties' must also be present
    # and non-empty.
    if "required" in schema:
        props = schema.get("properties")
        assert isinstance(props, dict) and props, (
            "Groq validation failure: 'required' is present but 'properties' "
            "is missing or empty. This causes a 400 BadRequestError (issue #1088)."
        )

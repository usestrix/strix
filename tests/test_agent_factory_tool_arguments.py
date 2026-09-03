"""Tests for tool-argument shape coercion in the agent factory."""

from __future__ import annotations

import json
from typing import Any, cast

import pytest
from agents.tool import FunctionTool

from strix.agents import factory
from strix.tools.notes.tools import list_notes
from strix.tools.reporting.tool import list_reports


def _capturing_tool(
    captured: dict[str, str], schema: dict[str, Any], name: str = "probe"
) -> FunctionTool:
    async def invoke(_ctx: Any, raw_input: str) -> str:
        captured["raw_input"] = raw_input
        return "ok"

    return FunctionTool(
        name=name,
        description="test tool",
        params_json_schema={"type": "object", "properties": schema},
        on_invoke_tool=invoke,
    )


async def _roundtrip(
    schema: dict[str, Any], payload: dict[str, Any], name: str = "probe"
) -> dict[str, Any]:
    captured: dict[str, str] = {}
    wrapped = factory._with_coerced_arguments(_capturing_tool(captured, schema, name))
    assert await wrapped.on_invoke_tool(cast("Any", None), json.dumps(payload)) == "ok"
    return cast("dict[str, Any]", json.loads(captured["raw_input"]))


_STRING = {"todos": {"type": "string"}}
_ARRAY = {"tags": {"type": "array", "items": {"type": "string"}}}
_NULLABLE_ARRAY = {
    "tags": {"anyOf": [{"type": "array", "items": {"type": "string"}}, {"type": "null"}]}
}
_OBJECT = {"modifications": {"type": "object"}}


@pytest.mark.asyncio
async def test_structured_value_is_encoded_for_a_string_parameter() -> None:
    parsed = await _roundtrip(_STRING, {"todos": [{"title": "Phase 1: recon"}]})

    assert parsed["todos"] == '[{"title": "Phase 1: recon"}]'


@pytest.mark.asyncio
async def test_string_parameter_keeps_an_already_encoded_value() -> None:
    parsed = await _roundtrip(_STRING, {"todos": '[{"title": "a"}]'})

    assert parsed["todos"] == '[{"title": "a"}]'


@pytest.mark.asyncio
@pytest.mark.parametrize("schema", [_ARRAY, _NULLABLE_ARRAY])
async def test_encoded_list_is_decoded_for_an_array_parameter(schema: dict[str, Any]) -> None:
    parsed = await _roundtrip(schema, {"tags": '["auth", "idor"]'})

    assert parsed["tags"] == ["auth", "idor"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "value",
    [
        "auth, idor",
        "auth\nidor",
        "auth",
        "Endpoint /admin leaks user data, and session tokens never expire",
        '"auth"',
    ],
)
async def test_free_form_strings_are_never_split_into_an_array(value: str) -> None:
    parsed = await _roundtrip(_ARRAY, {"tags": value})

    assert parsed["tags"] == value


@pytest.mark.asyncio
@pytest.mark.parametrize("schema", [_ARRAY, _NULLABLE_ARRAY])
@pytest.mark.parametrize("value", ["", "   "])
async def test_empty_string_becomes_an_empty_array(schema: dict[str, Any], value: str) -> None:
    parsed = await _roundtrip(schema, {"tags": value})

    assert parsed["tags"] == []


@pytest.mark.asyncio
async def test_empty_string_becomes_an_empty_object() -> None:
    parsed = await _roundtrip(_OBJECT, {"modifications": ""})

    assert parsed["modifications"] == {}


@pytest.mark.asyncio
async def test_empty_string_for_a_string_parameter_is_untouched() -> None:
    parsed = await _roundtrip(_STRING, {"todos": ""})

    assert parsed["todos"] == ""


@pytest.mark.asyncio
async def test_encoded_mapping_is_decoded_for_an_object_parameter() -> None:
    parsed = await _roundtrip(_OBJECT, {"modifications": '{"method": "POST"}'})

    assert parsed["modifications"] == {"method": "POST"}


@pytest.mark.asyncio
async def test_a_decoded_container_of_the_wrong_kind_is_not_substituted() -> None:
    parsed = await _roundtrip(_OBJECT, {"modifications": '["POST"]'})

    assert parsed["modifications"] == '["POST"]'


@pytest.mark.asyncio
async def test_values_matching_the_schema_are_left_alone() -> None:
    parsed = await _roundtrip({**_ARRAY, **_OBJECT}, {"tags": ["auth"], "modifications": {"a": 1}})

    assert parsed == {"tags": ["auth"], "modifications": {"a": 1}}


@pytest.mark.asyncio
async def test_unknown_and_null_arguments_are_untouched() -> None:
    parsed = await _roundtrip(_NULLABLE_ARRAY, {"tags": None, "other": ["x"]})

    assert parsed == {"tags": None, "other": ["x"]}


@pytest.mark.asyncio
async def test_non_object_payloads_pass_through_unchanged() -> None:
    captured: dict[str, str] = {}
    wrapped = factory._with_coerced_arguments(_capturing_tool(captured, _ARRAY))

    assert await wrapped.on_invoke_tool(cast("Any", None), "not json") == "ok"
    assert captured["raw_input"] == "not json"


@pytest.mark.asyncio
async def test_coercion_is_applied_once_per_tool() -> None:
    captured: dict[str, str] = {}
    tool = factory._with_coerced_arguments(_capturing_tool(captured, _ARRAY))

    assert factory._with_coerced_arguments(tool) is tool


_NULLABLE_STRING = {"category": {"anyOf": [{"type": "string"}, {"type": "null"}]}}
_NULLABLE_CONTENT = {"content": {"anyOf": [{"type": "string"}, {"type": "null"}]}}
_NULLABLE_STRING_TYPE_LIST = {"category": {"type": ["string", "null"]}}


@pytest.mark.asyncio
@pytest.mark.parametrize("schema", [_NULLABLE_STRING, _NULLABLE_STRING_TYPE_LIST])
@pytest.mark.parametrize("value", ["null", "none", "NULL", " None ", "nil", "undefined"])
async def test_nullish_string_on_a_nullable_parameter_becomes_none(
    schema: dict[str, Any], value: str
) -> None:
    parsed = await _roundtrip(schema, {"category": value}, "list_probes")

    assert parsed["category"] is None


@pytest.mark.asyncio
async def test_nullish_string_on_a_required_parameter_is_untouched() -> None:
    schema = {"content": {"type": "string"}}
    captured: dict[str, str] = {}
    tool = _capturing_tool(captured, schema, "list_probes")
    tool.params_json_schema["required"] = ["content"]
    wrapped = factory._with_coerced_arguments(tool)

    assert await wrapped.on_invoke_tool(cast("Any", None), json.dumps({"content": "none"})) == "ok"
    assert json.loads(captured["raw_input"])["content"] == "none"


@pytest.mark.asyncio
async def test_a_parameter_absent_from_required_is_treated_as_nullable() -> None:
    captured: dict[str, str] = {}
    tool = _capturing_tool(captured, {"category": {"type": "string"}}, "list_probes")
    tool.params_json_schema["required"] = []
    wrapped = factory._with_coerced_arguments(tool)

    assert await wrapped.on_invoke_tool(cast("Any", None), json.dumps({"category": "null"})) == "ok"
    assert json.loads(captured["raw_input"])["category"] is None


@pytest.mark.asyncio
async def test_nullish_string_without_a_required_list_is_untouched() -> None:
    parsed = await _roundtrip(_STRING, {"todos": "none"}, "list_probes")

    assert parsed["todos"] == "none"


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["update_note", "create_note", "record_coverage"])
@pytest.mark.parametrize("value", ["null", "none"])
async def test_a_nullish_value_survives_on_a_tool_that_writes(name: str, value: str) -> None:
    parsed = await _roundtrip(_NULLABLE_CONTENT, {"content": value}, name)

    assert parsed["content"] == value


@pytest.mark.asyncio
async def test_nullish_looking_content_is_not_coerced() -> None:
    parsed = await _roundtrip(
        _NULLABLE_STRING, {"category": "none of the endpoints reflect input"}, "list_probes"
    )

    assert parsed["category"] == "none of the endpoints reflect input"


@pytest.mark.asyncio
async def test_empty_string_on_a_nullable_string_parameter_is_untouched() -> None:
    parsed = await _roundtrip(_NULLABLE_STRING, {"category": ""})

    assert parsed["category"] == ""


@pytest.mark.asyncio
async def test_nullish_string_on_a_nullable_array_parameter_becomes_none() -> None:
    parsed = await _roundtrip(_NULLABLE_ARRAY, {"tags": "null"}, "list_probes")

    assert parsed["tags"] is None


def test_real_tool_schemas_declare_optional_filters_as_nullable() -> None:
    for tool, params in ((list_notes, ("category", "search")), (list_reports, ("target",))):
        schema = tool.params_json_schema
        for param in params:
            assert factory._is_nullable(param, schema["properties"][param], schema)

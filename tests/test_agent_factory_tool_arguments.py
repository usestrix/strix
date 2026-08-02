"""Tests for tool-argument shape coercion in the agent factory."""

from __future__ import annotations

import json
from typing import Any, cast

import pytest
from agents.tool import FunctionTool

from strix.agents import factory


def _capturing_tool(captured: dict[str, str], schema: dict[str, Any]) -> FunctionTool:
    async def invoke(_ctx: Any, raw_input: str) -> str:
        captured["raw_input"] = raw_input
        return "ok"

    return FunctionTool(
        name="probe",
        description="test tool",
        params_json_schema={"type": "object", "properties": schema},
        on_invoke_tool=invoke,
    )


async def _roundtrip(schema: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    captured: dict[str, str] = {}
    wrapped = factory._with_coerced_arguments(_capturing_tool(captured, schema))
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
        "",
    ],
)
async def test_free_form_strings_are_never_split_into_an_array(value: str) -> None:
    parsed = await _roundtrip(_ARRAY, {"tags": value})

    assert parsed["tags"] == value


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

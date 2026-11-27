"""Tests for planner agent tools."""

from __future__ import annotations

import json

from agents.tool_context import ToolContext

from strix.tools.planner.tools import (
    calculate_target_complexity,
    create_scan_plan,
    list_scan_modules,
)


def _make_ctx(tool_name: str) -> ToolContext:
    return ToolContext(
        context={"agent_id": "test-agent"},
        tool_name=tool_name,
        tool_call_id="call-1",
        tool_arguments="{}",
    )


async def test_calculate_target_complexity_tool() -> None:
    fp_json = json.dumps(
        {
            "open_ports": [443, 8080],
            "auth_patterns": ["jwt"],
            "api_surface": {"endpoints_count": 20},
            "waf_cdn": ["cloudflare"],
        }
    )

    result_raw = await calculate_target_complexity.on_invoke_tool(
        _make_ctx("calculate_target_complexity"),
        json.dumps({"target": "https://test.local", "fingerprint": fp_json}),
    )

    data = json.loads(result_raw)
    assert data["target"] == "https://test.local"
    assert "tci" in data
    assert 0.0 <= data["tci"] <= 100.0
    assert "sub_scores" in data
    assert "breakdown" in data
    assert "level" in data


async def test_create_scan_plan_tool() -> None:
    fp_json = json.dumps(
        {
            "target_type": "api",
            "open_ports": [443],
            "auth_patterns": ["jwt", "oauth2"],
            "api_surface": {"endpoints_count": 40, "api_types": ["rest"]},
            "data_sensitivity": "high",
        }
    )

    result_raw = await create_scan_plan.on_invoke_tool(
        _make_ctx("create_scan_plan"),
        json.dumps(
            {
                "target": "https://api.test.local",
                "fingerprint": fp_json,
                "scan_mode": "quick",
            }
        ),
    )

    data = json.loads(result_raw)
    assert data["target"] == "https://api.test.local"
    assert "tci" in data
    assert "plan" in data
    assert isinstance(data["plan"], list)
    assert len(data["plan"]) > 0

    step1 = data["plan"][0]
    assert "step" in step1
    assert "module" in step1
    assert "priority" in step1
    assert "safe_mode" in step1


async def test_list_scan_modules_tool() -> None:
    result_raw = await list_scan_modules.on_invoke_tool(
        _make_ctx("list_scan_modules"),
        json.dumps({}),
    )

    data = json.loads(result_raw)
    assert isinstance(data, list)
    assert len(data) >= 10

    names = [m["name"] for m in data]
    assert "auth-enum" in names
    assert "id_or" in names
    assert "sqli-fuzz" in names

    # Filtered by category
    filtered_raw = await list_scan_modules.on_invoke_tool(
        _make_ctx("list_scan_modules"),
        json.dumps({"category": "authentication"}),
    )
    filtered = json.loads(filtered_raw)
    for m in filtered:
        assert m["category"] == "authentication"


async def test_tools_reject_malformed_fingerprint_json() -> None:
    """Issue 4: malformed JSON returns an explicit error payload."""
    # 1. Malformed JSON to calculate_target_complexity
    raw_calc = await calculate_target_complexity.on_invoke_tool(
        _make_ctx("calculate_target_complexity"),
        json.dumps({"target": "https://test.local", "fingerprint": "{malformed json"}),
    )
    res_calc = json.loads(raw_calc)
    assert "error" in res_calc
    assert "Invalid fingerprint JSON" in res_calc["error"]

    # 2. Malformed JSON to create_scan_plan
    raw_plan = await create_scan_plan.on_invoke_tool(
        _make_ctx("create_scan_plan"),
        json.dumps({"target": "https://test.local", "fingerprint": "{malformed json"}),
    )
    res_plan = json.loads(raw_plan)
    assert "error" in res_plan
    assert "Invalid fingerprint JSON" in res_plan["error"]

    # 3. Non-dict JSON (e.g. array) to calculate_target_complexity
    raw_arr = await calculate_target_complexity.on_invoke_tool(
        _make_ctx("calculate_target_complexity"),
        json.dumps({"target": "https://test.local", "fingerprint": "[1, 2, 3]"}),
    )
    res_arr = json.loads(raw_arr)
    assert "error" in res_arr
    assert "must be an object" in res_arr["error"]

    # 4. Unknown target type returns explicit error
    raw_unk = await calculate_target_complexity.on_invoke_tool(
        _make_ctx("calculate_target_complexity"),
        json.dumps(
            {"target": "https://test.local", "fingerprint": json.dumps({"target_type": "quantum"})}
        ),
    )
    res_unk = json.loads(raw_unk)
    assert "error" in res_unk
    assert "Unknown target type" in res_unk["error"]

"""Textual SDK tool outputs must remain JSON-safe when projected for display."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
from agents import Agent
from agents.items import ItemHelpers, ToolCallItem, ToolCallOutputItem
from agents.stream_events import RunItemStreamEvent
from openai.types.responses import ResponseFunctionToolCall

from strix.core.sessions import open_agent_session
from strix.interface.tui.live_view import TuiLiveView
from strix.interface.viewer.transcript import build_run_state


if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("NaN", "NaN"),
        ("Infinity", "Infinity"),
        ("-Infinity", "-Infinity"),
        ("1e400", "1e400"),
        ("-1e400", "-1e400"),
        ('{"score": NaN}', '{"score": NaN}'),
        ("[Infinity]", "[Infinity]"),
        ('{"nested": [{"score": -1e400}]}', '{"nested": [{"score": -1e400}]}'),
        ('{"score": 1.25}', {"score": 1.25}),
        ("[1, -2.5, true, null]", [1, -2.5, True, None]),
        ("1e308", 1e308),
        ("-1e308", -1e308),
        ("1.25", 1.25),
        ("42", 42),
        ("true", True),
        ("false", False),
        ("null", None),
        ('"NaN"', "NaN"),
        ("plain output", "plain output"),
        ('{"score":', '{"score":'),
    ],
)
@pytest.mark.asyncio
async def test_sdk_tool_text_stays_json_safe_in_live_and_saved_transcripts(
    tmp_path: Path, output: str, expected: Any
) -> None:
    call = ResponseFunctionToolCall(
        type="function_call", call_id="c1", name="fixture_tool", arguments="{}"
    )
    raw_output = ItemHelpers.tool_call_output_item(call, output)
    # The SDK stores a valid string; only the display projection interprets it as JSON.
    assert raw_output["output"] == output
    json.dumps(raw_output, allow_nan=False)

    agent = Agent(name="fixture")
    live = TuiLiveView()
    live.ingest_sdk_event(
        "root", RunItemStreamEvent(name="tool_called", item=ToolCallItem(agent, call))
    )
    live.ingest_sdk_event(
        "root",
        RunItemStreamEvent(name="tool_output", item=ToolCallOutputItem(agent, raw_output, output)),
    )

    state_dir = tmp_path / ".state"
    state_dir.mkdir()
    (state_dir / "agents.json").write_text(
        json.dumps({"statuses": {"root": "completed"}}), encoding="utf-8"
    )
    session = open_agent_session("root", state_dir / "agents.db")
    try:
        await session.add_items([call.model_dump(exclude_none=True), raw_output])
        saved = build_run_state(tmp_path)
        # Display fallback must leave durable SDK history untouched.
        assert (await session.get_items())[-1]["output"] == output
    finally:
        session.close()

    for events in (live.events, saved["events"]):
        assert len(events) == 1
        assert events[0]["data"]["result"] == expected
        json.dumps(events, allow_nan=False)

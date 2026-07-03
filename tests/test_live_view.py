"""Tests verifying the tool-event agent-isolation and status-regression fixes."""

from types import SimpleNamespace
from typing import Any

from strix.interface.tui.live_view import TuiLiveView


def _call_item(call_id: str, name: str = "tool") -> Any:
    raw = SimpleNamespace(
        call_id=call_id,
        id=call_id,
        name=name,
        arguments="{}",
        type="function_call",
    )
    return SimpleNamespace(type="tool_call_item", raw_item=raw, title=None)


def _output_item(call_id: str, name: str = "tool", output: str = '{"success": true}') -> Any:
    raw = SimpleNamespace(call_id=call_id, id=call_id, name=name, type="function_call_output")
    return SimpleNamespace(type="tool_call_output_item", raw_item=raw, output=output)


def test_same_call_id_different_agents_stay_isolated() -> None:
    view = TuiLiveView()
    view._record_tool_call("agent-A", _call_item("shared-id", "read_file"))
    view._record_tool_call("agent-B", _call_item("shared-id", "write_file"))

    assert len(view.events_for_agent("agent-A")) == 1
    assert len(view.events_for_agent("agent-B")) == 1
    assert view.events_for_agent("agent-A")[0]["data"]["tool_name"] == "read_file"
    assert view.events_for_agent("agent-B")[0]["data"]["tool_name"] == "write_file"


def test_replayed_tool_call_does_not_regress_completed_status() -> None:
    view = TuiLiveView()
    view._record_tool_call("agent-A", _call_item("id-1"))
    view._record_tool_output(
        "agent-A",
        _output_item("id-1", output='{"success": true, "x": 1}'),
    )

    # simulate a duplicate/replayed tool_call_item
    view._record_tool_call("agent-A", _call_item("id-1"))

    event = view.events_for_agent("agent-A")[0]
    assert event["data"]["status"] == "completed"
    assert event["data"]["result"] == {"success": True, "x": 1}


def test_failed_result_keeps_failed_status_after_replay() -> None:
    view = TuiLiveView()
    view._record_tool_call("agent-A", _call_item("id-2"))
    view._record_tool_output("agent-A", _output_item("id-2", output='{"success": false}'))
    view._record_tool_call("agent-A", _call_item("id-2"))  # replay

    event = view.events_for_agent("agent-A")[0]
    assert event["data"]["status"] == "failed"

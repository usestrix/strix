"""Tool call/output events must stay isolated per agent and never regress
from a terminal status back to "running" on replay.

Covers usestrix/strix#660: two bugs in TuiLiveView's tool-event bookkeeping.
Bug 1 (events keyed only by call_id, colliding across agents) was already
fixed by fade370 ("fix viewer tool call collisions across agents", #917) -
this file adds the regression test that fix never got. Bug 2 (a replayed
tool_call_item resetting a completed/failed event back to "running") was
still present and is fixed here.
"""

from __future__ import annotations

from strix.interface.tui.live_view import TuiLiveView


def _call(call_id: str, tool_name: str = "shell") -> dict[str, object]:
    return {"call_id": call_id, "tool_name": tool_name, "args": {}}


def _output(call_id: str, output: object, tool_name: str = "shell") -> dict[str, object]:
    return {"call_id": call_id, "tool_name": tool_name, "output": output}


def test_tool_events_do_not_collide_across_agents_sharing_a_call_id() -> None:
    view = TuiLiveView()

    view._record_tool_call_data("agent-A", _call("shared-id", tool_name="nmap"))
    view._record_tool_call_data("agent-B", _call("shared-id", tool_name="curl"))

    a_events = view.events_for_agent("agent-A")
    b_events = view.events_for_agent("agent-B")

    assert len(a_events) == 1
    assert len(b_events) == 1
    assert a_events[0]["data"]["tool_name"] == "nmap"
    assert b_events[0]["data"]["tool_name"] == "curl"


def test_replayed_tool_call_does_not_revert_completed_status_to_running() -> None:
    view = TuiLiveView()

    view._record_tool_call_data("agent-A", _call("id-1"))
    view._record_tool_output_data("agent-A", _output("id-1", {"success": True}))

    event = view.events_for_agent("agent-A")[0]
    assert event["data"]["status"] == "completed"

    # Duplicate stream event / hydration replay of the same call.
    view._record_tool_call_data("agent-A", _call("id-1"))

    replayed = view.events_for_agent("agent-A")[0]
    assert replayed["data"]["status"] == "completed"
    assert replayed["data"]["result"] == {"success": True}


def test_replayed_tool_call_does_not_revert_failed_status_to_running() -> None:
    view = TuiLiveView()

    view._record_tool_call_data("agent-A", _call("id-1"))
    view._record_tool_output_data("agent-A", _output("id-1", {"success": False, "error": "x"}))

    assert view.events_for_agent("agent-A")[0]["data"]["status"] == "failed"

    view._record_tool_call_data("agent-A", _call("id-1"))

    assert view.events_for_agent("agent-A")[0]["data"]["status"] == "failed"


def test_first_tool_call_is_still_recorded_as_running() -> None:
    view = TuiLiveView()

    view._record_tool_call_data("agent-A", _call("id-1"))

    assert view.events_for_agent("agent-A")[0]["data"]["status"] == "running"

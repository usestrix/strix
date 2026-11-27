"""Execution receipts are runtime observations, not agent-asserted evidence."""

from __future__ import annotations

from strix.report.execution_evidence import execution_receipts, resolve_execution_refs


def _call(call_id: str, agent_id: str = "agent-1", tool: str = "exec_command") -> dict[str, str]:
    return {
        "call_id": call_id,
        "agent_id": agent_id,
        "tool": tool,
        "finished_at": "2026-11-13T10:00:00+00:00",
    }


def test_receipts_are_scoped_to_the_agent_and_exclude_bookkeeping() -> None:
    run = {
        "tool_calls": [
            _call("real-1"),
            _call("other", agent_id="agent-2"),
            _call("administrative", tool="record_coverage"),
            _call("other-admin", tool="think"),
            {"agent_id": "agent-1", "tool": "exec_command", "duration_ms": 3},
        ]
    }
    assert execution_receipts(run, "agent-1") == [
        {"call_id": "real-1", "tool": "exec_command", "finished_at": "2026-11-13T10:00:00+00:00"}
    ]
    assert execution_receipts(run, None) == []


def test_resolution_rejects_missing_cross_agent_duplicate_and_admin_refs() -> None:
    run = {
        "tool_calls": [
            _call("own"),
            _call("other", agent_id="agent-2"),
            _call("admin", tool="think"),
        ]
    }
    assert resolve_execution_refs(run, "agent-1", ["own"]) is not None
    for refs in (["missing"], ["other"], ["admin"], ["own", "own"], [], ["own"] * 9):
        assert resolve_execution_refs(run, "agent-1", refs) is None


def test_ambiguous_call_ids_fail_closed() -> None:
    run = {"tool_calls": [_call("reused"), _call("reused")]}
    assert resolve_execution_refs(run, "agent-1", ["reused"]) is None


def test_legacy_timing_records_do_not_pretend_to_be_receipts() -> None:
    run = {"tool_calls": [{"agent_id": "agent-1", "tool": "exec_command", "duration_ms": 10}]}
    assert execution_receipts(run, "agent-1") == []

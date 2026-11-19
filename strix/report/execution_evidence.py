"""Correlate agent coverage claims with completed, content-free tool receipts.

A matching receipt proves an invocation returned to the runtime, not that the
result establishes the security conclusion. Tool arguments and outputs are
never retained in this index.
"""

from __future__ import annotations

from typing import Any


_NON_EVIDENCE_TOOLS = frozenset(
    {
        "think",
        "load_skill",
        "create_todo",
        "list_todos",
        "update_todo",
        "mark_todo_done",
        "mark_todo_pending",
        "delete_todo",
        "create_note",
        "list_notes",
        "get_note",
        "update_note",
        "delete_note",
        "record_coverage",
        "update_coverage",
        "list_coverage",
        "list_execution_receipts",
        "finish_scan",
        "agent_finish",
        "wait_for_user",
        "list_mcps",
        "search_mcp_tools",
        "get_mcp_tool_schema",
        "describe_mcp",
        "list_reports",
        "get_report",
    }
)

ReceiptIndex = dict[tuple[str, str], dict[str, str] | None]


def execution_receipt_index(run_record: dict[str, Any]) -> ReceiptIndex:
    """Index valid completed calls once; duplicate IDs are ambiguous."""
    calls = run_record.get("tool_calls")
    if not isinstance(calls, list):
        return {}
    index: ReceiptIndex = {}
    for call in calls:
        if not isinstance(call, dict):
            continue
        agent_id, call_id = call.get("agent_id"), call.get("call_id")
        tool, finished_at = call.get("tool"), call.get("finished_at")
        if (
            not isinstance(agent_id, str)
            or not agent_id
            or not isinstance(call_id, str)
            or not call_id
            or not isinstance(tool, str)
            or not tool
            or tool in _NON_EVIDENCE_TOOLS
            or not isinstance(finished_at, str)
            or not finished_at
        ):
            continue
        key = (agent_id, call_id)
        if key in index:
            index[key] = None
        else:
            index[key] = {"call_id": call_id, "tool": tool, "finished_at": finished_at}
    return index


def execution_receipts(run_record: dict[str, Any], agent_id: str | None) -> list[dict[str, str]]:
    """Completed non-bookkeeping calls for one agent, newest first."""
    if not agent_id:
        return []
    return [
        receipt
        for (owner, _), receipt in reversed(list(execution_receipt_index(run_record).items()))
        if owner == agent_id and receipt is not None
    ]


def resolve_execution_refs(
    run_record: dict[str, Any],
    agent_id: str | None,
    refs: Any,
    *,
    index: ReceiptIndex | None = None,
) -> list[dict[str, str]] | None:
    """Return matching receipts, or None for missing, foreign, or ambiguous IDs."""
    if (
        not isinstance(refs, list)
        or not refs
        or len(refs) > 8
        or not agent_id
        or any(not isinstance(ref, str) or not ref for ref in refs)
        or len(set(refs)) != len(refs)
    ):
        return None
    by_id = index if index is not None else execution_receipt_index(run_record)
    matches: list[dict[str, str]] = []
    for ref in refs:
        receipt = by_id.get((agent_id, ref))
        if receipt is None:
            return None
        matches.append(receipt)
    return matches

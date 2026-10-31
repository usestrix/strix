"""``wait_for_user`` — hand control back to the user and wait for their reply."""

from __future__ import annotations

import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.core.agents import coordinator_from_context


def _ctx(ctx: RunContextWrapper) -> dict[str, Any]:
    return ctx.context if isinstance(ctx.context, dict) else {}


@function_tool
async def wait_for_user(ctx: RunContextWrapper) -> str:
    """Hand control to the user and wait for their reply.

    This is the ONLY way to yield to the user. It carries no text: everything
    you write as plain text is already shown to the user, so write your reply
    first, as plain text, then call this to stop and wait. Never restate in
    any form what you have already written.

    Call it when you have nothing to do until the user replies — you answered
    their question, you need a decision or a credential only they can give,
    or you finished a chunk of work and want direction. You resume exactly
    where you left off when they reply, with everything you have done so far
    intact.

    Do NOT call it to narrate progress or to think out loud: plain text is
    shown to the user as you work, so say whatever you like mid-task without
    stopping. Every call costs the user their attention.

    Not for these:

    - **Waiting on another agent** (a child's report, a peer's reply) —
      use ``wait_for_agents``.
    - **Ending the engagement** — use ``finish_scan`` (root) or
      ``agent_finish`` (subagent). Those are terminal; this is a pause.
    """
    inner = _ctx(ctx)
    coordinator = coordinator_from_context(inner)
    me = inner.get("agent_id")
    interactive = bool(inner.get("interactive", False))

    if coordinator is None or me is None:
        return json.dumps(
            {"success": False, "error": "Agent coordinator or agent_id missing in context"},
            ensure_ascii=False,
            default=str,
        )

    if not interactive:
        return json.dumps(
            {
                "success": False,
                "error": (
                    "No user is attached to an autonomous run. Keep working, and call "
                    "finish_scan (root) or agent_finish (subagent) when the task is done."
                ),
            },
            ensure_ascii=False,
            default=str,
        )

    async with coordinator._lock:
        stopped = coordinator.statuses.get(me) == "stopped"
    if stopped:
        return json.dumps(
            {"success": True, "wait_outcome": "stopped"},
            ensure_ascii=False,
            default=str,
        )

    # A message that arrived while this turn was running is the user already
    # talking: take it now instead of parking for one they have sent.
    pending, _ = await coordinator.consume_pending(me)
    if pending > 0:
        await coordinator.mark_running(me)
        return json.dumps(
            {
                "success": True,
                "wait_outcome": "message_arrived",
                "pending_messages": pending,
                "note": "The user had already sent a new message; keep going.",
            },
            ensure_ascii=False,
            default=str,
        )

    await coordinator.park_waiting(me, wait_kind="user")
    return json.dumps(
        {
            "success": True,
            "wait_outcome": "waiting",
            "note": "Parked until the user responds.",
        },
        ensure_ascii=False,
        default=str,
    )

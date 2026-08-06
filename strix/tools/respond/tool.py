"""``respond_to_user`` — deliver a reply and hand control back to the user."""

from __future__ import annotations

import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.core.agents import coordinator_from_context


def _ctx(ctx: RunContextWrapper) -> dict[str, Any]:
    return ctx.context if isinstance(ctx.context, dict) else {}


@function_tool
async def respond_to_user(ctx: RunContextWrapper, message: str) -> str:
    """Answer the user and hand control back to them.

    This is the ONLY way to yield to the user. Delivering the message and
    yielding are the same call on purpose: there is no way to answer and
    then forget to stop, and no way to stop without having answered.

    Call it when you have something for the user and nothing to do until
    they reply — you answered their question, you need a decision or a
    credential only they can give, or you finished a chunk of work and
    want direction. You resume exactly where you left off when they
    reply, with everything you have done so far intact.

    Do NOT call it to narrate progress or to think out loud. Plain text
    is still shown to the user as you work, so say whatever you like
    mid-task without stopping; ``respond_to_user`` is specifically the
    act of *waiting* for them. Every call costs the user their attention.

    Not for these:

    - **Waiting on another agent** (a child's report, a peer's reply) —
      use ``wait_for_agents``.
    - **Ending the engagement** — use ``finish_scan`` (root) or
      ``agent_finish`` (subagent). Those are terminal; this is a pause.

    Args:
        message: What to say to the user. Self-contained: they may not
            have followed the tool calls that led here. Lead with the
            answer or the decision you need, and if you are blocked, say
            exactly what you need from them.
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
            {"success": True, "wait_outcome": "stopped", "message": message},
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
                "message": message,
                "note": "Your reply was delivered; the user had already sent a new message.",
            },
            ensure_ascii=False,
            default=str,
        )

    await coordinator.park_waiting(me, wait_kind="user")
    return json.dumps(
        {
            "success": True,
            "wait_outcome": "waiting",
            "message": message,
            "note": "Reply delivered; parked until the user responds.",
        },
        ensure_ascii=False,
        default=str,
    )

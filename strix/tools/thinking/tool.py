"""``think`` — record a private chain-of-thought note with no side effects."""

from __future__ import annotations

import json

from agents import function_tool


@function_tool(timeout=10)
async def think(thought: str) -> str:
    """Record a private chain-of-thought note. No side effects, no new info.

    Use ``think`` when you need a dedicated space to reason before acting —
    not as an output channel. It's particularly valuable for:

    - **Tool output analysis** — carefully processing the output of a
      previous tool call before deciding the next step.
    - **Policy-heavy environments** — when you need to follow detailed
      guidelines (engagement scope, auth boundaries) and verify compliance
      before each action.
    - **Sequential decision making** — when each action builds on previous
      ones and mistakes are costly (e.g., destructive operations,
      irreversible auth changes).
    - **Multi-step exploit planning** — breaking down a complex chain into
      manageable steps and tracking what's been confirmed vs. assumed.

    Structure your thought to be useful: current state, what you've
    confirmed, your next planned actions, risk assessment. Don't use
    ``think`` to chat — use it to plan.

    Args:
        thought: The reasoning to record. Must be non-empty.
    """
    if not thought or not thought.strip():
        return json.dumps({"success": False, "error": "Thought cannot be empty"})
    return json.dumps({"success": True, "message": "Thought recorded"})

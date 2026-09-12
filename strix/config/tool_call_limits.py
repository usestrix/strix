"""Bound how many tool calls one assistant response may queue.

A degenerate generation can emit hundreds or thousands of tool calls in a
single response — typically a poll/wait loop the model writes out ahead of
time instead of issuing one call and yielding. The run loop honours all of
them, so the agent stops reacting to anything for hours. Keeping only the
first ``limit`` calls of a response bounds that blast radius; the model sees
their results on the next turn and can reconsider.
"""

from __future__ import annotations

from typing import Any

from openai.types.responses import ResponseFunctionToolCall


class TurnToolCallLimiter:
    """Decide, once per call, whether a turn's tool call is within the limit."""

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._decisions: dict[str, bool] = {}
        self._kept = 0
        self.dropped = 0

    @property
    def enabled(self) -> bool:
        return self._limit > 0

    def allow(self, item: Any) -> bool:
        if not self.enabled or not isinstance(item, ResponseFunctionToolCall):
            return True
        decided = self._decisions.get(item.call_id)
        if decided is not None:
            return decided
        allowed = self._kept < self._limit
        if allowed:
            self._kept += 1
        else:
            self.dropped += 1
        self._decisions[item.call_id] = allowed
        return allowed

    def filter_items(self, items: list[Any]) -> list[Any]:
        return [item for item in items if self.allow(item)]

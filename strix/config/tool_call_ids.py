"""Keep tool-call ids present and unique within a conversation.

Some providers return per-turn tool-call ids (``exec_command:0``,
``exec_command:1``, ...) whose counter restarts on every turn. Once the same
id appears twice in one conversation, the request payload has two assistant
tool calls sharing an id and strict providers reject the whole turn, which
permanently kills the agent because the malformed history is replayed on
every retry.

Others omit the id altogether, or return it as an empty string. That turns
the paired tool result into a ``tool`` message with an empty
``tool_call_id``, which strict providers reject the same way and with the
same permanent outcome. Rewriting both blank and duplicate ids to fresh
unique ones keeps the history valid for any provider.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any
from uuid import uuid4

from agents.models.fake_id import FAKE_RESPONSES_ID
from openai.types.responses import ResponseFunctionToolCall


def new_call_id() -> str:
    return f"call_{uuid4().hex}"


def _pairing_key(call_id: Any) -> str:
    """Bucket an id for call/output pairing; all blank ids share one bucket."""
    return call_id if isinstance(call_id, str) else ""


def collect_call_ids(items: list[Any]) -> set[str]:
    used: set[str] = set()
    for item in items:
        if isinstance(item, dict):
            call_id = item.get("call_id")
            if isinstance(call_id, str) and call_id:
                used.add(call_id)
        elif isinstance(item, ResponseFunctionToolCall) and item.call_id:
            used.add(item.call_id)
    return used


def dedupe_history_call_ids(items: list[Any]) -> tuple[list[Any], bool]:
    """Rewrite blank and duplicate call ids in a conversation history.

    Outputs are paired with their call by order, so parallel calls that share
    an id — or are all missing one — keep answering the right call after the
    rewrite.
    """
    used: set[str] = set()
    pending: dict[str, deque[str]] = defaultdict(deque)
    rebuilt: list[Any] = []
    changed = False

    for item in items:
        if not isinstance(item, dict):
            rebuilt.append(item)
            continue

        kind = item.get("type")
        if kind not in ("function_call", "function_call_output"):
            rebuilt.append(item)
            continue

        call_id = item.get("call_id")
        key = _pairing_key(call_id)
        if kind == "function_call":
            effective = key
            if not effective or effective in used:
                effective = new_call_id()
                item = {**item, "call_id": effective}  # noqa: PLW2901
                changed = True
            used.add(effective)
            pending[key].append(effective)
        else:
            queue = pending.get(key)
            if queue:
                effective = queue.popleft()
                if effective != call_id:
                    item = {**item, "call_id": effective}  # noqa: PLW2901
                    changed = True
        rebuilt.append(item)

    return rebuilt, changed


def dedupe_input(model_input: str | list[Any]) -> str | list[Any]:
    if isinstance(model_input, str):
        return model_input
    rebuilt, changed = dedupe_history_call_ids(model_input)
    return rebuilt if changed else model_input


class TurnCallIdRewriter:
    """Rewrite a single turn's tool-call ids that are blank or collide with the history.

    A turn's items surface several times (streamed item events, then the
    completed response), so the same original id must always map to the same
    replacement within the turn.
    """

    def __init__(self, model_input: str | list[Any]) -> None:
        self._used = set() if isinstance(model_input, str) else collect_call_ids(model_input)
        self._remap: dict[str, str] = {}
        self._blank_remap: dict[str, str] = {}
        self._settled: set[str] = set()

    def _rewrite_blank(
        self, item: ResponseFunctionToolCall, position: int | None
    ) -> ResponseFunctionToolCall:
        """Give a call with no id one that stays the same on every sighting.

        A real item id tells parallel calls apart. Chat Completions routes give
        every item the same placeholder id, so there the call's position in
        the turn's output tells them apart instead.
        """
        if item.id and item.id != FAKE_RESPONSES_ID:
            key = item.id
        else:
            key = f"{FAKE_RESPONSES_ID}#{position}"
        replacement = self._blank_remap.get(key)
        if replacement is None:
            replacement = new_call_id()
            self._blank_remap[key] = replacement
            self._used.add(replacement)
            self._settled.add(replacement)
        return item.model_copy(update={"call_id": replacement})

    def rewrite_item(self, item: Any, position: int | None = None) -> Any:
        """Rewrite one item; ``position`` is its index in the turn's output."""
        if not isinstance(item, ResponseFunctionToolCall):
            return item
        original = item.call_id
        if not original:
            return self._rewrite_blank(item, position)
        if original in self._settled:
            return item
        replacement = self._remap.get(original)
        if replacement is None:
            if original not in self._used:
                self._used.add(original)
                self._settled.add(original)
                return item
            replacement = new_call_id()
            self._remap[original] = replacement
            self._used.add(replacement)
            self._settled.add(replacement)
        return item.model_copy(update={"call_id": replacement})

    def rewrite_items(self, items: list[Any]) -> list[Any]:
        return [self.rewrite_item(item, position) for position, item in enumerate(items)]

"""SDK session helpers for Strix agents."""

from __future__ import annotations

import contextlib
import logging
from typing import TYPE_CHECKING, Any, cast

from agents.memory import SQLiteSession

from strix.core.tool_output import DEFAULT_MAX_TOOL_OUTPUT_CHARS, truncate_tool_output


if TYPE_CHECKING:
    from pathlib import Path

    from agents.items import TResponseInputItem
    from agents.memory import Session


logger = logging.getLogger(__name__)


def open_agent_session(agent_id: str, path: Path) -> SQLiteSession:
    path.parent.mkdir(parents=True, exist_ok=True)
    return SQLiteSession(session_id=agent_id, db_path=path)


_IMAGE_REJECTED_TEXT = "[image rejected by the model]"


async def _rewrite_session_items(session: Session, rebuilt: list[Any]) -> None:
    rebuilt_items = cast("list[TResponseInputItem]", rebuilt)
    await session.clear_session()
    try:
        await session.add_items(rebuilt_items)
    except Exception:
        with contextlib.suppress(Exception):
            await session.add_items(rebuilt_items)
        raise


async def strip_all_images_from_session(session: Session) -> bool:
    items = await session.get_items()
    if not items:
        return False

    rebuilt: list[Any] = []
    changed = False
    for item in items:
        item_dict = cast("dict[str, Any]", item) if isinstance(item, dict) else None
        if (
            item_dict is not None
            and item_dict.get("type") == "function_call_output"
            and isinstance(item_dict.get("output"), list)
            and any(
                isinstance(b, dict) and b.get("type") == "input_image" for b in item_dict["output"]
            )
        ):
            rebuilt.append(
                {
                    "type": "function_call_output",
                    "call_id": item_dict.get("call_id"),
                    "output": [{"type": "input_text", "text": _IMAGE_REJECTED_TEXT}],
                },
            )
            changed = True
        else:
            rebuilt.append(item)

    if not changed:
        return False

    await _rewrite_session_items(session, rebuilt)
    return True


def _truncate_function_output_value(output: Any, max_chars: int) -> tuple[Any, bool]:
    """Return ``(new_output, changed)`` for one function_call_output payload."""
    if isinstance(output, str):
        truncated = truncate_tool_output(output, max_chars)
        return truncated, truncated != output

    if isinstance(output, list):
        new_blocks: list[Any] = []
        changed = False
        for block in output:
            if isinstance(block, dict) and block.get("type") == "input_text":
                text = block.get("text")
                if isinstance(text, str):
                    truncated = truncate_tool_output(text, max_chars)
                    if truncated != text:
                        changed = True
                        new_blocks.append({**block, "text": truncated})
                        continue
            new_blocks.append(block)
        return new_blocks, changed

    return output, False


async def truncate_large_outputs_in_session(
    session: Session,
    max_chars: int = DEFAULT_MAX_TOOL_OUTPUT_CHARS,
) -> bool:
    """Truncate oversized ``function_call_output`` items already in the session.

    Used as recovery after a context-window rejection: huge tool results
    (semgrep dumps, etc.) sit in SQLite and get resent on the next turn.
    Returns True when at least one item was shortened.
    """
    if max_chars <= 0:
        return False

    items = await session.get_items()
    if not items:
        return False

    rebuilt: list[Any] = []
    changed = False
    for item in items:
        item_dict = cast("dict[str, Any]", item) if isinstance(item, dict) else None
        if item_dict is not None and item_dict.get("type") == "function_call_output":
            new_output, item_changed = _truncate_function_output_value(
                item_dict.get("output"),
                max_chars,
            )
            if item_changed:
                changed = True
                rebuilt.append({**item_dict, "output": new_output})
                continue
        rebuilt.append(item)

    if not changed:
        return False

    await _rewrite_session_items(session, rebuilt)
    logger.info(
        "Truncated oversized tool outputs in session (cap=%d chars)",
        max_chars,
    )
    return True

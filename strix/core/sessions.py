"""SDK session helpers for Strix agents."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any, cast
from weakref import WeakKeyDictionary

from agents.memory import SQLiteSession


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from agents.items import TResponseInputItem
    from agents.memory import Session


logger = logging.getLogger(__name__)


def open_agent_session(agent_id: str, path: Path) -> SQLiteSession:
    path.parent.mkdir(parents=True, exist_ok=True)
    return SQLiteSession(session_id=agent_id, db_path=path)


_IMAGE_REJECTED_TEXT = "[image rejected by the model]"
_IMAGE_ELIDED_TEXT = "[older screenshot elided to bound context memory]"
_INHERITED_IMAGE_TEXT = "[screenshot omitted from inherited context]"


def _output_has_image(item_dict: dict[str, Any]) -> bool:
    return (
        item_dict.get("type") == "function_call_output"
        and isinstance(item_dict.get("output"), list)
        and any(isinstance(b, dict) and b.get("type") == "input_image" for b in item_dict["output"])
    )


def _elided_output(item_dict: dict[str, Any], text: str) -> dict[str, Any]:
    # Replace only image blocks; sibling text blocks are preserved.
    output = item_dict.get("output")
    blocks = output if isinstance(output, list) else []
    return {
        "type": "function_call_output",
        "call_id": item_dict.get("call_id"),
        "output": [
            {"type": "input_text", "text": text}
            if isinstance(block, dict) and block.get("type") == "input_image"
            else block
            for block in blocks
        ],
    }


_session_write_locks: WeakKeyDictionary[Session, asyncio.Lock] = WeakKeyDictionary()


def session_write_lock(session: Session) -> asyncio.Lock:
    """Lock serialising all out-of-band writes to ``session``."""
    lock = _session_write_locks.get(session)
    if lock is None:
        lock = asyncio.Lock()
        _session_write_locks[session] = lock
    return lock


async def _rewrite_session(
    session: Session,
    transform: Callable[[list[Any]], tuple[list[Any], bool]],
) -> bool:
    """Read-modify-write a session under its write lock, restoring on failure."""
    async with session_write_lock(session):
        items = await session.get_items()
        if not items:
            return False
        rebuilt, changed = transform(list(items))
        if not changed:
            return False
        rebuilt_items = cast("list[TResponseInputItem]", rebuilt)
        original_items = cast("list[TResponseInputItem]", list(items))
        await session.clear_session()
        try:
            await session.add_items(rebuilt_items)
        except Exception:
            logger.exception("session rewrite failed; restoring original items")
            await session.clear_session()
            await session.add_items(original_items)
            raise
        return True


async def strip_all_images_from_session(session: Session) -> bool:
    """Replace every image tool output with a text placeholder (rejection recovery)."""

    def _transform(items: list[Any]) -> tuple[list[Any], bool]:
        rebuilt: list[Any] = []
        changed = False
        for item in items:
            item_dict = cast("dict[str, Any]", item) if isinstance(item, dict) else None
            if item_dict is not None and _output_has_image(item_dict):
                rebuilt.append(_elided_output(item_dict, _IMAGE_REJECTED_TEXT))
                changed = True
            else:
                rebuilt.append(item)
        return rebuilt, changed

    return await _rewrite_session(session, _transform)


async def enforce_image_budget(session: Session, max_images: int) -> bool:
    """Keep only the most recent ``max_images`` image outputs; elide older ones."""
    if max_images < 0:
        return False

    def _transform(items: list[Any]) -> tuple[list[Any], bool]:
        image_indices = [
            i
            for i, item in enumerate(items)
            if isinstance(item, dict) and _output_has_image(cast("dict[str, Any]", item))
        ]
        if len(image_indices) <= max_images:
            return items, False
        to_elide = set(image_indices[: len(image_indices) - max_images])
        rebuilt = [
            _elided_output(cast("dict[str, Any]", item), _IMAGE_ELIDED_TEXT)
            if i in to_elide
            else item
            for i, item in enumerate(items)
        ]
        return rebuilt, True

    return await _rewrite_session(session, _transform)


def scrub_images_from_items(items: list[Any]) -> list[Any]:
    """Return a copy of ``items`` with every image block replaced by text."""

    def _scrub(obj: Any) -> Any:
        if isinstance(obj, dict):
            if obj.get("type") == "input_image":
                return {"type": "input_text", "text": _INHERITED_IMAGE_TEXT}
            return {k: _scrub(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_scrub(v) for v in obj]
        return obj

    return [_scrub(item) for item in items]

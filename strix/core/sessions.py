"""SDK session helpers for Strix agents."""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any, cast

from agents.memory import SQLiteSession


if TYPE_CHECKING:
    from pathlib import Path

    from agents.items import TResponseInputItem
    from agents.memory import Session


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
    return {
        "type": "function_call_output",
        "call_id": item_dict.get("call_id"),
        "output": [{"type": "input_text", "text": text}],
    }


async def _rewrite_session(session: Session, items: list[Any]) -> None:
    rebuilt_items = cast("list[TResponseInputItem]", items)
    await session.clear_session()
    try:
        await session.add_items(rebuilt_items)
    except Exception:
        with contextlib.suppress(Exception):
            await session.add_items(rebuilt_items)
        raise


async def strip_all_images_from_session(session: Session) -> bool:
    """Replace every image tool output with a text placeholder.

    Reactive recovery for models that reject image inputs (vision not
    supported / payload too large). All-or-nothing by design.
    """
    items = await session.get_items()
    if not items:
        return False

    rebuilt: list[Any] = []
    changed = False
    for item in items:
        item_dict = cast("dict[str, Any]", item) if isinstance(item, dict) else None
        if item_dict is not None and _output_has_image(item_dict):
            rebuilt.append(_elided_output(item_dict, _IMAGE_REJECTED_TEXT))
            changed = True
        else:
            rebuilt.append(item)

    if not changed:
        return False

    await _rewrite_session(session, rebuilt)
    return True


async def enforce_image_budget(session: Session, max_images: int) -> bool:
    """Keep only the most recent ``max_images`` image outputs in the session.

    Screenshots (base64 ``input_image`` blocks from ``view_image``) otherwise
    accumulate for the whole agent lifetime and are re-materialised into RAM
    and re-sent to the model on every turn. Eliding the older ones bounds the
    per-agent context memory while preserving the most recent visual context.
    Returns ``True`` if anything was elided.
    """
    if max_images < 0:
        return False

    items = await session.get_items()
    if not items:
        return False

    image_indices = [
        i
        for i, item in enumerate(items)
        if isinstance(item, dict) and _output_has_image(cast("dict[str, Any]", item))
    ]
    if len(image_indices) <= max_images:
        return False

    to_elide = set(image_indices[: len(image_indices) - max_images])
    rebuilt = [
        _elided_output(cast("dict[str, Any]", item), _IMAGE_ELIDED_TEXT) if i in to_elide else item
        for i, item in enumerate(items)
    ]

    await _rewrite_session(session, rebuilt)
    return True


def scrub_images_from_items(items: list[Any]) -> list[Any]:
    """Return a copy of ``items`` with every image block replaced by text.

    Used before serialising a parent's history into a child agent's inherited
    context: without this, multi-MB base64 screenshots are ``json.dumps``-ed
    into the child's first message verbatim, duplicated across every spawned
    child, and can no longer be reclaimed by the reactive image strip (which
    only matches structured ``input_image`` blocks, not base64 inside text).
    """

    def _scrub(obj: Any) -> Any:
        if isinstance(obj, dict):
            if obj.get("type") == "input_image":
                return {"type": "input_text", "text": _INHERITED_IMAGE_TEXT}
            return {k: _scrub(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_scrub(v) for v in obj]
        return obj

    return [_scrub(item) for item in items]

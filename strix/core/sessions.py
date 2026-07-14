"""SDK session helpers for Strix agents."""

from __future__ import annotations

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

    rebuilt_items = cast("list[TResponseInputItem]", rebuilt)
    await session.clear_session()
    try:
        await session.add_items(rebuilt_items)
    except Exception:  # noqa: BLE001
        await session.add_items(rebuilt_items)
    return True

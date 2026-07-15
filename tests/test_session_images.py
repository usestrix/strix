"""Tests for image-memory bounding: proactive budget + inherited-context scrub."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast

import pytest

from strix.core.inputs import child_initial_input
from strix.core.sessions import (
    enforce_image_budget,
    open_agent_session,
    scrub_images_from_items,
)


if TYPE_CHECKING:
    from pathlib import Path

    from agents.items import TResponseInputItem
    from agents.memory import SQLiteSession


def _image_output(call_id: str) -> dict[str, Any]:
    return {
        "type": "function_call_output",
        "call_id": call_id,
        "output": [{"type": "input_image", "image_url": f"data:image/png;base64,{'A' * 2048}"}],
    }


async def _add(session: SQLiteSession, items: list[dict[str, Any]]) -> None:
    await session.add_items(cast("list[TResponseInputItem]", items))


def _live_image_call_ids(items: list[Any]) -> list[str]:
    return [
        item["call_id"]
        for item in items
        if isinstance(item, dict)
        and item.get("type") == "function_call_output"
        and any(b.get("type") == "input_image" for b in item.get("output", []))
    ]


@pytest.mark.asyncio
async def test_enforce_image_budget_keeps_only_most_recent(tmp_path: Path) -> None:
    session = open_agent_session("agent", tmp_path / "agents.db")
    try:
        await _add(session, [_image_output(f"c{i}") for i in range(6)])

        changed = await enforce_image_budget(session, 3)

        assert changed is True
        assert _live_image_call_ids(await session.get_items()) == ["c3", "c4", "c5"]
        # Idempotent once at/under budget.
        assert await enforce_image_budget(session, 3) is False
    finally:
        session.close()


@pytest.mark.asyncio
async def test_enforce_image_budget_zero_elides_all(tmp_path: Path) -> None:
    session = open_agent_session("agent", tmp_path / "agents.db")
    try:
        await _add(session, [_image_output("c0"), _image_output("c1")])

        assert await enforce_image_budget(session, 0) is True
        assert _live_image_call_ids(await session.get_items()) == []
    finally:
        session.close()


@pytest.mark.asyncio
async def test_enforce_image_budget_noop_when_under_limit(tmp_path: Path) -> None:
    session = open_agent_session("agent", tmp_path / "agents.db")
    try:
        await _add(session, [_image_output("c0")])
        assert await enforce_image_budget(session, 3) is False
    finally:
        session.close()


def test_scrub_images_from_items_removes_base64() -> None:
    items = [
        _image_output("c0"),
        {
            "role": "user",
            "content": [
                {"type": "input_text", "text": "hi"},
                {"type": "input_image", "image_url": "data:image/png;base64,ZZZ"},
            ],
        },
        {
            "type": "function_call_output",
            "call_id": "c1",
            "output": [{"type": "input_text", "text": "ok"}],
        },
    ]

    scrubbed = scrub_images_from_items(items)

    assert "base64" not in json.dumps(scrubbed)
    assert all(block["type"] != "input_image" for block in scrubbed[0]["output"])
    assert scrubbed[1]["content"][1]["type"] == "input_text"
    assert scrubbed[2] == items[2]


def test_child_initial_input_does_not_inline_screenshots() -> None:
    parent_history = [_image_output("c0")]

    result = child_initial_input(
        name="XSS",
        child_id="deadbeef",
        parent_id="cafe",
        task="find xss",
        parent_history=parent_history,
    )

    content = result[0]["content"]
    assert "base64" not in content
    assert "screenshot omitted" in content

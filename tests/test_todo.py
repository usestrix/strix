from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
from agents.tool_context import ToolContext

from strix.tools.todo import tools
from strix.tools.todo.tools import _coerce_priority, create_todo


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _isolate_store() -> Any:
    tools._todos_storage.clear()
    yield
    tools._todos_storage.clear()


async def _create(todos: list[Any], agent_id: str = "root") -> dict[str, Any]:
    ctx = ToolContext(
        context={"agent_id": agent_id},
        tool_name="create_todo",
        tool_call_id="call-1",
        tool_arguments="{}",
    )
    raw = await create_todo.on_invoke_tool(ctx, json.dumps({"todos": json.dumps(todos)}))
    return json.loads(raw)  # type: ignore[no-any-return]


def test_unknown_priority_falls_back_to_normal() -> None:
    assert _coerce_priority("medium") == "normal"
    assert _coerce_priority("urgent") == "normal"
    assert _coerce_priority("high") == "high"


@pytest.mark.asyncio
async def test_one_bad_priority_no_longer_discards_the_batch() -> None:
    result = await _create(
        [
            {"title": "Recon", "priority": "medium"},
            {"title": "Probe /admin", "priority": "sky-high"},
            {"title": "Report"},
        ]
    )

    assert result["success"] is True
    assert result["created_count"] == 3
    by_title = {c["title"]: c["priority"] for c in result["created"]}
    assert by_title["Recon"] == "normal"
    assert by_title["Probe /admin"] == "normal"
    assert by_title["Report"] == "normal"


@pytest.mark.asyncio
async def test_duplicate_titles_within_a_batch_are_skipped() -> None:
    result = await _create(
        [
            {"title": "Subdomain enumeration"},
            {"title": "Content discovery"},
            {"title": "Subdomain enumeration"},
            {"title": "content discovery"},
        ]
    )

    assert result["created_count"] == 2
    assert {c["title"] for c in result["created"]} == {
        "Subdomain enumeration",
        "Content discovery",
    }
    assert len(result["skipped"]) == 2
    assert all(s["reason"] == "duplicate title" for s in result["skipped"])


@pytest.mark.asyncio
async def test_a_title_already_on_the_list_is_not_created_again() -> None:
    await _create([{"title": "Crawl with katana"}])
    result = await _create([{"title": "crawl with katana"}, {"title": "JS analysis"}])

    assert [c["title"] for c in result["created"]] == ["JS analysis"]
    assert [s["title"] for s in result["skipped"]] == ["crawl with katana"]
    assert result["total_count"] == 2


def test_coerce_never_raises() -> None:
    assert _coerce_priority("nonsense") == "normal"
    assert _coerce_priority(None) == "normal"
    assert _coerce_priority("high") == "high"
    for value in (2, ["high"], {"p": 1}, True):
        assert _coerce_priority(value) == "normal"  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_non_string_priority_does_not_fail_the_batch() -> None:
    result = await _create(
        [
            {"title": "Recon", "priority": 2},
            {"title": "Probe", "priority": ["high"]},
            {"title": "Report"},
        ]
    )

    assert result["success"] is True
    assert result["created_count"] == 3
    assert {c["priority"] for c in result["created"]} == {"normal"}


@pytest.mark.parametrize(
    "invalid_field", [{"priority": "invalid"}, {"priority": "high", "status": "invalid"}]
)
async def test_rejected_todo_update_is_not_persisted_with_valid_sibling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid_field: dict[str, str]
) -> None:
    monkeypatch.setattr(tools, "_todos_path", None)
    tools.hydrate_todos_from_disk(tmp_path)
    created = await _create([{"title": "Original task"}, {"title": "Other task"}])
    rejected_id, accepted_id = [item["todo_id"] for item in created["created"]]
    original = tools._todos_storage["root"][rejected_id].copy()
    ctx = ToolContext(
        context={"agent_id": "root"},
        tool_name="update_todo",
        tool_call_id="call-update",
        tool_arguments="{}",
    )

    raw = await tools.update_todo.on_invoke_tool(
        ctx,
        json.dumps(
            {
                "updates": json.dumps(
                    [
                        {
                            "todo_id": rejected_id,
                            "title": "Rejected title",
                            "description": "Rejected description",
                            **invalid_field,
                        },
                        {"todo_id": accepted_id, "status": "done"},
                    ]
                )
            }
        ),
    )

    result = json.loads(raw)
    assert result["success"] is False
    assert result["updated"] == [accepted_id]
    assert result["errors"][0]["todo_id"] == rejected_id
    assert tools._todos_storage["root"][rejected_id] == original
    tools.hydrate_todos_from_disk(tmp_path)
    assert tools._todos_storage["root"][rejected_id] == original
    assert tools._todos_storage["root"][accepted_id]["status"] == "done"
    assert tools._todos_storage["root"][accepted_id]["completed_at"] is not None

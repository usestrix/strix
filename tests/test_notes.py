"""Tests for per-run notes storage."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

import pytest

import strix.tools.notes.tools as notes_tools


if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture(autouse=True)
def _reset_notes_storage(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(notes_tools, "_notes_path", None)
    with notes_tools._notes_lock:
        notes_tools._notes_storage.clear()
    yield
    with notes_tools._notes_lock:
        notes_tools._notes_storage.clear()


def test_create_note_retries_on_note_id_collision(monkeypatch: pytest.MonkeyPatch) -> None:
    generated_ids = iter(
        [
            uuid.UUID("abcdef00-0000-4000-8000-000000000000"),
            uuid.UUID("abcdef11-0000-4000-8000-000000000000"),
            uuid.UUID("12345600-0000-4000-8000-000000000000"),
        ]
    )
    monkeypatch.setattr("strix.tools.notes.tools.uuid.uuid4", lambda: next(generated_ids))

    first = notes_tools._create_note_impl("first", "original content")
    second = notes_tools._create_note_impl("second", "new content")

    assert first["success"] is True
    assert first["note_id"] == "abcdef"
    assert second["success"] is True
    assert second["note_id"] == "123456"
    assert second["total_count"] == 2
    assert notes_tools._notes_storage["abcdef"]["content"] == "original content"
    assert notes_tools._notes_storage["123456"]["content"] == "new content"


def test_create_note_returns_error_after_repeated_note_id_collisions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(notes_tools, "_NOTE_ID_GENERATION_ATTEMPTS", 2)
    monkeypatch.setattr(
        "strix.tools.notes.tools.uuid.uuid4",
        lambda: uuid.UUID("abcdef00-0000-4000-8000-000000000000"),
    )
    notes_tools._notes_storage["abcdef"] = {"content": "existing"}

    result = notes_tools._create_note_impl("second", "new content")

    assert result == {
        "success": False,
        "error": "Failed to generate a unique note ID",
        "note_id": None,
    }
    assert notes_tools._notes_storage == {"abcdef": {"content": "existing"}}


def test_create_note_records_author() -> None:
    result = notes_tools._create_note_impl("t", "c", agent_id="agent-1", agent_name="Agent One")
    note = notes_tools._notes_storage[result["note_id"]]
    assert note["agent_id"] == "agent-1"
    assert note["agent_name"] == "Agent One"


def test_list_notes_exposes_author_and_flags_caller() -> None:
    notes_tools._create_note_impl("mine", "c", agent_id="agent-1", agent_name="Agent One")
    notes_tools._create_note_impl("theirs", "c", agent_id="agent-2", agent_name="Agent Two")

    result = notes_tools._list_notes_impl(caller_agent_id="agent-1")
    by_title = {n["title"]: n for n in result["notes"]}
    assert by_title["mine"]["agent_name"] == "Agent One"
    assert by_title["mine"].get("by_you") is True
    assert by_title["theirs"]["agent_name"] == "Agent Two"
    assert "by_you" not in by_title["theirs"]


def test_list_notes_without_author_has_no_attribution() -> None:
    notes_tools._create_note_impl("anon", "c")
    entry = notes_tools._list_notes_impl(caller_agent_id="agent-1")["notes"][0]
    assert "agent_name" not in entry
    assert "by_you" not in entry


def test_get_note_flags_caller_ownership() -> None:
    note_id = notes_tools._create_note_impl(
        "mine", "c", agent_id="agent-1", agent_name="Agent One"
    )["note_id"]
    mine = notes_tools._get_note_impl(note_id, caller_agent_id="agent-1")
    assert mine["note"].get("by_you") is True
    assert mine["note"]["agent_name"] == "Agent One"
    theirs = notes_tools._get_note_impl(note_id, caller_agent_id="agent-9")
    assert "by_you" not in theirs["note"]

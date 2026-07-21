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
    monkeypatch.setattr(notes_tools.uuid, "uuid4", lambda: next(generated_ids))

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
        notes_tools.uuid,
        "uuid4",
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

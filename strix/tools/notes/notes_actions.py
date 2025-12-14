import uuid
from datetime import UTC, datetime
from typing import Any

from strix.tools.registry import register_tool


_notes_storage: dict[str, dict[str, Any]] = {}


def _filter_notes(
    category: str | None = None,
    tags: list[str] | None = None,
    search_query: str | None = None,
) -> list[dict[str, Any]]:
    filtered_notes = []

    for note_id, note in _notes_storage.items():
        if category and note.get("category") != category:
            continue

        if tags:
            note_tags = note.get("tags", [])
            if not any(tag in note_tags for tag in tags):
                continue

        if search_query:
            search_lower = search_query.lower()
            title_match = search_lower in note.get("title", "").lower()
            content_match = search_lower in note.get("content", "").lower()
            if not (title_match or content_match):
                continue

        note_with_id = note.copy()
        note_with_id["note_id"] = note_id
        filtered_notes.append(note_with_id)

    filtered_notes.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return filtered_notes


@register_tool(sandbox_execution=False)
def create_note(
    title: str,
    content: str,
    category: str = "general",
    tags: list[str] | None = None,
) -> dict[str, Any]:
    try:
        if not title or not title.strip():
            return {"success": False, "error": "Title cannot be empty", "note_id": None}

        if not content or not content.strip():
            return {"success": False, "error": "Content cannot be empty", "note_id": None}

        valid_categories = ["general", "findings", "methodology", "questions", "plan"]
        if category not in valid_categories:
            return {
                "success": False,
                "error": f"Invalid category. Must be one of: {', '.join(valid_categories)}",
                "note_id": None,
            }

        note_id = str(uuid.uuid4())[:5]
        timestamp = datetime.now(UTC).isoformat()

        note = {
            "title": title.strip(),
            "content": content.strip(),
            "category": category,
            "tags": tags or [],
            "created_at": timestamp,
            "updated_at": timestamp,
        }

        _notes_storage[note_id] = note

    except (ValueError, TypeError) as e:
        return {"success": False, "error": f"Failed to create note: {e}", "note_id": None}
    else:
        return {
            "success": True,
            "note_id": note_id,
            "message": f"Note '{title}' created successfully",
        }


@register_tool(sandbox_execution=False)
def list_notes(
    category: str | None = None,
    tags: list[str] | None = None,
    search: str | None = None,
) -> dict[str, Any]:
    try:
        filtered_notes = _filter_notes(category=category, tags=tags, search_query=search)

        return {
            "success": True,
            "notes": filtered_notes,
            "total_count": len(filtered_notes),
        }

    except (ValueError, TypeError) as e:
        return {
            "success": False,
            "error": f"Failed to list notes: {e}",
            "notes": [],
            "total_count": 0,
        }


@register_tool(sandbox_execution=False)
def update_note(
    note_id: str,
    title: str | None = None,
    content: str | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    try:
        if note_id not in _notes_storage:
            return {"success": False, "error": f"Note with ID '{note_id}' not found"}

        note = _notes_storage[note_id]

        if title is not None:
            if not title.strip():
                return {"success": False, "error": "Title cannot be empty"}
            note["title"] = title.strip()

        if content is not None:
            if not content.strip():
                return {"success": False, "error": "Content cannot be empty"}
            note["content"] = content.strip()

        if tags is not None:
            note["tags"] = tags

        note["updated_at"] = datetime.now(UTC).isoformat()

        return {
            "success": True,
            "message": f"Note '{note['title']}' updated successfully",
        }

    except (ValueError, TypeError) as e:
        return {"success": False, "error": f"Failed to update note: {e}"}


@register_tool(sandbox_execution=False)
def delete_note(note_id: str) -> dict[str, Any]:
    try:
        if note_id not in _notes_storage:
            return {"success": False, "error": f"Note with ID '{note_id}' not found"}

        note_title = _notes_storage[note_id]["title"]
        del _notes_storage[note_id]

    except (ValueError, TypeError) as e:
        return {"success": False, "error": f"Failed to delete note: {e}"}
    else:
        return {
            "success": True,
            "message": f"Note '{note_title}' deleted successfully",
        }

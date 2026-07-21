"""Per-run notes storage — mirrored to {state_dir}/notes.json."""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)


_notes_storage: dict[str, dict[str, Any]] = {}
_VALID_NOTE_CATEGORIES = ["general", "findings", "methodology", "questions", "plan", "wiki"]
_notes_lock = threading.RLock()
_DEFAULT_CONTENT_PREVIEW_CHARS = 280
_NOTE_ID_GENERATION_ATTEMPTS = 1024

_notes_path: Path | None = None


def _generate_note_id() -> str | None:
    for _ in range(_NOTE_ID_GENERATION_ATTEMPTS):
        note_id = uuid.uuid4().hex[:6]
        if note_id not in _notes_storage:
            return note_id
    return None


def hydrate_notes_from_disk(state_dir: Path) -> None:
    global _notes_path  # noqa: PLW0603
    _notes_path = state_dir / "notes.json"
    with _notes_lock:
        _notes_storage.clear()
        if not _notes_path.exists():
            return
        try:
            data = json.loads(_notes_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception(
                "notes.json at %s is unreadable; starting with empty notes",
                _notes_path,
            )
            return
        if not isinstance(data, dict):
            return
        _notes_storage.update(
            {
                nid: note
                for nid, note in data.items()
                if isinstance(nid, str) and isinstance(note, dict)
            }
        )
        logger.info(
            "notes hydrated from %s (%d note(s))",
            _notes_path,
            len(_notes_storage),
        )


def _persist() -> None:
    path = _notes_path
    if path is None:
        return
    try:
        payload = json.dumps(_notes_storage, ensure_ascii=False, default=str)
        path.parent.mkdir(parents=True, exist_ok=True)
        with (
            _notes_lock,
            tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=str(path.parent),
                prefix=f".{path.name}.",
                suffix=".tmp",
                delete=False,
            ) as tmp,
        ):
            tmp.write(payload)
            tmp_path = Path(tmp.name)
        tmp_path.replace(path)
    except Exception:
        logger.exception("notes persist to %s failed", path)


def _filter_notes(
    category: str | None = None,
    tags: list[str] | None = None,
    search_query: str | None = None,
) -> list[dict[str, Any]]:
    filtered: list[dict[str, Any]] = []
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
        entry = note.copy()
        entry["note_id"] = note_id
        filtered.append(entry)
    filtered.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return filtered


def _to_note_listing_entry(
    note: dict[str, Any],
    *,
    include_content: bool = False,
) -> dict[str, Any]:
    entry = {
        "note_id": note.get("note_id"),
        "title": note.get("title", ""),
        "category": note.get("category", "general"),
        "tags": note.get("tags", []),
        "created_at": note.get("created_at", ""),
        "updated_at": note.get("updated_at", ""),
    }
    content = str(note.get("content", ""))
    if include_content:
        entry["content"] = content
    elif content:
        if len(content) > _DEFAULT_CONTENT_PREVIEW_CHARS:
            entry["content_preview"] = f"{content[:_DEFAULT_CONTENT_PREVIEW_CHARS].rstrip()}..."
        else:
            entry["content_preview"] = content
    return entry


def _create_note_impl(
    title: str,
    content: str,
    category: str = "general",
    tags: list[str] | None = None,
) -> dict[str, Any]:
    with _notes_lock:
        try:
            if not title or not title.strip():
                return {"success": False, "error": "Title cannot be empty", "note_id": None}
            if not content or not content.strip():
                return {"success": False, "error": "Content cannot be empty", "note_id": None}
            if category not in _VALID_NOTE_CATEGORIES:
                return {
                    "success": False,
                    "error": (
                        f"Invalid category. Must be one of: {', '.join(_VALID_NOTE_CATEGORIES)}"
                    ),
                    "note_id": None,
                }

            note_id = _generate_note_id()
            if note_id is None:
                return {
                    "success": False,
                    "error": "Failed to generate a unique note ID",
                    "note_id": None,
                }

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
            _persist()
            return {
                "success": True,
                "note_id": note_id,
                "message": f"Note '{title}' created successfully",
                "total_count": len(_notes_storage),
            }


def _list_notes_impl(
    category: str | None = None,
    tags: list[str] | None = None,
    search: str | None = None,
    include_content: bool = False,
) -> dict[str, Any]:
    with _notes_lock:
        try:
            filtered = _filter_notes(category=category, tags=tags, search_query=search)
            notes = [_to_note_listing_entry(n, include_content=include_content) for n in filtered]
        except (ValueError, TypeError) as e:
            return {
                "success": False,
                "error": f"Failed to list notes: {e}",
                "notes": [],
                "filtered_count": 0,
                "total_count": 0,
            }
        return {
            "success": True,
            "notes": notes,
            "filtered_count": len(notes),
            "total_count": len(_notes_storage),
        }


def _get_note_impl(note_id: str) -> dict[str, Any]:
    with _notes_lock:
        try:
            if not note_id or not note_id.strip():
                return {"success": False, "error": "Note ID cannot be empty", "note": None}
            note = _notes_storage.get(note_id)
            if note is None:
                return {
                    "success": False,
                    "error": f"Note with ID '{note_id}' not found",
                    "note": None,
                }
            note_with_id = note.copy()
            note_with_id["note_id"] = note_id
        except (ValueError, TypeError) as e:
            return {"success": False, "error": f"Failed to get note: {e}", "note": None}
        else:
            return {"success": True, "note": note_with_id}


def _update_note_impl(
    note_id: str,
    title: str | None = None,
    content: str | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    with _notes_lock:
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
        except (ValueError, TypeError) as e:
            return {"success": False, "error": f"Failed to update note: {e}"}
        else:
            _persist()
            return {
                "success": True,
                "note_id": note_id,
                "message": f"Note '{note['title']}' updated successfully",
                "total_count": len(_notes_storage),
            }


def _delete_note_impl(note_id: str) -> dict[str, Any]:
    with _notes_lock:
        try:
            if note_id not in _notes_storage:
                return {"success": False, "error": f"Note with ID '{note_id}' not found"}
            note = _notes_storage[note_id]
            note_title = note["title"]
            del _notes_storage[note_id]
        except (ValueError, TypeError) as e:
            return {"success": False, "error": f"Failed to delete note: {e}"}
        else:
            _persist()
            return {
                "success": True,
                "note_id": note_id,
                "message": f"Note '{note_title}' deleted successfully",
                "total_count": len(_notes_storage),
            }


@function_tool(timeout=30)
async def create_note(
    ctx: RunContextWrapper,
    title: str,
    content: str,
    category: str = "general",
    tags: list[str] | None = None,
) -> str:
    """Document an observation, finding, methodology step, or research note.

    Notes are visible to every agent in the same scan for the lifetime
    of the run; they live in-memory only and are cleared when the
    process exits.

    For actionable tasks, use ``todo`` instead — notes are for capturing
    information, todos are for tracking work.

    Categories:

    - ``general`` — default, anything that doesn't fit elsewhere.
    - ``findings`` — confirmed vulnerabilities or weaknesses (write
      these up promptly; you'll cite them when filing reports).
    - ``methodology`` — what you tried, what worked, what didn't —
      useful for the final scan report.
    - ``questions`` — open questions / things to come back to.
    - ``plan`` — multi-step plans you want to track.
    - ``wiki`` — long-form repository or target maps.

    Tags are free-form (e.g. ``["sqli", "auth", "critical"]``) — useful
    for later ``list_notes(tags=...)`` filtering.

    Args:
        title: Short headline.
        content: Full note body. Markdown is preserved.
        category: One of the categories above. Default ``"general"``.
        tags: Optional free-form tags.
    """
    return json.dumps(
        await asyncio.to_thread(_create_note_impl, title, content, category, tags),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def list_notes(
    ctx: RunContextWrapper,
    category: str | None = None,
    tags: list[str] | None = None,
    search: str | None = None,
    include_content: bool = False,
) -> str:
    """List existing notes — metadata-first by default.

    Filters compose: passing ``category="findings"`` and
    ``tags=["sqli"]`` returns notes that are *both* in the findings
    category AND have at least one of those tags.

    By default each entry includes a ``content_preview`` (first 280
    chars). Set ``include_content=True`` to get full bodies — useful
    when you need to scan many notes; expensive in tokens for large
    notes.

    Args:
        category: Filter by category.
        tags: Filter to notes that have any of these tags.
        search: Substring match against title and content.
        include_content: When False (default) entries have a preview;
            when True the full ``content`` is included.
    """
    return json.dumps(
        await asyncio.to_thread(
            _list_notes_impl,
            category=category,
            tags=tags,
            search=search,
            include_content=include_content,
        ),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def get_note(ctx: RunContextWrapper, note_id: str) -> str:
    """Fetch one note by its 6-char ID. Returns the full content.

    Args:
        note_id: Note id from ``create_note`` or a ``list_notes`` entry.
    """
    return json.dumps(
        await asyncio.to_thread(_get_note_impl, note_id), ensure_ascii=False, default=str
    )


@function_tool(timeout=30)
async def update_note(
    ctx: RunContextWrapper,
    note_id: str,
    title: str | None = None,
    content: str | None = None,
    tags: list[str] | None = None,
) -> str:
    """Update a note's title, content, or tags.

    Pass ``None`` for any field you want left unchanged. Replacing
    ``content`` is a full overwrite — to append, fetch first with
    ``get_note``, concat, and pass the result.

    Args:
        note_id: Target note's 6-char ID.
        title: New title, or ``None`` to keep.
        content: New content, or ``None`` to keep.
        tags: New tags list, or ``None`` to keep.
    """
    return json.dumps(
        await asyncio.to_thread(
            _update_note_impl,
            note_id=note_id,
            title=title,
            content=content,
            tags=tags,
        ),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def delete_note(ctx: RunContextWrapper, note_id: str) -> str:
    """Delete a note.

    Args:
        note_id: Note id to delete.
    """
    return json.dumps(
        await asyncio.to_thread(_delete_note_impl, note_id), ensure_ascii=False, default=str
    )

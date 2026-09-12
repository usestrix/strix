"""Per-agent todo tools — mirrored to {state_dir}/todos.json."""

from __future__ import annotations

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


VALID_PRIORITIES = ["low", "normal", "high", "critical"]
VALID_STATUSES = ["pending", "in_progress", "done"]

_PRIORITY_RANK = {"critical": 0, "high": 1, "normal": 2, "low": 3}
_STATUS_RANK = {"done": 0, "in_progress": 1, "pending": 2}


def _todo_sort_key(todo: dict[str, Any]) -> tuple[int, int, str]:
    return (
        _STATUS_RANK.get(todo.get("status", "pending"), 99),
        _PRIORITY_RANK.get(todo.get("priority", "normal"), 99),
        todo.get("created_at", ""),
    )


_todos_storage: dict[str, dict[str, dict[str, Any]]] = {}

_todos_path: Path | None = None
_todos_io_lock = threading.RLock()


def hydrate_todos_from_disk(state_dir: Path) -> None:
    global _todos_path  # noqa: PLW0603
    _todos_path = state_dir / "todos.json"
    with _todos_io_lock:
        _todos_storage.clear()
        if not _todos_path.exists():
            return
        try:
            data = json.loads(_todos_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception(
                "todos.json at %s is unreadable; starting with empty todos",
                _todos_path,
            )
            return
        if not isinstance(data, dict):
            return
        loaded = 0
        for aid, by_id in data.items():
            if not isinstance(aid, str) or not isinstance(by_id, dict):
                continue
            cleaned = {
                str(tid): t
                for tid, t in by_id.items()
                if isinstance(tid, str) and isinstance(t, dict)
            }
            if cleaned:
                _todos_storage[aid] = cleaned
                loaded += len(cleaned)
        logger.info(
            "todos hydrated from %s (%d agent(s), %d todo(s))",
            _todos_path,
            len(_todos_storage),
            loaded,
        )


def _persist() -> None:
    path = _todos_path
    if path is None:
        return
    try:
        payload = json.dumps(_todos_storage, ensure_ascii=False, default=str)
        path.parent.mkdir(parents=True, exist_ok=True)
        with (
            _todos_io_lock,
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
        logger.exception("todos persist to %s failed", path)


def _agent_id_from(ctx: RunContextWrapper) -> str:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    return str(inner.get("agent_id") or "default")


def _get_agent_todos(agent_id: str) -> dict[str, dict[str, Any]]:
    return _todos_storage.setdefault(agent_id, {})


def _normalize_priority(priority: str | None, default: str = "normal") -> str:
    candidate = str(priority or default or "normal").strip().lower()
    if candidate not in VALID_PRIORITIES:
        raise ValueError(f"Invalid priority. Must be one of: {', '.join(VALID_PRIORITIES)}")
    return candidate


def _coerce_priority(priority: str | None, default: str = "normal") -> str:
    try:
        return _normalize_priority(priority, default)
    except ValueError:
        return default


def _sorted_todos(agent_id: str) -> list[dict[str, Any]]:
    todos_list = [
        {**todo, "todo_id": todo_id} for todo_id, todo in _get_agent_todos(agent_id).items()
    ]
    todos_list.sort(key=_todo_sort_key)
    return todos_list


def _normalize_todo_ids(raw_ids: Any) -> list[str]:
    if raw_ids is None:
        return []
    if isinstance(raw_ids, str):
        stripped = raw_ids.strip()
        if not stripped:
            return []
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            data = stripped.split(",") if "," in stripped else [stripped]
        if isinstance(data, list):
            return [str(item).strip() for item in data if str(item).strip()]
        return [str(data).strip()]
    if isinstance(raw_ids, list):
        return [str(item).strip() for item in raw_ids if str(item).strip()]
    return [str(raw_ids).strip()]


def _normalize_bulk_updates(raw_updates: Any) -> list[dict[str, Any]]:
    if raw_updates is None:
        return []
    data: Any = raw_updates
    if isinstance(raw_updates, str):
        stripped = raw_updates.strip()
        if not stripped:
            return []
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as e:
            raise ValueError("Updates must be valid JSON") from e

    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise TypeError("Updates must be a list of update objects")

    normalized: list[dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict):
            raise TypeError("Each update must be an object with todo_id")
        todo_id = item.get("todo_id") or item.get("id")
        if not todo_id:
            raise ValueError("Each update must include 'todo_id'")
        normalized.append(
            {
                "todo_id": str(todo_id).strip(),
                "title": item.get("title"),
                "description": item.get("description"),
                "priority": item.get("priority"),
                "status": item.get("status"),
            },
        )
    return normalized


def _normalize_bulk_todos(raw_todos: Any) -> list[dict[str, Any]]:
    if raw_todos is None:
        return []
    data: Any = raw_todos
    if isinstance(raw_todos, str):
        stripped = raw_todos.strip()
        if not stripped:
            return []
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            entries = [line.strip(" -*\t") for line in stripped.splitlines() if line.strip(" -*\t")]
            return [{"title": entry} for entry in entries]

    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise TypeError("Todos must be provided as a list, dict, or JSON string")

    normalized: list[dict[str, Any]] = []
    for item in data:
        if isinstance(item, str):
            title = item.strip()
            if title:
                normalized.append({"title": title})
            continue
        if not isinstance(item, dict):
            raise TypeError("Each todo entry must be a string or object with a title")
        title = item.get("title", "")
        if not isinstance(title, str) or not title.strip():
            raise ValueError("Each todo entry must include a non-empty 'title'")
        normalized.append(
            {
                "title": title.strip(),
                "description": (item.get("description") or "").strip() or None,
                "priority": item.get("priority"),
            },
        )
    return normalized


def _apply_single_update(
    agent_todos: dict[str, dict[str, Any]],
    todo_id: str,
    title: str | None = None,
    description: str | None = None,
    priority: str | None = None,
    status: str | None = None,
) -> dict[str, Any] | None:
    if todo_id not in agent_todos:
        return {"todo_id": todo_id, "error": f"Todo with ID '{todo_id}' not found"}
    todo = agent_todos[todo_id]
    if title is not None:
        if not title.strip():
            return {"todo_id": todo_id, "error": "Title cannot be empty"}
        todo["title"] = title.strip()
    if description is not None:
        todo["description"] = description.strip() if description else None
    if priority is not None:
        try:
            todo["priority"] = _normalize_priority(priority, str(todo.get("priority", "normal")))
        except ValueError as exc:
            return {"todo_id": todo_id, "error": str(exc)}
    if status is not None:
        status_candidate = status.lower()
        if status_candidate not in VALID_STATUSES:
            return {
                "todo_id": todo_id,
                "error": f"Invalid status. Must be one of: {', '.join(VALID_STATUSES)}",
            }
        todo["status"] = status_candidate
        todo["completed_at"] = datetime.now(UTC).isoformat() if status_candidate == "done" else None
    todo["updated_at"] = datetime.now(UTC).isoformat()
    return None


@function_tool(timeout=30)
async def create_todo(ctx: RunContextWrapper, todos: str) -> str:
    """Create one or many todos for the current agent.

    Always pass a list, even for a single todo (wrap it in a one-item array).

    Each agent (including subagents) has its **own private todo list** —
    your todos don't leak to other agents and vice versa.

    When to use:

    - Planning multi-step assessments with parallel workstreams.
    - Tracking work you'll come back to later.
    - Breaking down complex scopes (per-endpoint, per-target, per-vuln-class).

    When NOT to use:

    - Simple linear workflows where progress is obvious.
    - Single quick task — just do it.

    Args:
        todos: JSON array of todo objects. For one todo, pass a one-item
            list. Each object's fields:

            - ``title`` (str, **required**): short actionable title,
              e.g. ``"Test /api/admin for IDOR"``.
            - ``description`` (str, optional): extra context or
              acceptance criteria.
            - ``priority`` (str, optional): one of ``"low"`` /
              ``"normal"`` / ``"high"`` / ``"critical"``. Anything else,
              including omitting it, falls back to ``"normal"`` rather
              than failing.

            Example: ``[{"title": "Probe /admin", "priority": "high"},
            {"title": "Check JWT alg=none"}]``.

        A title already on the list, or repeated within this call, is
        skipped rather than duplicated; skipped titles come back under
        ``skipped``.
    """
    agent_id = _agent_id_from(ctx)
    try:
        tasks = _normalize_bulk_todos(todos)
        if not tasks:
            return json.dumps(
                {"success": False, "error": "Provide a non-empty 'todos' list to create"},
                ensure_ascii=False,
                default=str,
            )

        agent_todos = _get_agent_todos(agent_id)
        seen = {todo["title"].strip().lower() for todo in agent_todos.values()}
        created: list[dict[str, Any]] = []
        skipped: list[dict[str, str]] = []
        for task in tasks:
            title = task["title"]
            key = title.lower()
            if key in seen:
                skipped.append({"title": title, "reason": "duplicate title"})
                continue
            seen.add(key)
            task_priority = _coerce_priority(task.get("priority"))
            todo_id = str(uuid.uuid4())[:6]
            timestamp = datetime.now(UTC).isoformat()
            agent_todos[todo_id] = {
                "title": title,
                "description": task.get("description"),
                "priority": task_priority,
                "status": "pending",
                "created_at": timestamp,
                "updated_at": timestamp,
                "completed_at": None,
            }
            created.append({"todo_id": todo_id, "title": title, "priority": task_priority})
    except (ValueError, TypeError) as e:
        return json.dumps(
            {"success": False, "error": f"Failed to create todo: {e}"},
            ensure_ascii=False,
            default=str,
        )

    _persist()
    return json.dumps(
        {
            "success": True,
            "created": created,
            "created_count": len(created),
            "skipped": skipped,
            "todos": _sorted_todos(agent_id),
            "total_count": len(_get_agent_todos(agent_id)),
        },
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def list_todos(
    ctx: RunContextWrapper,
    status: str | None = None,
    priority: str | None = None,
) -> str:
    """List the current agent's todos, sorted by status then priority.

    Sort order: status (done → in_progress → pending), then priority
    within each status (critical → high → normal → low).

    Args:
        status: Filter — ``"pending"`` / ``"in_progress"`` / ``"done"``.
        priority: Filter — ``"low"`` / ``"normal"`` / ``"high"`` /
            ``"critical"``.
    """
    agent_id = _agent_id_from(ctx)
    try:
        agent_todos = _get_agent_todos(agent_id)
        status_filter = status.lower() if isinstance(status, str) else None
        priority_filter = priority.lower() if isinstance(priority, str) else None

        todos_list: list[dict[str, Any]] = []
        for todo_id, todo in agent_todos.items():
            if status_filter and todo.get("status") != status_filter:
                continue
            if priority_filter and todo.get("priority") != priority_filter:
                continue
            entry = todo.copy()
            entry["todo_id"] = todo_id
            todos_list.append(entry)

        todos_list.sort(key=_todo_sort_key)

        summary: dict[str, int] = {"pending": 0, "in_progress": 0, "done": 0}
        for todo in todos_list:
            sv = todo.get("status", "pending")
            summary[sv] = summary.get(sv, 0) + 1
    except (ValueError, TypeError) as e:
        return json.dumps(
            {
                "success": False,
                "error": f"Failed to list todos: {e}",
                "todos": [],
                "filtered_count": 0,
                "total_count": 0,
                "summary": {"pending": 0, "in_progress": 0, "done": 0},
            },
            ensure_ascii=False,
            default=str,
        )

    return json.dumps(
        {
            "success": True,
            "todos": todos_list,
            "filtered_count": len(todos_list),
            "total_count": len(agent_todos),
            "summary": summary,
        },
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def update_todo(ctx: RunContextWrapper, updates: str) -> str:
    """Update one or many todos.

    Always pass a list, even for a single update (wrap it in a one-item
    array).

    For toggling status only, prefer the dedicated ``mark_todo_done`` /
    ``mark_todo_pending`` tools — they're simpler and accept the same
    list-of-ids form.

    Args:
        updates: JSON array of update objects. For one update, pass a
            one-item list. Each object's fields:

            - ``todo_id`` (str, **required**): ID returned by
              ``create_todo``.
            - ``title`` (str, optional): new title.
            - ``description`` (str, optional): new description (empty
              string clears it).
            - ``priority`` (str, optional): one of ``"low"`` /
              ``"normal"`` / ``"high"`` / ``"critical"``.
            - ``status`` (str, optional): one of ``"pending"`` /
              ``"in_progress"`` / ``"done"``.

            Omitted fields stay unchanged. Example:
            ``[{"todo_id": "abc", "status": "in_progress",
            "priority": "high"}]``.
    """
    agent_id = _agent_id_from(ctx)
    try:
        agent_todos = _get_agent_todos(agent_id)
        updates_to_apply = _normalize_bulk_updates(updates)
        if not updates_to_apply:
            return json.dumps(
                {"success": False, "error": "Provide a non-empty 'updates' list"},
                ensure_ascii=False,
                default=str,
            )

        updated: list[str] = []
        errors: list[dict[str, Any]] = []
        for upd in updates_to_apply:
            err = _apply_single_update(
                agent_todos,
                upd["todo_id"],
                upd.get("title"),
                upd.get("description"),
                upd.get("priority"),
                upd.get("status"),
            )
            if err:
                errors.append(err)
            else:
                updated.append(upd["todo_id"])
    except (ValueError, TypeError) as e:
        return json.dumps({"success": False, "error": str(e)}, ensure_ascii=False, default=str)

    if updated:
        _persist()
    response: dict[str, Any] = {
        "success": len(errors) == 0,
        "updated": updated,
        "updated_count": len(updated),
        "todos": _sorted_todos(agent_id),
        "total_count": len(agent_todos),
    }
    if errors:
        response["errors"] = errors
    return json.dumps(response, ensure_ascii=False, default=str)


def _mark(*, agent_id: str, todo_ids: str, new_status: str) -> str:
    try:
        agent_todos = _get_agent_todos(agent_id)
        ids = _normalize_todo_ids(todo_ids)
        if not ids:
            msg = f"Provide a non-empty 'todo_ids' list to mark as {new_status}"
            return json.dumps({"success": False, "error": msg}, ensure_ascii=False, default=str)

        marked: list[str] = []
        errors: list[dict[str, Any]] = []
        timestamp = datetime.now(UTC).isoformat()
        for tid in ids:
            if tid not in agent_todos:
                errors.append({"todo_id": tid, "error": f"Todo with ID '{tid}' not found"})
                continue
            todo = agent_todos[tid]
            todo["status"] = new_status
            todo["completed_at"] = timestamp if new_status == "done" else None
            todo["updated_at"] = timestamp
            marked.append(tid)
    except (ValueError, TypeError) as e:
        return json.dumps({"success": False, "error": str(e)}, ensure_ascii=False, default=str)

    if marked:
        _persist()
    response: dict[str, Any] = {
        "success": len(errors) == 0,
        "marked": marked,
        "marked_count": len(marked),
        "new_status": new_status,
        "todos": _sorted_todos(agent_id),
        "total_count": len(agent_todos),
    }
    if errors:
        response["errors"] = errors
    return json.dumps(response, ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def mark_todo_done(ctx: RunContextWrapper, todo_ids: str) -> str:
    """Mark one or many todos as done.

    Always pass a list, even for a single ID (wrap it in a one-item array).

    Args:
        todo_ids: JSON array of todo IDs to mark done. For one todo,
            pass a one-item list.
    """
    return _mark(agent_id=_agent_id_from(ctx), todo_ids=todo_ids, new_status="done")


@function_tool(timeout=30)
async def mark_todo_pending(ctx: RunContextWrapper, todo_ids: str) -> str:
    """Reset one or many todos to pending (e.g., to retry a failed task).

    Always pass a list, even for a single ID (wrap it in a one-item array).

    Args:
        todo_ids: JSON array of todo IDs to reset to pending. For one
            todo, pass a one-item list.
    """
    return _mark(agent_id=_agent_id_from(ctx), todo_ids=todo_ids, new_status="pending")


@function_tool(timeout=30)
async def delete_todo(ctx: RunContextWrapper, todo_ids: str) -> str:
    """Delete one or many todos. Removes them entirely (no soft-delete).

    Always pass a list, even for a single ID (wrap it in a one-item array).

    Args:
        todo_ids: JSON array of todo IDs to delete. For one todo, pass
            a one-item list.
    """
    agent_id = _agent_id_from(ctx)
    try:
        agent_todos = _get_agent_todos(agent_id)
        ids = _normalize_todo_ids(todo_ids)
        if not ids:
            return json.dumps(
                {"success": False, "error": "Provide a non-empty 'todo_ids' list to delete"},
                ensure_ascii=False,
                default=str,
            )

        deleted: list[str] = []
        errors: list[dict[str, Any]] = []
        for tid in ids:
            if tid not in agent_todos:
                errors.append({"todo_id": tid, "error": f"Todo with ID '{tid}' not found"})
                continue
            del agent_todos[tid]
            deleted.append(tid)
    except (ValueError, TypeError) as e:
        return json.dumps({"success": False, "error": str(e)}, ensure_ascii=False, default=str)

    if deleted:
        _persist()
    response: dict[str, Any] = {
        "success": len(errors) == 0,
        "deleted": deleted,
        "deleted_count": len(deleted),
        "todos": _sorted_todos(agent_id),
        "total_count": len(agent_todos),
    }
    if errors:
        response["errors"] = errors
    return json.dumps(response, ensure_ascii=False, default=str)

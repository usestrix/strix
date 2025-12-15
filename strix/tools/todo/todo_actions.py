import json
import uuid
from datetime import UTC, datetime
from typing import Any

from strix.tools.registry import register_tool


VALID_PRIORITIES = ["low", "normal", "high", "critical"]
VALID_STATUSES = ["pending", "in_progress", "done"]

_todos_storage: dict[str, dict[str, dict[str, Any]]] = {}


def _get_agent_todos(agent_id: str) -> dict[str, dict[str, Any]]:
    if agent_id not in _todos_storage:
        _todos_storage[agent_id] = {}
    return _todos_storage[agent_id]


def _normalize_priority(priority: str | None, default: str = "normal") -> str:
    candidate = (priority or default or "normal").lower()
    if candidate not in VALID_PRIORITIES:
        raise ValueError(f"Invalid priority. Must be one of: {', '.join(VALID_PRIORITIES)}")
    return candidate


def _sorted_todos(agent_id: str) -> list[dict[str, Any]]:
    agent_todos = _get_agent_todos(agent_id)

    todos_list: list[dict[str, Any]] = []
    for todo_id, todo in agent_todos.items():
        entry = todo.copy()
        entry["todo_id"] = todo_id
        todos_list.append(entry)

    priority_order = {"critical": 0, "high": 1, "normal": 2, "low": 3}
    status_order = {"done": 0, "in_progress": 1, "pending": 2}

    todos_list.sort(
        key=lambda x: (
            status_order.get(x.get("status", "pending"), 99),
            priority_order.get(x.get("priority", "normal"), 99),
            x.get("created_at", ""),
        )
    )
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

    data = raw_updates
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
            }
        )

    return normalized


def _normalize_bulk_todos(raw_todos: Any) -> list[dict[str, Any]]:
    if raw_todos is None:
        return []

    data = raw_todos
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
            }
        )

    return normalized


@register_tool(sandbox_execution=False)
def create_todo(
    agent_state: Any,
    title: str | None = None,
    description: str | None = None,
    priority: str = "normal",
    todos: Any | None = None,
) -> dict[str, Any]:
    try:
        agent_id = agent_state.agent_id
        default_priority = _normalize_priority(priority)

        tasks_to_create: list[dict[str, Any]] = []

        if todos is not None:
            tasks_to_create.extend(_normalize_bulk_todos(todos))

        if title and title.strip():
            tasks_to_create.append(
                {
                    "title": title.strip(),
                    "description": description.strip() if description else None,
                    "priority": default_priority,
                }
            )

        if not tasks_to_create:
            return {
                "success": False,
                "error": "Provide a title or 'todos' list to create.",
                "todo_id": None,
            }

        agent_todos = _get_agent_todos(agent_id)
        created: list[dict[str, Any]] = []

        for task in tasks_to_create:
            task_priority = _normalize_priority(task.get("priority"), default_priority)
            todo_id = str(uuid.uuid4())[:6]
            timestamp = datetime.now(UTC).isoformat()

            todo = {
                "title": task["title"],
                "description": task.get("description"),
                "priority": task_priority,
                "status": "pending",
                "created_at": timestamp,
                "updated_at": timestamp,
                "completed_at": None,
            }

            agent_todos[todo_id] = todo
            created.append(
                {
                    "todo_id": todo_id,
                    "title": task["title"],
                    "priority": task_priority,
                }
            )

    except (ValueError, TypeError) as e:
        return {"success": False, "error": f"Failed to create todo: {e}", "todo_id": None}
    else:
        todos_list = _sorted_todos(agent_id)

        response: dict[str, Any] = {
            "success": True,
            "created": created,
            "count": len(created),
            "todos": todos_list,
            "total_count": len(todos_list),
        }
        return response


@register_tool(sandbox_execution=False)
def list_todos(
    agent_state: Any,
    status: str | None = None,
    priority: str | None = None,
) -> dict[str, Any]:
    try:
        agent_id = agent_state.agent_id
        agent_todos = _get_agent_todos(agent_id)

        status_filter = status.lower() if isinstance(status, str) else None
        priority_filter = priority.lower() if isinstance(priority, str) else None

        todos_list = []
        for todo_id, todo in agent_todos.items():
            if status_filter and todo.get("status") != status_filter:
                continue

            if priority_filter and todo.get("priority") != priority_filter:
                continue

            todo_with_id = todo.copy()
            todo_with_id["todo_id"] = todo_id
            todos_list.append(todo_with_id)

        priority_order = {"critical": 0, "high": 1, "normal": 2, "low": 3}
        status_order = {"done": 0, "in_progress": 1, "pending": 2}

        todos_list.sort(
            key=lambda x: (
                status_order.get(x.get("status", "pending"), 99),
                priority_order.get(x.get("priority", "normal"), 99),
                x.get("created_at", ""),
            )
        )

        summary_counts = {
            "pending": 0,
            "in_progress": 0,
            "done": 0,
        }
        for todo in todos_list:
            status_value = todo.get("status", "pending")
            if status_value not in summary_counts:
                summary_counts[status_value] = 0
            summary_counts[status_value] += 1

        return {
            "success": True,
            "todos": todos_list,
            "total_count": len(todos_list),
            "summary": summary_counts,
        }

    except (ValueError, TypeError) as e:
        return {
            "success": False,
            "error": f"Failed to list todos: {e}",
            "todos": [],
            "total_count": 0,
            "summary": {"pending": 0, "in_progress": 0, "done": 0},
        }


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
        if status_candidate == "done":
            todo["completed_at"] = datetime.now(UTC).isoformat()
        else:
            todo["completed_at"] = None

    todo["updated_at"] = datetime.now(UTC).isoformat()
    return None


@register_tool(sandbox_execution=False)
def update_todo(
    agent_state: Any,
    todo_id: str | None = None,
    title: str | None = None,
    description: str | None = None,
    priority: str | None = None,
    status: str | None = None,
    updates: Any | None = None,
) -> dict[str, Any]:
    try:
        agent_id = agent_state.agent_id
        agent_todos = _get_agent_todos(agent_id)

        updates_to_apply: list[dict[str, Any]] = []

        if updates is not None:
            updates_to_apply.extend(_normalize_bulk_updates(updates))

        if todo_id is not None:
            updates_to_apply.append(
                {
                    "todo_id": todo_id,
                    "title": title,
                    "description": description,
                    "priority": priority,
                    "status": status,
                }
            )

        if not updates_to_apply:
            return {
                "success": False,
                "error": "Provide todo_id or 'updates' list to update.",
            }

        updated: list[str] = []
        errors: list[dict[str, Any]] = []

        for update in updates_to_apply:
            error = _apply_single_update(
                agent_todos,
                update["todo_id"],
                update.get("title"),
                update.get("description"),
                update.get("priority"),
                update.get("status"),
            )
            if error:
                errors.append(error)
            else:
                updated.append(update["todo_id"])

        todos_list = _sorted_todos(agent_id)

        response: dict[str, Any] = {
            "success": len(errors) == 0,
            "updated": updated,
            "updated_count": len(updated),
            "todos": todos_list,
            "total_count": len(todos_list),
        }

        if errors:
            response["errors"] = errors

    except (ValueError, TypeError) as e:
        return {"success": False, "error": str(e)}
    else:
        return response


@register_tool(sandbox_execution=False)
def mark_todo_done(
    agent_state: Any,
    todo_id: str | None = None,
    todo_ids: Any | None = None,
) -> dict[str, Any]:
    try:
        agent_id = agent_state.agent_id
        agent_todos = _get_agent_todos(agent_id)

        ids_to_mark: list[str] = []
        if todo_ids is not None:
            ids_to_mark.extend(_normalize_todo_ids(todo_ids))
        if todo_id is not None:
            ids_to_mark.append(todo_id)

        if not ids_to_mark:
            return {"success": False, "error": "Provide todo_id or todo_ids to mark as done."}

        marked: list[str] = []
        errors: list[dict[str, Any]] = []
        timestamp = datetime.now(UTC).isoformat()

        for tid in ids_to_mark:
            if tid not in agent_todos:
                errors.append({"todo_id": tid, "error": f"Todo with ID '{tid}' not found"})
                continue

            todo = agent_todos[tid]
            todo["status"] = "done"
            todo["completed_at"] = timestamp
            todo["updated_at"] = timestamp
            marked.append(tid)

        todos_list = _sorted_todos(agent_id)

        response: dict[str, Any] = {
            "success": len(errors) == 0,
            "marked_done": marked,
            "marked_count": len(marked),
            "todos": todos_list,
            "total_count": len(todos_list),
        }

        if errors:
            response["errors"] = errors

    except (ValueError, TypeError) as e:
        return {"success": False, "error": str(e)}
    else:
        return response


@register_tool(sandbox_execution=False)
def mark_todo_pending(
    agent_state: Any,
    todo_id: str | None = None,
    todo_ids: Any | None = None,
) -> dict[str, Any]:
    try:
        agent_id = agent_state.agent_id
        agent_todos = _get_agent_todos(agent_id)

        ids_to_mark: list[str] = []
        if todo_ids is not None:
            ids_to_mark.extend(_normalize_todo_ids(todo_ids))
        if todo_id is not None:
            ids_to_mark.append(todo_id)

        if not ids_to_mark:
            return {"success": False, "error": "Provide todo_id or todo_ids to mark as pending."}

        marked: list[str] = []
        errors: list[dict[str, Any]] = []
        timestamp = datetime.now(UTC).isoformat()

        for tid in ids_to_mark:
            if tid not in agent_todos:
                errors.append({"todo_id": tid, "error": f"Todo with ID '{tid}' not found"})
                continue

            todo = agent_todos[tid]
            todo["status"] = "pending"
            todo["completed_at"] = None
            todo["updated_at"] = timestamp
            marked.append(tid)

        todos_list = _sorted_todos(agent_id)

        response: dict[str, Any] = {
            "success": len(errors) == 0,
            "marked_pending": marked,
            "marked_count": len(marked),
            "todos": todos_list,
            "total_count": len(todos_list),
        }

        if errors:
            response["errors"] = errors

    except (ValueError, TypeError) as e:
        return {"success": False, "error": str(e)}
    else:
        return response


@register_tool(sandbox_execution=False)
def delete_todo(
    agent_state: Any,
    todo_id: str | None = None,
    todo_ids: Any | None = None,
) -> dict[str, Any]:
    try:
        agent_id = agent_state.agent_id
        agent_todos = _get_agent_todos(agent_id)

        ids_to_delete: list[str] = []
        if todo_ids is not None:
            ids_to_delete.extend(_normalize_todo_ids(todo_ids))
        if todo_id is not None:
            ids_to_delete.append(todo_id)

        if not ids_to_delete:
            return {"success": False, "error": "Provide todo_id or todo_ids to delete."}

        deleted: list[str] = []
        errors: list[dict[str, Any]] = []

        for tid in ids_to_delete:
            if tid not in agent_todos:
                errors.append({"todo_id": tid, "error": f"Todo with ID '{tid}' not found"})
                continue

            del agent_todos[tid]
            deleted.append(tid)

        todos_list = _sorted_todos(agent_id)

        response: dict[str, Any] = {
            "success": len(errors) == 0,
            "deleted": deleted,
            "deleted_count": len(deleted),
            "todos": todos_list,
            "total_count": len(todos_list),
        }

        if errors:
            response["errors"] = errors

    except (ValueError, TypeError) as e:
        return {"success": False, "error": str(e)}
    else:
        return response

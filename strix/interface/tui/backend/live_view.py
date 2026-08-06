"""Go-TUI event projection layered on the shared base projection."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from strix.interface.tui.live_view import TuiLiveView as BaseLiveView


_MAX_LIVE_EVENTS = 10_000


class TuiLiveView(BaseLiveView):
    """Add protocol cursors and bounds on top of the shared projection state."""

    def __init__(self) -> None:
        super().__init__()
        self._event_cursor = 0
        self._event_change_cursor: dict[str, int] = {}
        self._events_by_id: dict[str, dict[str, Any]] = {}

    def upsert_agent(  # type: ignore[override]
        self,
        agent_id: str,
        *,
        name: str | None = None,
        parent_id: str | None = None,
        status: str | None = None,
        error_message: str | None = None,
    ) -> bool:
        now = datetime.now(UTC).isoformat()
        current = self.agents.get(agent_id)
        if current is None:
            current = {
                "id": agent_id,
                "name": name or agent_id,
                "parent_id": parent_id,
                "status": status or "running",
                "created_at": now,
                "updated_at": now,
            }
            if error_message:
                current["error_message"] = error_message
            self.agents[agent_id] = current
            return True

        changed = False
        if name is not None and current.get("name") != name:
            current["name"] = name
            changed = True
        if (parent_id is not None or "parent_id" not in current) and current.get(
            "parent_id"
        ) != parent_id:
            current["parent_id"] = parent_id
            changed = True
        if status is not None and current.get("status") != status:
            current["status"] = status
            changed = True
        if error_message and current.get("error_message") != error_message:
            current["error_message"] = error_message
            changed = True
        if changed:
            current["updated_at"] = now
        return changed

    def _append_event(
        self,
        agent_id: str,
        event_type: str,
        data: dict[str, Any],
        *,
        timestamp: str | None = None,
    ) -> dict[str, Any]:
        event = super()._append_event(
            agent_id,
            event_type,
            data,
            timestamp=timestamp,
        )
        self._events_by_id[event["id"]] = event
        self._mark_event_changed(event)
        if len(self.events) > _MAX_LIVE_EVENTS:
            removed = self.events.pop(0)
            removed_id = str(removed.get("id", ""))
            self._events_by_id.pop(removed_id, None)
            self._event_change_cursor.pop(removed_id, None)
            self._open_assistant_event_by_agent = {
                current_agent_id: current
                for current_agent_id, current in self._open_assistant_event_by_agent.items()
                if current is not removed
            }
            self._tool_event_by_agent_and_call_id = {
                key: current
                for key, current in self._tool_event_by_agent_and_call_id.items()
                if current is not removed
            }
        return event

    def _bump_event(  # type: ignore[override]
        self,
        event: dict[str, Any],
        *,
        timestamp: str | None = None,
    ) -> None:
        event["version"] = int(event.get("version", 0)) + 1
        event["timestamp"] = timestamp or datetime.now(UTC).isoformat()
        self._mark_event_changed(event)

    def _mark_event_changed(self, event: dict[str, Any]) -> None:
        event_id = event.get("id")
        if not isinstance(event_id, str) or not event_id:
            return
        self._event_cursor += 1
        self._event_change_cursor[event_id] = self._event_cursor

    def event_snapshot(self, *, limit: int | None = None) -> tuple[int, list[dict[str, Any]]]:
        events = self.events[-limit:] if limit is not None else self.events
        return self._event_cursor, list(events)

    def event_changes_since(self, cursor: int) -> tuple[int, list[dict[str, Any]]]:
        if cursor < 0 or cursor > self._event_cursor:
            raise ValueError("event cursor is outside the available history")
        changed_ids = sorted(
            (
                (change_cursor, event_id)
                for event_id, change_cursor in self._event_change_cursor.items()
                if change_cursor > cursor
            )
        )
        changed = [
            self._events_by_id[event_id]
            for _change_cursor, event_id in changed_ids
            if event_id in self._events_by_id
        ]
        return self._event_cursor, changed

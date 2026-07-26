"""TUI-owned projection of SDK session history and stream events."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from pathlib import Path

from strix.core.paths import runtime_state_dir
from strix.interface.tui.history import load_session_history


class TuiLiveView:
    def __init__(self) -> None:
        self.agents: dict[str, dict[str, Any]] = {}
        self.events: list[dict[str, Any]] = []
        self._next_event_id = 1
        self._open_assistant_event_by_agent: dict[str, dict[str, Any]] = {}
        self._tool_event_by_call_id: dict[str, dict[str, Any]] = {}

    def hydrate_from_run_dir(self, run_dir: Path) -> None:
        state_dir = runtime_state_dir(run_dir)
        agents_path = state_dir / "agents.json"
        if not agents_path.exists():
            return
        try:
            agents_data = json.loads(agents_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        statuses = agents_data.get("statuses") or {}
        names = agents_data.get("names") or {}
        parent_of = agents_data.get("parent_of") or {}
        if not isinstance(statuses, dict):
            return
        for agent_id, status in statuses.items():
            if not isinstance(agent_id, str):
                continue
            self.upsert_agent(
                agent_id,
                name=names.get(agent_id, agent_id) if isinstance(names, dict) else agent_id,
                parent_id=parent_of.get(agent_id) if isinstance(parent_of, dict) else None,
                status=str(status),
            )
        self._hydrate_sdk_session_history(run_dir, statuses.keys())

    def _hydrate_sdk_session_history(self, run_dir: Path, agent_ids: Any) -> None:
        for agent_id, item, timestamp in load_session_history(run_dir, agent_ids):
            self._ingest_session_history_item(
                agent_id,
                item,
                timestamp=timestamp,
            )

    def upsert_agent(
        self,
        agent_id: str,
        *,
        name: str | None = None,
        parent_id: str | None = None,
        status: str | None = None,
        error_message: str | None = None,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        current = self.agents.setdefault(
            agent_id,
            {
                "id": agent_id,
                "name": name or agent_id,
                "parent_id": parent_id,
                "status": status or "running",
                "created_at": now,
                "updated_at": now,
            },
        )
        if name is not None:
            current["name"] = name
        if parent_id is not None or "parent_id" not in current:
            current["parent_id"] = parent_id
        if status is not None:
            current["status"] = status
        if error_message:
            current["error_message"] = error_message
        current["updated_at"] = now

    def record_agent_error(self, agent_id: str, error: str) -> None:
        self._append_event(
            agent_id,
            "chat",
            {
                "role": "assistant",
                "content": (f"An error occurred: {error}\nI'm now waiting for new instructions."),
                "metadata": {"source": "agent_error"},
            },
        )

    def record_user_message(self, agent_id: str, content: str) -> None:
        self._append_event(
            agent_id,
            "chat",
            {
                "role": "user",
                "content": content,
                "metadata": {"source": "tui_user"},
            },
        )

    def ingest_sdk_event(self, agent_id: str, event: Any) -> None:
        event_type = getattr(event, "type", "")
        if event_type == "raw_response_event":
            self._ingest_raw_response_event(agent_id, getattr(event, "data", None))
            return
        if event_type != "run_item_stream_event":
            return

        item = getattr(event, "item", None)
        item_type = getattr(item, "type", "")
        if item_type == "message_output_item":
            self._record_assistant_message(agent_id, _sdk_message_text(item), final=True)
        elif item_type == "tool_call_item":
            self._record_tool_call(agent_id, item)
        elif item_type == "tool_call_output_item":
            self._record_tool_output(agent_id, item)

    def events_for_agent(self, agent_id: str) -> list[dict[str, Any]]:
        return [event for event in self.events if event.get("agent_id") == agent_id]

    def has_events_for_agent(self, agent_id: str) -> bool:
        return any(event.get("agent_id") == agent_id for event in self.events)

    def _ingest_raw_response_event(self, agent_id: str, data: Any) -> None:
        data_type = getattr(data, "type", "")
        if data_type == "response.output_text.delta":
            delta = getattr(data, "delta", "")
            if delta:
                self._record_assistant_message(agent_id, str(delta), final=False)

    def _ingest_session_history_item(
        self,
        agent_id: str,
        item: dict[str, Any],
        *,
        timestamp: str,
    ) -> None:
        item_type = item.get("type")
        role = item.get("role")
        if role in {"user", "assistant"} and (item_type in {None, "message"}):
            content = _session_message_text(item)
            if content:
                self._append_event(
                    agent_id,
                    "chat",
                    {
                        "role": role,
                        "content": content,
                        "metadata": {"source": "sdk_session"},
                    },
                    timestamp=timestamp,
                )
            return

        if item_type == "function_call":
            self._record_tool_call_data(
                agent_id,
                {
                    "call_id": str(item.get("call_id") or item.get("id") or ""),
                    "tool_name": str(item.get("name") or "tool"),
                    "args": _parse_json_object(item.get("arguments")),
                },
                timestamp=timestamp,
            )
            return

        if item_type == "function_call_output":
            self._record_tool_output_data(
                agent_id,
                {
                    "call_id": str(item.get("call_id") or item.get("id") or ""),
                    "tool_name": "tool",
                    "output": item.get("output"),
                },
                timestamp=timestamp,
            )

    def _record_assistant_message(self, agent_id: str, content: str, *, final: bool) -> None:
        if not content:
            return
        existing = self._open_assistant_event_by_agent.get(agent_id)
        if existing is None:
            event = self._append_event(
                agent_id,
                "chat",
                {
                    "role": "assistant",
                    "content": content,
                    "metadata": {"source": "sdk_stream", "streaming": not final},
                },
            )
            if not final:
                self._open_assistant_event_by_agent[agent_id] = event
            return

        data = existing["data"]
        if final:
            data["content"] = content
            data["metadata"]["streaming"] = False
            self._open_assistant_event_by_agent.pop(agent_id, None)
        else:
            data["content"] = f"{data.get('content', '')}{content}"
        self._bump_event(existing)

    def _record_tool_call(self, agent_id: str, item: Any) -> None:
        self._record_tool_call_data(agent_id, _sdk_tool_call_data(item))

    def _record_tool_call_data(
        self,
        agent_id: str,
        call: dict[str, Any],
        *,
        timestamp: str | None = None,
    ) -> None:
        call_id = call["call_id"]
        existing = self._tool_event_by_call_id.get(call_id)
        tool_data = {
            "tool_name": call["tool_name"],
            "args": call["args"],
            "status": "running",
            "agent_id": agent_id,
            "call_id": call_id,
        }
        if existing is None:
            event = self._append_event(agent_id, "tool", tool_data, timestamp=timestamp)
            self._tool_event_by_call_id[call_id] = event
        else:
            existing["data"].update(tool_data)
            self._bump_event(existing, timestamp=timestamp)

    def _record_tool_output(self, agent_id: str, item: Any) -> None:
        self._record_tool_output_data(agent_id, _sdk_tool_output_data(item))

    def _record_tool_output_data(
        self,
        agent_id: str,
        output: dict[str, Any],
        *,
        timestamp: str | None = None,
    ) -> None:
        call_id = output["call_id"]
        event = self._tool_event_by_call_id.get(call_id)
        if event is None:
            event = self._append_event(
                agent_id,
                "tool",
                {
                    "tool_name": output["tool_name"],
                    "args": {},
                    "status": "completed",
                    "agent_id": agent_id,
                    "call_id": call_id,
                },
                timestamp=timestamp,
            )
            self._tool_event_by_call_id[call_id] = event

        result = _parse_json_value(output["output"])
        event["data"]["result"] = result
        event["data"]["status"] = _tool_status_from_result(result)
        self._bump_event(event, timestamp=timestamp)

    def _append_event(
        self,
        agent_id: str,
        event_type: str,
        data: dict[str, Any],
        *,
        timestamp: str | None = None,
    ) -> dict[str, Any]:
        event = {
            "id": f"{event_type}_{self._next_event_id}",
            "type": event_type,
            "agent_id": agent_id,
            "timestamp": timestamp or datetime.now(UTC).isoformat(),
            "version": 0,
            "data": data,
        }
        self._next_event_id += 1
        self.events.append(event)
        return event

    @staticmethod
    def _bump_event(event: dict[str, Any], *, timestamp: str | None = None) -> None:
        event["version"] = int(event.get("version", 0)) + 1
        event["timestamp"] = timestamp or datetime.now(UTC).isoformat()


def _sdk_tool_call_data(item: Any) -> dict[str, Any]:
    raw = getattr(item, "raw_item", None)
    call_id = str(_raw_field(raw, "call_id") or _raw_field(raw, "id") or id(item))
    tool_name = str(
        _raw_field(raw, "name") or _raw_field(raw, "type") or getattr(item, "title", None) or "tool"
    )
    return {
        "call_id": call_id,
        "tool_name": tool_name,
        "args": _parse_json_object(_raw_field(raw, "arguments")),
    }


def _sdk_tool_output_data(item: Any) -> dict[str, Any]:
    raw = getattr(item, "raw_item", None)
    call_id = str(_raw_field(raw, "call_id") or _raw_field(raw, "id") or id(item))
    return {
        "call_id": call_id,
        "tool_name": str(_raw_field(raw, "name") or _raw_field(raw, "type") or "tool"),
        "output": getattr(item, "output", _raw_field(raw, "output")),
    }


def _sdk_message_text(item: Any) -> str:
    raw = getattr(item, "raw_item", None)
    return _message_content_text(_raw_field(raw, "content", []))


def _session_message_text(item: dict[str, Any]) -> str:
    return _message_content_text(item.get("content", ""))


def _message_content_text(content: Any) -> str:
    parts: list[str] = []
    content_items = content if isinstance(content, list) else [content]
    for part in content_items:
        if isinstance(part, str):
            parts.append(part)
            continue
        text = _raw_field(part, "text")
        if isinstance(text, str):
            parts.append(text)
    return "".join(parts)


def _raw_field(raw: Any, key: str, default: Any = None) -> Any:
    if isinstance(raw, dict):
        return raw.get(key, default)
    return getattr(raw, key, default)


def _parse_json_object(value: Any) -> dict[str, Any]:
    parsed = _parse_json_value(value)
    return parsed if isinstance(parsed, dict) else {}


def _parse_json_value(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _tool_status_from_result(result: Any) -> str:
    if isinstance(result, dict) and result.get("success") is False:
        return "failed"
    return "completed"

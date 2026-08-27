"""TUI-owned projection of SDK session history and stream events."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from pathlib import Path

from agents.tool import ToolOutputImage

from strix.core.paths import runtime_state_dir
from strix.interface.tui.history import load_session_history
from strix.tools.mcp import resolve_mcp_call


class TuiLiveView:
    def __init__(self) -> None:
        self.agents: dict[str, dict[str, Any]] = {}
        self.events: list[dict[str, Any]] = []
        self._next_event_id = 1
        self._open_assistant_event_by_agent: dict[str, dict[str, Any]] = {}
        self._tool_event_by_agent_and_call_id: dict[tuple[str, str], dict[str, Any]] = {}
        self._user_instruction: str | None = None
        self._user_instruction_at: str | None = None
        self._user_instruction_shown = False

    def _mcp_tool_fields(self, tool_name: str, args: dict[str, Any]) -> dict[str, str]:
        """Event fields naming the MCP server a tool call went out to, if any.

        Delegates to the shared engine resolver :func:`resolve_mcp_call` so a
        dispatch call is attributed the same way here and in strix-pro's tracer.
        The projection has no live registry, so it passes none: it reports the
        connection and tool read from the call's arguments and leaves the provider
        out. Empty for every other tool, which is what tells an interface to
        render the call as one of its own rather than as a call to a user's
        server. ``describe_mcp`` resolves with an empty tool, which tells both
        renderers to present the row as inspecting the connection itself.
        """
        info = resolve_mcp_call(tool_name, args)
        if info is None:
            return {}
        return {"mcp_connection": info.connection, "mcp_tool": info.tool}

    def set_user_instruction(self, text: str | None, *, timestamp: str | None = None) -> None:
        """Open the transcript with what the user asked for.

        The prompt from the start screen, ``--instruction`` and
        ``--instruction-file`` all reach the agent folded into its task, which the
        transcript does not show. This replays it as their first message instead,
        once, against the root agent - which may not exist yet, so it is held
        until that agent appears.
        """
        if self._user_instruction_shown or not (text or "").strip():
            return
        self._user_instruction = str(text).strip()
        self._user_instruction_at = timestamp
        self.flush_user_instruction()

    def flush_user_instruction(self) -> bool:
        """Post the held opening message once a root agent exists, once.

        Driven from wherever the agent graph is refreshed rather than from
        ``upsert_agent``, which subclasses override without calling back here.
        Returns whether it posted, so callers can report the change.
        """
        if self._user_instruction_shown or not self._user_instruction:
            return False
        root_id = next(
            (agent_id for agent_id, agent in self.agents.items() if agent.get("parent_id") is None),
            None,
        )
        if root_id is None:
            return False
        self._user_instruction_shown = True
        self._append_event(
            root_id,
            "chat",
            {
                "role": "user",
                "content": self._user_instruction,
                "metadata": {"source": "user_instruction"},
            },
            timestamp=self._user_instruction_at,
        )
        return True

    def hydrate_from_run_dir(self, run_dir: Path) -> None:
        # Armed before the agents are added so the root agent's arrival puts the
        # user's opening message ahead of the replayed history.
        self._load_run_record(run_dir)
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
        # Ahead of the replayed history, so it opens the transcript.
        self.flush_user_instruction()
        self._hydrate_sdk_session_history(run_dir, statuses.keys())

    def _load_run_record(self, run_dir: Path) -> None:
        """Take the user's opening message off the record."""
        try:
            record = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(record, dict):
            return
        instruction = record.get("user_instruction")
        if not isinstance(instruction, str):
            return
        start_time = record.get("start_time")
        # Stamped with the run's start so it sorts ahead of replayed history.
        self.set_user_instruction(
            instruction,
            timestamp=start_time if isinstance(start_time, str) else None,
        )

    def _hydrate_sdk_session_history(self, run_dir: Path, agent_ids: Any) -> None:
        # An agent's first user turn is the task it was launched with, not
        # something the user typed at it, so it is replayed as context rather
        # than as a message.
        tasked: set[str] = set()
        for agent_id, item, timestamp in load_session_history(run_dir, agent_ids):
            first_user_turn = agent_id not in tasked
            if item.get("role") == "user" and item.get("type") in {None, "message"}:
                tasked.add(agent_id)
            self._ingest_session_history_item(
                agent_id,
                item,
                timestamp=timestamp,
                first_user_turn=first_user_turn,
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
        if error_message is not None:
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
        first_user_turn: bool = False,
    ) -> None:
        item_type = item.get("type")
        role = item.get("role")
        if role in {"user", "assistant"} and (item_type in {None, "message"}):
            content = _session_message_text(item)
            if not content:
                return
            # A live run only shows what the user actually typed; the agent's
            # task and the guidance the system feeds it stay out of the
            # transcript. Replayed history has to make the same distinction, or
            # resuming attributes all of it to the user.
            if role == "user" and (first_user_turn or _is_internal_agent_turn(content)):
                return
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
        event_key = (agent_id, call_id)
        existing = self._tool_event_by_agent_and_call_id.get(event_key)
        tool_data = {
            "tool_name": call["tool_name"],
            "args": call["args"],
            "status": "running",
            "agent_id": agent_id,
            "call_id": call_id,
            **self._mcp_tool_fields(call["tool_name"], call["args"]),
        }
        if existing is None:
            event = self._append_event(agent_id, "tool", tool_data, timestamp=timestamp)
            self._tool_event_by_agent_and_call_id[event_key] = event
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
        event_key = (agent_id, call_id)
        event = self._tool_event_by_agent_and_call_id.get(event_key)
        if event is None:
            # No prior call event to update, so its arguments are gone and the
            # connection an MCP call went out to cannot be recovered. The matching
            # call event, when there is one, already carries the MCP fields; this
            # arrives only when the call was never projected, so it stays generic.
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
            self._tool_event_by_agent_and_call_id[event_key] = event

        result = _normalize_image_result(_parse_json_value(output["output"]))
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


# Guidance the system feeds an agent is injected as a user turn, which is the
# same shape a typed message takes, so replayed history cannot tell them apart by
# role alone. These are the exact openings it arrives with. Matching the full
# opening rather than just a leading bracket keeps pasted JSON, markdown links and
# a typed "[URGENT] stop" out of it.
_INTERNAL_TURN_PREFIXES = (
    # strix.core.agents._message_to_session_item: everything the coordinator
    # delivers from another agent or from the system, which wraps the stall,
    # terminal and budget-extension notices in strix.core.execution too.
    "[Message from ",
    # strix.core.inputs.child_initial_input: a subagent's parent context.
    "== Inherited context from parent",
    # strix.core.execution: the no-tool-call recovery nudge, both modes.
    "Your previous message ended a turn without a tool call.",
    "Your previous response ended the autonomous run without a lifecycle tool call.",
    # strix.core.hooks: budget warnings, the only notices injected unwrapped.
    *(
        f"[{label}] {subject}"
        for label in ("NOTICE", "URGENT", "CRITICAL")
        for subject in ("Turn budget:", "Scan cost budget:")
    ),
)


def _is_internal_agent_turn(content: str) -> bool:
    """Report whether a replayed user turn is system guidance, not a typed message."""
    return content.lstrip().startswith(_INTERNAL_TURN_PREFIXES)


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


def _normalize_image_result(result: Any) -> Any:
    image_url = _image_url_from_result(result)
    if image_url is None:
        return result
    return {"type": "image", "image_url": image_url}


def _image_url_from_result(result: Any) -> str | None:
    if isinstance(result, list):
        for block in result:
            url = _image_url_from_result(block)
            if url is not None:
                return url
        return None
    if isinstance(result, dict):
        if result.get("type") in {"image", "input_image", "output_image"}:
            url = result.get("image_url")
            return url if isinstance(url, str) and url.startswith("data:image/") else None
        return None
    if isinstance(result, ToolOutputImage) and isinstance(result.image_url, str):
        return result.image_url if result.image_url.startswith("data:image/") else None
    return None


def _tool_status_from_result(result: Any) -> str:
    if isinstance(result, dict) and result.get("success") is False:
        return "failed"
    return "completed"

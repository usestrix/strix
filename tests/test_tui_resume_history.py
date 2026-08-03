"""Resumed history must attribute only typed messages to the user.

Guidance the system feeds an agent is injected as a user turn, so replayed
history cannot tell it apart from a typed message by role alone. A live run only
shows what the user actually typed; resuming has to match that.
"""

from __future__ import annotations

import json
import sqlite3
from typing import TYPE_CHECKING, Any

from strix.core.paths import runtime_state_dir
from strix.interface.tui.live_view import TuiLiveView, _is_internal_agent_turn


if TYPE_CHECKING:
    from pathlib import Path


def _write_run(run_dir: Path, items: list[dict[str, Any]], agent_id: str = "root") -> None:
    """Persist an agent snapshot plus a session history for hydration to read."""
    state_dir = runtime_state_dir(run_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "agents.json").write_text(
        json.dumps({"statuses": {agent_id: "running"}, "names": {agent_id: "recon"}}),
        encoding="utf-8",
    )
    connection = sqlite3.connect(state_dir / "agents.db")
    try:
        connection.execute(
            "create table agent_messages (id integer primary key, session_id text, "
            "message_data text, created_at text)"
        )
        for index, item in enumerate(items, start=1):
            connection.execute(
                "insert into agent_messages (id, session_id, message_data, created_at) "
                "values (?, ?, ?, ?)",
                (index, agent_id, json.dumps(item), f"2026-01-01T00:00:{index:02d}+00:00"),
            )
        connection.commit()
    finally:
        connection.close()


def _user_messages(view: TuiLiveView) -> list[str]:
    return [
        str(event["data"]["content"])
        for event in view.events
        if event.get("type") == "chat" and event["data"].get("role") == "user"
    ]


def test_resume_hides_system_guidance_injected_as_user_turns(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_run(
        run_dir,
        [
            # The task the agent was launched with, not a typed message.
            {"role": "user", "content": "\n\nURLs: - https://example.com"},
            {"role": "assistant", "content": "starting"},
            {
                "role": "user",
                "content": "[Message from system (system) | type=auto_resume | priority=normal]\n"
                "Waiting timeout reached.",
            },
            {"role": "user", "content": "[NOTICE] Turn budget: 350/500 used (70%)."},
            {"role": "user", "content": "[Agent stalled] recon (a1) kept ending turns"},
            {
                "role": "user",
                "content": "Your previous message ended a turn without a tool call. "
                "Plain text never ends execution.",
            },
            {"role": "assistant", "content": "continuing"},
        ],
    )
    view = TuiLiveView()

    view.hydrate_from_run_dir(run_dir)

    assert _user_messages(view) == []
    # The agent's own side of the conversation is untouched.
    assert [
        str(event["data"]["content"])
        for event in view.events
        if event.get("type") == "chat" and event["data"].get("role") == "assistant"
    ] == ["starting", "continuing"]


def test_resume_keeps_messages_the_user_actually_typed(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_run(
        run_dir,
        [
            {"role": "user", "content": "\n\nURLs: - https://example.com"},
            {"role": "assistant", "content": "starting"},
            {"role": "user", "content": "check the coupon endpoint next"},
            {"role": "assistant", "content": "on it"},
            {"role": "user", "content": "[NOTICE] Turn budget: 350/500 used (70%)."},
            {"role": "user", "content": "stop testing the admin panel"},
        ],
    )
    view = TuiLiveView()

    view.hydrate_from_run_dir(run_dir)

    assert _user_messages(view) == [
        "check the coupon endpoint next",
        "stop testing the admin panel",
    ]


def test_resume_treats_each_agents_first_user_turn_as_its_task(tmp_path: Path) -> None:
    """Subagents get their task the same way, so it is skipped per agent."""
    run_dir = tmp_path / "run"
    state_dir = runtime_state_dir(run_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "agents.json").write_text(
        json.dumps(
            {
                "statuses": {"root": "running", "child": "running"},
                "names": {"root": "root", "child": "recon"},
                "parent_of": {"child": "root"},
            }
        ),
        encoding="utf-8",
    )
    connection = sqlite3.connect(state_dir / "agents.db")
    try:
        connection.execute(
            "create table agent_messages (id integer primary key, session_id text, "
            "message_data text, created_at text)"
        )
        rows = [
            ("root", {"role": "user", "content": "\n\nURLs: - https://example.com"}),
            ("child", {"role": "user", "content": "Audit the login flow."}),
            ("child", {"role": "user", "content": "also try the password reset"}),
        ]
        for index, (session_id, item) in enumerate(rows, start=1):
            connection.execute(
                "insert into agent_messages (id, session_id, message_data, created_at) "
                "values (?, ?, ?, ?)",
                (index, session_id, json.dumps(item), f"2026-01-01T00:00:{index:02d}+00:00"),
            )
        connection.commit()
    finally:
        connection.close()
    view = TuiLiveView()

    view.hydrate_from_run_dir(run_dir)

    # Both tasks are skipped; only the follow-up typed at the child remains.
    assert _user_messages(view) == ["also try the password reset"]


def test_internal_turn_classifier() -> None:
    for content in (
        "[Message from recon (a1) | type=information | priority=normal]\nfound it",
        "[Agent completed] recon (a1) finished",
        "[URGENT] Scan cost budget: $9.50/$10.00 spent (95%).",
        "== Inherited context from parent (background only) ==",
        "Your previous message ended a turn without a tool call.",
        "Your previous response ended the autonomous Strix run without a lifecycle tool call.",
    ):
        assert _is_internal_agent_turn(content), content
    for content in (
        "check the coupon endpoint next",
        "Use creds admin:hunter2 for the login form",
        "stop",
    ):
        assert not _is_internal_agent_turn(content), content

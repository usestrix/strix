"""Resumed history must attribute only typed messages to the user.

Guidance the system feeds an agent is injected as a user turn, so replayed
history cannot tell it apart from a typed message by role alone. A live run only
shows what the user actually typed; resuming has to match that.
"""

from __future__ import annotations

import ast
import json
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from strix.core import execution
from strix.core.paths import runtime_state_dir
from strix.interface.tui.backend.live_view import TuiLiveView as GoTuiLiveView
from strix.interface.tui.live_view import (
    _INTERNAL_TURN_PREFIXES,
    TuiLiveView,
    _is_internal_agent_turn,
)


if TYPE_CHECKING:
    from types import ModuleType


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
            # A stall notice reaches the parent through the coordinator, so it
            # arrives wrapped rather than as a bare "[Agent stalled]".
            {
                "role": "user",
                "content": "[Message from recon (a1) | type=stalled | priority=high]\n"
                "[Agent stalled] recon (a1) kept ending turns",
            },
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


def test_resume_hydrates_saved_agent_errors(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    state_dir = runtime_state_dir(run_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "agents.json").write_text(
        json.dumps(
            {
                "statuses": {"root": "failed"},
                "names": {"root": "Strix"},
                "parent_of": {"root": None},
                "errors": {"root": "provider rejected request"},
            }
        ),
        encoding="utf-8",
    )

    view = GoTuiLiveView()
    view.hydrate_from_run_dir(run_dir)

    assert view.agents["root"]["status"] == "failed"
    assert view.agents["root"]["error_message"] == "provider rejected request"


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


def test_internal_turn_classifier_matches_every_injected_form() -> None:
    for content in (
        # Coordinator deliveries, which wrap the stall, terminal and budget notices.
        "[Message from recon (a1) | type=information | priority=normal]\nfound it",
        "[Message from recon (a1) | type=stalled | priority=high]\n[Agent stalled] recon (a1)",
        "[Message from system (system) | type=budget_extended | priority=normal]\n"
        "[Budget] extended",
        # Budget warnings, the only notices injected without a wrapper.
        "[NOTICE] Turn budget: 350/500 used (70%).",
        "[URGENT] Scan cost budget: $9.50/$10.00 spent (95%).",
        "[CRITICAL] Turn budget: 480/500 used (96%).",
        "== Inherited context from parent (background only) ==",
        "Your previous message ended a turn without a tool call.",
        "Your previous response ended the autonomous run without a lifecycle tool call.",
    ):
        assert _is_internal_agent_turn(content), content


def _injected_strings(module: ModuleType) -> list[str]:
    """Every string a module can inject, and nothing it merely mentions.

    Parsing rather than searching the text keeps comments out of it, so a stale
    copy of a message left in a comment cannot pass for the message itself. It
    also joins adjacent literals for free, which the line wrapping needs, and
    docstrings are dropped because they describe the code rather than run in it.
    """
    tree = ast.parse(Path(module.__file__ or "").read_text(encoding="utf-8"))
    docstrings = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        first = node.body[0] if node.body else None
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
            docstrings.add(id(first.value))

    literals: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str) and id(node) not in docstrings:
                literals.append(node.value)
        elif isinstance(node, ast.JoinedStr):
            literals.append(
                "".join(
                    part.value
                    for part in node.values
                    if isinstance(part, ast.Constant) and isinstance(part.value, str)
                )
            )
    return literals


def test_internal_turn_prefixes_still_match_what_is_injected() -> None:
    """The classifier copies sentences out of another module, so they can drift.

    Both nudges are written inline in strix.core.execution, so there is nothing to
    import and compare against. Read them back out of what that module can inject.
    """
    injected = _injected_strings(execution)
    nudges = [prefix for prefix in _INTERNAL_TURN_PREFIXES if prefix.startswith("Your previous")]
    assert nudges, "the no-tool-call nudges are no longer in the classifier"
    for nudge in nudges:
        assert any(nudge in literal for literal in injected), (
            f"the classifier expects {nudge!r}, which strix.core.execution no longer "
            f"injects. A resumed scan would show that nudge as the user's own message."
        )


def test_internal_turn_classifier_keeps_bracketed_user_text() -> None:
    """A leading bracket is not enough: typed text often starts with one."""
    for content in (
        '[{"id": 1, "role": "admin"}, {"id": 2}]',
        "[link](https://example.com) check this endpoint",
        "[URGENT] stop testing the admin panel",
        "[2026-01-01 12:00:03] ERROR auth failed - look into this",
        "[note] creds are admin:hunter2",
        "[Agent] can you check this?",
        "[]",
        "check the coupon endpoint next",
        "Use creds admin:hunter2 for the login form",
        "stop",
    ):
        assert not _is_internal_agent_turn(content), content


@pytest.mark.parametrize("view_class", [TuiLiveView, GoTuiLiveView])
def test_user_instruction_opens_the_transcript_when_the_root_agent_appears(
    view_class: type[TuiLiveView],
) -> None:
    """A live scan has no root agent yet, so the message waits for it.

    Exercised against the projection the Go TUI actually uses as well as the
    base one: that subclass overrides upsert_agent without calling back, so a
    hook placed there would silently never run.
    """
    view = view_class()

    view.set_user_instruction("find IDOR in the checkout flow")
    assert _user_messages(view) == []

    view.upsert_agent("ab12", name="Strix", parent_id=None, status="running")
    assert view.flush_user_instruction() is True
    assert _user_messages(view) == ["find IDOR in the checkout flow"]

    # Repeated agent syncs and subagents must not repeat it.
    view.upsert_agent("cd34", name="recon", parent_id="ab12", status="running")
    view.upsert_agent("ab12", status="running")
    assert view.flush_user_instruction() is False
    assert _user_messages(view) == ["find IDOR in the checkout flow"]


def test_blank_user_instruction_adds_nothing() -> None:
    view = TuiLiveView()

    view.set_user_instruction("   ")
    view.set_user_instruction(None)
    view.upsert_agent("ab12", name="Strix", parent_id=None, status="running")

    assert _user_messages(view) == []


def test_replayed_run_opens_with_the_users_instruction(tmp_path: Path) -> None:
    """It comes from the run record and sorts ahead of replayed history."""
    run_dir = tmp_path / "run"
    _write_run(
        run_dir,
        [
            {"role": "user", "content": "\n\nURLs: - https://example.com"},
            {"role": "assistant", "content": "starting"},
            {"role": "user", "content": "also check coupons"},
        ],
    )
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "start_time": "2026-01-01T00:00:00+00:00",
                # instruction carries the diff-scope preamble; only the user's own
                # text belongs in the transcript.
                "instruction": "[diff-scope preamble]\n\naudit the auth flow",
                "user_instruction": "audit the auth flow",
            }
        ),
        encoding="utf-8",
    )
    view = TuiLiveView()

    view.hydrate_from_run_dir(run_dir)

    assert _user_messages(view) == ["audit the auth flow", "also check coupons"]
    first = view.events[0]
    assert first["data"]["content"] == "audit the auth flow"
    # Stamped with the run's start, so ordering by timestamp keeps it first.
    assert first["timestamp"] == "2026-01-01T00:00:00+00:00"


def test_replayed_run_without_an_instruction_is_unchanged(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir, [{"role": "assistant", "content": "starting"}])
    (run_dir / "run.json").write_text(
        json.dumps({"start_time": "2026-01-01T00:00:00+00:00"}), encoding="utf-8"
    )
    view = TuiLiveView()

    view.hydrate_from_run_dir(run_dir)

    assert _user_messages(view) == []

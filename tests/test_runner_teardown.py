from __future__ import annotations

import asyncio
import types
from typing import Any

import pytest
from agents import ModelSettings

import strix.tools.notes.tools as notes_tools
import strix.tools.todo.tools as todo_tools
from strix.core import runner
from strix.core.agents import AgentCoordinator
from strix.runtime import session_manager


def _wire_runner(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    monkeypatch.setattr(runner, "run_dir_for", lambda _scan_id: tmp_path)
    monkeypatch.setattr(runner, "runtime_state_dir", lambda _run_dir: tmp_path)
    monkeypatch.setattr(runner, "setup_scan_logging", lambda _run_dir: lambda: None)
    monkeypatch.setattr(runner, "set_scan_id", lambda _scan_id: None)

    settings = _settings()
    monkeypatch.setattr(runner, "load_settings", lambda: settings)
    monkeypatch.setattr(runner, "configure_sdk_model_defaults", lambda _s: None)
    monkeypatch.setattr(runner, "uses_chat_completions_tool_schema", lambda _m, _s: False)
    monkeypatch.setattr(todo_tools, "hydrate_todos_from_disk", lambda _d: None)
    monkeypatch.setattr(notes_tools, "hydrate_notes_from_disk", lambda _d: None)

    async def _create_or_reuse(*_a: Any, **_k: Any) -> dict[str, Any]:
        return {"client": object(), "session": object(), "caido_client": None}

    async def _cleanup(*_a: Any, **_k: Any) -> None:
        return None

    monkeypatch.setattr(session_manager, "create_or_reuse", _create_or_reuse)
    monkeypatch.setattr(session_manager, "cleanup", _cleanup)
    monkeypatch.setattr(runner, "build_root_task", lambda _c: "task")
    monkeypatch.setattr(runner, "build_scope_context", lambda _c: "")
    monkeypatch.setattr(runner, "make_model_settings", lambda *_a, **_k: ModelSettings())
    monkeypatch.setattr(runner, "build_strix_agent", lambda **_k: object())
    monkeypatch.setattr(runner, "make_child_factory", lambda **_k: lambda **_kk: object())
    monkeypatch.setattr(runner, "open_agent_session", lambda _root_id, _db: object())


def _settings() -> Any:
    return types.SimpleNamespace(
        llm=types.SimpleNamespace(
            model="openai/gpt-4o",
            reasoning_effort="high",
            force_required_tool_choice=False,
            timeout=300,
            prompt_cache=True,
            extra_headers=None,
        ),
        runtime=types.SimpleNamespace(max_context_images=3),
    )


@pytest.mark.asyncio
async def test_a_live_child_is_settled_before_sessions_close(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    _wire_runner(monkeypatch, tmp_path)
    coordinator = AgentCoordinator()
    child_started = asyncio.Event()
    child_task: dict[str, asyncio.Task[None]] = {}

    async def _root_finishes(**kwargs: Any) -> None:
        root_id = kwargs["agent_id"]

        async def _child_mid_turn() -> None:
            child_started.set()
            await asyncio.sleep(3600)

        await coordinator.register("child", "Child", parent_id=root_id)
        task = asyncio.create_task(_child_mid_turn())
        child_task["t"] = task
        await coordinator.attach_runtime("child", task=task)
        await child_started.wait()

    monkeypatch.setattr(runner, "run_agent_loop", _root_finishes)

    await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep", "safety_mode": "off"},
        scan_id="scan-test",
        image="img",
        coordinator=coordinator,
    )

    task = child_task["t"]
    assert task.done(), "the child task was left running past scan teardown"
    assert task.cancelled(), "the child was not cancelled cleanly on a finish"

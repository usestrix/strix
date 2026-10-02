from __future__ import annotations

import asyncio
import json
import types
from typing import TYPE_CHECKING, Any

import pytest
from agents import ModelSettings

import strix.tools.notes.tools as notes_tools
import strix.tools.todo.tools as todo_tools
from strix.core import execution, runner
from strix.core.agents import AgentCoordinator
from strix.runtime import session_manager
from tests.test_fix_reliability import LocalSandbox


if TYPE_CHECKING:
    from pathlib import Path


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
        return {
            "client": object(),
            "session": LocalSandbox(tmp_path / "sandbox"),
            "caido_client": None,
        }

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
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-test",
        image="img",
        coordinator=coordinator,
    )

    task = child_task["t"]
    assert task.done(), "the child task was left running past scan teardown"
    assert task.cancelled(), "the child was not cancelled cleanly on a finish"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "interactive,local_branches,is_resume",
    [
        (interactive, local_branches, resume)
        for interactive in (False, True)
        for local_branches in (False, True)
        for resume in ((False, True) if interactive else (False,))
    ],
)
async def test_assessment_publishes_before_fixes_end_and_sandbox_teardown(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    interactive: bool,
    local_branches: bool,
    is_resume: bool,
) -> None:
    _wire_runner(monkeypatch, tmp_path)
    events: list[str] = []

    class State:
        defer_completion = False

        def __init__(self) -> None:
            self.scan_results = {"scan_completed": True}

        def get_existing_vulnerabilities(self) -> list[Any]:
            return []

        def get_total_llm_cost(self) -> float:
            return 0.0

        def save_run_data(self, **_: Any) -> None:
            events.append("save")

    class Fixes:
        def __init__(self, **options: Any) -> None:
            assert (options["sink"] is not None) is not local_branches

        def start(self, *_: Any) -> None:
            events.append("fixes listening")

        async def wait(self) -> tuple[list[Any], list[Any]]:
            events.append("fixes finished")
            return [], []

        async def close(self) -> None:
            events.append("fixes closed")

    async def assessment(_: Any) -> None:
        events.append("assessment published")

    async def platform_fix_sink(*_: Any) -> bool:
        return True

    async def root(**kwargs: Any) -> types.SimpleNamespace:
        assert kwargs["interactive"] is interactive
        assert kwargs["return_on_completion"] is True
        return types.SimpleNamespace(final_output={"scan_completed": True})

    async def cleanup(*_: Any) -> None:
        events.append("sandbox deleted")

    if is_resume:
        coordinator = AgentCoordinator()
        await coordinator.register("root", "Root Agent", parent_id=None)
        await coordinator.set_status("root", "completed")
        (tmp_path / "agents.json").write_text(json.dumps(await coordinator.snapshot()))
        (tmp_path / "agents.db").touch()

        async def unexpected_cycle(*_args: Any, **_kwargs: Any) -> None:
            raise AssertionError("Resume must finish pending fixes without restarting root")

        monkeypatch.setattr(execution, "_run_until_lifecycle", unexpected_cycle)

    monkeypatch.setattr(runner, "get_global_report_state", State)
    monkeypatch.setattr(runner, "ScanFixes", Fixes)
    if not is_resume:
        monkeypatch.setattr(runner, "run_agent_loop", root)
    monkeypatch.setattr(session_manager, "cleanup", cleanup)
    await runner.run_strix_scan(
        scan_config={
            "targets": [],
            "scan_mode": "deep",
        },
        scan_id="scan",
        image="image",
        local_sources=[{"source_path": str(tmp_path)}],
        assessment_sink=assessment,
        fix_sink=None if local_branches else platform_fix_sink,
        interactive=interactive,
    )
    assert events.index("assessment published") < events.index("fixes finished")
    assert events.index("fixes finished") < events.index("sandbox deleted")


@pytest.mark.asyncio
@pytest.mark.parametrize("interactive", [False, True])
@pytest.mark.parametrize("is_resume", [False, True])
@pytest.mark.parametrize(
    "fix_config",
    [
        {"auto_fix_enabled": False},
        {"mode": "pr_review"},
        {
            "mode": "pr_review",
            "auto_fix_enabled": True,
        },
    ],
)
async def test_disabled_auto_fix_skips_fix_runtime(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    interactive: bool,
    is_resume: bool,
    fix_config: dict[str, Any],
) -> None:
    _wire_runner(monkeypatch, tmp_path)
    events: list[str] = []

    class State:
        defer_completion = False

        def __init__(self) -> None:
            self.scan_results = {"scan_completed": True}

        def get_existing_vulnerabilities(self) -> list[Any]:
            return []

        def get_total_llm_cost(self) -> float:
            return 0.0

        def save_run_data(self, **_: Any) -> None:
            events.append("save")

    class Fixes:
        def __init__(self, **_: Any) -> None:
            raise AssertionError("ScanFixes must not be constructed")

    async def assessment(_: Any) -> None:
        events.append("assessment published")

    async def root(**kwargs: Any) -> types.SimpleNamespace:
        assert kwargs["return_on_completion"] is False
        return types.SimpleNamespace(final_output={"scan_completed": True})

    if is_resume:
        coordinator = AgentCoordinator()
        await coordinator.register("root", "Root Agent", parent_id=None)
        await coordinator.set_status("root", "completed")
        await coordinator.register("repair", "Fix agent", parent_id="root", skills=["fix_task"])
        await coordinator.register(
            "reviewer", "Independent fix verifier", parent_id="repair", skills=["fix_task"]
        )
        (tmp_path / "agents.json").write_text(json.dumps(await coordinator.snapshot()))
        (tmp_path / "agents.db").touch()

        async def unexpected_child(**_: Any) -> None:
            events.append("fix agent resumed")
            raise AssertionError("Disabled fixes must not respawn repair or reviewer agents")

        monkeypatch.setattr(execution, "spawn_child_agent", unexpected_child)

    monkeypatch.setattr(runner, "get_global_report_state", State)
    monkeypatch.setattr(runner, "ScanFixes", Fixes)
    monkeypatch.setattr(runner, "run_agent_loop", root)
    await runner.run_strix_scan(
        scan_config={
            "targets": [],
            "scan_mode": "deep",
            **fix_config,
        },
        scan_id="scan",
        image="image",
        local_sources=[{"source_path": str(tmp_path)}],
        assessment_sink=assessment,
        interactive=interactive,
    )

    assert events == ["assessment published", "save"]

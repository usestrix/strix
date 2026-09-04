"""The runner attaches MCP connections source-agnostically.

When a caller supplies ``mcp_connection_requests`` the runner attaches those;
when it does not, the runner reads ``~/.strix/mcp-servers.json`` itself and wraps
each config in a bare request. Either way the one shared ``attach_mcp_requests``
routine does the connecting.
"""

from __future__ import annotations

import types
from typing import Any

import pytest
from agents import ModelSettings

import strix.tools.mcp as mcp_pkg
import strix.tools.notes.tools as notes_tools
import strix.tools.todo.tools as todo_tools
from strix.core import runner
from strix.core.agents import AgentCoordinator
from strix.runtime import session_manager
from strix.tools.mcp import McpConnectionConfig, McpConnectionRequest


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


def _wire_runner(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    monkeypatch.setattr(runner, "run_dir_for", lambda _scan_id: tmp_path)
    monkeypatch.setattr(runner, "runtime_state_dir", lambda _run_dir: tmp_path)
    monkeypatch.setattr(runner, "setup_scan_logging", lambda _run_dir: lambda: None)
    monkeypatch.setattr(runner, "set_scan_id", lambda _scan_id: None)
    monkeypatch.setattr(runner, "load_settings", _settings)
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
    monkeypatch.setattr(runner, "build_scope_context", lambda _c: {})
    monkeypatch.setattr(runner, "make_model_settings", lambda *_a, **_k: ModelSettings())
    monkeypatch.setattr(runner, "build_strix_agent", lambda **_k: object())
    monkeypatch.setattr(runner, "make_child_factory", lambda **_k: lambda **_kk: object())
    monkeypatch.setattr(runner, "open_agent_session", lambda _root_id, _db: object())

    async def _run_agent_loop(**_kwargs: Any) -> None:
        return None

    monkeypatch.setattr(runner, "run_agent_loop", _run_agent_loop)


@pytest.mark.asyncio
async def test_none_default_attaches_from_the_user_config_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    _wire_runner(monkeypatch, tmp_path)

    file_config = McpConnectionConfig(
        name="local_fs", transport="stdio", command="npx", notes="local files"
    )
    monkeypatch.setattr(mcp_pkg, "load_user_mcp_configs", lambda: [file_config])

    captured: list[list[McpConnectionRequest]] = []

    async def _capture(requests: list[McpConnectionRequest], _registry: Any) -> list[Any]:
        captured.append(requests)
        return []

    monkeypatch.setattr(mcp_pkg, "attach_mcp_requests", _capture)

    await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-none",
        image="img",
        coordinator=AgentCoordinator(),
    )

    # Each config from the file is wrapped in a bare request: no provider, no
    # transform, no explicit purpose (purpose falls back to notes at attach time).
    (requests,) = captured
    assert len(requests) == 1
    assert requests[0].config is file_config
    assert requests[0].provider is None
    assert requests[0].result_transform is None
    assert requests[0].purpose is None


@pytest.mark.asyncio
async def test_supplied_requests_are_attached_and_the_user_file_is_not_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    _wire_runner(monkeypatch, tmp_path)

    def _fail_if_read() -> list[Any]:
        raise AssertionError("load_user_mcp_configs must not be read when requests are supplied")

    monkeypatch.setattr(mcp_pkg, "load_user_mcp_configs", _fail_if_read)

    captured: list[list[McpConnectionRequest]] = []

    async def _capture(requests: list[McpConnectionRequest], _registry: Any) -> list[Any]:
        captured.append(requests)
        return []

    monkeypatch.setattr(mcp_pkg, "attach_mcp_requests", _capture)

    supplied = [
        McpConnectionRequest(
            config=McpConnectionConfig(name="db", url="https://mcp.example.com"),
            provider="supabase",
        )
    ]

    await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-supplied",
        image="img",
        coordinator=AgentCoordinator(),
        mcp_connection_requests=supplied,
    )

    assert captured == [supplied]


@pytest.mark.asyncio
async def test_roster_is_persisted_even_without_a_status_sink(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """The viewer reads the roster off disk, so persistence must not depend on the
    interface status sink: with ``mcp_status_sink=None`` the connect-time roster is
    still written, carrying only the non-secret name/provider/tool_count/dead."""
    _wire_runner(monkeypatch, tmp_path)
    monkeypatch.setattr(
        mcp_pkg,
        "load_user_mcp_configs",
        lambda: [McpConnectionConfig(name="local_fs", transport="stdio", command="npx")],
    )

    class _FakeSession:
        is_dead = False

        def set_on_dead(self, _callback: Any) -> None:
            return None

    async def _attach(_requests: list[McpConnectionRequest], registry: Any) -> list[Any]:
        registry.add(name="local_fs", session=_FakeSession(), tool_count=3, provider=None)
        entry = registry.get("local_fs")
        return [types.SimpleNamespace(name="local_fs", tool_count=3, session=entry.session)]

    monkeypatch.setattr(mcp_pkg, "attach_mcp_requests", _attach)

    persisted: list[list[dict[str, Any]]] = []

    def _capture_persist(roster: list[dict[str, Any]]) -> None:
        persisted.append(roster)

    monkeypatch.setattr(runner, "_persist_mcp_status", _capture_persist)

    await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-persist",
        image="img",
        coordinator=AgentCoordinator(),
        mcp_status_sink=None,
    )

    assert persisted, "roster must persist even when no status sink is attached"
    assert persisted[-1] == [{"name": "local_fs", "provider": None, "tool_count": 3, "dead": False}]

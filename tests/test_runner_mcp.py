"""The runner attaches MCP connections source-agnostically.

When a caller supplies ``mcp_connection_requests`` the runner attaches those;
when it does not, the runner reads ``~/.strix/mcp-servers.json`` itself and wraps
each config in a bare request. Either way the one shared ``attach_mcp_requests``
routine does the connecting.
"""

from __future__ import annotations

import importlib
import types
from typing import Any

import pytest
from agents import ModelSettings

import strix.tools.mcp as mcp_pkg
import strix.tools.notes.tools as notes_tools
import strix.tools.todo.tools as todo_tools
from strix.agents import factory
from strix.core import runner
from strix.core.agents import AgentCoordinator
from strix.runtime import session_manager
from strix.tools.mcp import McpConnectionConfig, McpConnectionRequest
from strix.tools.mcp import client as mcp_client


_test_mcp_client = importlib.import_module("tests.test_mcp_client")
FakeMCPServer: Any = _test_mcp_client.FakeMCPServer
_mcp_tool: Any = _test_mcp_client._mcp_tool


def _built_server(server: Any) -> Any:
    return mcp_client.BuiltMcpServer(server, None)


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
    monkeypatch.setattr(
        mcp_client,
        "_build_server",
        lambda config: _built_server(FakeMCPServer(config.name, [])),
    )

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

    captured: list[McpConnectionRequest] = []
    original_register = mcp_pkg.McpRegistry.register

    def _capture(registry: Any, request: McpConnectionRequest) -> Any:
        captured.append(request)
        return original_register(registry, request)

    monkeypatch.setattr(mcp_pkg.McpRegistry, "register", _capture)

    await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-none",
        image="img",
        coordinator=AgentCoordinator(),
    )

    # Each config from the file is wrapped in a bare request: no provider, no
    # transform, no explicit purpose (purpose falls back to notes at attach time).
    (request,) = captured
    assert request.config is file_config
    assert request.provider is None
    assert request.result_transform is None
    assert request.purpose is None


@pytest.mark.asyncio
async def test_supplied_requests_are_attached_and_the_user_file_is_not_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    _wire_runner(monkeypatch, tmp_path)

    def _fail_if_read() -> list[Any]:
        raise AssertionError("load_user_mcp_configs must not be read when requests are supplied")

    monkeypatch.setattr(mcp_pkg, "load_user_mcp_configs", _fail_if_read)

    captured: list[McpConnectionRequest] = []
    original_register = mcp_pkg.McpRegistry.register

    def _capture(registry: Any, request: McpConnectionRequest) -> Any:
        captured.append(request)
        return original_register(registry, request)

    monkeypatch.setattr(mcp_pkg.McpRegistry, "register", _capture)

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

    assert captured == supplied


@pytest.mark.asyncio
async def test_roster_is_persisted_even_without_a_status_sink(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """The viewer reads the roster off disk, so persistence must not depend on the
    interface status sink: with ``mcp_status_sink=None`` the configured roster is
    still written, carrying only non-secret lifecycle fields."""
    _wire_runner(monkeypatch, tmp_path)
    monkeypatch.setattr(
        mcp_pkg,
        "load_user_mcp_configs",
        lambda: [McpConnectionConfig(name="local_fs", transport="stdio", command="npx")],
    )
    monkeypatch.setattr(
        mcp_client,
        "_build_server",
        lambda _config: _built_server(FakeMCPServer("local_fs", [])),
    )

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
    assert persisted[0] == [
        {
            "name": "local_fs",
            "provider": None,
            "tool_count": 0,
            "dead": False,
            "state": "configured",
        }
    ]


@pytest.mark.asyncio
async def test_warmup_listing_failure_does_not_interrupt_scan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    _wire_runner(monkeypatch, tmp_path)

    server = FakeMCPServer("db", [])

    async def _failing_list_tools(
        run_context: Any = None,
        agent: Any = None,
    ) -> list[Any]:
        del run_context, agent
        raise RuntimeError("catalog unavailable")

    server.list_tools = _failing_list_tools

    monkeypatch.setattr(
        mcp_client,
        "_build_server",
        lambda _config: _built_server(server),
    )
    root_builds: list[dict[str, Any]] = []
    monkeypatch.setattr(runner, "build_strix_agent", lambda **kwargs: root_builds.append(kwargs))

    await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-mcp-list-failure",
        image="img",
        coordinator=AgentCoordinator(),
        mcp_connection_requests=[
            McpConnectionRequest(
                config=McpConnectionConfig(name="db", url="https://mcp.example.com")
            )
        ],
    )

    assert len(root_builds) == 1


@pytest.mark.asyncio
async def test_warmed_tool_counts_reach_root_and_child_agent_builds(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    _wire_runner(monkeypatch, tmp_path)
    server = FakeMCPServer("db", [_mcp_tool(f"tool_{index}") for index in range(3)])
    monkeypatch.setattr(mcp_client, "_build_server", lambda _config: _built_server(server))

    root_builds: list[dict[str, Any]] = []

    def _build_root(**kwargs: Any) -> object:
        root_builds.append(kwargs)
        return object()

    monkeypatch.setattr(
        runner,
        "build_strix_agent",
        _build_root,
    )
    child_builds: list[dict[str, Any]] = []

    def _build_child(**kwargs: Any) -> object:
        child_builds.append(kwargs)
        return object()

    monkeypatch.setattr(
        factory,
        "build_strix_agent",
        _build_child,
    )
    real_make_child_factory = factory.make_child_factory
    child_factory_capture: dict[str, Any] = {}

    def _make_child_factory(**kwargs: Any) -> Any:
        child_factory_capture["context"] = kwargs["system_prompt_context"]
        child_factory_capture["factory"] = real_make_child_factory(**kwargs)
        return child_factory_capture["factory"]

    monkeypatch.setattr(runner, "make_child_factory", _make_child_factory)
    request = McpConnectionRequest(
        config=McpConnectionConfig(name="db", url="https://mcp.example.com", notes="database")
    )

    await runner.run_strix_scan(
        scan_config={"targets": [], "scan_mode": "deep"},
        scan_id="scan-mcp-prompt-counts",
        image="img",
        coordinator=AgentCoordinator(),
        mcp_connection_requests=[request],
    )

    root_context = root_builds[0]["system_prompt_context"]
    assert root_context["mcp_connections"][0]["tool_count"] == 3
    assert child_factory_capture["context"] is root_context
    assert child_factory_capture["context"]["mcp_connections"][0]["tool_count"] == 3

    child_factory_capture["factory"](name="child", skills=[])
    assert child_builds[0]["system_prompt_context"] is child_factory_capture["context"]
    assert child_builds[0]["system_prompt_context"]["mcp_connections"][0]["tool_count"] == 3

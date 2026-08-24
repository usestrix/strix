"""Tests for the generic MCP client: config contract, namespacing, and filtering."""

from __future__ import annotations

import asyncio
import json
import re
from typing import TYPE_CHECKING, Any

import pytest
from agents.mcp import MCPServer, MCPServerStdio, MCPServerStreamableHttp
from mcp.types import CallToolResult, TextContent
from mcp.types import Tool as MCPTool
from pydantic import ValidationError

from strix.agents import factory
from strix.core.runner import _mcp_connection_notes
from strix.interface.tui.live_view import TuiLiveView, _tool_status_from_result
from strix.tools.mcp import (
    BearerAuth,
    ConnectedMcpServer,
    McpConnectionConfig,
    load_user_mcp_configs,
    namespaced_tool_name,
    resolve_mcp_tool,
)
from strix.tools.mcp import client as mcp_client
from strix.tools.mcp.client import _auth_headers, _build_server, _register_server_tools


if TYPE_CHECKING:
    from pathlib import Path

    from agents.tool import Tool


class FakeMCPServer(MCPServer):
    """A connected MCP server stand-in, so tests never touch the network."""

    def __init__(self, name: str, tools: list[MCPTool]) -> None:
        super().__init__()
        self._name = name
        self._tools = tools
        self.calls: list[tuple[str, dict[str, Any] | None]] = []

    @property
    def name(self) -> str:
        return self._name

    async def connect(self) -> None:
        return None

    async def cleanup(self) -> None:
        return None

    async def list_tools(
        self,
        run_context: Any = None,
        agent: Any = None,
    ) -> list[MCPTool]:
        return list(self._tools)

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None,
        meta: dict[str, Any] | None = None,
    ) -> CallToolResult:
        self.calls.append((tool_name, arguments))
        return CallToolResult(content=[TextContent(type="text", text=f"routed:{tool_name}")])

    async def list_prompts(self) -> Any:
        raise NotImplementedError

    async def get_prompt(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        raise NotImplementedError


def _mcp_tool(name: str) -> MCPTool:
    return MCPTool(
        name=name,
        description=f"remote tool {name}",
        inputSchema={"type": "object", "properties": {}},
    )


def _config(name: str, allowed_tools: list[str]) -> McpConnectionConfig:
    return McpConnectionConfig(
        name=name,
        url="https://mcp.example.com",
        auth=BearerAuth(token="run-token"),
        allowed_tools=allowed_tools,
    )


@pytest.fixture(autouse=True)
def _clear_mcp_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Hide any MCP settings the developer has exported in their own shell.

    The loader reads these to resolve the config path and the per-run
    include/exclude selection, so a shell that has them set (from using
    --mcp-config or --mcp-server) would otherwise filter what these tests see.
    """
    for name in ("STRIX_MCP_CONFIG", "STRIX_MCP_ONLY", "STRIX_MCP_EXCLUDE"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _reset_registry() -> Any:
    saved = list(factory._EXTRA_TOOLS)
    factory._EXTRA_TOOLS.clear()
    try:
        yield
    finally:
        factory._EXTRA_TOOLS[:] = saved


# --- config contract ---------------------------------------------------------


def test_bearer_config_parses_from_dict() -> None:
    config = McpConnectionConfig.model_validate(
        {
            "name": "files_main",
            "transport": "http",
            "url": "https://mcp.example.com",
            "auth": {"kind": "bearer", "token": "abc"},
            "allowed_tools": ["list_files"],
        }
    )

    assert isinstance(config.auth, BearerAuth)
    assert config.auth.token == "abc"
    assert config.allowed_tools == ["list_files"]


def test_unknown_auth_kind_is_rejected() -> None:
    with pytest.raises(ValidationError):
        McpConnectionConfig.model_validate(
            {
                "name": "x",
                "url": "https://mcp.example.com",
                "auth": {"kind": "oauth", "token": "abc"},
            }
        )


def test_stdio_config_parses_from_dict() -> None:
    config = McpConnectionConfig.model_validate(
        {
            "name": "local_fs",
            "transport": "stdio",
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv/data"],
            "env": {"FOO": "bar"},
        }
    )

    assert config.transport == "stdio"
    assert config.command == "npx"
    assert config.args == ["-y", "@modelcontextprotocol/server-filesystem", "/srv/data"]
    assert config.env == {"FOO": "bar"}
    # A local stdio server needs no auth, and omitting allowed_tools means "all".
    assert config.auth is None
    assert config.allowed_tools is None


def test_http_config_without_url_is_rejected() -> None:
    with pytest.raises(ValidationError):
        McpConnectionConfig.model_validate(
            {
                "name": "x",
                "transport": "http",
                "auth": {"kind": "bearer", "token": "abc"},
            }
        )


def test_stdio_config_without_command_is_rejected() -> None:
    with pytest.raises(ValidationError):
        McpConnectionConfig.model_validate(
            {
                "name": "x",
                "transport": "stdio",
            }
        )


def test_empty_name_is_rejected() -> None:
    with pytest.raises(ValidationError):
        McpConnectionConfig.model_validate(
            {
                "name": "",
                "url": "https://mcp.example.com",
                "auth": {"kind": "bearer", "token": "abc"},
            }
        )


def test_unknown_field_is_rejected() -> None:
    with pytest.raises(ValidationError):
        McpConnectionConfig.model_validate(
            {
                "name": "x",
                "url": "https://mcp.example.com",
                "auth": {"kind": "bearer", "token": "abc"},
                "surprise": True,
            }
        )


# --- auth headers ------------------------------------------------------------


def test_bearer_auth_builds_authorization_header() -> None:
    headers = _auth_headers(_config("files_main", []))

    assert headers == {"Authorization": "Bearer run-token"}


# --- namespacing and filtering -----------------------------------------------


def _registered_names() -> list[str]:
    return [tool.name for tool in factory.registered_agent_tools()]


@pytest.mark.asyncio
async def test_tools_are_namespaced_per_connection() -> None:
    server_a = FakeMCPServer("conn_a", [_mcp_tool("describe")])
    server_b = FakeMCPServer("conn_b", [_mcp_tool("describe")])

    await _register_server_tools(_config("conn_a", ["describe"]), server_a)
    await _register_server_tools(_config("conn_b", ["describe"]), server_b)

    # Same remote tool name on two connections does not collide.
    assert _registered_names() == ["conn_a_describe", "conn_b_describe"]


@pytest.mark.asyncio
async def test_registered_names_are_valid_tool_names() -> None:
    # Model APIs reject a tool name containing anything but letters, digits,
    # underscores and hyphens, and reject the whole request rather than the one
    # tool. A server naming its own tools with dots, or a connection named with
    # a space in the user's config, must not be able to break a run.
    server = FakeMCPServer("my server", [_mcp_tool("db.query"), _mcp_tool("ok_tool")])

    await _register_server_tools(_config("my server", None), server)

    names = _registered_names()
    assert names == ["my_server_db_query", "my_server_ok_tool"]
    assert all(re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", name) for name in names)


@pytest.mark.asyncio
async def test_a_rename_does_not_change_which_tool_is_called() -> None:
    # Only the model-facing name is sanitized; the server is always asked for the
    # tool name it reported.
    server = FakeMCPServer("my server", [_mcp_tool("db.query")])

    tools = await _register_server_tools(_config("my server", None), server)

    assert tools[0].name == "my_server_db_query"
    await tools[0].on_invoke_tool(None, "{}")
    assert server.calls == [("db.query", {})]


@pytest.mark.asyncio
async def test_disallowed_tool_is_not_registered() -> None:
    server = FakeMCPServer(
        "files_main",
        [_mcp_tool("list_files"), _mcp_tool("search")],
    )

    await _register_server_tools(_config("files_main", ["list_files"]), server)

    names = _registered_names()
    assert "files_main_list_files" in names
    assert "files_main_search" not in names


@pytest.mark.asyncio
async def test_allowed_tools_none_registers_every_listed_tool() -> None:
    server = FakeMCPServer(
        "local_fs",
        [_mcp_tool("read_file"), _mcp_tool("write_file")],
    )
    config = McpConnectionConfig(name="local_fs", url="https://mcp.example.com", allowed_tools=None)

    await _register_server_tools(config, server)

    names = _registered_names()
    assert "local_fs_read_file" in names
    assert "local_fs_write_file" in names


@pytest.mark.asyncio
async def test_allowed_tools_list_restricts_registration() -> None:
    server = FakeMCPServer(
        "local_fs",
        [_mcp_tool("read_file"), _mcp_tool("write_file")],
    )

    await _register_server_tools(_config("local_fs", ["read_file"]), server)

    names = _registered_names()
    assert names == ["local_fs_read_file"]


@pytest.mark.asyncio
async def test_registered_tool_routes_to_its_server_with_the_original_name() -> None:
    server = FakeMCPServer("files_main", [_mcp_tool("list_files")])

    tools: list[Tool] = await _register_server_tools(_config("files_main", ["list_files"]), server)
    tool = tools[0]

    output = await tool.on_invoke_tool(None, "{}")  # type: ignore[union-attr]

    # The call reaches the right server, addressed by the unprefixed remote name.
    assert server.calls == [("list_files", {})]
    assert output == {"type": "text", "text": "routed:list_files"}


# --- result transform --------------------------------------------------------


@pytest.mark.asyncio
async def test_result_transform_receives_namespaced_name_and_structured_result() -> None:
    server = FakeMCPServer("files_main", [_mcp_tool("list_files")])
    seen: list[tuple[str, Any]] = []

    def transform(name: str, structured: Any) -> Any:
        seen.append((name, structured))
        return {"kept": structured["content"][0]["text"]}

    tools: list[Tool] = await _register_server_tools(
        _config("files_main", ["list_files"]), server, result_transform=transform
    )

    output = await tools[0].on_invoke_tool(None, "{}")  # type: ignore[union-attr]

    # The underlying MCP call still routes by the unprefixed remote name.
    assert server.calls == [("list_files", {})]

    # The transform is called with the namespaced name and the parsed result.
    assert len(seen) == 1
    name, structured = seen[0]
    assert name == "files_main_list_files"
    # A parsed CallToolResult (dict/list), not a pre-serialized string.
    assert structured["content"][0]["text"] == "routed:list_files"
    assert structured["isError"] is False

    # The transform's return value is exactly what the tool yields.
    assert output == {"kept": "routed:list_files"}


@pytest.mark.asyncio
async def test_result_transform_can_rewrite_the_tool_output() -> None:
    server = FakeMCPServer("files_main", [_mcp_tool("list_files")])

    def transform(_name: str, structured: Any) -> Any:
        # Keep only a truncated view of the text field.
        return structured["content"][0]["text"][:6]

    tools: list[Tool] = await _register_server_tools(
        _config("files_main", ["list_files"]), server, result_transform=transform
    )

    output = await tools[0].on_invoke_tool(None, "{}")  # type: ignore[union-attr]

    assert output == "routed"


@pytest.mark.asyncio
async def test_without_result_transform_output_is_unchanged() -> None:
    server = FakeMCPServer("files_main", [_mcp_tool("list_files")])

    tools: list[Tool] = await _register_server_tools(
        _config("files_main", ["list_files"]), server, result_transform=None
    )

    output = await tools[0].on_invoke_tool(None, "{}")  # type: ignore[union-attr]

    # Same shape the SDK produces today: no transform in the path.
    assert server.calls == [("list_files", {})]
    assert output == {"type": "text", "text": "routed:list_files"}


# --- error status capture ----------------------------------------------------


class ErroringMCPServer(FakeMCPServer):
    """A connected server whose calls come back as MCP errors (isError=True)."""

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None,
        meta: dict[str, Any] | None = None,
    ) -> CallToolResult:
        self.calls.append((tool_name, arguments))
        return CallToolResult(
            content=[TextContent(type="text", text=f"boom:{tool_name}")],
            isError=True,
        )


@pytest.mark.asyncio
async def test_errored_mcp_result_is_flagged_failed_for_the_tui() -> None:
    server = ErroringMCPServer("files_main", [_mcp_tool("list_files")])

    tools: list[Tool] = await _register_server_tools(_config("files_main", ["list_files"]), server)
    output = await tools[0].on_invoke_tool(None, "{}")  # type: ignore[union-attr]

    # The error text stays exactly what the agent gets today; a success:False tag
    # rides alongside it purely so the TUI can tell the call apart from a success.
    assert output == {"type": "text", "text": "boom:list_files", "success": False}
    assert _tool_status_from_result(output) == "failed"


@pytest.mark.asyncio
async def test_successful_mcp_result_stays_completed_for_the_tui() -> None:
    server = FakeMCPServer("files_main", [_mcp_tool("list_files")])

    tools: list[Tool] = await _register_server_tools(_config("files_main", ["list_files"]), server)
    output = await tools[0].on_invoke_tool(None, "{}")  # type: ignore[union-attr]

    # A non-error result is untouched and keeps rendering as done.
    assert output == {"type": "text", "text": "routed:list_files"}
    assert _tool_status_from_result(output) == "completed"


# --- server build branch -----------------------------------------------------


def test_build_server_stdio_branch() -> None:
    config = McpConnectionConfig(
        name="local_fs",
        transport="stdio",
        command="my-server",
        args=["--flag", "value"],
        env={"TOKEN": "x"},
    )

    server = _build_server(config)

    # Built, not connected: no subprocess is launched here.
    assert isinstance(server, MCPServerStdio)
    assert server.name == "local_fs"
    assert server.params.command == "my-server"
    assert server.params.args == ["--flag", "value"]
    assert server.params.env == {"TOKEN": "x"}


def test_build_server_http_branch() -> None:
    server = _build_server(_config("files_main", ["list_files"]))

    assert isinstance(server, MCPServerStreamableHttp)
    assert server.name == "files_main"


# --- loader ------------------------------------------------------------------


def test_loader_parses_stdio_and_http_entries(tmp_path: Path) -> None:
    config_file = tmp_path / "mcp-servers.json"
    config_file.write_text(
        json.dumps(
            [
                {
                    "name": "local_fs",
                    "transport": "stdio",
                    "command": "npx",
                    "args": ["-y", "server-filesystem"],
                },
                {
                    "name": "files_main",
                    "transport": "http",
                    "url": "https://mcp.example.com",
                    "auth": {"kind": "bearer", "token": "abc"},
                    "allowed_tools": ["list_files"],
                },
            ]
        ),
        encoding="utf-8",
    )

    configs = load_user_mcp_configs(config_file)

    assert [c.name for c in configs] == ["local_fs", "files_main"]
    assert configs[0].transport == "stdio"
    assert configs[1].allowed_tools == ["list_files"]


def test_loader_skips_bad_entry_but_keeps_good_ones(tmp_path: Path) -> None:
    config_file = tmp_path / "mcp-servers.json"
    config_file.write_text(
        json.dumps(
            [
                {"name": "broken", "transport": "http"},  # missing url
                {
                    "name": "local_fs",
                    "transport": "stdio",
                    "command": "npx",
                },
            ]
        ),
        encoding="utf-8",
    )

    configs = load_user_mcp_configs(config_file)

    assert [c.name for c in configs] == ["local_fs"]


def test_loader_returns_empty_when_file_absent(tmp_path: Path) -> None:
    assert load_user_mcp_configs(tmp_path / "does-not-exist.json") == []


def test_loader_reads_env_var_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_file = tmp_path / "from-env.json"
    config_file.write_text(
        json.dumps([{"name": "local_fs", "transport": "stdio", "command": "npx"}]),
        encoding="utf-8",
    )
    monkeypatch.setenv("STRIX_MCP_CONFIG", str(config_file))

    configs = load_user_mcp_configs()

    assert [c.name for c in configs] == ["local_fs"]


# --- connection notes --------------------------------------------------------


@pytest.mark.asyncio
async def test_connection_notes_are_carried_on_the_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = FakeMCPServer("db", [_mcp_tool("query")])
    monkeypatch.setattr(mcp_client, "_build_server", lambda _config: server)
    config = McpConnectionConfig(
        name="db",
        url="https://mcp.example.com",
        notes="Staging analytics DB; read-only.",
        allowed_tools=["query"],
    )

    connections = await mcp_client.connect_mcp_servers([config])

    # Notes ride on the connection (surfaced once), not stapled onto each tool.
    assert connections[0].notes == "Staging analytics DB; read-only."


def test_connection_notes_block_lists_only_noted_connections() -> None:
    connections = [
        ConnectedMcpServer(
            server=FakeMCPServer("db", []), name="db", tool_count=2, notes="staging, read-only"
        ),
        ConnectedMcpServer(server=FakeMCPServer("fs", []), name="fs", tool_count=1, notes=None),
    ]

    block = _mcp_connection_notes(connections)

    assert block is not None
    assert "db" in block
    assert "staging, read-only" in block
    # A connection without notes is not listed.
    assert "fs" not in block


def test_connection_notes_block_is_none_without_notes() -> None:
    connections = [
        ConnectedMcpServer(server=FakeMCPServer("db", []), name="db", tool_count=1, notes=None)
    ]

    assert _mcp_connection_notes(connections) is None


# --- cancellation cleanup ----------------------------------------------------


@pytest.mark.asyncio
async def test_connect_cleans_up_when_cancelled_mid_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleaned: list[str] = []

    class _Tracking(FakeMCPServer):
        def __init__(self, name: str, *, fail_connect: bool = False) -> None:
            super().__init__(name, [_mcp_tool("t")])
            self._fail_connect = fail_connect

        async def connect(self) -> None:
            if self._fail_connect:
                raise asyncio.CancelledError

        async def cleanup(self) -> None:
            cleaned.append(self._name)

    servers = {"good": _Tracking("good"), "bad": _Tracking("bad", fail_connect=True)}
    monkeypatch.setattr(mcp_client, "_build_server", lambda config: servers[config.name])

    configs = [
        McpConnectionConfig(name="good", url="https://mcp.example.com", allowed_tools=["t"]),
        McpConnectionConfig(name="bad", url="https://mcp.example.com", allowed_tools=["t"]),
    ]

    with pytest.raises(asyncio.CancelledError):
        await mcp_client.connect_mcp_servers(configs)

    # The server being connected when cancelled, and the one already connected,
    # are both cleaned up rather than orphaned.
    assert cleaned == ["bad", "good"]


# --- duplicate names and run selection ---------------------------------------


def _names_file(tmp_path: Path, *names: str) -> Path:
    config_file = tmp_path / "mcp-servers.json"
    config_file.write_text(
        json.dumps([{"name": n, "transport": "stdio", "command": "npx"} for n in names]),
        encoding="utf-8",
    )
    return config_file


def test_loader_drops_duplicate_named_connections(tmp_path: Path) -> None:
    config_file = tmp_path / "mcp-servers.json"
    config_file.write_text(
        json.dumps(
            [
                {"name": "dup", "transport": "stdio", "command": "first"},
                {"name": "dup", "transport": "stdio", "command": "second"},
                {"name": "other", "transport": "stdio", "command": "npx"},
            ]
        ),
        encoding="utf-8",
    )

    configs = load_user_mcp_configs(config_file)

    # Duplicate name is dropped; the first entry wins.
    assert [c.name for c in configs] == ["dup", "other"]
    assert configs[0].command == "first"


def test_loader_include_selection_keeps_only_named(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_file = _names_file(tmp_path, "a", "b", "c")
    monkeypatch.setenv("STRIX_MCP_ONLY", "a,c")

    configs = load_user_mcp_configs(config_file)

    assert [c.name for c in configs] == ["a", "c"]


def test_loader_exclude_selection_drops_named(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_file = _names_file(tmp_path, "a", "b", "c")
    monkeypatch.setenv("STRIX_MCP_EXCLUDE", "b")

    configs = load_user_mcp_configs(config_file)

    assert [c.name for c in configs] == ["a", "c"]


# --- reading a tool call back to the server it went out to -------------------


def test_resolve_mcp_tool_splits_against_the_run_connections() -> None:
    assert resolve_mcp_tool("local_fs_read_file", ["github", "local_fs"]) == (
        "local_fs",
        "read_file",
    )


def test_resolve_mcp_tool_prefers_the_longest_matching_connection() -> None:
    # One connection's name being a prefix of another's must not misattribute.
    assert resolve_mcp_tool("files_main_list", ["files", "files_main"]) == ("files_main", "list")


def test_resolve_mcp_tool_matches_a_connection_name_it_had_to_sanitize() -> None:
    # "my server" reaches the model as "my_server_db_query".
    tool_name = namespaced_tool_name("my server", "db.query")

    assert resolve_mcp_tool(tool_name, ["my server"]) == ("my server", "db_query")


def test_resolve_mcp_tool_ignores_tools_that_are_not_a_connection_s() -> None:
    assert resolve_mcp_tool("exec_command", ["local_fs"]) is None
    # A name that merely starts like a connection is not one of its tools.
    assert resolve_mcp_tool("local_fsx", ["local_fs"]) is None


def test_projected_tool_call_names_the_server_it_went_out_to() -> None:
    view = TuiLiveView()
    view.set_mcp_connections(["local_fs"])

    view._record_tool_call_data(
        "agent-1",
        {"call_id": "c1", "tool_name": "local_fs_read_file", "args": {"path": "/etc/hosts"}},
    )
    view._record_tool_call_data(
        "agent-1",
        {"call_id": "c2", "tool_name": "exec_command", "args": {"cmd": "ls"}},
    )

    mcp_call, built_in = (event["data"] for event in view.events)
    assert (mcp_call["mcp_connection"], mcp_call["mcp_tool"]) == ("local_fs", "read_file")
    # A built-in call carries no connection, which is what keeps it rendering as one.
    assert "mcp_connection" not in built_in

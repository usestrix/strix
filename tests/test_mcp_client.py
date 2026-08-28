"""Tests for the generic MCP dispatch model.

Connections are connected without being registered as agent tools; their live
sessions go into a per-run registry; and every agent reaches them through the
two dispatch tools ``describe_mcp`` and ``call_mcp``.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import time
from functools import partial
from typing import TYPE_CHECKING, Any

import pytest
from agents.mcp import MCPServer, MCPServerStdio, MCPServerStreamableHttp
from agents.tool_context import ToolContext
from mcp.types import CallToolResult, TextContent
from mcp.types import Tool as MCPTool
from pydantic import ValidationError

from strix.agents import factory
from strix.agents.prompt import render_system_prompt
from strix.interface.tui.live_view import TuiLiveView
from strix.tools.mcp import (
    MCP_REGISTRY_CONTEXT_KEY,
    BearerAuth,
    McpCallInfo,
    McpConnectionConfig,
    McpConnectionRequest,
    McpRegistry,
    SupervisedMcpSession,
    attach_mcp_requests,
    call_mcp,
    describe_mcp,
    list_mcps,
    load_user_mcp_configs,
    namespaced_tool_name,
    resolve_mcp_call,
)
from strix.tools.mcp import client as mcp_client
from strix.tools.mcp import session as mcp_session_mod


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


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


class MultiBlockErrorServer(FakeMCPServer):
    """An errored call whose serialized output is a list (multiple content blocks)."""

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None,
        meta: dict[str, Any] | None = None,
    ) -> CallToolResult:
        self.calls.append((tool_name, arguments))
        return CallToolResult(
            content=[
                TextContent(type="text", text="first"),
                TextContent(type="text", text="second"),
            ],
            isError=True,
        )


class StructuredErrorServer(FakeMCPServer):
    """An errored call whose serialized output is a string (structured content)."""

    def __init__(self, name: str, tools: list[MCPTool]) -> None:
        super().__init__(name, tools)
        # The base server sets this in __init__, so flip it on the instance to
        # take the structured-content serialization branch.
        self.use_structured_content = True

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None,
        meta: dict[str, Any] | None = None,
    ) -> CallToolResult:
        self.calls.append((tool_name, arguments))
        return CallToolResult(
            content=[TextContent(type="text", text="ignored")],
            structuredContent={"error": "boom"},
            isError=True,
        )


def _mcp_tool(name: str, *, description: str | None = None) -> MCPTool:
    return MCPTool(
        name=name,
        description=description if description is not None else f"remote tool {name}",
        inputSchema={"type": "object", "properties": {"path": {"type": "string"}}},
    )


def _config(name: str, allowed_tools: list[str] | None) -> McpConnectionConfig:
    return McpConnectionConfig(
        name=name,
        url="https://mcp.example.com",
        auth=BearerAuth(token="run-token"),  # nosec B106
        allowed_tools=allowed_tools,
    )


def _built_server(server: MCPServer) -> mcp_client.BuiltMcpServer:
    return mcp_client.BuiltMcpServer(server, None)


def _ctx(registry: McpRegistry | None) -> ToolContext[dict[str, Any]]:
    context: dict[str, Any] = {} if registry is None else {MCP_REGISTRY_CONTEXT_KEY: registry}
    return ToolContext(
        context=context,
        tool_name="mcp",
        tool_call_id="call-1",
        tool_arguments="{}",
    )


async def _aclose_all(connections: list[Any]) -> None:
    """Close every supervised session a connect/attach test opened, so no
    supervising task leaks into the event loop's teardown."""
    for connection in connections:
        await connection.session.aclose()


@pytest.fixture(autouse=True)
def _clear_mcp_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Hide any MCP settings the developer has exported in their own shell."""
    for name in ("STRIX_MCP_CONFIG", "STRIX_MCP_ONLY", "STRIX_MCP_EXCLUDE"):
        monkeypatch.delenv(name, raising=False)


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
    assert config.auth.token == "abc"  # nosec B105
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
        McpConnectionConfig.model_validate({"name": "x", "transport": "stdio"})


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
    headers = mcp_client._auth_headers(_config("files_main", []))

    assert headers == {"Authorization": "Bearer run-token"}


# --- connect without global registration -------------------------------------


@pytest.mark.asyncio
async def test_connect_returns_sessions_without_registering_agent_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = list(factory.registered_agent_tools())
    servers = {
        "fs": FakeMCPServer("fs", [_mcp_tool("read_file"), _mcp_tool("write_file")]),
        "db": FakeMCPServer("db", [_mcp_tool("query")]),
    }
    monkeypatch.setattr(
        mcp_client, "_build_server", lambda config: _built_server(servers[config.name])
    )

    connections = await mcp_client.connect_mcp_servers(
        [_config("fs", None), _config("db", ["query"])]
    )

    # The live sessions come back with their tool counts, and nothing was added
    # to the global agent-tool registry that pro shares.
    assert [(c.name, c.tool_count) for c in connections] == [("fs", 2), ("db", 1)]
    assert list(factory.registered_agent_tools()) == before

    await _aclose_all(connections)


@pytest.mark.asyncio
async def test_tool_count_honors_the_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    server = FakeMCPServer("fs", [_mcp_tool("read_file"), _mcp_tool("write_file")])
    monkeypatch.setattr(mcp_client, "_build_server", lambda _config: _built_server(server))

    connections = await mcp_client.connect_mcp_servers([_config("fs", ["read_file"])])

    assert connections[0].tool_count == 1

    await _aclose_all(connections)


@pytest.mark.asyncio
async def test_connection_notes_ride_on_the_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = FakeMCPServer("db", [_mcp_tool("query")])
    monkeypatch.setattr(mcp_client, "_build_server", lambda _config: _built_server(server))
    config = McpConnectionConfig(
        name="db",
        url="https://mcp.example.com",
        notes="Staging analytics DB; read-only.",
        allowed_tools=["query"],
    )

    connections = await mcp_client.connect_mcp_servers([config])

    assert connections[0].notes == "Staging analytics DB; read-only."

    await _aclose_all(connections)


# --- server build branch -----------------------------------------------------


def test_build_server_stdio_branch() -> None:
    config = McpConnectionConfig(
        name="local_fs",
        transport="stdio",
        command="my-server",
        args=["--flag", "value"],
        env={"TOKEN": "x"},
    )

    server = mcp_client._build_server(config).server

    assert isinstance(server, MCPServerStdio)
    assert server.name == "local_fs"
    assert server.params.command == "my-server"
    assert server.params.args == ["--flag", "value"]
    assert server.params.env == {"TOKEN": "x"}


def test_build_server_http_branch() -> None:
    server = mcp_client._build_server(_config("files_main", ["list_files"])).server

    assert isinstance(server, MCPServerStreamableHttp)
    assert server.name == "files_main"


# --- registry ----------------------------------------------------------------


def test_registry_add_get_and_names() -> None:
    registry = McpRegistry()
    server = FakeMCPServer("fs", [_mcp_tool("read_file")])

    registry.add(name="fs", server=server, purpose="local files", tool_count=1)

    entry = registry.get("fs")
    assert entry is not None
    assert entry.server is server
    assert entry.purpose == "local files"
    assert entry.tool_count == 1
    assert registry.get("missing") is None
    assert registry.names() == ["fs"]
    assert bool(registry) is True
    assert len(registry) == 1


def test_registry_summaries() -> None:
    registry = McpRegistry()
    registry.add(name="fs", server=FakeMCPServer("fs", []), purpose="local files", tool_count=2)
    registry.add(name="db", server=FakeMCPServer("db", []), purpose=None, tool_count=1)

    summaries = registry.summaries()
    assert [(s.name, s.purpose, s.tool_count) for s in summaries] == [
        ("fs", "local files", 2),
        ("db", None, 1),
    ]


# --- list_mcps ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_mcps_returns_connections_with_ids_and_descriptions() -> None:
    registry = McpRegistry()
    registry.add(name="fs", server=FakeMCPServer("fs", []), purpose="local files", tool_count=2)
    registry.add(name="db", server=FakeMCPServer("db", []), purpose=None, tool_count=1)

    out = await list_mcps.on_invoke_tool(_ctx(registry), "{}")

    # ``id`` is the exact connection name describe_mcp/call_mcp accept;
    # ``description`` is the summary's purpose; ``dead`` is the connection's live
    # health (both healthy here); no tool schemas are included.
    assert out == {
        "connections": [
            {
                "id": "fs",
                "name": "fs",
                "description": "local files",
                "tool_count": 2,
                "dead": False,
            },
            {"id": "db", "name": "db", "description": None, "tool_count": 1, "dead": False},
        ]
    }


@pytest.mark.asyncio
async def test_list_mcps_empty_without_a_registry() -> None:
    assert await list_mcps.on_invoke_tool(_ctx(None), "{}") == {"connections": []}


@pytest.mark.asyncio
async def test_list_mcps_empty_when_registry_has_no_connections() -> None:
    assert await list_mcps.on_invoke_tool(_ctx(McpRegistry()), "{}") == {"connections": []}


# --- describe_mcp ------------------------------------------------------------


@pytest.mark.asyncio
async def test_describe_mcp_returns_tool_names_and_schemas() -> None:
    registry = McpRegistry()
    server = FakeMCPServer("fs", [_mcp_tool("read_file", description="Read a file")])
    registry.add(name="fs", server=server, purpose=None, tool_count=1)

    out = await describe_mcp.on_invoke_tool(_ctx(registry), json.dumps({"connection": "fs"}))

    assert "read_file" in out
    assert "Read a file" in out
    # The tool's JSON input schema is shown so the model can build call arguments.
    assert '"path"' in out


@pytest.mark.asyncio
async def test_describe_mcp_errors_clearly_on_unknown_connection() -> None:
    registry = McpRegistry()
    registry.add(name="fs", server=FakeMCPServer("fs", []), purpose=None, tool_count=0)

    out = await describe_mcp.on_invoke_tool(_ctx(registry), json.dumps({"connection": "nope"}))

    assert "Unknown MCP connection 'nope'" in out
    assert "fs" in out


@pytest.mark.asyncio
async def test_describe_mcp_without_any_connections() -> None:
    out = await describe_mcp.on_invoke_tool(_ctx(None), json.dumps({"connection": "fs"}))

    assert out == "No MCP connections are configured for this run."


# --- call_mcp ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_call_mcp_dispatches_and_returns_converted_output() -> None:
    registry = McpRegistry()
    server = FakeMCPServer("fs", [_mcp_tool("read_file")])
    registry.add(name="fs", server=server, purpose=None, tool_count=1)

    out = await call_mcp.on_invoke_tool(
        _ctx(registry),
        json.dumps({"connection": "fs", "tool": "read_file", "arguments": {"path": "/etc/hosts"}}),
    )

    # The call reaches the server by the unprefixed tool name with its arguments.
    assert server.calls == [("read_file", {"path": "/etc/hosts"})]
    assert out == {"type": "text", "text": "routed:read_file"}


@pytest.mark.asyncio
async def test_call_mcp_defaults_missing_arguments_to_empty_object() -> None:
    registry = McpRegistry()
    server = FakeMCPServer("fs", [_mcp_tool("ping")])
    registry.add(name="fs", server=server, purpose=None, tool_count=1)

    await call_mcp.on_invoke_tool(_ctx(registry), json.dumps({"connection": "fs", "tool": "ping"}))

    assert server.calls == [("ping", {})]


@pytest.mark.asyncio
async def test_call_mcp_coerces_json_string_arguments() -> None:
    # Some models serialize the schema-less ``arguments`` object as a JSON string;
    # a correct call must not be rejected over that encoding.
    registry = McpRegistry()
    server = FakeMCPServer("fs", [_mcp_tool("read_file")])
    registry.add(name="fs", server=server, purpose=None, tool_count=1)

    out = await call_mcp.on_invoke_tool(
        _ctx(registry),
        json.dumps(
            {"connection": "fs", "tool": "read_file", "arguments": '{"path": "/etc/hosts"}'}
        ),
    )

    assert server.calls == [("read_file", {"path": "/etc/hosts"})]
    assert out == {"type": "text", "text": "routed:read_file"}


@pytest.mark.asyncio
async def test_call_mcp_errors_on_unparseable_string_arguments() -> None:
    registry = McpRegistry()
    server = FakeMCPServer("fs", [_mcp_tool("read_file")])
    registry.add(name="fs", server=server, purpose=None, tool_count=1)

    out = await call_mcp.on_invoke_tool(
        _ctx(registry),
        json.dumps({"connection": "fs", "tool": "read_file", "arguments": "not json"}),
    )

    assert "expected a JSON object" in out
    assert server.calls == []


@pytest.mark.asyncio
async def test_call_mcp_errors_on_unknown_connection() -> None:
    registry = McpRegistry()
    registry.add(name="fs", server=FakeMCPServer("fs", []), purpose=None, tool_count=0)

    out = await call_mcp.on_invoke_tool(
        _ctx(registry), json.dumps({"connection": "nope", "tool": "x"})
    )

    assert "Unknown MCP connection 'nope'" in out
    assert "fs" in out


@pytest.mark.asyncio
async def test_call_mcp_errors_on_unknown_tool() -> None:
    registry = McpRegistry()
    server = FakeMCPServer("fs", [_mcp_tool("read_file")])
    registry.add(name="fs", server=server, purpose=None, tool_count=1)

    out = await call_mcp.on_invoke_tool(
        _ctx(registry), json.dumps({"connection": "fs", "tool": "delete_everything"})
    )

    assert "Unknown tool 'delete_everything'" in out
    assert "read_file" in out
    # A rejected tool name never reaches the server.
    assert server.calls == []


@pytest.mark.asyncio
async def test_call_mcp_errors_on_non_dict_arguments() -> None:
    registry = McpRegistry()
    server = FakeMCPServer("fs", [_mcp_tool("read_file")])
    registry.add(name="fs", server=server, purpose=None, tool_count=1)

    out = await call_mcp.on_invoke_tool(
        _ctx(registry),
        json.dumps({"connection": "fs", "tool": "read_file", "arguments": ["not", "a", "dict"]}),
    )

    assert "expected a JSON object" in out
    assert server.calls == []


@pytest.mark.asyncio
async def test_call_mcp_applies_a_connection_result_transform() -> None:
    registry = McpRegistry()
    server = FakeMCPServer("fs", [_mcp_tool("read_file")])
    seen: list[tuple[str, Any]] = []

    def transform(label: str, structured: Any) -> Any:
        seen.append((label, structured))
        return {"kept": structured["content"][0]["text"]}

    registry.add(name="fs", server=server, purpose=None, tool_count=1, result_transform=transform)

    out = await call_mcp.on_invoke_tool(
        _ctx(registry), json.dumps({"connection": "fs", "tool": "read_file"})
    )

    # The transform sees the model-facing <connection>_<tool> label and the
    # parsed CallToolResult, and its return becomes the tool output.
    assert seen[0][0] == "fs_read_file"
    assert seen[0][1]["content"][0]["text"] == "routed:read_file"
    assert out == {"kept": "routed:read_file"}


@pytest.mark.asyncio
async def test_call_mcp_flags_an_errored_result_failed_for_the_tui() -> None:
    registry = McpRegistry()
    server = ErroringMCPServer("fs", [_mcp_tool("read_file")])
    registry.add(name="fs", server=server, purpose=None, tool_count=1)

    out = await call_mcp.on_invoke_tool(
        _ctx(registry), json.dumps({"connection": "fs", "tool": "read_file"})
    )

    # The agent content is unchanged; success:False rides alongside so the TUI
    # can tell an errored call from a done one.
    assert out == {"type": "text", "text": "boom:read_file", "success": False}


# --- the two tools are the only MCP surface every agent gets -----------------


def test_agent_carries_exactly_the_dispatch_tools_regardless_of_connections() -> None:
    """No matter how many MCP connections a run makes, an agent's tool list gains
    exactly list_mcps, describe_mcp, and call_mcp and never a per-connection
    provider tool."""
    root = factory.build_strix_agent(is_root=True)
    child = factory.build_strix_agent(is_root=False)

    root_names = [t.name for t in root.tools]
    child_names = [t.name for t in child.tools]

    assert {"list_mcps", "describe_mcp", "call_mcp"} <= set(root_names)
    assert {"list_mcps", "describe_mcp", "call_mcp"} <= set(child_names)

    # Five hypothetical connections would once have added ~all their tools as
    # namespaced provider tools; none of those names may appear now.
    provider_names = {
        namespaced_tool_name(f"conn{i}", tool)
        for i in range(5)
        for tool in ("read_file", "write_file", "query")
    }
    assert provider_names.isdisjoint(root_names)
    assert provider_names.isdisjoint(child_names)

    # The tool list does not grow with connection count: it is the same set of
    # names whether or not any connection exists, because connections never
    # contribute tools.
    assert root_names == [t.name for t in factory.build_strix_agent(is_root=True).tools]


# --- prompt guidance replaces the old per-connection inventory ---------------


def test_prompt_renders_static_three_tool_guidance_when_mcp_available() -> None:
    prompt = render_system_prompt(system_prompt_context={"mcp_available": True})

    assert "MCP CONNECTIONS" in prompt
    # The three discovery/dispatch tools are named as the way in.
    assert "list_mcps" in prompt
    assert "describe_mcp" in prompt
    assert "call_mcp" in prompt


def test_prompt_has_no_mcp_section_without_availability() -> None:
    assert "MCP CONNECTIONS" not in render_system_prompt(system_prompt_context={})


def test_prompt_renders_named_connection_inventory() -> None:
    """With mcp_available set, the prompt names each connected server (name, tool
    count, purpose) so every agent sees what is available at the start, alongside
    the three dispatch tools for re-listing and inspecting them at run time."""
    prompt = render_system_prompt(
        system_prompt_context={
            "mcp_available": True,
            "mcp_connections": [
                {"name": "supabase", "purpose": "read the app's schema", "tool_count": 13}
            ],
        }
    )

    assert "MCP CONNECTIONS" in prompt
    assert "supabase" in prompt
    assert "13 tools" in prompt
    assert "read the app's schema" in prompt


def test_prompt_inventory_is_gated_on_availability() -> None:
    """The block is gated on ``mcp_available``; an ``mcp_connections`` payload
    without it renders nothing, so a stale or spoofed list cannot leak names."""
    prompt = render_system_prompt(
        system_prompt_context={
            "mcp_connections": [{"name": "secret-conn", "purpose": "x", "tool_count": 3}]
        }
    )

    assert "MCP CONNECTIONS" not in prompt
    assert "secret-conn" not in prompt


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
                {"name": "broken", "transport": "http"},
                {"name": "local_fs", "transport": "stdio", "command": "npx"},
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


# --- cancellation cleanup ----------------------------------------------------


@pytest.mark.asyncio
async def test_connect_skips_a_connection_whose_connect_is_cancelled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Each connection now connects on its own supervising task. A cancellation of
    # one session's connect (the transport scope dying mid-connect) is contained
    # to that task: the connection is skipped and cleaned up, and the run's attach
    # keeps going rather than being cancelled.
    cleaned: list[str] = []

    class _Tracking(FakeMCPServer):
        def __init__(self, name: str, *, cancel_connect: bool = False) -> None:
            super().__init__(name, [_mcp_tool("t")])
            self._cancel_connect = cancel_connect

        async def connect(self) -> None:
            if self._cancel_connect:
                raise asyncio.CancelledError

        async def cleanup(self) -> None:
            cleaned.append(self._name)

    servers = {"good": _Tracking("good"), "bad": _Tracking("bad", cancel_connect=True)}
    monkeypatch.setattr(
        mcp_client, "_build_server", lambda config: _built_server(servers[config.name])
    )

    configs = [_config("good", ["t"]), _config("bad", ["t"])]

    connections = await mcp_client.connect_mcp_servers(configs)

    # The cancelled connect is skipped and cleaned up; the good one is returned.
    assert [c.name for c in connections] == ["good"]
    assert "bad" in cleaned

    await _aclose_all(connections)
    assert "good" in cleaned


@pytest.mark.asyncio
async def test_connect_cleans_up_started_sessions_when_attach_is_cancelled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # If the attach coroutine itself is cancelled (the run going down) while a
    # later connection is still connecting, every session started so far is closed
    # on its own task before the cancellation is re-raised, so nothing is orphaned.
    cleaned: list[str] = []

    class _Tracking(FakeMCPServer):
        def __init__(self, name: str, *, block_connect: bool = False) -> None:
            super().__init__(name, [_mcp_tool("t")])
            self._block_connect = block_connect

        async def connect(self) -> None:
            if self._block_connect:
                await asyncio.Event().wait()  # never completes

        async def cleanup(self) -> None:
            cleaned.append(self._name)

    servers = {"good": _Tracking("good"), "slow": _Tracking("slow", block_connect=True)}
    monkeypatch.setattr(
        mcp_client, "_build_server", lambda config: _built_server(servers[config.name])
    )

    async def _attach() -> list[Any]:
        # Connect "good" first, then hang forever connecting "slow".
        return await mcp_client.connect_mcp_servers(
            [_config("good", ["t"]), _config("slow", ["t"])]
        )

    task = asyncio.create_task(_attach())
    # Give the loop time to connect good and reach slow's hanging connect.
    for _ in range(100):
        await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # The already-connected "good" session was cleaned up, not orphaned.
    assert "good" in cleaned


# --- reading a tool call back to the server it went out to -------------------
# namespaced_tool_name stays in strix.tools.mcp.naming so call_mcp can build the
# result_transform label. The connection a call went out to is read off the
# call's arguments by the TUI projection, not off the tool name.


def test_namespaced_name_is_a_valid_tool_name() -> None:
    # A connection named with a space and a server tool named with a dot still
    # sanitize to a valid model-facing label for the result_transform.
    name = namespaced_tool_name("my server", "db.query")

    assert name == "my_server_db_query"
    assert re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", name)


def test_projected_call_mcp_names_the_server_and_tool_from_its_args() -> None:
    view = TuiLiveView()

    view._record_tool_call_data(
        "agent-1",
        {
            "call_id": "c1",
            "tool_name": "call_mcp",
            "args": {"connection": "local_fs", "tool": "read_file", "arguments": {"path": "/x"}},
        },
    )
    view._record_tool_call_data(
        "agent-1",
        {"call_id": "c2", "tool_name": "exec_command", "args": {"cmd": "ls"}},
    )

    mcp_call, built_in = (event["data"] for event in view.events)
    assert (mcp_call["mcp_connection"], mcp_call["mcp_tool"]) == ("local_fs", "read_file")
    assert "mcp_connection" not in built_in


def test_projected_describe_mcp_names_the_connection_with_no_tool() -> None:
    view = TuiLiveView()

    view._record_tool_call_data(
        "agent-1",
        {"call_id": "c1", "tool_name": "describe_mcp", "args": {"connection": "local_fs"}},
    )

    (describe,) = (event["data"] for event in view.events)
    # An empty tool is what tells both renderers to present the row as inspecting
    # the connection rather than as a call to a tool on it.
    assert describe["mcp_connection"] == "local_fs"
    assert describe["mcp_tool"] == ""


# --- source-agnostic attach --------------------------------------------------


@pytest.mark.asyncio
async def test_attach_populates_registry_with_provider_and_transform(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = FakeMCPServer("db", [_mcp_tool("query")])
    monkeypatch.setattr(mcp_client, "_build_server", lambda _config: _built_server(server))

    def transform(_label: str, structured: Any) -> Any:
        return {"kept": structured}

    registry = McpRegistry()
    request = McpConnectionRequest(
        config=_config("db", ["query"]),
        provider="supabase",
        result_transform=transform,
        purpose="Customer DB",
    )

    connections = await attach_mcp_requests([request], registry)

    assert [(c.name, c.tool_count) for c in connections] == [("db", 1)]
    entry = registry.get("db")
    assert entry is not None
    assert entry.server is server
    assert entry.provider == "supabase"
    assert entry.purpose == "Customer DB"
    assert entry.result_transform is transform

    await _aclose_all(connections)


@pytest.mark.asyncio
async def test_attach_bare_request_matches_the_command_line_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The command-line path wraps each config in a bare request (no provider or
    # transform); purpose then falls back to the connection's notes.
    server = FakeMCPServer("db", [_mcp_tool("query")])
    monkeypatch.setattr(mcp_client, "_build_server", lambda _config: _built_server(server))
    config = McpConnectionConfig(
        name="db",
        url="https://mcp.example.com",
        notes="Staging analytics DB; read-only.",
        allowed_tools=["query"],
    )

    registry = McpRegistry()
    connections = await attach_mcp_requests([McpConnectionRequest(config=config)], registry)

    entry = registry.get("db")
    assert entry is not None
    assert entry.provider is None
    assert entry.result_transform is None
    assert entry.purpose == "Staging analytics DB; read-only."

    await _aclose_all(connections)


@pytest.mark.asyncio
async def test_attach_is_fail_open_and_skips_a_failed_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    good = FakeMCPServer("good", [_mcp_tool("t")])

    class _Failing(FakeMCPServer):
        async def connect(self) -> None:
            raise RuntimeError("cannot reach server")

    servers = {"good": good, "bad": _Failing("bad", [_mcp_tool("t")])}
    monkeypatch.setattr(
        mcp_client, "_build_server", lambda config: _built_server(servers[config.name])
    )

    registry = McpRegistry()
    connections = await attach_mcp_requests(
        [
            McpConnectionRequest(config=_config("bad", ["t"]), provider="p"),
            McpConnectionRequest(config=_config("good", ["t"]), provider="q"),
        ],
        registry,
    )

    # The failed connection is skipped without raising; the good one is attached.
    assert [c.name for c in connections] == ["good"]
    assert registry.names() == ["good"]
    assert registry.get("good") is not None
    assert registry.get("bad") is None

    await _aclose_all(connections)


# --- provider on the registry ------------------------------------------------


def test_provider_round_trips_through_registry_and_summaries() -> None:
    registry = McpRegistry()
    registry.add(
        name="db",
        server=FakeMCPServer("db", []),
        purpose="Customer DB",
        tool_count=1,
        provider="supabase",
    )
    registry.add(name="fs", server=FakeMCPServer("fs", []), purpose=None, tool_count=0)

    assert registry.get("db").provider == "supabase"  # type: ignore[union-attr]
    # A connection with no provider defaults to None, not an error.
    assert registry.get("fs").provider is None  # type: ignore[union-attr]

    summaries = {s.name: s.provider for s in registry.summaries()}
    assert summaries == {"db": "supabase", "fs": None}


# --- resolve_mcp_call --------------------------------------------------------


def test_resolve_call_mcp_reads_connection_tool_and_provider() -> None:
    registry = McpRegistry()
    registry.add(name="db", server=FakeMCPServer("db", []), tool_count=1, provider="supabase")

    info = resolve_mcp_call(
        "call_mcp", {"connection": "db", "tool": "query", "arguments": {}}, registry
    )

    assert info == McpCallInfo(connection="db", tool="query", provider="supabase")


def test_resolve_describe_mcp_has_an_empty_tool() -> None:
    registry = McpRegistry()
    registry.add(name="db", server=FakeMCPServer("db", []), tool_count=1, provider="supabase")

    info = resolve_mcp_call("describe_mcp", {"connection": "db"}, registry)

    assert info == McpCallInfo(connection="db", tool="", provider="supabase")


def test_resolve_without_a_registry_omits_the_provider() -> None:
    # The OSS viewer projects calls with no live registry: it still reads the
    # connection and tool, and simply leaves the provider out.
    info = resolve_mcp_call("call_mcp", {"connection": "db", "tool": "query"})

    assert info == McpCallInfo(connection="db", tool="query", provider=None)


def test_resolve_returns_none_for_a_non_dispatch_tool() -> None:
    assert resolve_mcp_call("exec_command", {"cmd": "ls"}) is None


def test_resolve_returns_none_for_an_unknown_connection_with_a_registry() -> None:
    registry = McpRegistry()
    registry.add(name="db", server=FakeMCPServer("db", []), tool_count=1)

    assert resolve_mcp_call("call_mcp", {"connection": "nope", "tool": "x"}, registry) is None


def test_resolve_returns_none_when_the_connection_is_missing_from_args() -> None:
    assert resolve_mcp_call("call_mcp", {"tool": "query"}) is None


# --- errored results surface as failed regardless of output shape ------------


@pytest.mark.asyncio
async def test_errored_dict_output_carries_success_false() -> None:
    registry = McpRegistry()
    server = ErroringMCPServer("fs", [_mcp_tool("read_file")])
    registry.add(name="fs", server=server, tool_count=1)

    out = await call_mcp.on_invoke_tool(
        _ctx(registry), json.dumps({"connection": "fs", "tool": "read_file"})
    )

    # A single content block is a dict; success:False rides alongside and the
    # SDK's ToolOutput projection drops it before the agent, so the agent keeps
    # the exact error content.
    assert out == {"type": "text", "text": "boom:read_file", "success": False}


@pytest.mark.asyncio
async def test_errored_list_output_is_wrapped_with_success_false() -> None:
    registry = McpRegistry()
    server = MultiBlockErrorServer("fs", [_mcp_tool("read_file")])
    registry.add(name="fs", server=server, tool_count=1)

    out = await call_mcp.on_invoke_tool(
        _ctx(registry), json.dumps({"connection": "fs", "tool": "read_file"})
    )

    # Multiple content blocks serialize to a list, which has no top-level dict to
    # carry the flag, so it is wrapped under ``content`` with success:False.
    assert out == {
        "success": False,
        "content": [
            {"type": "text", "text": "first"},
            {"type": "text", "text": "second"},
        ],
    }


@pytest.mark.asyncio
async def test_errored_structured_output_is_wrapped_with_success_false() -> None:
    registry = McpRegistry()
    server = StructuredErrorServer("fs", [_mcp_tool("read_file")])
    registry.add(name="fs", server=server, tool_count=1)

    out = await call_mcp.on_invoke_tool(
        _ctx(registry), json.dumps({"connection": "fs", "tool": "read_file"})
    )

    # Structured content serializes to a JSON string; it too is wrapped under
    # ``content`` so the failure flag has a top-level dict to ride on.
    assert out == {"success": False, "content": json.dumps({"error": "boom"})}


# --- per-session isolation: containment, reconnect-retry, mark-dead ----------
# Each MCP connection's live session is owned by its own supervising task. A
# background failure in one session is contained to that task: the agent's call
# comes back as a value, the run keeps going, and the session reconnects once and
# retries the failed call once before it is marked unavailable.


class _DyingHttpServer(FakeMCPServer):
    """A connected server whose ``call_tool`` fails to model a session death.

    ``death`` is the exception raised on a call: a plain ``Exception`` models an
    HTTP/transport error, and ``asyncio.CancelledError`` models the streamable-HTTP
    transport's task group cancelling the supervising task from a background POST
    error (for example a provider 403). ``alive`` flips to stop dying, so a
    reconnected replacement can succeed.
    """

    def __init__(
        self,
        name: str,
        tools: list[MCPTool],
        *,
        death: BaseException,
        alive: bool = False,
    ) -> None:
        super().__init__(name, tools)
        self._death = death
        self.alive = alive

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None,
        meta: dict[str, Any] | None = None,
    ) -> CallToolResult:
        if not self.alive:
            raise self._death
        return await super().call_tool(tool_name, arguments)


def _secret_config(name: str) -> McpConnectionConfig:
    return McpConnectionConfig(
        name=name,
        url="https://mcp.example.com",
        auth=BearerAuth(token="super-secret-bearer-token-42"),  # nosec B106
        allowed_tools=["read_file"],
    )


async def _started_session(config: McpConnectionConfig) -> SupervisedMcpSession:
    session = SupervisedMcpSession(config)
    assert await session.start()
    return session


@pytest.mark.asyncio
async def test_call_mcp_reconnects_and_retries_after_a_session_death(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The first session dies on its call; the supervisor rebuilds the connection
    # once (reusing the existing _build_server + connect), retries the one call
    # once, and the retry lands on the healthy replacement.
    first = _DyingHttpServer("fs", [_mcp_tool("read_file")], death=ConnectionError("403"))
    second = FakeMCPServer("fs", [_mcp_tool("read_file")])
    built = iter([first, second])
    monkeypatch.setattr(mcp_client, "_build_server", lambda _config: _built_server(next(built)))

    session = await _started_session(_secret_config("fs"))
    registry = McpRegistry()
    registry.add(name="fs", session=session, tool_count=1)

    out = await call_mcp.on_invoke_tool(
        _ctx(registry), json.dumps({"connection": "fs", "tool": "read_file"})
    )

    # The caller gets the tool output as a value, and the retried call ran on the
    # reconnected server.
    assert out == {"type": "text", "text": "routed:read_file"}
    assert second.calls == [("read_file", {})]
    assert session.is_dead is False

    await session.aclose()


@pytest.mark.asyncio
async def test_call_mcp_marks_connection_dead_when_reconnect_keeps_failing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Reconnect failures are retried and then quarantine the connection rather
    # than permanently retiring it on the first failed reconnect.
    first = _DyingHttpServer("fs", [_mcp_tool("read_file")], death=ConnectionError("403"))
    built = {"n": 0}

    def _build(_config: McpConnectionConfig) -> mcp_client.BuiltMcpServer:
        built["n"] += 1
        if built["n"] == 1:
            return _built_server(first)
        raise ConnectionError("cannot reconnect")

    monkeypatch.setattr(mcp_client, "_build_server", _build)

    session = await _started_session(_secret_config("fs"))
    registry = McpRegistry()
    registry.add(name="fs", session=session, tool_count=1)

    out = await call_mcp.on_invoke_tool(
        _ctx(registry), json.dumps({"connection": "fs", "tool": "read_file"})
    )

    # A dead connection surfaces as an ordinary failed tool call, not an exception.
    assert isinstance(out, dict)
    assert out["success"] is False
    assert "unavailable" in out["content"]
    assert session.is_dead is False
    assert session.is_unavailable is True
    assert session.server is None
    assert session._task is not None and not session._task.done()

    # A later call during cooldown short-circuits to the same failed output.
    again = await call_mcp.on_invoke_tool(
        _ctx(registry), json.dumps({"connection": "fs", "tool": "read_file"})
    )
    assert again["success"] is False

    # describe_mcp reports the connection unavailable, and list_mcps still lists it.
    described = await describe_mcp.on_invoke_tool(_ctx(registry), json.dumps({"connection": "fs"}))
    assert "unavailable" in described
    listed = await list_mcps.on_invoke_tool(_ctx(registry), "{}")
    assert [c["id"] for c in listed["connections"]] == ["fs"]

    await session.aclose()


async def _pump_until(predicate: Callable[[], bool], *, limit: int = 100) -> None:
    """Yield to the event loop until ``predicate`` holds, so a background
    supervising task can advance its reconnect without a real timer."""
    for _ in range(limit):
        if predicate():
            return
        await asyncio.sleep(0)
    raise AssertionError("condition not reached")


def _quarantine_reached(session: SupervisedMcpSession, count: int) -> bool:
    return session.is_dead or session._quarantine_count >= count


@pytest.mark.asyncio
async def test_idle_session_death_self_heals_on_reconnect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A session that dies while idle (its supervising task cancelled between calls,
    # modeling the transport scope dying with no call in flight) is quarantined and
    # keeps serving, rather than ending its supervising task.
    first = FakeMCPServer("fs", [_mcp_tool("read_file")])
    second = FakeMCPServer("fs", [_mcp_tool("read_file")])
    built = iter([first, second])
    monkeypatch.setattr(mcp_client, "_build_server", lambda _config: _built_server(next(built)))

    session = await _started_session(_secret_config("fs"))
    registry = McpRegistry()
    registry.add(name="fs", session=session, tool_count=1)

    assert session._task is not None
    session._task.cancel()  # idle transport death: no call in flight
    await _pump_until(lambda: session.is_unavailable)
    assert session.is_dead is False
    assert session.server is None

    # Once the cooldown expires, the next call reconnects onto a fresh session.
    session._unavailable_until = time.monotonic() - 1
    out = await call_mcp.on_invoke_tool(
        _ctx(registry), json.dumps({"connection": "fs", "tool": "read_file"})
    )
    assert out == {"type": "text", "text": "routed:read_file"}
    await session.aclose()


@pytest.mark.asyncio
async def test_flapping_idle_session_is_marked_dead_without_looping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Repeated idle deaths consume quarantine slots; the supervisor stays alive
    # until the configured permanent-death threshold is reached.
    first = FakeMCPServer("fs", [_mcp_tool("read_file")])
    second = FakeMCPServer("fs", [_mcp_tool("read_file")])
    built = iter([first, second])
    monkeypatch.setattr(mcp_client, "_build_server", lambda _config: _built_server(next(built)))

    session = await _started_session(_secret_config("fs"))
    registry = McpRegistry()
    registry.add(name="fs", session=session, tool_count=1)

    assert session._task is not None
    # Three idle deaths exhaust the quarantine budget.
    for count in range(1, 4):
        session._task.cancel()
        await _pump_until(partial(_quarantine_reached, session, count))
        if session.is_dead:
            break
    await _pump_until(lambda: session._task is not None and session._task.done())
    assert session.is_dead is True

    out = await call_mcp.on_invoke_tool(
        _ctx(registry), json.dumps({"connection": "fs", "tool": "read_file"})
    )
    assert out["success"] is False
    assert "unavailable" in out["content"]

    await session.aclose()


class _HangingCallServer(FakeMCPServer):
    """A connected server whose ``call_tool`` never returns, modeling a hung
    in-flight call so teardown can be tested for boundedness."""

    def __init__(self, name: str, tools: list[MCPTool]) -> None:
        super().__init__(name, tools)
        self.cleaned = False

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None,
        meta: dict[str, Any] | None = None,
    ) -> CallToolResult:
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    async def cleanup(self) -> None:
        self.cleaned = True


class _HangingConnectServer(FakeMCPServer):
    """A server whose ``connect`` never finishes, so ``start`` blocks on readiness
    and can be cancelled mid-connect."""

    def __init__(self, name: str, tools: list[MCPTool]) -> None:
        super().__init__(name, tools)
        self.cleaned = False

    async def connect(self) -> None:
        await asyncio.Event().wait()

    async def cleanup(self) -> None:
        self.cleaned = True


@pytest.mark.asyncio
async def test_aclose_is_bounded_when_an_in_flight_call_hangs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A hung call must not queue the shutdown sentinel behind itself forever:
    # aclose falls back to cancelling the supervising task, and cleanup still runs.
    monkeypatch.setattr(mcp_session_mod, "_SHUTDOWN_TIMEOUT", 0.2)
    server = _HangingCallServer("fs", [_mcp_tool("read_file")])
    monkeypatch.setattr(mcp_client, "_build_server", lambda _config: _built_server(server))

    session = await _started_session(_secret_config("fs"))
    call = asyncio.create_task(session.dispatch("read_file", {}, label="fs_read_file"))
    await asyncio.sleep(0.05)  # let the serve loop pick up the request and hang

    # Must return promptly rather than block on the hung call.
    await asyncio.wait_for(session.aclose(), timeout=3.0)
    assert session._task is not None and session._task.done()
    assert server.cleaned is True

    # The abandoned caller gets a value (dead), not a hang.
    out = await asyncio.wait_for(call, timeout=3.0)
    assert isinstance(out, dict) and out["success"] is False


@pytest.mark.asyncio
async def test_aclose_cleans_up_when_connect_is_cancelled_mid_await(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # If the scan is cancelled while start() awaits readiness, the readiness future
    # is cancelled; aclose must not raise on it and must still cancel + clean up the
    # partially connected supervisor.
    server = _HangingConnectServer("fs", [_mcp_tool("read_file")])
    monkeypatch.setattr(mcp_client, "_build_server", lambda _config: _built_server(server))

    session = SupervisedMcpSession(_secret_config("fs"))
    start = asyncio.create_task(session.start())
    await asyncio.sleep(0.05)  # let the supervisor reach the hanging connect()
    start.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await start

    await asyncio.wait_for(session.aclose(), timeout=3.0)
    assert session._task is not None and session._task.done()
    assert server.cleaned is True


@pytest.mark.asyncio
async def test_a_session_death_is_contained_and_other_connections_survive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A background failure that surfaces as a cancellation (the transport scope
    # dying) is contained to that one session: the caller gets a value, not a
    # raised CancelledError, and a second healthy connection keeps working.
    dying = _DyingHttpServer("dying", [_mcp_tool("read_file")], death=asyncio.CancelledError())
    healthy = FakeMCPServer("healthy", [_mcp_tool("read_file")])
    dying_builds = {"n": 0}

    def _build(config: McpConnectionConfig) -> mcp_client.BuiltMcpServer:
        if config.name == "healthy":
            return _built_server(healthy)
        # The dying connection connects once, then its rebuild raises, so it ends
        # up marked dead rather than recovering.
        dying_builds["n"] += 1
        if dying_builds["n"] == 1:
            return _built_server(dying)
        raise ConnectionError("cannot reconnect")

    monkeypatch.setattr(mcp_client, "_build_server", _build)

    dying_session = await _started_session(_secret_config("dying"))
    healthy_session = await _started_session(_secret_config("healthy"))
    registry = McpRegistry()
    registry.add(name="dying", session=dying_session, tool_count=1)
    registry.add(name="healthy", session=healthy_session, tool_count=1)

    dead_out = await call_mcp.on_invoke_tool(
        _ctx(registry), json.dumps({"connection": "dying", "tool": "read_file"})
    )
    # Contained: a value came back rather than a CancelledError tearing down the run.
    assert isinstance(dead_out, dict)
    assert dead_out["success"] is False

    good_out = await call_mcp.on_invoke_tool(
        _ctx(registry), json.dumps({"connection": "healthy", "tool": "read_file"})
    )
    assert good_out == {"type": "text", "text": "routed:read_file"}

    await dying_session.aclose()
    await healthy_session.aclose()


@pytest.mark.asyncio
async def test_reconnect_reuses_the_stored_config_and_never_logs_the_token(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # The reconnect path rebuilds from the config held on the session, reusing the
    # same bearer token, and that token never reaches a log line, a repr, or the
    # inventory list_mcps emits.
    seen_tokens: list[str | None] = []

    def _build(config: McpConnectionConfig) -> mcp_client.BuiltMcpServer:
        seen_tokens.append(config.auth.token if config.auth else None)
        if len(seen_tokens) == 1:
            return _built_server(
                _DyingHttpServer("fs", [_mcp_tool("read_file")], death=ConnectionError("403"))
            )
        return _built_server(FakeMCPServer("fs", [_mcp_tool("read_file")]))

    monkeypatch.setattr(mcp_client, "_build_server", _build)

    config = _secret_config("fs")
    token = config.auth.token if config.auth else ""
    session = await _started_session(config)
    registry = McpRegistry()
    entry = registry.add(name="fs", session=session, tool_count=1)

    with caplog.at_level("DEBUG", logger="strix.tools.mcp.session"):
        out = await call_mcp.on_invoke_tool(
            _ctx(registry), json.dumps({"connection": "fs", "tool": "read_file"})
        )

    # The retry succeeded, and both the initial connect and the reconnect used the
    # same token from the stored config (never re-fetched).
    assert out == {"type": "text", "text": "routed:read_file"}
    assert seen_tokens == [token, token]

    # The token appears in no log line, no repr of the session or entry, and not in
    # the inventory the agent sees.
    assert token not in caplog.text
    assert token not in repr(session)
    assert token not in repr(entry)
    listed = await list_mcps.on_invoke_tool(_ctx(registry), "{}")
    assert token not in json.dumps(listed)
    # The config is still reachable in memory for the reconnect path.
    assert entry.config is config

    await session.aclose()


# --- connection status signal ------------------------------------------------


class _RaisingMCPServer(FakeMCPServer):
    """A connected server whose every call raises, so the session dies."""

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None,
        meta: dict[str, Any] | None = None,
    ) -> CallToolResult:
        raise RuntimeError("connection lost")


@pytest.mark.asyncio
async def test_session_on_dead_fires_once_on_the_death_transition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An adopted session with no config cannot reconnect, so repeated transient
    # exhaustion eventually marks it dead; the callback fires once on that edge.
    server = _RaisingMCPServer("db", [_mcp_tool("read")])
    session = SupervisedMcpSession.adopt(server, name="db")
    fires: list[int] = []
    session.set_on_dead(lambda: fires.append(1))

    clock = [100.0]
    monkeypatch.setattr("strix.tools.mcp.session.time.monotonic", lambda: clock[0])
    monkeypatch.setattr(mcp_session_mod, "_retry_delay", lambda _attempt, _retry_after: 0)

    async def no_sleep(_delay: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", no_sleep)
    out = await session.dispatch("read", {}, label="db_read")

    assert session.is_dead is False
    assert isinstance(out, dict) and out.get("success") is False
    assert fires == []

    clock[0] += 31
    await session.dispatch("read", {}, label="db_read")
    assert session.is_dead is False
    clock[0] += 61
    await session.dispatch("read", {}, label="db_read")
    assert fires == [1]
    assert session.is_dead is True


def test_registry_statuses_report_the_live_dead_flag_and_provider() -> None:
    registry = McpRegistry()
    alive = SupervisedMcpSession.adopt(FakeMCPServer("a", []), name="a")
    gone = SupervisedMcpSession.adopt(FakeMCPServer("b", []), name="b")
    registry.add(name="a", session=alive, tool_count=2, provider="supabase")
    registry.add(name="b", session=gone, tool_count=1, provider=None)
    gone._mark_dead()

    statuses = {status.name: status for status in registry.statuses()}
    assert statuses["a"].dead is False
    assert statuses["a"].tool_count == 2
    assert statuses["a"].provider == "supabase"
    assert statuses["b"].dead is True
    assert statuses["b"].provider is None

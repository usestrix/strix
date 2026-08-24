"""Focused unit tests for scan-scoped MCP tool handling."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from agents.tool import FunctionTool

from strix.config.settings import McpServerExtras
from strix.mcp import runtime
from strix.mcp.config import EnabledMcpServer, McpDefinition


def test_public_tool_names_are_stable_unique_and_bounded() -> None:
    used: set[str] = set()
    first = runtime._public_tool_name("x" * 80, "read", used)
    second = runtime._public_tool_name("x" * 80, "read", used)

    assert first != second
    assert len(first) <= 64
    assert len(second) <= 64
    assert first == runtime._shorten(
        "mcp_" + "x" * 80 + "__read", "x" * 80 + "\0read", force_hash=False
    )


def test_allow_deny_filter_gives_deny_precedence() -> None:
    item = _item(allow_tools=["read_*", "delete_*"], deny_tools=["delete_*"])

    assert runtime._tool_allowed("read_issue", item)
    assert not runtime._tool_allowed("delete_issue", item)
    assert not runtime._tool_allowed("write_issue", item)


def test_server_uses_call_timeout_for_client_session(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class FakeStdio:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

    monkeypatch.setattr(runtime, "MCPServerStdio", FakeStdio)
    item = _item()
    item = EnabledMcpServer(
        item.definition,
        item.extras.model_copy(update={"call_timeout_s": 120}),
        item.params,
    )

    runtime._make_server(item)

    assert captured["client_session_timeout_seconds"] == 120


@pytest.mark.asyncio
async def test_structured_output_is_bounded_and_images_are_preserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runtime, "bound_and_store", _prefix_bound)

    assert await runtime._normalize_output("plain") == "plain"
    assert await runtime._normalize_output({"type": "text", "text": "large"}) == {
        "type": "text",
        "text": "bounded:large",
    }
    image = {"type": "image", "image_url": "data:image/png;base64,abc"}
    assert await runtime._normalize_output(image) is image
    unknown = await runtime._normalize_output({"unexpected": "value"})
    assert unknown["type"] == "text"
    assert unknown["text"].startswith("bounded:")


@pytest.mark.asyncio
async def test_output_bounds_all_text_blocks_once(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    async def spill(text: str, **_kwargs: Any) -> str:
        calls.append(text)
        return "[bounded aggregate]"

    _output_settings(monkeypatch, max_bytes=100, max_lines=100, max_images=3)
    monkeypatch.setattr(runtime, "bound_and_store", spill)
    result = await runtime._normalize_output(
        [{"type": "text", "text": "x" * 40} for _ in range(10)]
    )

    assert calls == ["\n".join(["x" * 40] * 10)]
    assert result == [{"type": "text", "text": "[bounded aggregate]"}]


@pytest.mark.asyncio
async def test_output_bounds_lines_across_blocks(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    async def spill(text: str, **_kwargs: Any) -> str:
        calls.append(text)
        return "[bounded aggregate]"

    _output_settings(monkeypatch, max_bytes=10_000, max_lines=3, max_images=3)
    monkeypatch.setattr(runtime, "bound_and_store", spill)
    result = await runtime._normalize_output([{"type": "text", "text": "line"} for _ in range(5)])

    assert calls == ["line\nline\nline\nline\nline"]
    assert result == [{"type": "text", "text": "[bounded aggregate]"}]


@pytest.mark.asyncio
async def test_output_limits_images_and_keeps_excess_visible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _output_settings(monkeypatch, max_bytes=10_000, max_lines=100, max_images=3)
    images = [{"type": "image", "id": number} for number in range(5)]

    result = await runtime._normalize_output(images)

    assert [block["id"] for block in result if block["type"] == "image"] == [0, 1, 2]
    assert result[-1] == {"type": "text", "text": "[... 2 image block(s) omitted ...]"}


@pytest.mark.asyncio
async def test_output_allows_no_images_when_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    _output_settings(monkeypatch, max_bytes=10_000, max_lines=100, max_images=0)

    assert await runtime._normalize_output({"type": "image", "id": 1}) == {
        "type": "text",
        "text": "[... 1 image block(s) omitted ...]",
    }


@pytest.mark.asyncio
async def test_mixed_small_output_and_plain_string_keep_their_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _output_settings(monkeypatch, max_bytes=10_000, max_lines=100, max_images=1)
    text = {"type": "text", "text": "small"}
    image = {"type": "image", "id": 1}
    result = await runtime._normalize_output(
        [text, image, {"unexpected": "value"}, {"type": "image", "id": 2}]
    )

    assert result == [
        text,
        image,
        {"type": "text", "text": '{"unexpected": "value"}'},
        {"type": "text", "text": "[... 1 image block(s) omitted ...]"},
    ]
    assert await runtime._normalize_output("plain") == "plain"
    assert await runtime._normalize_output({"type": "text", "text": "small"}) == text


async def _prefix_bound(text: str, **_kwargs: Any) -> str:
    return "bounded:" + text


def _output_settings(
    monkeypatch: pytest.MonkeyPatch, *, max_bytes: int, max_lines: int, max_images: int
) -> None:
    monkeypatch.setattr(
        runtime,
        "load_settings",
        lambda: SimpleNamespace(
            context=SimpleNamespace(
                tool_output_max_bytes=max_bytes,
                tool_output_max_lines=max_lines,
            ),
            runtime=SimpleNamespace(max_context_images=max_images),
        ),
    )


def _item(
    *,
    allow_tools: list[str] | None = None,
    deny_tools: list[str] | None = None,
    root_only: bool = False,
) -> EnabledMcpServer:
    definition = McpDefinition("server", Path("server.json"), {"command": "tool"}, "hash")
    extras = McpServerExtras(
        enabled=True,
        source="server.json",
        definition_hash="hash",
        allow_tools=allow_tools or ["*"],
        deny_tools=deny_tools or [],
        root_only=root_only,
    )
    return EnabledMcpServer(definition, extras, {"command": "tool"})


class FakeManager:
    def __init__(self, servers: list[Any], **_kwargs: Any) -> None:
        self.active_servers = servers
        self.errors: dict[Any, BaseException] = {}
        self.cleaned = False

    async def connect_all(self) -> list[Any]:
        return self.active_servers

    async def cleanup_all(self) -> None:
        self.cleaned = True


class FakeServer:
    def __init__(self, name: str) -> None:
        self.name = name

    async def list_tools(self) -> list[Any]:
        return [SimpleNamespace(name="shared", inputSchema={"type": "object"})]


class FailingManager(FakeManager):
    def __init__(self, servers: list[Any], **kwargs: Any) -> None:
        super().__init__(servers, **kwargs)
        failed = next(server for server in servers if server.name == "server")
        self.active_servers = [server for server in servers if server is not failed]
        self.errors = {failed: RuntimeError("offline")}


class CancellingServer:
    def __init__(
        self, name: str, *, cancel_on_connect: bool = False, cancel_on_list: bool = False
    ) -> None:
        self.name = name
        self.cancel_on_connect = cancel_on_connect
        self.cancel_on_list = cancel_on_list
        self.connected = False
        self.cleaned = False

    async def connect(self) -> None:
        self.connected = True
        if self.cancel_on_connect:
            raise asyncio.CancelledError

    async def cleanup(self) -> None:
        self.cleaned = True

    async def list_tools(self) -> list[Any]:
        if self.cancel_on_list:
            raise asyncio.CancelledError
        return []


@pytest.mark.asyncio
async def test_runtime_separates_root_only_tools_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shared = _item()
    root_only = _item(root_only=True)
    root_only = EnabledMcpServer(
        McpDefinition("root", root_only.definition.source, root_only.definition.raw, "root-hash"),
        root_only.extras.model_copy(
            update={"source": str(root_only.definition.source), "definition_hash": "root-hash"}
        ),
        root_only.params,
    )
    servers = {"server": FakeServer("server"), "root": FakeServer("root")}
    monkeypatch.setattr(runtime, "enabled_servers", lambda **_kwargs: [shared, root_only])
    monkeypatch.setattr(runtime, "MCPServerManager", FakeManager)
    monkeypatch.setattr(runtime, "_make_server", lambda item: servers[item.definition.name])
    monkeypatch.setattr(runtime.MCPUtil, "to_function_tool", _function_tool)

    bundle = await runtime.setup_mcp_servers()
    assert [tool.name for tool in bundle.shared_tools] == ["mcp_server__shared"]
    assert [tool.name for tool in bundle.root_only_tools] == ["mcp_root__shared"]
    tools = [*bundle.shared_tools, *bundle.root_only_tools]
    assert all(tool.timeout_seconds == 120 for tool in tools)

    await bundle.close()
    assert bundle.manager.cleaned


@pytest.mark.asyncio
async def test_failed_server_does_not_hide_healthy_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    broken = _item()
    healthy = EnabledMcpServer(
        McpDefinition("healthy", broken.definition.source, broken.definition.raw, "healthy-hash"),
        broken.extras.model_copy(
            update={"source": str(broken.definition.source), "definition_hash": "healthy-hash"}
        ),
        broken.params,
    )
    servers = {"server": FakeServer("server"), "healthy": FakeServer("healthy")}
    monkeypatch.setattr(runtime, "enabled_servers", lambda **_kwargs: [broken, healthy])
    monkeypatch.setattr(runtime, "MCPServerManager", FailingManager)
    monkeypatch.setattr(runtime, "_make_server", lambda item: servers[item.definition.name])
    monkeypatch.setattr(runtime.MCPUtil, "to_function_tool", _function_tool)

    bundle = await runtime.setup_mcp_servers()

    assert [tool.name for tool in bundle.shared_tools] == ["mcp_healthy__shared"]
    assert "offline" in bundle.warnings[0]


@pytest.mark.asyncio
async def test_connection_cancellation_stops_later_servers_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = CancellingServer("first", cancel_on_connect=True)
    second = CancellingServer("second")
    monkeypatch.setattr(
        runtime,
        "enabled_servers",
        lambda **_kwargs: [_named_item("first"), _named_item("second")],
    )
    monkeypatch.setattr(
        runtime,
        "_make_server",
        lambda item: {"first": first, "second": second}[item.definition.name],
    )

    with pytest.raises(asyncio.CancelledError):
        await runtime.setup_mcp_servers()

    assert first.cleaned
    assert not second.connected


@pytest.mark.asyncio
async def test_tool_discovery_cancellation_cleans_up(monkeypatch: pytest.MonkeyPatch) -> None:
    server = CancellingServer("server", cancel_on_list=True)
    monkeypatch.setattr(runtime, "enabled_servers", lambda **_kwargs: [_item()])
    monkeypatch.setattr(runtime, "_make_server", lambda _item: server)

    with pytest.raises(asyncio.CancelledError):
        await runtime.setup_mcp_servers()

    assert server.cleaned


@pytest.mark.asyncio
async def test_stdio_echo_connects_invokes_and_cleans_up(monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = Path(__file__).parent / "fixtures" / "mcp_echo.py"
    definition = McpDefinition("echo", fixture, {"command": sys.executable}, "echo-hash")
    extras = McpServerExtras(
        enabled=True,
        source=str(fixture),
        definition_hash="echo-hash",
        allow_tools=["*"],
    )
    server = EnabledMcpServer(
        definition,
        extras,
        {"command": sys.executable, "args": [str(fixture)]},
    )
    monkeypatch.setattr(runtime, "enabled_servers", lambda **_kwargs: [server])

    bundle = await runtime.setup_mcp_servers()
    try:
        assert [tool.name for tool in bundle.shared_tools] == ["mcp_echo__echo"]
        assert await bundle.shared_tools[0].on_invoke_tool(None, '{"value":"ok"}') == {
            "type": "text",
            "text": "ok",
        }
    finally:
        await bundle.close()


def _function_tool(
    *_args: Any, tool_name_override: str | None = None, **_kwargs: Any
) -> FunctionTool:
    async def invoke(_ctx: Any, _raw: str) -> str:
        return "ok"

    return FunctionTool(
        name=tool_name_override or "tool",
        description="test",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=invoke,
    )


def _named_item(name: str) -> EnabledMcpServer:
    item = _item()
    return EnabledMcpServer(
        McpDefinition(name, item.definition.source, item.definition.raw, f"{name}-hash"),
        item.extras.model_copy(update={"definition_hash": f"{name}-hash"}),
        item.params,
    )

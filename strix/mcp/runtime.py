"""Scan-scoped host-side MCP connections and SDK tool conversion."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import TYPE_CHECKING, Any, cast

from agents.mcp import (
    MCPServerManager,
    MCPServerSse,
    MCPServerStdio,
    MCPServerStreamableHttp,
    MCPUtil,
)

from strix.config import load_settings
from strix.mcp.config import EnabledMcpServer, enabled_servers
from strix.tools.output_store import bound_and_store


if TYPE_CHECKING:
    from agents.mcp import MCPServerStdioParams
    from agents.tool import FunctionTool


StatusSink = Callable[[str], None]
_MAX_TOOL_NAME = 64


@dataclass
class McpBundle:
    manager: MCPServerManager
    shared_tools: list[FunctionTool]
    root_only_tools: list[FunctionTool]
    active_servers: list[str]
    warnings: list[str]

    async def close(self) -> None:
        await self.manager.cleanup_all()


async def setup_mcp_servers(
    *, names: set[str] | None = None, status_sink: StatusSink | None = None
) -> McpBundle:
    """Connect enabled servers and build only the tools this scan may expose."""
    configured = sorted(enabled_servers(names=names), key=lambda item: item.definition.name)
    manager = MCPServerManager(
        [_make_server(item) for item in configured],
        connect_timeout_seconds=load_settings().mcp.connect_timeout_s,
        drop_failed_servers=True,
        strict=False,
        suppress_cancelled_error=False,
    )
    warnings: list[str] = []
    if configured and status_sink is not None:
        status_sink("Connecting user-enabled MCP servers on the host (outside the sandbox)")
    try:
        await manager.connect_all()
        active_by_name = {server.name: server for server in manager.active_servers}
        for server, error in manager.errors.items():
            warnings.append(f"MCP server '{server.name}' unavailable: {error}")

        shared_tools: list[FunctionTool] = []
        root_only_tools: list[FunctionTool] = []
        used_names: set[str] = set()
        for item in configured:
            active_server = active_by_name.get(item.definition.name)
            if active_server is None:
                continue
            try:
                raw_tools = await active_server.list_tools()
            except Exception as exc:  # noqa: BLE001 - a broken optional server must not stop a scan
                warnings.append(f"MCP server '{active_server.name}' tools unavailable: {exc}")
                continue
            selected = [tool for tool in raw_tools if _tool_allowed(tool.name, item)]
            if not selected:
                warnings.append(f"MCP server '{active_server.name}' exposed no allowed tools")
                continue
            for tool in selected:
                public_name = _public_tool_name(active_server.name, tool.name, used_names)
                function_tool = MCPUtil.to_function_tool(
                    tool,
                    active_server,
                    convert_schemas_to_strict=True,
                    tool_name_override=public_name,
                )
                function_tool.timeout_seconds = item.extras.call_timeout_s
                _normalize_mcp_output(function_tool)
                (root_only_tools if item.extras.root_only else shared_tools).append(function_tool)

        active_names = [server.name for server in manager.active_servers]
        if active_names and status_sink is not None:
            status_sink("MCP tools active on host: " + ", ".join(active_names))
        for warning in warnings:
            if status_sink is not None:
                status_sink("MCP warning: " + warning)
        return McpBundle(manager, shared_tools, root_only_tools, active_names, warnings)
    except BaseException:
        await manager.cleanup_all()
        raise


def _make_server(item: EnabledMcpServer) -> Any:
    params = item.params
    name = item.definition.name
    if "command" in params:
        stdio_params = {"command": params["command"], "args": params.get("args", [])}
        if params.get("env"):
            stdio_params["env"] = params["env"]
        return MCPServerStdio(
            name=name,
            cache_tools_list=False,
            client_session_timeout_seconds=item.extras.call_timeout_s,
            params=cast("MCPServerStdioParams", stdio_params),
        )
    server_type = params.get("type")
    server_cls = MCPServerSse if server_type == "sse" else MCPServerStreamableHttp
    return server_cls(
        name=name,
        cache_tools_list=False,
        client_session_timeout_seconds=item.extras.call_timeout_s,
        params={"url": params["url"], "headers": params.get("headers", {})},
    )


def _tool_allowed(name: str, item: EnabledMcpServer) -> bool:
    extras = item.extras
    return any(fnmatchcase(name, pattern) for pattern in extras.allow_tools) and not any(
        fnmatchcase(name, pattern) for pattern in extras.deny_tools
    )


def _public_tool_name(server: str, tool: str, used: set[str]) -> str:
    base = "mcp_" + _safe_part(server, "server") + "__" + _safe_part(tool, "tool")
    seed = f"{server}\0{tool}"
    candidate = _shorten(base, seed, force_hash=base in used)
    index = 1
    while candidate in used:
        candidate = _shorten(base, f"{seed}\0{index}", force_hash=True)
        index += 1
    used.add(candidate)
    return candidate


def _safe_part(value: str, fallback: str) -> str:
    safe = "".join(
        char if char.isascii() and (char.isalnum() or char == "_") else "_" for char in value
    )
    return safe.strip("_") or fallback


def _shorten(value: str, seed: str, *, force_hash: bool) -> str:
    if not force_hash and len(value) <= _MAX_TOOL_NAME:
        return value
    suffix = "_" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8]
    return value[: _MAX_TOOL_NAME - len(suffix)].rstrip("_") + suffix


def _normalize_mcp_output(tool: FunctionTool) -> None:
    """Bound SDK block outputs while leaving plain strings for Strix's existing wrapper."""
    invoke = tool.on_invoke_tool

    async def wrapped(ctx: Any, raw_input: str) -> Any:
        return await _normalize_output(await invoke(ctx, raw_input))

    tool.on_invoke_tool = wrapped


async def _normalize_output(value: Any) -> Any:
    if isinstance(value, str):
        return value
    blocks = value if isinstance(value, list) else [value]
    max_images = load_settings().runtime.max_context_images
    normalized: list[dict[str, Any]] = []
    text_blocks: list[dict[str, Any]] = []
    image_count = 0
    omitted_images = 0
    for block in blocks:
        if isinstance(block, dict) and block.get("type") == "image":
            if image_count < max_images:
                normalized.append(block)
                image_count += 1
            else:
                omitted_images += 1
            continue
        normalized_block = _text_block(block)
        normalized.append(normalized_block)
        text_blocks.append(normalized_block)
    if omitted_images:
        placeholder = {
            "type": "text",
            "text": f"[... {omitted_images} image block(s) omitted ...]",
        }
        normalized.append(placeholder)
        text_blocks.append(placeholder)
    if not text_blocks:
        return normalized if isinstance(value, list) else normalized[0]

    text = "\n".join(block["text"] for block in text_blocks)
    context = load_settings().context
    bounded = await bound_and_store(
        text,
        max_lines=context.tool_output_max_lines,
        max_bytes=context.tool_output_max_bytes,
    )
    if bounded == text:
        return normalized if isinstance(value, list) else normalized[0]

    result: list[dict[str, Any]] = []
    inserted = False
    for block in normalized:
        if block.get("type") == "image":
            result.append(block)
        elif not inserted:
            result.append({"type": "text", "text": bounded})
            inserted = True
    return result if isinstance(value, list) else result[0]


def _text_block(value: Any) -> dict[str, Any]:
    if (
        isinstance(value, dict)
        and value.get("type") == "text"
        and isinstance(value.get("text"), str)
    ):
        return dict(value)
    text = (
        json.dumps(value, ensure_ascii=False, default=str)
        if isinstance(value, (dict, list))
        else str(value)
    )
    return {"type": "text", "text": text}

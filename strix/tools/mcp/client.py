"""Connect to MCP servers and expose their tools to the agent.

Given one :class:`McpConnectionConfig` per server, :func:`connect_mcp_servers`
lists each server's tools, keeps the ones on the connection's allowlist (or all
of them when none is set), prefixes each with the connection name so servers do
not collide, and registers them through the agent factory. The factory applies
output bounding, per-call timeouts, and structured errors to every registered
tool, so this layer does not reimplement them.

A server that cannot connect, or a tool set that cannot be registered, is logged
and skipped, so one bad connection never fails the run.
"""

from __future__ import annotations

import contextlib
import json
import logging
from typing import TYPE_CHECKING, Any, NamedTuple, cast

from agents.exceptions import ModelBehaviorError
from agents.mcp import (
    MCPServer,
    MCPServerStdio,
    MCPServerStdioParams,
    MCPServerStreamableHttp,
    MCPServerStreamableHttpParams,
    MCPUtil,
    create_static_tool_filter,
)

from strix.agents.factory import register_agent_tools
from strix.tools.mcp.naming import namespaced_tool_name


if TYPE_CHECKING:
    from collections.abc import Callable

    from agents.tool import FunctionTool, Tool
    from mcp.types import Tool as MCPTool

    from strix.tools.mcp.config import McpConnectionConfig

    # Runs on each tool's structured result before it reaches the agent. Called
    # ``result_transform(namespaced_tool_name, structured_result)`` and its return
    # value becomes the tool's output. ``structured_result`` is the parsed
    # ``CallToolResult`` as a dict (not a serialized string), so the transform can
    # project or drop individual fields.
    ResultTransform = Callable[[str, Any], Any]


logger = logging.getLogger(__name__)


class ConnectedMcpServer(NamedTuple):
    """One successfully connected MCP server and how many tools it registered.

    ``server`` is kept so the caller can clean it up when the run ends;
    ``name`` and ``tool_count`` let the caller show the user a startup summary;
    ``notes`` carries the connection's optional free-text description so the
    caller can surface it to the agent as context about the connection.
    """

    server: MCPServer
    name: str
    tool_count: int
    notes: str | None = None


def _auth_headers(config: McpConnectionConfig) -> dict[str, str]:
    """Build the per-server request headers from the connection's auth."""
    auth = config.auth
    if auth is None:
        return {}
    return {"Authorization": f"Bearer {auth.token}"}


def _build_server(config: McpConnectionConfig) -> MCPServer:
    """Construct (but do not connect) the SDK server for one connection.

    When ``allowed_tools`` is a list the static filter means the server will not
    even list tools outside it; :func:`_register_server_tools` re-applies the
    same allowlist as the authoritative gate on what gets registered. When it is
    ``None`` no filter is applied and every listed tool is registered.
    """
    tool_filter = (
        create_static_tool_filter(allowed_tool_names=config.allowed_tools)
        if config.allowed_tools is not None
        else None
    )

    if config.transport == "stdio":
        stdio_params: MCPServerStdioParams = {
            "command": cast("str", config.command),
            "args": config.args,
            "env": config.env,
        }
        return MCPServerStdio(
            params=stdio_params,
            name=config.name,
            tool_filter=tool_filter,
            cache_tools_list=True,
        )

    http_params: MCPServerStreamableHttpParams = {
        "url": cast("str", config.url),
        "headers": _auth_headers(config),
    }
    return MCPServerStreamableHttp(
        params=http_params,
        name=config.name,
        tool_filter=tool_filter,
        cache_tools_list=True,
    )


def _build_tool(
    config: McpConnectionConfig,
    server: MCPServer,
    mcp_tool: MCPTool,
    result_transform: ResultTransform | None,
) -> FunctionTool:
    """Build one namespaced FunctionTool from a listed MCP tool.

    The SDK builds the tool (so name override, input schema, approval policy,
    error-as-result handling, and tool-origin metadata are unchanged). With a
    ``result_transform`` we route the underlying MCP call through
    :func:`_install_result_transform` so the transform sees the structured result
    and decides the tool's output. Without one (the stock path), we still route
    the call, through :func:`_install_error_status_capture`, so an errored result
    reads as failed in the TUI while the agent's content is unchanged.
    """
    namespaced_name = namespaced_tool_name(config.name, mcp_tool.name)
    tool = MCPUtil.to_function_tool(
        mcp_tool,
        server,
        convert_schemas_to_strict=False,
        tool_name_override=namespaced_name,
    )
    if result_transform is not None:
        _install_result_transform(tool, server, mcp_tool.name, namespaced_name, result_transform)
    else:
        _install_error_status_capture(tool, server, mcp_tool.name, namespaced_name)
    return tool


def _install_result_transform(
    tool: FunctionTool,
    server: MCPServer,
    base_tool_name: str,
    namespaced_name: str,
    result_transform: ResultTransform,
) -> None:
    """Route a tool's MCP call through ``result_transform``, innermost.

    ``MCPUtil.to_function_tool`` serializes the result inside its own invoke, so
    the structured result cannot be intercepted through it. Instead we call
    ``server.call_tool`` ourselves, hand the parsed :class:`CallToolResult` to the
    transform, and return the transform's output as the tool result.

    This runs INSIDE the tool's invoke. The agent factory wraps a registered
    tool's ``on_invoke_tool`` with output bounding, disk spill, and tracing at
    agent-build time, which is OUTSIDE this invoke, so the transform is genuinely
    the innermost step: nothing sees the raw result before the transform does.

    ``to_function_tool`` wraps the real invoke in the SDK's failure-handling
    invoker, which stores the inner coroutine on ``_invoke_tool_impl`` and calls
    it inside its try/except. Swapping that inner impl keeps the SDK's
    error-as-result handling and all tool metadata while inserting the transform.
    If the SDK ever renames that attribute we fail loudly rather than silently
    skip the transform.
    """

    async def _invoke(_ctx: Any, input_json: str) -> Any:
        parsed: Any = json.loads(input_json) if input_json else {}
        if not isinstance(parsed, dict):
            raise ModelBehaviorError(
                f"Invalid JSON input for tool {namespaced_name}: expected a JSON object"
            )
        args = cast("dict[str, Any]", parsed)
        result = await server.call_tool(base_tool_name, args)
        structured_result = result.model_dump(mode="json")
        return result_transform(namespaced_name, structured_result)

    _replace_tool_invoke(tool, _invoke)


def _replace_tool_invoke(tool: FunctionTool, invoke: Callable[[Any, str], Any]) -> None:
    """Swap a FunctionTool's inner invoke, failing loudly if the SDK shape changed.

    ``to_function_tool`` wraps the real invoke in the SDK's failure-handling
    invoker, which stores the inner coroutine on ``_invoke_tool_impl`` and calls
    it inside its own try/except. Swapping that inner impl keeps the SDK's
    error-as-result handling and every piece of tool metadata intact. It is a
    plain object with the coroutine as an attribute, not a function, so we treat
    it as untyped to swap it. If the SDK ever renames that attribute we raise
    rather than silently leave the swap un-applied.
    """
    invoker = cast("Any", tool.on_invoke_tool)
    if not hasattr(invoker, "_invoke_tool_impl"):
        raise RuntimeError(
            "agents SDK FunctionTool invoker shape changed: cannot swap the tool "
            "invoke without risking it being silently skipped."
        )
    invoker._invoke_tool_impl = invoke


def _mcp_result_to_tool_output(server: MCPServer, result: Any) -> Any:
    """Serialize a ``CallToolResult`` to a tool output, mirroring the agents SDK.

    This reproduces the serialization in ``agents.mcp.util.MCPUtil.invoke_mcp_tool``
    (structured-content JSON when the server asks for it, otherwise text/image
    content blocks, unwrapping a single block). Because the stock path now routes
    its own call, this is what makes the agent see byte-identical content to what
    the SDK would have produced on its own.
    """
    if getattr(server, "use_structured_content", False) and result.structuredContent:
        return json.dumps(result.structuredContent)

    outputs: list[dict[str, Any]] = []
    for item in result.content:
        if item.type == "text":
            outputs.append({"type": "text", "text": item.text})
        elif item.type == "image":
            outputs.append(
                {"type": "image", "image_url": f"data:{item.mimeType};base64,{item.data}"}
            )
        else:
            outputs.append({"type": "text", "text": str(item.model_dump(mode="json"))})
    if len(outputs) == 1:
        return outputs[0]
    return outputs


def _install_error_status_capture(
    tool: FunctionTool,
    server: MCPServer,
    base_tool_name: str,
    namespaced_name: str,
) -> None:
    """Make an errored MCP result read as failed in the TUI, agent content unchanged.

    The stock SDK invoke returns only the text/image tool output and drops the
    ``CallToolResult.isError`` flag, so the TUI cannot tell an errored MCP call
    (which it renders as a green "done") from a successful one. We route the call
    the same way :func:`_install_result_transform` does, read ``isError`` off the
    full result, and on an error tag the returned output dict with
    ``success: False``.

    That tag reaches the human-facing status but not the agent. The SDK stores the
    raw return value on the run item's ``output`` (which the TUI reads to derive a
    tool's status), but hands the agent the value re-projected through its
    ToolOutput schema, which keeps only the known ``type``/``text`` fields and
    drops the extra ``success`` key. So the status flips to failed while the agent
    still receives exactly the same error content it does today. Non-error calls
    return the stock output unchanged and keep rendering as done.
    """

    async def _invoke(_ctx: Any, input_json: str) -> Any:
        parsed: Any = json.loads(input_json) if input_json else {}
        if not isinstance(parsed, dict):
            raise ModelBehaviorError(
                f"Invalid JSON input for tool {namespaced_name}: expected a JSON object"
            )
        args = cast("dict[str, Any]", parsed)
        result = await server.call_tool(base_tool_name, args)
        tool_output = _mcp_result_to_tool_output(server, result)
        if getattr(result, "isError", False) and isinstance(tool_output, dict):
            return {**tool_output, "success": False}
        return tool_output

    _replace_tool_invoke(tool, _invoke)


async def _register_server_tools(
    config: McpConnectionConfig,
    server: MCPServer,
    result_transform: ResultTransform | None = None,
) -> list[Tool]:
    """List a connected server's tools, prefix + filter them, and register them.

    ``allowed_tools`` of ``None`` registers every listed tool; a list restricts
    to exactly those names.
    """
    allowed = config.allowed_tools
    mcp_tools = await server.list_tools()

    tools: list[Tool] = [
        _build_tool(config, server, mcp_tool, result_transform)
        for mcp_tool in mcp_tools
        if allowed is None or mcp_tool.name in allowed
    ]

    register_agent_tools(*tools)
    return tools


async def connect_mcp_servers(
    configs: list[McpConnectionConfig],
    result_transform: ResultTransform | None = None,
) -> list[ConnectedMcpServer]:
    """Connect to each MCP server and register its tools.

    When ``result_transform`` is given, every registered tool routes its result
    through it before the result reaches the agent (see
    :func:`_install_result_transform`). When it is ``None`` the tools behave
    exactly as the SDK builds them.

    Returns one :class:`ConnectedMcpServer` per server that connected, carrying
    the SDK server (so the caller can clean it up when the run ends) plus the
    server name and how many tools it registered (so the caller can show the
    user a startup summary). Connections that fail are skipped rather than
    raised.
    """
    connected: list[ConnectedMcpServer] = []
    for config in configs:
        server: MCPServer | None = None
        try:
            server = _build_server(config)
            await server.connect()  # type: ignore[no-untyped-call]
            tools = await _register_server_tools(config, server, result_transform)
        except Exception:
            logger.exception("Skipping MCP connection %r", config.name)
            if server is not None:
                with contextlib.suppress(Exception):
                    await server.cleanup()  # type: ignore[no-untyped-call]
            continue
        except BaseException:
            # A cancellation (or other non-Exception failure) mid-connect must not
            # orphan MCP subprocesses or HTTP sessions. Clean up the server being
            # connected and every server already connected, then re-raise so the
            # caller still stops. The runner only receives the list on a clean
            # return, so on an abnormal exit this function owns the cleanup.
            if server is not None:
                with contextlib.suppress(Exception):
                    await server.cleanup()  # type: ignore[no-untyped-call]
            for established in connected:
                with contextlib.suppress(Exception):
                    await established.server.cleanup()  # type: ignore[no-untyped-call]
            raise

        logger.info("Connected MCP server %r (%d tools)", config.name, len(tools))
        connected.append(
            ConnectedMcpServer(
                server=server, name=config.name, tool_count=len(tools), notes=config.notes
            )
        )

    return connected

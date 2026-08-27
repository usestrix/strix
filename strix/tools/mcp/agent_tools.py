"""The three generic MCP dispatch tools every agent carries.

Under the generic-dispatch model an agent does not get one tool per MCP tool.
It gets exactly these three and discovers connections on demand:

- ``list_mcps()`` returns the connections available this run — each connection's
  id, name, description, and tool count, with no tool schemas — so the model can
  discover what it can reach without any inventory in the system prompt.
- ``describe_mcp(connection)`` returns, as text, one connection's tools with
  their names, descriptions, and JSON input schemas — the schemas the model
  needs, fetched on demand instead of loaded onto every request up front.
- ``call_mcp(connection, tool, arguments)`` dispatches one call to a
  connection's tool and returns its result.

All three read the per-run :class:`~strix.tools.mcp.registry.McpRegistry` from the
run context under :data:`~strix.tools.mcp.registry.MCP_REGISTRY_CONTEXT_KEY`. They
are ordinary ``FunctionTool`` objects placed in the agent factory's base tool set,
so the factory's output-bounding and disk-spill wrapping apply to their results
automatically.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from agents import RunContextWrapper, function_tool

from strix.tools.mcp.client import _errored_tool_output
from strix.tools.mcp.naming import namespaced_tool_name
from strix.tools.mcp.registry import MCP_REGISTRY_CONTEXT_KEY, McpRegistry
from strix.tools.mcp.session import McpConnectionUnavailableError


if TYPE_CHECKING:
    from mcp.types import Tool as MCPTool


def _registry_from_ctx(ctx: RunContextWrapper) -> McpRegistry | None:
    context = ctx.context if isinstance(ctx.context, dict) else {}
    registry = context.get(MCP_REGISTRY_CONTEXT_KEY)
    return registry if isinstance(registry, McpRegistry) else None


_NO_CONNECTIONS = "No MCP connections are configured for this run."


def _unknown_connection(connection: str, registry: McpRegistry) -> str:
    available = ", ".join(registry.names()) or "(none)"
    return f"Unknown MCP connection {connection!r}. Available connections: {available}."


def _unavailable_connection(connection: str) -> str:
    return (
        f"MCP connection {connection!r} is unavailable: its live session failed and "
        "could not be reconnected, so it is unavailable for the rest of this run."
    )


def _format_tool(tool: MCPTool) -> str:
    schema = json.dumps(tool.inputSchema or {"type": "object"}, indent=2, ensure_ascii=False)
    description = (tool.description or "").strip() or "(no description)"
    return f"- {tool.name}: {description}\n  input schema:\n{schema}"


@function_tool(timeout=60)
async def list_mcps(ctx: RunContextWrapper) -> dict[str, Any]:
    """List the MCP connections available this run, so you can discover them.

    Read-only. Returns one entry per connection with its ``id`` (the exact name
    you pass to ``describe_mcp`` and ``call_mcp``), ``name``, ``description``, and
    ``tool_count`` — no tool schemas. The three MCP tools work in order: call
    ``list_mcps`` to discover the available connections, then ``describe_mcp`` on
    one connection to inspect its tools and their input schemas, then ``call_mcp``
    to run one of its tools. Returns an empty ``connections`` list when the run has
    no MCP connections.
    """
    registry = _registry_from_ctx(ctx)
    if registry is None or not registry:
        return {"connections": []}
    dead_by_name = {status.name: status.dead for status in registry.statuses()}
    return {
        "connections": [
            {
                "id": summary.name,
                "name": summary.name,
                "description": summary.purpose,
                "tool_count": summary.tool_count,
                "dead": dead_by_name.get(summary.name, False),
            }
            for summary in registry.summaries()
        ]
    }


@function_tool(timeout=60)
async def describe_mcp(ctx: RunContextWrapper, connection: str) -> str:
    """List the tools one MCP connection offers, with their input schemas.

    Read-only. Look up a connection by the id ``list_mcps`` reported for it; this
    returns each of its tools with the tool's name, description, and JSON input
    schema — the argument shape you pass to ``call_mcp``. Call this before
    ``call_mcp`` on any connection you have not used yet. Nothing is fetched from
    or run against the connection's data.

    Args:
        connection: The connection name exactly as reported by ``list_mcps``.
    """
    registry = _registry_from_ctx(ctx)
    if registry is None or not registry:
        return _NO_CONNECTIONS
    entry = registry.get(connection)
    if entry is None:
        return _unknown_connection(connection, registry)
    try:
        tools = await entry.session.list_tools()
    except McpConnectionUnavailableError:
        return _unavailable_connection(connection)
    if not tools:
        return f"MCP connection {connection!r} offers no tools."
    header = f"MCP connection {connection!r} offers {len(tools)} tool(s):"
    body = "\n".join(_format_tool(tool) for tool in tools)
    return f"{header}\n{body}"


@function_tool(timeout=120, strict_mode=False)
async def call_mcp(
    ctx: RunContextWrapper,
    connection: str,
    tool: str,
    arguments: Any = None,
) -> Any:
    """Call one tool on one MCP connection and return its result.

    Address the tool by the connection id from ``list_mcps`` and the tool name
    from ``describe_mcp`` on that connection. Pass the tool's arguments as an
    object matching the input schema ``describe_mcp`` showed for it (omit it, or
    pass an empty object, for a tool that takes no arguments).

    Args:
        connection: The connection name exactly as reported by ``list_mcps``.
        tool: The tool name, exactly as reported by ``describe_mcp``.
        arguments: The tool's arguments as a JSON object of names to values (for
            example ``{"path": "app.py"}``), or omitted/empty for a tool that
            takes none. Pass an object, not a stringified one. Its shape is
            whatever ``describe_mcp`` showed for the tool rather than a shape this
            tool fixes in advance.
    """
    registry = _registry_from_ctx(ctx)
    if registry is None or not registry:
        return _NO_CONNECTIONS
    entry = registry.get(connection)
    if entry is None:
        return _unknown_connection(connection, registry)
    invalid_arguments = (
        f"Invalid arguments for {connection!r}.{tool}: expected a JSON object of "
        "argument names to values, or none. Call describe_mcp for the input schema."
    )
    if isinstance(arguments, str):
        # The ``arguments`` parameter is schema-less (an open object is not
        # expressible as a strict tool schema), so some models serialize it as a
        # JSON string instead of a bare object. Accept a string that decodes to an
        # object so a correct call is not rejected over its encoding.
        stripped = arguments.strip()
        try:
            arguments = json.loads(stripped) if stripped else {}
        except json.JSONDecodeError:
            return invalid_arguments
    if arguments is not None and not isinstance(arguments, dict):
        return invalid_arguments
    try:
        available = await entry.session.list_tools()
    except McpConnectionUnavailableError:
        return _errored_tool_output(_unavailable_connection(connection))
    valid_names = {mcp_tool.name for mcp_tool in available}
    if tool not in valid_names:
        offered = ", ".join(sorted(valid_names)) or "(none)"
        return (
            f"Unknown tool {tool!r} on MCP connection {connection!r}. "
            f"Tools this connection offers: {offered}. "
            "Call describe_mcp for their input schemas."
        )
    return await entry.session.dispatch(
        tool,
        arguments or {},
        label=namespaced_tool_name(connection, tool),
        result_transform=entry.result_transform,
    )

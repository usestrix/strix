"""Generic MCP client: connect MCP servers and expose their tools."""

from __future__ import annotations

from strix.tools.mcp.client import ConnectedMcpServer, connect_mcp_servers
from strix.tools.mcp.config import (
    BearerAuth,
    McpAuth,
    McpConnectionConfig,
)
from strix.tools.mcp.loader import load_user_mcp_configs
from strix.tools.mcp.naming import McpToolOrigin, namespaced_tool_name, resolve_mcp_tool


__all__ = [
    "BearerAuth",
    "ConnectedMcpServer",
    "McpAuth",
    "McpConnectionConfig",
    "McpToolOrigin",
    "connect_mcp_servers",
    "load_user_mcp_configs",
    "namespaced_tool_name",
    "resolve_mcp_tool",
]

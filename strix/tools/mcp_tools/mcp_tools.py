import os
import sys
from contextlib import AsyncExitStack


current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "../../../"))
sys.path.append(project_root)
from dataclasses import dataclass
from typing import Any

from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.client.sse import sse_client
from mcp.client.streamable_http import streamablehttp_client

from strix.tools.registry import register_mcp_tool


class TransportType:
    STDIO = "stdio"
    STREAMABLE_HTTP = "streamable-http"
    SSE = "sse"


@dataclass
class Configuration:
    transport_type: str = TransportType.STDIO
    command: str = "npx"  # Example default
    args: list | None = None
    env: dict[str, str] | None = None
    cwd: str | None = None
    url: str | None = None
    headers: dict[str, Any] | None = None
    encoding: str = "utf-8"


class MCPClient:
    def __init__(self, config: Configuration | dict[str, Any], timeout: int = 300):
        if isinstance(config, dict):
            self.config = Configuration(**config)
        else:
            self.config = config

        self.exit_stack = AsyncExitStack()
        self.session = None
        self.timeout = timeout
        print(f"MCPClient initialized with transport type: {self.config.transport_type}")

    async def connect(self):
        transport_type = self.config.transport_type

        if transport_type == TransportType.STDIO:
            server_params = StdioServerParameters(
                command=self.config.command,
                args=self.config.args or [],
                env=self.config.env,
                cwd=self.config.cwd,
                encoding=self.config.encoding,
            )

            stdio_transport = await self.exit_stack.enter_async_context(
                stdio_client(server=server_params)
            )
            read, write = stdio_transport

            self.session = await self.exit_stack.enter_async_context(ClientSession(read, write))
        elif transport_type == TransportType.STREAMABLE_HTTP:
            if not self.config.url:
                raise ValueError("URL must be provided for STREAMABLE_HTTP transport.")

            http_transport = await self.exit_stack.enter_async_context(
                streamablehttp_client(
                    url=self.config.url,
                    headers=self.config.headers or {},
                )
            )
            read, write, _ = http_transport

            self.session = await self.exit_stack.enter_async_context(ClientSession(read, write))

        elif transport_type == TransportType.SSE:
            if not self.config.url:
                raise ValueError("URL must be provided for SSE transport.")
            sse_transport = await self.exit_stack.enter_async_context(
                sse_client(
                    url=self.config.url,
                    headers=self.config.headers,
                )
            )
            read, write = sse_transport
            self.session = await self.exit_stack.enter_async_context(ClientSession(read, write))

        else:
            raise ValueError(f"Unsupported transport type: {transport_type}")

        await self.session.initialize()

    def _generate_xml_schema(self, name, inputSchema, description) -> str:
        name_str = f'<tool name="{name}">'
        desc_str = f"<description>{description}</description>"
        properties = ""
        if inputSchema["properties"]:
            for key, value in inputSchema["properties"].items():
                properties += f'<property name="{key}" type="{value["type"]}" require="{"true" if key in inputSchema["required"] else "false"}"/>'

        return f"""{name_str}\n   {desc_str}\n    <input>\n{properties if inputSchema["properties"] else ""}\n    </input>\n</tool>"""

    async def register_tools(self):
        if not self.session:
            raise RuntimeError("Client is not connected. Call connect() first.")

        response = await self.session.list_tools()
        tools = response.tools

        for tool in tools:
            name = tool.name

            async def dummy_func(tool_name=name, **kwargs) -> Any:
                return await self.session.call_tool(tool_name, arguments=kwargs)

            tool_xml = self._generate_xml_schema(
                name=tool.name, inputSchema=tool.inputSchema, description=tool.description
            )
            register_mcp_tool(
                name=tool.name, func=dummy_func, module="unknown", xml_schema=tool_xml
            )

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.cleanup()

    async def __aenter__(self):
        await self.connect()
        return self

    async def cleanup(self):
        await self.exit_stack.aclose()


class MCP:
    def __init__(self, config: dict[str, Any], timeout: int = 300):
        self.config = config
        self.timeout = timeout
        self.client: list[MCPClient] = []

    async def connect(self) -> MCPClient:
        mcp_server_config = self.config.get("mcpServers", {})
        for server_name, server_config in mcp_server_config.items():
            client = MCPClient(config=server_config, timeout=self.timeout)
            await client.connect()
            await client.register_tools()
            self.client.append(client)

    async def cleanup(self):
        for client in self.client:
            await client.cleanup()

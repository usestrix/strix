import asyncio
import json
import os
import sys
from contextlib import AsyncExitStack
from dataclasses import dataclass
from pathlib import Path  # Use Path for modern path manipulation
from typing import Any

# INP001: Ensure 'strix\tools\mcp_tools' directory contains an __init__.py file
# to resolve this error.

# Using pathlib for cleaner path handling (PTH120, PTH100, PTH118)
current_dir = Path(__file__).resolve().parent
project_root = current_dir.parent.parent.parent.resolve()
sys.path.append(str(project_root))

# E402: Imports moved to the top of the file
from strix.tools.registry import register_mcp_tool


class TransportType:
    STDIO = "stdio"


@dataclass
class Configuration:
    transport_type: str = TransportType.STDIO
    command: str = "npx"  # Example default
    args: list | None = None
    env: dict | None = None
    cwd: str | None = None
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
        # Removed T201: print(f"MCPClient initialized with transport type: {self.config.transport_type}")

    async def connect(self):
        transport_type = self.config.transport_type

        if transport_type == TransportType.STDIO:
            from mcp import ClientSession, StdioServerParameters, stdio_client

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

            self.session = await self.exit_stack.enter_async_context(
                ClientSession(read, write)
            )

            await self.session.initialize()

        else:
            raise ValueError(f"Unsupported transport type: {transport_type}")

    # Renamed inputSchema to input_schema (N803)
    def _generate_xml_schema(self, name, input_schema, description) -> str:
        name_str = f'<tool name="{name}">'
        desc_str = f"<description>{description}</description>"
        properties = ""
        # Used tuple for multi-line string concatenation to avoid E501
        if input_schema["properties"]:
            for key, value in input_schema["properties"].items():
                is_required = "true" if key in input_schema["required"] else "false"
                properties += (
                    f'<property name="{key}" type="{value["type"]}" '
                    f'require="{is_required}"/>'
                )

        # Used tuple for multi-line string concatenation to avoid E501
        input_content = properties if input_schema["properties"] else ""
        return (
            f"""{name_str}\n   {desc_str}\n    <input>\n"""
            f"""{input_content}\n    </input>\n</tool>"""
        )

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
                name=tool.name,
                input_schema=tool.inputSchema,  # Note: The tool object still uses inputSchema
                description=tool.description,
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


async def main():
    # Example Usage
    # Removed ERA001: Commented-out code

    # Mocking data for demonstration
    # Used Path.open() (PTH123)
    with (Path(r"strix/tools/mcp_tools/mcp.json")).open() as f:
        config_data = json.load(f)
    # Removed T201: print("--- Connecting via explicit connect() ---")

    client = MCPClient(config_data["mcpServers"]["weather"])
    try:
        await client.connect()
        await client.register_tools()
    finally:
        await client.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
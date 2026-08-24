"""Small management CLI for the explicit MCP enablement state."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from rich.console import Console

from strix.config import apply_config_override, load_settings
from strix.config.loader import update_mcp_server
from strix.mcp.config import (
    McpConfigError,
    McpDefinition,
    discover_servers,
    server_statuses,
    validate_definition,
)
from strix.mcp.runtime import setup_mcp_servers


def run_mcp(argv: list[str]) -> int:
    """Dispatch MCP management subcommands from CLI arguments."""
    console = Console()
    parser = argparse.ArgumentParser(prog="strix mcp")
    parser.add_argument("--config", type=Path, help="Strix config file to update")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list")
    enable = commands.add_parser("enable")
    enable.add_argument("name")
    group = enable.add_mutually_exclusive_group(required=True)
    group.add_argument("--allow", action="append", default=[])
    group.add_argument("--all-tools", action="store_true")
    enable.add_argument("--root-only", action="store_true")
    enable.add_argument("--deny", action="append", default=[])
    enable.add_argument("--call-timeout", type=int, default=120)
    disable = commands.add_parser("disable")
    disable.add_argument("name")
    test = commands.add_parser("test")
    test.add_argument("name", nargs="?")
    args = parser.parse_args(argv)

    if args.config:
        apply_config_override(args.config.resolve())
    try:
        if args.command == "list":
            for name, status in server_statuses().items():
                console.print(f"{name}: {status}")
            return 0
        if args.command == "enable":
            definitions = discover_servers()
            definition = _definition_or_error(definitions, args.name)
            validate_definition(args.name, definition.raw)
            if args.call_timeout <= 0:
                parser.error("--call-timeout must be greater than 0")
            allow = ["*"] if args.all_tools else args.allow
            _save_server(
                args.name,
                {
                    "enabled": True,
                    "source": str(definition.source),
                    "definition_hash": definition.definition_hash,
                    "root_only": args.root_only,
                    "allow_tools": allow,
                    "deny_tools": args.deny,
                    "call_timeout_s": args.call_timeout,
                },
            )
            console.print(
                f"Enabled MCP server '{args.name}' (runs on the host outside the sandbox)."
            )
            return 0
        if args.command == "disable":
            if args.name not in load_settings().mcp.servers:
                _definition_or_error(discover_servers(), args.name)
            _save_server(args.name, {"enabled": False})
            console.print(f"Disabled MCP server '{args.name}'.")
            return 0
        return asyncio.run(_test(args.name, console))
    except (McpConfigError, TypeError, ValueError) as exc:
        parser.error(str(exc))


def _save_server(name: str, updates: dict[str, object]) -> None:
    update_mcp_server(name, updates)


def _definition_or_error(definitions: dict[str, McpDefinition], name: str) -> McpDefinition:
    definition = definitions.get(name)
    if definition is None:
        raise McpConfigError(f"Unknown MCP server: {name}")
    return definition


async def _test(name: str | None, console: Console) -> int:
    bundle = await setup_mcp_servers(names={name} if name else None)
    try:
        for warning in bundle.warnings:
            console.print(f"warning: {warning}")
        if bundle.active_servers:
            console.print("Connected: " + ", ".join(bundle.active_servers))
            return 0
        console.print("No enabled MCP servers connected.")
        return 1
    finally:
        await bundle.close()

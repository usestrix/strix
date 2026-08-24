"""How an MCP server's tools are named for the model, and how to read that back.

Kept apart from the client, and stdlib-only, so the interfaces can resolve which
connection a tool call went to without importing the MCP client (and through it
the agents SDK and every registered tool).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, NamedTuple


if TYPE_CHECKING:
    from collections.abc import Iterable


# A tool name offered to a model has to be letters, digits, underscores or
# hyphens; anything else is rejected outright by the model APIs. Three things can
# put a stray character in one: the separator between the connection and the tool
# name, a name the server chose for its own tool (servers commonly namespace
# theirs), and the connection name out of the user's config file. Sanitizing the
# finished name covers all three rather than only the separator.
_INVALID_TOOL_NAME_CHARS = re.compile(r"[^a-zA-Z0-9_-]")


def namespaced_tool_name(connection: str, tool: str) -> str:
    """The name a connection's tool is offered to the model under.

    Only the model-facing name is rewritten. Every call to the server uses the
    tool name the server itself reported, so sanitizing here can never change
    which tool is invoked.
    """
    return _INVALID_TOOL_NAME_CHARS.sub("_", f"{connection}_{tool}")


class McpToolOrigin(NamedTuple):
    """Where a model-facing tool name came from, for showing the user.

    ``connection`` is the name the user gave the connection in their config, so
    it reads the way they wrote it. ``tool`` is what is left of the model-facing
    name once the connection prefix is removed, which is the server's own name
    for the tool and the part a reader cares about.
    """

    connection: str
    tool: str


def resolve_mcp_tool(tool_name: str, connections: Iterable[str]) -> McpToolOrigin | None:
    """Split a model-facing tool name against the run's connections, or ``None``.

    Matched against the connections the run actually made rather than by
    splitting the name on the separator: the connection name and the server's own
    tool name can both contain underscores, so a split is ambiguous and would
    attribute calls to a connection that does not exist. Each connection name is
    sanitized the same way :func:`namespaced_tool_name` sanitizes it before
    comparing, so a connection whose name has characters a model-facing name
    cannot carry still matches.

    The longest match wins, so one connection whose name is a prefix of another's
    still resolves to the right one. The character after the prefix has to be a
    separator rather than more of a name, which any non-alphanumeric satisfies,
    so this holds whichever separator :func:`namespaced_tool_name` uses.
    """
    best: McpToolOrigin | None = None
    best_length = 0
    for connection in connections:
        prefix = _INVALID_TOOL_NAME_CHARS.sub("_", connection)
        if not prefix or len(tool_name) <= len(prefix) or not tool_name.startswith(prefix):
            continue
        if tool_name[len(prefix)].isalnum():
            continue
        if len(prefix) > best_length:
            # Past the prefix and its single separator character is the tool's
            # own name; if a server named a tool nothing but separators, fall
            # back to the whole name so the row still says something.
            tool = tool_name[len(prefix) + 1 :] or tool_name
            best, best_length = McpToolOrigin(connection, tool), len(prefix)
    return best

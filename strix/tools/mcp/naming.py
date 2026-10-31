"""How an MCP server's tools are named for the model.

Kept apart from the client, and stdlib-only, so a caller can build the
model-facing name for a connection's tool without importing the MCP client (and
through it the agents SDK and every registered tool).
"""

from __future__ import annotations

import re


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

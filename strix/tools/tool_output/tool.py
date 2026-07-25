"""``read_tool_output`` — page through a previously truncated tool result."""

from __future__ import annotations

from agents import function_tool

from strix.tools.output_store import read_stored_output


@function_tool(timeout=10)
async def read_tool_output(output_id: str, offset: int = 0, limit: int = 51200) -> str:
    """Read the full content of an earlier tool result that was truncated.

    When a tool's output is too large it is trimmed to a head+tail preview in
    the conversation and the complete text is saved with an ``output_id`` shown
    in the truncation notice. Use this to retrieve the parts that were elided
    (e.g. a specific match buried in the middle of a long scan or file dump).

    Args:
        output_id: The id from the truncation notice (a 32-char hex token).
        offset: Zero-based byte offset to start reading from.
        limit: Maximum number of bytes to return (capped at 50 KiB). Page
            forward by calling again with the ``offset`` printed in the hint at
            the end of each page until no hint remains.
    """
    return read_stored_output(output_id, offset=offset, limit=limit)

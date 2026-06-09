"""Credential access tool for Strix agents."""

from __future__ import annotations

import json
from typing import Any

from agents import RunContextWrapper, function_tool


async def _get_credential_impl(ctx: RunContextWrapper, name: str) -> str:
    context: dict[str, Any] = ctx.context if isinstance(ctx.context, dict) else {}
    credentials: dict[str, str] = context.get("credentials") or {}
    value = credentials.get(name)
    if value is None:
        return json.dumps(
            {
                "error": f"Credential '{name}' not found.",
                "available": sorted(credentials.keys()),
            }
        )
    return json.dumps({"value": value})


get_credential = function_tool(name_override="get_credential", timeout=10)(_get_credential_impl)
get_credential.__doc__ = (
    "Retrieve a named credential value supplied via --credentials or --credentials-file. "
    "Credential values are never stored in conversation history — call this tool each time "
    "you need a value (e.g., to fill a login form or set an auth header). "
    "Pass the exact key name shown in the CREDENTIALS AVAILABLE system prompt block."
)

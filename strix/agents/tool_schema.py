"""Tool-schema normalization utilities.

Kept in a standalone module so it can be imported without pulling in the full
Strix runtime (docker, sandbox, etc.).  ``factory.py`` re-exports the public
helpers from here.
"""

from __future__ import annotations

from typing import Any

from agents.tool import FunctionTool


def sanitize_tool_schema(tool: FunctionTool) -> FunctionTool:
    """Remove schema fields that strict providers (e.g. Groq) reject.

    The ``@function_tool`` decorator generates a ``params_json_schema`` of::

        {"type": "object", "properties": {}, "required": [], "additionalProperties": false}

    for zero-argument tools such as ``view_agent_graph``.  Groq's API
    validation rejects this with::

        'required' present but 'properties' is missing

    (It interprets an empty ``properties`` object as absent.)  An empty
    ``required`` array is also semantically meaningless: it constrains nothing.
    Strip it — and the now-redundant ``additionalProperties`` flag — so the
    schema degenerates to the universally-accepted ``{"type": "object"}`` form
    when there are truly no parameters.  Tools that do have parameters are
    left unchanged.

    This mutates ``params_json_schema`` in place (idempotent).
    """
    schema: dict[str, Any] = tool.params_json_schema
    properties = schema.get("properties")
    required = schema.get("required")

    # Only sanitize when the tool genuinely has no user-visible parameters.
    if (
        isinstance(properties, dict)
        and not properties
        and isinstance(required, list)
        and not required
    ):
        schema.pop("required", None)
        schema.pop("additionalProperties", None)
        schema.pop("properties", None)

    return tool

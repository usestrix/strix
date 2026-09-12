"""``load_skill`` — fetch skill reference material into the conversation."""

from __future__ import annotations

from agents import RunContextWrapper, function_tool

from strix.skills import load_skills, validate_requested_skills
from strix.skills import search_skills as _search_skills


@function_tool(timeout=10)
async def load_skill(ctx: RunContextWrapper, skills: list[str]) -> str:
    """Return the markdown body of one or more skills as reference material.

    Use this when you need exact syntax / workflow / payload guidance
    right before acting on a technology that wasn't preloaded for your
    agent. The skill content lands inline as a tool result — no
    permanent prompt change, just in-conversation reference.

    For permanent skill assignment, pass ``skills=[…]`` to
    ``create_agent`` when spawning a specialist child instead.

    Args:
        skills: List of skill names (e.g. ``["xss", "sql_injection"]``).
            Max 5. Names match the bare files under
            ``strix/skills/<category>/<name>.md``.
    """
    del ctx
    requested = list(skills or [])
    err = validate_requested_skills(requested)
    if err:
        return f"load_skill: {err}"
    contents = load_skills(requested)
    if not contents:
        return "load_skill: no content loaded for requested skills."
    sections = [f"## Skill: {name}\n\n{body}" for name, body in contents.items()]
    return "\n\n---\n\n".join(sections)


@function_tool(timeout=10)
async def search_skills(ctx: RunContextWrapper, query: str, top_k: int = 5) -> str:
    """Find skills matching a fuzzy need when you don't know the exact skill name.

    Use this before ``load_skill`` when you know roughly what you need
    (a vuln class, protocol, tool, or framework) but not the exact
    filename-derived skill name — e.g. "GraphQL introspection" or
    "JWT token handling". It ranks skills by lexical overlap with your
    query and returns name/category/description only; call
    ``load_skill`` on the name you pick to get the full guidance.

    Args:
        query: Free-text description of what you're looking for.
        top_k: Maximum number of ranked matches to return (default 5).
    """
    del ctx
    results = _search_skills(query, top_k=top_k)
    if not results:
        return f"search_skills: no matching skills found for query {query!r}."
    lines = [
        f"- {result['category']}/{result['name']}: {result['description']}"
        if result["description"]
        else f"- {result['category']}/{result['name']}"
        for result in results
    ]
    return "\n".join(lines)

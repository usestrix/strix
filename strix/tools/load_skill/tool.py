"""``load_skill`` — fetch skill reference material into the conversation."""

from __future__ import annotations

from agents import RunContextWrapper, function_tool

from strix.skills import load_skills, validate_requested_skills


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

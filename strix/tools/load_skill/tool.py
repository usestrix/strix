"""``load_skill`` — fetch skill reference material into the conversation."""

from __future__ import annotations

import json

from agents import RunContextWrapper, function_tool

from strix.skills import load_skills, validate_requested_skills


@function_tool(timeout=10, strict_mode=False)
async def load_skill(ctx: RunContextWrapper, skills: str | list[str]) -> str:
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
    # Tolerate LLM providers that pass array params as JSON-encoded strings.
    # Validate decoded shape: reject anything that isn't a list of strings.
    if isinstance(skills, str):
        original_skills = skills
        try:
            decoded_skills = json.loads(skills)
        except json.JSONDecodeError:
            skills = [s.strip() for s in skills.split(",") if s.strip()]
        else:
            if isinstance(decoded_skills, str):
                skills = [decoded_skills]
            elif isinstance(decoded_skills, list) and all(
                isinstance(skill, str) for skill in decoded_skills
            ):
                skills = decoded_skills
            else:
                skills = [original_skills]
    requested = list(skills or [])
    err = validate_requested_skills(requested)
    if err:
        return f"load_skill: {err}"
    contents = load_skills(requested)
    if not contents:
        return "load_skill: no content loaded for requested skills."
    sections = [f"## Skill: {name}\n\n{body}" for name, body in contents.items()]
    return "\n\n---\n\n".join(sections)

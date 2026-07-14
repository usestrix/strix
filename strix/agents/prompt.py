"""Jinja-based system-prompt renderer."""

from __future__ import annotations

import logging
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from strix.skills import get_available_skills, load_skills, skill_search_dirs
from strix.utils.resource_paths import get_strix_resource_path


logger = logging.getLogger(__name__)


_PROMPT_DIRNAME = "prompts"


def _resolve_skills(
    *,
    requested: list[str] | None,
    scan_mode: str = "deep",
    is_whitebox: bool = False,
    is_root: bool = False,
) -> list[str]:
    """Build the deduped, ordered skills list for the prompt render.

    Order:

    1. Whatever the caller asked for, in order.
    2. ``scan_modes/<mode>`` (always).
    3. ``tooling/agent_browser`` (always — every agent has shell + the
       agent-browser CLI).
    4. ``tooling/python`` (always — Python runs through ``exec_command``;
       sandbox scripts can import ``caido_api`` for Caido automation).
    5. ``coordination/root_agent`` for the root agent only — orchestration
       guidance for delegating to specialist subagents.
    6. Whitebox-specific skills if applicable.
    """
    ordered: list[str] = list(requested or [])
    ordered.append(f"scan_modes/{scan_mode}")
    ordered.append("tooling/agent_browser")
    ordered.append("tooling/python")
    if is_root:
        ordered.append("coordination/root_agent")
    if is_whitebox:
        ordered.append("coordination/source_aware_whitebox")
        ordered.append("custom/source_aware_sast")

    deduped: list[str] = []
    seen: set[str] = set()
    for skill in ordered:
        if skill and skill not in seen:
            deduped.append(skill)
            seen.add(skill)
    return deduped


def render_system_prompt(
    *,
    skills: list[str] | None = None,
    scan_mode: str = "deep",
    is_whitebox: bool = False,
    is_root: bool = False,
    interactive: bool = False,
    system_prompt_context: dict[str, Any] | None = None,
) -> str:
    """Render the system prompt. Returns empty string on template failure."""
    try:
        prompt_dir = get_strix_resource_path("agents", _PROMPT_DIRNAME)
        loader_dirs = [prompt_dir, *skill_search_dirs()]
        env = Environment(
            loader=FileSystemLoader(loader_dirs),
            autoescape=select_autoescape(
                enabled_extensions=(),
                default_for_string=False,
            ),
        )

        skills_to_load = _resolve_skills(
            requested=skills,
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            is_root=is_root,
        )
        skill_content = load_skills(skills_to_load)
        env.globals["get_skill"] = lambda name: skill_content.get(name, "")

        rendered = env.get_template("system_prompt.jinja").render(
            loaded_skill_names=list(skill_content.keys()),
            available_skills=get_available_skills(),
            interactive=interactive,
            system_prompt_context=system_prompt_context or {},
            **skill_content,
        )
    except Exception:
        logger.exception("render_system_prompt failed; returning empty prompt")
        return ""
    else:
        logger.debug(
            "render_system_prompt: scan_mode=%s root=%s whitebox=%s skills=%d prompt_len=%d",
            scan_mode,
            is_root,
            is_whitebox,
            len(skill_content),
            len(rendered),
        )
        return str(rendered)

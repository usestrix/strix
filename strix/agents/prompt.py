"""Jinja-based system-prompt renderer."""

from __future__ import annotations

import logging
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from strix.skills import get_available_skills, load_skills, skill_search_dirs
from strix.utils.resource_paths import get_strix_resource_path


logger = logging.getLogger(__name__)


_PROMPT_DIRNAME = "prompts"

# Marks where the system prompt is split so the part before it can be cached.
# Removed before the prompt is sent.
CACHE_POINT = "<cache_point>"


def _resolve_skills(
    *,
    requested: list[str] | None,
    scan_mode: str = "deep",
    is_whitebox: bool = False,
    is_root: bool = False,
    is_diff_scoped: bool = False,
) -> list[str]:
    """Build the deduped, ordered skills list for the prompt render.

    Order:

    1. Whatever the caller asked for, in order.
    2. ``scan_modes/<mode>`` (always), plus ``scan_modes/diff`` when the
       run is scoped to a change set — diff scope overlays the depth
       mode rather than replacing it.
    3. ``tooling/agent_browser`` (always — every agent has shell + the
       agent-browser CLI).
    4. ``tooling/python`` (always — Python runs through ``exec_command``;
       sandbox scripts can import ``caido_api`` for Caido automation).
    5. ``analysis/counterevidence`` and ``analysis/severity_calibration``
       (always — closure discipline and severity rubric apply to every
       agent that can open or close a candidate, or file a report).
    6. ``coordination/root_agent`` for the root agent only — orchestration
       guidance for delegating to specialist subagents.
    7. Whitebox-specific skills if applicable, including
       ``analysis/fix_verification`` (only whitebox agents can attach an
       applyable ``fix_after``) and ``analysis/source_aware_discovery``.
    """
    ordered: list[str] = list(requested or [])
    ordered.append(f"scan_modes/{scan_mode}")
    if is_diff_scoped:
        ordered.append("scan_modes/diff")
    ordered.append("tooling/agent_browser")
    ordered.append("tooling/python")
    ordered.append("analysis/counterevidence")
    ordered.append("analysis/severity_calibration")
    if is_root:
        ordered.append("coordination/root_agent")
    if is_whitebox:
        ordered.append("coordination/source_aware_whitebox")
        ordered.append("custom/source_aware_sast")
        ordered.append("analysis/source_aware_discovery")
        ordered.append("analysis/fix_verification")

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
    is_diff_scoped: bool = False,
    interactive: bool = False,
    system_prompt_context: dict[str, Any] | None = None,
    include_scope: bool = True,
    supports_images: bool = True,
) -> str:
    """Render the system prompt. Returns empty string on template failure.

    The per-run scope (targets, MCP connections) goes last so the rest of the
    prompt is an identical prefix across runs and can be served from cache.
    """
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

        shared = {
            name.split("/")[-1]
            for name in _resolve_skills(
                requested=None,
                scan_mode=scan_mode,
                is_whitebox=is_whitebox,
                is_root=is_root,
                is_diff_scoped=is_diff_scoped,
            )
        }
        skills_to_load = _resolve_skills(
            requested=skills,
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            is_root=is_root,
            is_diff_scoped=is_diff_scoped,
        )
        skill_content = load_skills(skills_to_load, supports_images=supports_images)
        env.globals["get_skill"] = lambda name: skill_content.get(name, "")

        # Skills every agent of this kind loads come first, so siblings share them
        # as a cached prefix; the ones the caller asked for vary and go after.
        rendered = env.get_template("system_prompt.jinja").render(
            shared_skill_names=[name for name in skill_content if name in shared],
            requested_skill_names=[name for name in skill_content if name not in shared],
            available_skills=get_available_skills(),
            interactive=interactive,
            is_root=is_root,
            system_prompt_context=system_prompt_context or {},
            include_scope=include_scope,
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


def render_scope_prompt(system_prompt_context: dict[str, Any] | None) -> str:
    """Render only the per-run scope block that ends the system prompt."""
    prompt_dir = get_strix_resource_path("agents", _PROMPT_DIRNAME)
    env = Environment(
        loader=FileSystemLoader(prompt_dir),
        autoescape=select_autoescape(enabled_extensions=(), default_for_string=False),
    )
    rendered = env.get_template("scope.jinja").render(
        system_prompt_context=system_prompt_context or {},
    )
    return str(rendered).strip()

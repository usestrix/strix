from typing import Any

from strix.runtime_agent_registry import get_agent_instance
from strix.skills.runtime_tooling import canonical_runtime_skill_name
from strix.tools.registry import register_tool


@register_tool(sandbox_execution=False)
def load_skill(agent_state: Any, skills: str) -> dict[str, Any]:
    try:
        requested_skills = [s.strip() for s in skills.split(",") if s.strip()]
        if not requested_skills:
            return {
                "success": False,
                "error": "No skills provided. Pass one or more comma-separated skill names.",
                "requested_skills": [],
            }

        from strix.skills import load_skills

        valid_skills: list[str] = []
        invalid_skills: list[str] = []

        for skill_name in requested_skills:
            if load_skills([skill_name]):
                valid_skills.append(skill_name)
            else:
                invalid_skills.append(skill_name)

        if invalid_skills:
            return {
                "success": False,
                "error": f"Invalid skills: {invalid_skills}",
                "requested_skills": requested_skills,
                "loaded_skills": [],
                "invalid_skills": invalid_skills,
            }

        current_agent = get_agent_instance(agent_state.agent_id)
        if current_agent is None or not hasattr(current_agent, "llm"):
            return {
                "success": False,
                "error": (
                    "Could not find running agent instance for runtime skill loading. "
                    "Try again in the current active agent."
                ),
                "requested_skills": requested_skills,
                "loaded_skills": [],
            }

        canonical_valid_skills = [canonical_runtime_skill_name(skill) for skill in valid_skills]
        newly_loaded = current_agent.llm.add_runtime_skills(canonical_valid_skills)
        already_loaded = [skill for skill in canonical_valid_skills if skill not in newly_loaded]

        prior = agent_state.context.get("runtime_skills_loaded", [])
        if not isinstance(prior, list):
            prior = []
        canonical_prior = [canonical_runtime_skill_name(skill) for skill in prior]
        merged_runtime = sorted(set(canonical_prior).union(canonical_valid_skills))
        agent_state.update_context("runtime_skills_loaded", merged_runtime)

    except Exception as e:  # noqa: BLE001
        fallback_requested_skills = (
            requested_skills
            if "requested_skills" in locals()
            else [s.strip() for s in skills.split(",") if s.strip()]
        )
        return {
            "success": False,
            "error": f"Failed to load skill(s): {e!s}",
            "requested_skills": fallback_requested_skills,
            "loaded_skills": [],
        }
    else:
        return {
            "success": True,
            "requested_skills": requested_skills,
            "loaded_skills": canonical_valid_skills,
            "newly_loaded_skills": newly_loaded,
            "already_loaded_skills": already_loaded,
            "message": (
                "Runtime skills loaded into this agent prompt context. "
                "Continue with commands using the newly loaded guidance."
            ),
        }

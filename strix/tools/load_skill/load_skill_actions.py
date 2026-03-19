from typing import Any

from strix.tools.registry import register_tool


@register_tool(sandbox_execution=False)
def load_skill(agent_state: Any, skills: str) -> dict[str, Any]:
    try:
        from strix.skills import parse_skill_list, validate_requested_skills

        requested_skills = parse_skill_list(skills)
        if not requested_skills:
            return {
                "success": False,
                "error": "No skills provided. Pass one or more comma-separated skill names.",
                "requested_skills": [],
            }

        validation_error = validate_requested_skills(requested_skills)
        if validation_error:
            return {
                "success": False,
                "error": validation_error,
                "requested_skills": requested_skills,
                "loaded_skills": [],
            }

        from strix.tools.agents_graph.agents_graph_actions import _agent_instances

        current_agent = _agent_instances.get(agent_state.agent_id)
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

        newly_loaded = current_agent.llm.add_skills(requested_skills)
        already_loaded = [skill for skill in requested_skills if skill not in newly_loaded]

        prior = agent_state.context.get("loaded_skills", [])
        if not isinstance(prior, list):
            prior = []
        merged_skills = sorted(set(prior).union(requested_skills))
        agent_state.update_context("loaded_skills", merged_skills)

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
            "loaded_skills": requested_skills,
            "newly_loaded_skills": newly_loaded,
            "already_loaded_skills": already_loaded,
            "message": "Skills loaded into this agent prompt context.",
        }

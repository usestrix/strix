import re
from typing import Any

from strix.skills import (
    get_all_skill_names,
    get_available_skills,
    validate_skill_names,
)
from strix.skills import (
    load_skills as load_skills_content,
)
from strix.tools.registry import register_tool
from strix.utils.resource_paths import get_strix_resource_path


_FRONTMATTER_PATTERN = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)
_NAME_PATTERN = re.compile(r"^name:\s*(.+)$", re.MULTILINE)
_DESCRIPTION_PATTERN = re.compile(r"^description:\s*(.+)$", re.MULTILINE)


def _extract_frontmatter(content: str) -> dict[str, str] | None:
    """Extract name and description from YAML frontmatter using simple regex parsing."""
    match = _FRONTMATTER_PATTERN.match(content)
    if not match:
        return None

    frontmatter_text = match.group(1)
    metadata: dict[str, str] = {}

    name_match = _NAME_PATTERN.search(frontmatter_text)
    if name_match:
        metadata["name"] = name_match.group(1).strip()

    desc_match = _DESCRIPTION_PATTERN.search(frontmatter_text)
    if desc_match:
        metadata["description"] = desc_match.group(1).strip()

    return metadata if metadata else None


def _get_skill_metadata(skill_name: str, category: str | None = None) -> dict[str, str] | None:
    """Get metadata (name, description) for a specific skill by reading its file."""
    skills_dir = get_strix_resource_path("skills")

    if category:
        skill_path = skills_dir / category / f"{skill_name}.md"
    else:
        all_categories = get_available_skills()
        skill_path = None
        for cat, skills in all_categories.items():
            if skill_name in skills:
                skill_path = skills_dir / cat / f"{skill_name}.md"
                break

        if not skill_path:
            root_candidate = skills_dir / f"{skill_name}.md"
            if root_candidate.exists():
                skill_path = root_candidate

    if skill_path and skill_path.exists():
        try:
            content = skill_path.read_text()
            return _extract_frontmatter(content)
        except (FileNotFoundError, OSError):
            return None

    return None


@register_tool(sandbox_execution=False)
def list_skills(
    category: str | None = None,
) -> dict[str, Any]:
    """List available skills, optionally filtered by category.

    Always includes name and description metadata for each skill.
    """
    try:
        available_skills = get_available_skills()

        if category:
            if category in available_skills:
                filtered_skills = {category: available_skills[category]}
            else:
                categories_str = ", ".join(sorted(available_skills.keys()))
                return {
                    "success": False,
                    "error": (
                        f"Category '{category}' not found. Available categories: {categories_str}"
                    ),
                    "skills_by_category": {},
                    "all_skills": [],
                    "categories": list(available_skills.keys()),
                    "metadata": {},
                }
        else:
            filtered_skills = available_skills

        metadata: dict[str, dict[str, str]] = {}
        for cat, skills in filtered_skills.items():
            for skill_name in skills:
                skill_meta = _get_skill_metadata(skill_name, cat)
                if skill_meta:
                    metadata[skill_name] = skill_meta

        all_filtered_skills: list[str] = []
        for skills in filtered_skills.values():
            all_filtered_skills.extend(skills)
        all_filtered_skills = sorted(set(all_filtered_skills))

        return {
            "success": True,
            "skills_by_category": filtered_skills,
            "all_skills": all_filtered_skills
            if not category
            else filtered_skills.get(category, []),
            "categories": list(available_skills.keys()),
            "metadata": metadata,
        }
    except Exception as e:  # noqa: BLE001
        return {
            "success": False,
            "error": f"Failed to list skills: {e}",
            "skills_by_category": {},
            "all_skills": [],
            "categories": [],
            "metadata": {},
        }


@register_tool(sandbox_execution=False)
def load_skills(
    agent_state: Any,
    skills: str,
) -> dict[str, Any]:
    """Load skill content dynamically at runtime for immediate use."""
    try:
        skill_list = [s.strip() for s in skills.split(",") if s.strip()]

        if not skill_list:
            return {
                "success": False,
                "error": "No skills specified. Provide comma-separated skill names.",
                "loaded_skills": {},
                "loaded_count": 0,
                "invalid_skills": [],
                "warnings": [],
            }

        def _bare_name(s: str) -> str:
            return s.split("/")[-1]

        validation = validate_skill_names([_bare_name(s) for s in skill_list])
        invalid_bare = set(validation.get("invalid", []))
        valid_skills = [s for s in skill_list if _bare_name(s) not in invalid_bare]
        invalid_skills = [s for s in skill_list if _bare_name(s) in invalid_bare]

        warnings: list[str] = []
        if invalid_skills:
            available_skills = list(get_all_skill_names())
            warnings.append(
                f"Invalid skills: {', '.join(invalid_skills)}. "
                f"Available skills: {', '.join(sorted(available_skills))}"
            )

        loaded_content = load_skills_content(valid_skills)

        loaded_skill_names = set(loaded_content.keys())
        requested_skill_names = {s.split("/")[-1] for s in valid_skills}
        missing_skills = requested_skill_names - loaded_skill_names
        if missing_skills:
            warnings.append(f"Some skills could not be loaded: {', '.join(missing_skills)}")

        result: dict[str, Any] = {
            "success": len(loaded_content) > 0,
            "loaded_skills": loaded_content,
            "loaded_count": len(loaded_content),
            "invalid_skills": invalid_skills,
            "warnings": warnings,
        }
        if not result["success"] and not loaded_content:
            result["error"] = (
                "No skills could be loaded. "
                + (warnings[0] if warnings else "Check skill names with list_skills.")
            )
        return result
    except Exception as e:  # noqa: BLE001
        return {
            "success": False,
            "error": f"Failed to load skills: {e}",
            "loaded_skills": {},
            "loaded_count": 0,
            "invalid_skills": [],
            "warnings": [],
        }

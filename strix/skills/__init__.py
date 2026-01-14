from jinja2 import Environment

from strix.utils.resource_paths import get_strix_resource_path


def get_available_skills() -> dict[str, list[str]]:
    skills_dir = get_strix_resource_path("skills")
    available_skills: dict[str, list[str]] = {}

    if not skills_dir.exists():
        return available_skills

    for category_dir in skills_dir.iterdir():
        if category_dir.is_dir() and not category_dir.name.startswith("__"):
            category_name = category_dir.name
            skills = []

            for file_path in category_dir.glob("*.jinja"):
                skill_name = file_path.stem
                skills.append(skill_name)

            if skills:
                available_skills[category_name] = sorted(skills)

    return available_skills


def get_all_skill_names() -> set[str]:
    all_skills = set()
    for category_skills in get_available_skills().values():
        all_skills.update(category_skills)
    return all_skills


def validate_skill_names(skill_names: list[str]) -> dict[str, list[str]]:
    available_skills = get_all_skill_names()
    valid_skills = []
    invalid_skills = []

    for skill_name in skill_names:
        if skill_name in available_skills:
            valid_skills.append(skill_name)
        else:
            invalid_skills.append(skill_name)

    return {"valid": valid_skills, "invalid": invalid_skills}


def generate_skills_description() -> str:
    available_skills = get_available_skills()

    if not available_skills:
        return "No skills available"

    all_skill_names = get_all_skill_names()

    if not all_skill_names:
        return "No skills available"

    sorted_skills = sorted(all_skill_names)
    skills_str = ", ".join(sorted_skills)

    description = f"List of skills to load for this agent (max 5). Available skills: {skills_str}. "

    example_skills = sorted_skills[:2]
    if example_skills:
        example = f"Example: {', '.join(example_skills)} for specialized agent"
        description += example

    return description


def load_skills(skill_names: list[str], jinja_env: Environment) -> dict[str, str]:
    import logging

    logger = logging.getLogger(__name__)
    skill_content = {}
    skills_dir = get_strix_resource_path("skills")

    available_skills = get_available_skills()

    for skill_name in skill_names:
        try:
            skill_path = None

            if "/" in skill_name:
                skill_path = f"{skill_name}.jinja"
            else:
                for category, skills in available_skills.items():
                    if skill_name in skills:
                        skill_path = f"{category}/{skill_name}.jinja"
                        break

                if not skill_path:
                    root_candidate = f"{skill_name}.jinja"
                    if (skills_dir / root_candidate).exists():
                        skill_path = root_candidate

            if skill_path and (skills_dir / skill_path).exists():
                template = jinja_env.get_template(skill_path)
                var_name = skill_name.split("/")[-1]
                skill_content[var_name] = template.render()
                logger.info(f"Loaded skill: {skill_name} -> {var_name}")
            else:
                logger.warning(f"Skill not found: {skill_name}")

        except (FileNotFoundError, OSError, ValueError) as e:
            logger.warning(f"Failed to load skill {skill_name}: {e}")

    return skill_content

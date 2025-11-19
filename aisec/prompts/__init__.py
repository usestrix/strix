from pathlib import Path

from jinja2 import Environment


def get_available_prompt_modules() -> dict[str, list[str]]:
    modules_dir = Path(__file__).parent
    available_modules = {}

    for category_dir in modules_dir.iterdir():
        if category_dir.is_dir() and not category_dir.name.startswith("__"):
            category_name = category_dir.name
            modules = []

            for file_path in category_dir.glob("*.jinja"):
                module_name = file_path.stem
                modules.append(module_name)

            if modules:
                available_modules[category_name] = sorted(modules)

    return available_modules


def get_all_module_names() -> set[str]:
    all_modules = set()
    for category_modules in get_available_prompt_modules().values():
        all_modules.update(category_modules)
    return all_modules


def validate_module_names(module_names: list[str]) -> dict[str, list[str]]:
    available_modules = get_all_module_names()
    valid_modules = []
    invalid_modules = []

    for module_name in module_names:
        if module_name in available_modules:
            valid_modules.append(module_name)
        else:
            invalid_modules.append(module_name)

    return {"valid": valid_modules, "invalid": invalid_modules}


def generate_modules_description() -> str:
    available_modules = get_available_prompt_modules()

    if not available_modules:
        return "No prompt modules available"

    all_module_names = get_all_module_names()

    if not all_module_names:
        return "No prompt modules available"

    sorted_modules = sorted(all_module_names)
    modules_str = ", ".join(sorted_modules)

    description = (
        f"List of prompt modules to load for this agent (max 5). Available modules: {modules_str}. "
    )

    example_modules = sorted_modules[:2]
    if example_modules:
        example = f"Example: {', '.join(example_modules)} for specialized agent"
        description += example

    return description


def load_prompt_modules(module_names: list[str], jinja_env: Environment) -> dict[str, str]:
    import logging

    logger = logging.getLogger(__name__)
    module_content = {}
    prompts_dir = Path(__file__).parent

    available_modules = get_available_prompt_modules()

    for module_name in module_names:
        try:
            module_path = None

            if "/" in module_name:
                module_path = f"{module_name}.jinja"
            else:
                for category, modules in available_modules.items():
                    if module_name in modules:
                        module_path = f"{category}/{module_name}.jinja"
                        break

                if not module_path:
                    root_candidate = f"{module_name}.jinja"
                    if (prompts_dir / root_candidate).exists():
                        module_path = root_candidate

            if module_path and (prompts_dir / module_path).exists():
                template = jinja_env.get_template(module_path)
                var_name = module_name.split("/")[-1]
                module_content[var_name] = template.render()
                logger.info(f"Loaded prompt module: {module_name} -> {var_name}")
            else:
                logger.warning(f"Prompt module not found: {module_name}")

        except (FileNotFoundError, OSError, ValueError) as e:
            logger.warning(f"Failed to load prompt module {module_name}: {e}")

    return module_content

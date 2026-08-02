"""Installation helpers for the portable Strix agent skill."""

from __future__ import annotations

from pathlib import Path


def skill_path() -> Path:
    """Return the skill directory in a checkout or installed wheel."""
    module_path = Path(__file__).resolve()
    candidates = (
        module_path.parents[2] / "skills" / "strix-security",
        module_path.parents[1] / "agent_skills" / "strix-security",
    )
    for candidate in candidates:
        if (candidate / "SKILL.md").is_file():
            return candidate
    raise FileNotFoundError("The packaged strix-security skill could not be located")


def print_skill_path() -> None:
    """Print a shell-safe-to-quote path for agent skill installation."""
    print(skill_path())  # noqa: T201 - this command intentionally prints its result.


if __name__ == "__main__":
    print_skill_path()

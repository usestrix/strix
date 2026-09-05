"""Tests for strix.skills catalog loading and validation."""

from __future__ import annotations

import pytest

from strix.skills import (
    _INTERNAL_SKILL_CATEGORIES,
    get_all_skill_names,
    get_available_skills,
    load_skills,
    validate_requested_skills,
)
from strix.utils.resource_paths import get_strix_resource_path


def test_internal_categories_excluded_from_user_skill_names() -> None:
    names = get_all_skill_names()
    grouped = get_available_skills()
    skills_dir = get_strix_resource_path("skills")

    for category in _INTERNAL_SKILL_CATEGORIES:
        assert category not in grouped
        for skill_file in (skills_dir / category).glob("*.md"):
            assert skill_file.stem not in names


def test_merged_security_skills_are_registered() -> None:
    """Regression guard for community skills shipped on main."""
    expected = {
        "oauth",
        "aws",
        "django",
        "prototype_pollution",
        "insecure_deserialization",
    }
    names = get_all_skill_names()
    missing = expected - names
    assert not missing, f"Expected skills missing from catalog: {sorted(missing)}"


@pytest.mark.parametrize(
    ("skill_list", "expected_substring"),
    [
        ([], None),
        (["idor", "xss"], None),
        (["a", "b", "c", "d", "e", "f"], "more than 5"),
        (["not_a_real_skill"], "Invalid skill name"),
        (["idor", "fake_skill"], "Invalid skill name"),
    ],
)
def test_validate_requested_skills(
    skill_list: list[str],
    expected_substring: str | None,
) -> None:
    result = validate_requested_skills(skill_list)
    if expected_substring is None:
        assert result is None
    else:
        assert result is not None
        assert expected_substring in result


def test_load_skills_strips_frontmatter_and_resolves_bare_name() -> None:
    content = load_skills(["idor"])
    assert "idor" in content
    body = content["idor"]
    assert not body.startswith("---")
    assert "# IDOR" in body
    assert "name: idor" not in body


def test_load_skills_accepts_category_prefixed_name() -> None:
    content = load_skills(["vulnerabilities/idor"])
    assert "idor" in content
    assert "# IDOR" in content["idor"]


def test_load_skills_skips_missing_skill() -> None:
    assert load_skills(["definitely_missing_skill_xyz"]) == {}


def test_every_user_selectable_skill_loads_nonempty() -> None:
    for name in sorted(get_all_skill_names()):
        content = load_skills([name])
        assert name in content, f"{name}: load_skills did not return content"
        assert content[name].strip(), f"{name}: loaded body is empty"

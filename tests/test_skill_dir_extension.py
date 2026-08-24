from collections.abc import Iterator
from pathlib import Path

import pytest

import strix.skills as skills_mod
from strix.agents.prompt import render_system_prompt
from strix.skills import (
    get_all_skill_names,
    get_available_skills,
    load_skills,
    register_skill_dir,
    registered_skill_dirs,
    skill_search_dirs,
    validate_requested_skills,
)
from strix.utils.resource_paths import get_strix_resource_path


@pytest.fixture(autouse=True)
def _clear_extra_dirs() -> Iterator[None]:
    original = list(skills_mod._EXTRA_SKILL_DIRS)
    skills_mod._EXTRA_SKILL_DIRS.clear()
    try:
        yield
    finally:
        skills_mod._EXTRA_SKILL_DIRS[:] = original


def _write_skill(root: Path, category: str, name: str, body: str) -> None:
    category_dir = root / category
    category_dir.mkdir(parents=True, exist_ok=True)
    (category_dir / f"{name}.md").write_text(body, encoding="utf-8")


def _write_root_skill(root: Path, name: str, body: str) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / f"{name}.md").write_text(body, encoding="utf-8")


def test_no_registration_leaves_builtin_only() -> None:
    assert registered_skill_dirs() == ()
    builtin = get_strix_resource_path("skills")
    assert skill_search_dirs() == (builtin,)
    assert {"nmap", "subfinder"}.issubset(
        {skill["name"] for skill in get_available_skills()["tooling"]}
    )


def test_register_is_idempotent_and_ordered(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()

    register_skill_dir(a)
    register_skill_dir(b)
    register_skill_dir(a)

    # Most recently registered wins → highest precedence first.
    assert registered_skill_dirs() == (b, a)


def test_registered_dir_adds_new_skill(tmp_path: Path) -> None:
    _write_skill(tmp_path, "extra", "widget", "widget body")
    register_skill_dir(tmp_path)

    assert "widget" in get_all_skill_names()
    assert get_available_skills()["extra"] == [{"name": "widget", "description": ""}]
    assert load_skills(["widget"]) == {"widget": "widget body"}


def test_available_skill_includes_frontmatter_description(tmp_path: Path) -> None:
    _write_skill(
        tmp_path,
        "extra",
        "widget",
        "---\nname: widget\ndescription: Useful widget guidance\n---\nwidget body",
    )
    register_skill_dir(tmp_path)

    assert get_available_skills()["extra"] == [
        {"name": "widget", "description": "Useful widget guidance"}
    ]


def test_available_skill_supports_colon_in_description(tmp_path: Path) -> None:
    _write_skill(
        tmp_path,
        "extra",
        "widget",
        '---\nname: widget\ndescription: "Useful widget: handles YAML"\n---\nwidget body',
    )
    register_skill_dir(tmp_path)

    assert get_available_skills()["extra"] == [
        {"name": "widget", "description": "Useful widget: handles YAML"}
    ]


def test_available_skill_normalizes_quoted_description(tmp_path: Path) -> None:
    _write_skill(
        tmp_path,
        "extra",
        "widget",
        '---\nname: widget\ndescription: "Useful: widget guidance"\n---\nwidget body',
    )
    register_skill_dir(tmp_path)

    assert get_available_skills()["extra"] == [
        {"name": "widget", "description": "Useful: widget guidance"}
    ]


def test_available_skill_normalizes_multiline_descriptions(tmp_path: Path) -> None:
    _write_skill(
        tmp_path,
        "extra",
        "block",
        "---\nname: block\n\ndescription: |\n"
        "  First paragraph\n\n  Second paragraph\n\n---\nblock body",
    )
    _write_skill(
        tmp_path,
        "extra",
        "plain",
        "---\nname: plain\n\ndescription: First line\n  Second line\n\n---\nplain body",
    )
    register_skill_dir(tmp_path)

    available = {skill["name"]: skill["description"] for skill in get_available_skills()["extra"]}
    assert available == {
        "block": "First paragraph Second paragraph",
        "plain": "First line Second line",
    }


def test_available_skill_supports_block_scalar_trailing_comment(tmp_path: Path) -> None:
    _write_skill(
        tmp_path,
        "extra",
        "commented",
        "---\nname: commented\ndescription: | # paragraph\n"
        "  First line\n  Second line\n---\ncommented body",
    )
    register_skill_dir(tmp_path)

    assert get_available_skills()["extra"] == [
        {"name": "commented", "description": "First line Second line"}
    ]


def test_malformed_frontmatter_keeps_skill_body(tmp_path: Path) -> None:
    _write_skill(
        tmp_path,
        "extra",
        "broken",
        "---\nname: [broken\ndescription: should be empty\n---\nbroken body",
    )
    register_skill_dir(tmp_path)

    assert get_available_skills()["extra"] == [{"name": "broken", "description": ""}]
    assert load_skills(["extra/broken"]) == {"broken": "broken body"}


def test_system_prompt_renders_skill_descriptions() -> None:
    prompt = render_system_prompt(scan_mode="quick", is_root=True)

    assert "- technologies/firebase: Firebase security testing covering" in prompt


def test_system_prompt_omits_empty_skill_description(tmp_path: Path) -> None:
    _write_skill(tmp_path, "extra", "widget", "---\nname: widget\ndescription:\n---\nwidget body")
    register_skill_dir(tmp_path)

    prompt = render_system_prompt(scan_mode="quick", is_root=True)

    assert "- extra/widget\n" in prompt
    assert "- extra/widget: " not in prompt


def test_registered_root_skill_is_discoverable_and_valid(tmp_path: Path) -> None:
    _write_root_skill(tmp_path, "widget", "widget body")
    register_skill_dir(tmp_path)

    assert "widget" in get_all_skill_names()
    assert get_available_skills()["root"] == [{"name": "widget", "description": ""}]
    assert validate_requested_skills(["widget"]) is None
    assert validate_requested_skills(["root/widget"]) is None
    assert load_skills(["widget"]) == {"widget": "widget body"}
    assert load_skills(["root/widget"]) == {"widget": "widget body"}


def test_ambiguous_bare_skill_requires_qualified_name(tmp_path: Path) -> None:
    _write_skill(tmp_path, "alpha", "widget", "alpha body")
    _write_skill(tmp_path, "beta", "widget", "beta body")
    register_skill_dir(tmp_path)

    assert "widget" in get_all_skill_names()
    assert get_available_skills()["alpha"] == [{"name": "widget", "description": ""}]
    assert get_available_skills()["beta"] == [{"name": "widget", "description": ""}]
    assert validate_requested_skills(["alpha/widget"]) is None
    assert validate_requested_skills(["beta/widget"]) is None

    error = validate_requested_skills(["widget"])
    assert error is not None
    assert "Ambiguous skill name" in error
    assert "alpha/widget" in error
    assert "beta/widget" in error

    assert load_skills(["widget"]) == {}
    assert load_skills(["alpha/widget"]) == {"widget": "alpha body"}
    assert load_skills(["beta/widget"]) == {"widget": "beta body"}


def test_registered_dir_overrides_builtin_skill(tmp_path: Path) -> None:
    _write_skill(tmp_path, "coordination", "root_agent", "overridden root agent")
    register_skill_dir(tmp_path)

    loaded = load_skills(["coordination/root_agent"])
    assert loaded["root_agent"] == "overridden root agent"


def test_builtin_skill_still_loads_when_not_overridden(tmp_path: Path) -> None:
    _write_skill(tmp_path, "extra", "widget", "widget body")
    register_skill_dir(tmp_path)

    # A packaged skill the registered dir does not shadow still resolves.
    assert load_skills(["scan_modes/deep"]).get("deep")


def test_missing_skill_is_skipped(tmp_path: Path) -> None:
    register_skill_dir(tmp_path)
    assert load_skills(["does_not_exist"]) == {}

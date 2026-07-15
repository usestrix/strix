from pathlib import Path

import pytest

import strix.skills as skills_mod
from strix.skills import (
    get_all_skill_names,
    get_available_skills,
    load_skills,
    register_skill_dir,
    registered_skill_dirs,
    skill_search_dirs,
    validate_requested_skills,
)


@pytest.fixture(autouse=True)
def _clear_extra_dirs() -> None:
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
    builtin = skills_mod.get_strix_resource_path("skills")
    assert skill_search_dirs() == (builtin,)
    assert {"nmap", "subfinder"}.issubset(get_available_skills()["tooling"])


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
    assert get_available_skills()["extra"] == ["widget"]
    assert load_skills(["widget"]) == {"widget": "widget body"}


def test_registered_root_skill_is_discoverable_and_valid(tmp_path: Path) -> None:
    _write_root_skill(tmp_path, "widget", "widget body")
    register_skill_dir(tmp_path)

    assert "widget" in get_all_skill_names()
    assert get_available_skills()["root"] == ["widget"]
    assert validate_requested_skills(["widget"]) is None
    assert validate_requested_skills(["root/widget"]) is None
    assert load_skills(["widget"]) == {"widget": "widget body"}
    assert load_skills(["root/widget"]) == {"widget": "widget body"}


def test_ambiguous_bare_skill_requires_qualified_name(tmp_path: Path) -> None:
    _write_skill(tmp_path, "alpha", "widget", "alpha body")
    _write_skill(tmp_path, "beta", "widget", "beta body")
    register_skill_dir(tmp_path)

    assert "widget" in get_all_skill_names()
    assert get_available_skills()["alpha"] == ["widget"]
    assert get_available_skills()["beta"] == ["widget"]
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

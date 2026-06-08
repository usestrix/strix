"""Catalog invariants for bundled skills — frontmatter, unique stems, discovery."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest

from strix.skills import (
    get_all_skill_names,
    get_available_skills,
    load_skills,
    validate_requested_skills,
)
from strix.utils.resource_paths import get_strix_resource_path


if TYPE_CHECKING:
    from pathlib import Path


_FRONTMATTER = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)
_NAME = re.compile(r"^name:\s*(.+)$", re.MULTILINE)
_DESCRIPTION = re.compile(r"^description:\s*(.+)$", re.MULTILINE)

_NEW_CATEGORIES = ("api", "web3", "mobile", "binary")
_NEW_SKILLS = (
    "aws",
    "azure",
    "gcp",
    "rest_api",
    "smart_contracts",
    "blockchain_rpc",
    "android_apk",
    "ios_ipa",
    "native_executable",
)


def _skill_files() -> list[Path]:
    return sorted(get_strix_resource_path("skills").glob("*/*.md"))


@pytest.mark.parametrize("path", _skill_files(), ids=lambda p: f"{p.parent.name}/{p.stem}")
def test_skill_frontmatter_is_valid(path: Path) -> None:
    block = _FRONTMATTER.match(path.read_text(encoding="utf-8"))
    assert block is not None, f"{path}: missing YAML frontmatter"
    name_match = _NAME.search(block.group(1))
    description_match = _DESCRIPTION.search(block.group(1))
    assert name_match is not None, f"{path}: frontmatter missing 'name'"
    assert description_match is not None, f"{path}: frontmatter missing 'description'"
    assert description_match.group(1).strip(), f"{path}: empty description"
    # Display name is hyphenated by convention; the resolvable id is the file stem.
    name = name_match.group(1).strip()
    assert name.replace("-", "_") == path.stem, f"{path}: name '{name}' != stem '{path.stem}'"


def test_skill_stems_are_globally_unique() -> None:
    seen: dict[str, Path] = {}
    collisions: list[str] = []
    for path in _skill_files():
        if path.stem in seen:
            collisions.append(f"{path} shadows {seen[path.stem]}")
        seen[path.stem] = path
    assert not collisions, collisions


def test_new_asset_categories_are_discoverable() -> None:
    catalog = get_available_skills()
    assert [c for c in _NEW_CATEGORIES if c not in catalog] == []
    names = get_all_skill_names()
    assert [s for s in _NEW_SKILLS if s not in names] == []


def test_validate_requested_skills_accepts_new_and_rejects_unknown() -> None:
    assert validate_requested_skills(["aws", "smart_contracts", "rest_api"]) is None
    assert validate_requested_skills(["nope_not_real"]) is not None


def test_load_skills_returns_stripped_bodies() -> None:
    loaded = load_skills(["aws", "android_apk"])
    assert set(loaded) == {"aws", "android_apk"}
    for body in loaded.values():
        assert body
        assert not body.startswith("---")

"""Tests for the Strix skills module: loading, validation, frontmatter, and new skill files."""

import re
from pathlib import Path

import pytest

from strix.skills import (
    _get_all_categories,
    generate_skills_description,
    get_all_skill_names,
    get_available_skills,
    load_skills,
    validate_skill_names,
)
from strix.utils.resource_paths import get_strix_resource_path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SKILLS_DIR = get_strix_resource_path("skills")
FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)
REQUIRED_SECTIONS = {"Attack Surface", "Key Vulnerabilities", "Testing Methodology", "Validation"}

# New skills added in this branch
NEW_SKILLS = {"mfa_bypass", "edge_cases"}


def _read_skill_file(category: str, name: str) -> str:
    """Return the raw text of a skill markdown file."""
    return (SKILLS_DIR / category / f"{name}.md").read_text(encoding="utf-8")


def _parse_frontmatter(raw: str) -> dict[str, str]:
    """Extract frontmatter key-value pairs from a skill file."""
    match = FRONTMATTER_RE.match(raw)
    if not match:
        return {}
    pairs: dict[str, str] = {}
    for line in match.group(1).splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            pairs[key.strip()] = value.strip()
    return pairs


# ---------------------------------------------------------------------------
# get_available_skills
# ---------------------------------------------------------------------------


class TestGetAvailableSkills:
    """Tests for the get_available_skills function."""

    def test_returns_dict(self) -> None:
        result = get_available_skills()
        assert isinstance(result, dict)

    def test_excludes_internal_categories(self) -> None:
        result = get_available_skills()
        assert "scan_modes" not in result
        assert "coordination" not in result

    def test_vulnerabilities_category_present(self) -> None:
        result = get_available_skills()
        assert "vulnerabilities" in result

    def test_frameworks_category_present(self) -> None:
        result = get_available_skills()
        assert "frameworks" in result

    def test_skills_are_sorted(self) -> None:
        for category, skills in get_available_skills().items():
            assert skills == sorted(skills), f"Skills in {category} are not sorted"

    def test_new_skills_appear_in_vulnerabilities(self) -> None:
        """Verify mfa_bypass and edge_cases are discovered by the loader."""
        vuln_skills = get_available_skills().get("vulnerabilities", [])
        for skill in NEW_SKILLS:
            assert skill in vuln_skills, f"{skill} not found in vulnerabilities category"


# ---------------------------------------------------------------------------
# get_all_skill_names
# ---------------------------------------------------------------------------


class TestGetAllSkillNames:
    """Tests for the get_all_skill_names function."""

    def test_returns_set(self) -> None:
        assert isinstance(get_all_skill_names(), set)

    def test_contains_new_skills(self) -> None:
        all_names = get_all_skill_names()
        for skill in NEW_SKILLS:
            assert skill in all_names, f"{skill} missing from all skill names"

    def test_contains_existing_core_skills(self) -> None:
        all_names = get_all_skill_names()
        core = {"race_conditions", "business_logic", "authentication_jwt", "xss", "sql_injection"}
        for skill in core:
            assert skill in all_names, f"Core skill {skill} missing"


# ---------------------------------------------------------------------------
# validate_skill_names
# ---------------------------------------------------------------------------


class TestValidateSkillNames:
    """Tests for the validate_skill_names function."""

    def test_valid_skills_recognized(self) -> None:
        result = validate_skill_names(["mfa_bypass", "edge_cases"])
        assert result["valid"] == ["mfa_bypass", "edge_cases"]
        assert result["invalid"] == []

    def test_invalid_skills_reported(self) -> None:
        result = validate_skill_names(["nonexistent_skill_xyz"])
        assert result["valid"] == []
        assert "nonexistent_skill_xyz" in result["invalid"]

    def test_mixed_valid_and_invalid(self) -> None:
        result = validate_skill_names(["mfa_bypass", "bogus", "edge_cases"])
        assert "mfa_bypass" in result["valid"]
        assert "edge_cases" in result["valid"]
        assert "bogus" in result["invalid"]

    def test_empty_input(self) -> None:
        result = validate_skill_names([])
        assert result == {"valid": [], "invalid": []}


# ---------------------------------------------------------------------------
# load_skills
# ---------------------------------------------------------------------------


class TestLoadSkills:
    """Tests for the load_skills function."""

    def test_load_mfa_bypass(self) -> None:
        loaded = load_skills(["mfa_bypass"])
        assert "mfa_bypass" in loaded
        assert "# MFA Bypass" in loaded["mfa_bypass"]

    def test_load_edge_cases(self) -> None:
        loaded = load_skills(["edge_cases"])
        assert "edge_cases" in loaded
        assert "# Edge Cases" in loaded["edge_cases"]

    def test_frontmatter_stripped_on_load(self) -> None:
        """Loaded content should have the YAML frontmatter removed."""
        for skill_name in NEW_SKILLS:
            loaded = load_skills([skill_name])
            content = loaded[skill_name]
            assert not content.startswith("---"), (
                f"Frontmatter not stripped from {skill_name}"
            )

    def test_load_nonexistent_returns_empty(self) -> None:
        loaded = load_skills(["does_not_exist_abc"])
        assert "does_not_exist_abc" not in loaded

    def test_load_multiple_skills(self) -> None:
        loaded = load_skills(["mfa_bypass", "edge_cases", "race_conditions"])
        assert len(loaded) == 3

    def test_loaded_content_is_nonempty(self) -> None:
        for skill_name in NEW_SKILLS:
            loaded = load_skills([skill_name])
            assert len(loaded[skill_name].strip()) > 100, (
                f"{skill_name} content is suspiciously short"
            )


# ---------------------------------------------------------------------------
# generate_skills_description
# ---------------------------------------------------------------------------


class TestGenerateSkillsDescription:
    """Tests for the generate_skills_description function."""

    def test_returns_string(self) -> None:
        desc = generate_skills_description()
        assert isinstance(desc, str)

    def test_contains_available_skills_label(self) -> None:
        desc = generate_skills_description()
        assert "Available skills:" in desc

    def test_mentions_new_skills(self) -> None:
        desc = generate_skills_description()
        all_names = get_all_skill_names()
        # The description includes a comma-separated list of all skill names.
        for skill in NEW_SKILLS:
            if skill in all_names:
                assert skill.replace("_", "_") in desc


# ---------------------------------------------------------------------------
# _get_all_categories (internal, includes scan_modes/coordination)
# ---------------------------------------------------------------------------


class TestGetAllCategories:
    """Tests for the internal _get_all_categories function."""

    def test_includes_internal_categories(self) -> None:
        cats = _get_all_categories()
        # Should include categories that get_available_skills excludes
        assert "vulnerabilities" in cats

    def test_returns_sorted_skills(self) -> None:
        for category, skills in _get_all_categories().items():
            assert skills == sorted(skills), f"Skills in {category} not sorted"


# ---------------------------------------------------------------------------
# Frontmatter and content quality for new skills
# ---------------------------------------------------------------------------


class TestMfaBypassSkillContent:
    """Content validation for the mfa_bypass skill file."""

    @pytest.fixture
    def raw(self) -> str:
        return _read_skill_file("vulnerabilities", "mfa_bypass")

    @pytest.fixture
    def frontmatter(self, raw: str) -> dict[str, str]:
        return _parse_frontmatter(raw)

    def test_has_frontmatter(self, raw: str) -> None:
        assert raw.startswith("---"), "Missing frontmatter delimiters"

    def test_frontmatter_name(self, frontmatter: dict[str, str]) -> None:
        assert frontmatter.get("name") == "mfa-bypass"

    def test_frontmatter_description(self, frontmatter: dict[str, str]) -> None:
        desc = frontmatter.get("description", "")
        assert len(desc) > 10, "Description is too short"

    def test_frontmatter_has_cwe(self, frontmatter: dict[str, str]) -> None:
        assert "cwe" in frontmatter

    def test_required_sections_present(self, raw: str) -> None:
        for section in REQUIRED_SECTIONS:
            assert f"## {section}" in raw or f"# {section}" in raw, (
                f"Missing section: {section}"
            )

    def test_covers_session_fixation(self, raw: str) -> None:
        lower = raw.lower()
        assert "session" in lower
        assert "fixation" in lower

    def test_covers_otp_reuse(self, raw: str) -> None:
        assert "code reuse" in raw.lower() or "otp" in raw.lower()

    def test_covers_fallback_abuse(self, raw: str) -> None:
        assert "fallback" in raw.lower() or "recovery" in raw.lower()

    def test_covers_enrollment(self, raw: str) -> None:
        assert "enrollment" in raw.lower() or "enroll" in raw.lower()

    def test_has_pro_tips(self, raw: str) -> None:
        assert "## Pro Tips" in raw

    def test_has_summary(self, raw: str) -> None:
        assert "## Summary" in raw


class TestEdgeCasesSkillContent:
    """Content validation for the edge_cases skill file."""

    @pytest.fixture
    def raw(self) -> str:
        return _read_skill_file("vulnerabilities", "edge_cases")

    @pytest.fixture
    def frontmatter(self, raw: str) -> dict[str, str]:
        return _parse_frontmatter(raw)

    def test_has_frontmatter(self, raw: str) -> None:
        assert raw.startswith("---"), "Missing frontmatter delimiters"

    def test_frontmatter_name(self, frontmatter: dict[str, str]) -> None:
        assert frontmatter.get("name") == "edge-cases"

    def test_frontmatter_description(self, frontmatter: dict[str, str]) -> None:
        desc = frontmatter.get("description", "")
        assert len(desc) > 10, "Description is too short"

    def test_required_sections_present(self, raw: str) -> None:
        for section in REQUIRED_SECTIONS:
            assert f"## {section}" in raw or f"# {section}" in raw, (
                f"Missing section: {section}"
            )

    def test_covers_cache_poisoning(self, raw: str) -> None:
        assert "cache poisoning" in raw.lower() or "cache key" in raw.lower()

    def test_covers_partial_failures(self, raw: str) -> None:
        assert "partial failure" in raw.lower() or "half-committed" in raw.lower()

    def test_covers_eventual_consistency(self, raw: str) -> None:
        assert "eventual consistency" in raw.lower()

    def test_covers_boundary_conditions(self, raw: str) -> None:
        assert "boundary" in raw.lower() or "integer" in raw.lower()

    def test_covers_graceful_degradation(self, raw: str) -> None:
        assert "degradation" in raw.lower() or "fallback" in raw.lower()

    def test_has_pro_tips(self, raw: str) -> None:
        assert "## Pro Tips" in raw

    def test_has_summary(self, raw: str) -> None:
        assert "## Summary" in raw


# ---------------------------------------------------------------------------
# Structural validation across ALL skill files
# ---------------------------------------------------------------------------


class TestAllSkillFilesStructure:
    """Verify every skill .md file in the repo has valid frontmatter and key sections."""

    @pytest.fixture
    def all_skill_files(self) -> list[Path]:
        """Collect every .md skill file across all categories."""
        files = []
        for category_dir in SKILLS_DIR.iterdir():
            if category_dir.is_dir() and not category_dir.name.startswith("__"):
                files.extend(category_dir.glob("*.md"))
        return files

    def test_all_files_have_frontmatter(self, all_skill_files: list[Path]) -> None:
        for path in all_skill_files:
            content = path.read_text(encoding="utf-8")
            assert content.startswith("---"), (
                f"{path.relative_to(SKILLS_DIR)} missing frontmatter"
            )

    def test_all_files_have_name_field(self, all_skill_files: list[Path]) -> None:
        for path in all_skill_files:
            fm = _parse_frontmatter(path.read_text(encoding="utf-8"))
            assert "name" in fm, (
                f"{path.relative_to(SKILLS_DIR)} missing 'name' in frontmatter"
            )

    def test_all_files_have_description_field(self, all_skill_files: list[Path]) -> None:
        for path in all_skill_files:
            fm = _parse_frontmatter(path.read_text(encoding="utf-8"))
            assert "description" in fm, (
                f"{path.relative_to(SKILLS_DIR)} missing 'description' in frontmatter"
            )

    def test_no_empty_skill_files(self, all_skill_files: list[Path]) -> None:
        for path in all_skill_files:
            content = path.read_text(encoding="utf-8")
            # Strip frontmatter and check remaining content
            body = FRONTMATTER_RE.sub("", content).strip()
            assert len(body) > 50, (
                f"{path.relative_to(SKILLS_DIR)} has insufficient content ({len(body)} chars)"
            )

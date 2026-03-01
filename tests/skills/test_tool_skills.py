"""Tests for the operator-assisted tool skills in strix/skills/tools/."""

import re

import pytest

from strix.skills import (
    get_all_skill_names,
    get_available_skills,
    load_skills,
    validate_skill_names,
)
from strix.utils.resource_paths import get_strix_resource_path


SKILLS_DIR = get_strix_resource_path("skills")
TOOLS_DIR = SKILLS_DIR / "tools"
FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)

# All 25 tool skill file stems (must match filenames without .md)
TOOL_SKILLS = [
    "nmap",
    "nikto",
    "gobuster",
    "ffuf",
    "theharvester",
    "nuclei",
    "wpscan",
    "metasploit",
    "sqlmap",
    "hydra",
    "beef",
    "set",
    "burp_suite",
    "owasp_zap",
    "wireshark",
    "john_the_ripper",
    "hashcat",
    "netexec",
    "responder",
    "bettercap",
    "bloodhound",
    "ghidra",
    "volatility",
    "aircrack_ng",
    "maltego",
]


def _parse_frontmatter(raw: str) -> dict[str, str]:
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
# Category discovery
# ---------------------------------------------------------------------------


class TestToolsCategoryDiscovery:
    """Verify the tools category is discovered by the skill loader."""

    def test_tools_category_exists(self) -> None:
        available = get_available_skills()
        assert "tools" in available, "tools category not discovered by loader"

    def test_tools_category_has_25_skills(self) -> None:
        available = get_available_skills()
        assert len(available["tools"]) == 25

    def test_all_tool_skills_in_all_names(self) -> None:
        all_names = get_all_skill_names()
        for skill in TOOL_SKILLS:
            assert skill in all_names, f"{skill} not in get_all_skill_names()"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class TestToolSkillValidation:
    """Verify tool skills pass name validation."""

    def test_all_tool_skills_valid(self) -> None:
        result = validate_skill_names(TOOL_SKILLS)
        assert result["invalid"] == [], f"Invalid tool skills: {result['invalid']}"
        assert len(result["valid"]) == 25


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


class TestToolSkillLoading:
    """Verify all tool skills load correctly with frontmatter stripped."""

    @pytest.fixture
    def loaded(self) -> dict[str, str]:
        return load_skills(TOOL_SKILLS)

    def test_all_25_load(self, loaded: dict[str, str]) -> None:
        assert len(loaded) == 25, f"Only {len(loaded)}/25 skills loaded"

    def test_frontmatter_stripped(self, loaded: dict[str, str]) -> None:
        for name, content in loaded.items():
            assert not content.startswith("---"), f"Frontmatter not stripped from {name}"

    def test_content_not_empty(self, loaded: dict[str, str]) -> None:
        for name, content in loaded.items():
            assert len(content.strip()) > 200, f"{name} content suspiciously short"


# ---------------------------------------------------------------------------
# Frontmatter quality
# ---------------------------------------------------------------------------


class TestToolSkillFrontmatter:
    """Verify every tool skill has valid frontmatter with required fields."""

    @pytest.fixture
    def all_tool_files(self) -> list[tuple[str, str]]:
        """Return (stem, raw_content) for each tool skill."""
        return [
            (md.stem, md.read_text(encoding="utf-8"))
            for md in sorted(TOOLS_DIR.glob("*.md"))
        ]

    def test_all_have_frontmatter(self, all_tool_files: list[tuple[str, str]]) -> None:
        for stem, content in all_tool_files:
            assert content.startswith("---"), f"{stem}.md missing frontmatter"

    def test_all_have_name_field(self, all_tool_files: list[tuple[str, str]]) -> None:
        for stem, content in all_tool_files:
            fm = _parse_frontmatter(content)
            assert "name" in fm, f"{stem}.md missing name in frontmatter"

    def test_all_have_description_field(self, all_tool_files: list[tuple[str, str]]) -> None:
        for stem, content in all_tool_files:
            fm = _parse_frontmatter(content)
            assert "description" in fm, f"{stem}.md missing description in frontmatter"
            assert len(fm["description"]) > 20, f"{stem}.md description too short"

    def test_all_have_category_tools(self, all_tool_files: list[tuple[str, str]]) -> None:
        for stem, content in all_tool_files:
            fm = _parse_frontmatter(content)
            assert fm.get("category") == "tools", f"{stem}.md category is not 'tools'"

    def test_all_have_operator_assisted_tag(self, all_tool_files: list[tuple[str, str]]) -> None:
        for stem, content in all_tool_files:
            fm = _parse_frontmatter(content)
            tags = fm.get("tags", "")
            assert "operator-assisted" in tags, f"{stem}.md missing operator-assisted tag"


# ---------------------------------------------------------------------------
# HIL content structure
# ---------------------------------------------------------------------------


class TestToolSkillHILContent:
    """Verify every tool skill has the required operator-assisted workflow sections."""

    @pytest.fixture
    def all_tool_files(self) -> list[tuple[str, str]]:
        return [
            (md.stem, md.read_text(encoding="utf-8"))
            for md in sorted(TOOLS_DIR.glob("*.md"))
        ]

    def test_has_operator_assisted_workflow(self, all_tool_files: list[tuple[str, str]]) -> None:
        for stem, content in all_tool_files:
            assert "operator-assisted workflow" in content.lower(), (
                f"{stem}.md missing Operator-Assisted Workflow section"
            )

    def test_has_key_commands(self, all_tool_files: list[tuple[str, str]]) -> None:
        for stem, content in all_tool_files:
            lower = content.lower()
            has_commands = (
                "## key commands" in lower
                or "## key workflows" in lower
                or "## key transforms" in lower
            )
            assert has_commands, f"{stem}.md missing Key Commands/Workflows/Transforms section"

    def test_has_output_analysis(self, all_tool_files: list[tuple[str, str]]) -> None:
        for stem, content in all_tool_files:
            assert "## output analysis" in content.lower(), (
                f"{stem}.md missing Output Analysis section"
            )

    def test_has_integration_section(self, all_tool_files: list[tuple[str, str]]) -> None:
        for stem, content in all_tool_files:
            assert "## integration with strix" in content.lower(), (
                f"{stem}.md missing Integration with Strix section"
            )

    def test_has_when_to_request(self, all_tool_files: list[tuple[str, str]]) -> None:
        for stem, content in all_tool_files:
            assert "## when to request" in content.lower(), (
                f"{stem}.md missing When to Request section"
            )

    def test_workflow_has_numbered_steps(self, all_tool_files: list[tuple[str, str]]) -> None:
        """Each HIL workflow should have numbered steps (at least 3)."""
        for stem, content in all_tool_files:
            # Count lines starting with a number followed by a period in the workflow section
            workflow_steps = len(re.findall(r"^\d+\.\s", content, re.MULTILINE))
            assert workflow_steps >= 3, (
                f"{stem}.md has fewer than 3 numbered workflow steps ({workflow_steps})"
            )


# ---------------------------------------------------------------------------
# File count sanity check
# ---------------------------------------------------------------------------


class TestToolSkillFileCount:
    """Verify the tools directory has exactly 25 .md files."""

    def test_exactly_25_files(self) -> None:
        md_files = list(TOOLS_DIR.glob("*.md"))
        assert len(md_files) == 25, (
            f"Expected 25 tool skill files, found {len(md_files)}: "
            f"{[f.stem for f in md_files]}"
        )

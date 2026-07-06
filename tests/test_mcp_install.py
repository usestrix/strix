from strix.mcp.install import skill_path


def test_packaged_skill_path_contains_valid_skill() -> None:
    path = skill_path()

    assert path.name == "strix-security"
    assert (path / "SKILL.md").is_file()
    assert (path / "references" / "mcp-tools.md").is_file()

"""Names derived from user targets must stay usable as one path component."""

import pytest

from strix.interface.utils import derive_repo_base_name, sanitize_name


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("repo", "repo"),
        ("coll-uid_1.2", "coll-uid_1.2"),
        ("with space", "with-space"),
        ("a/b", "a-b"),
        ("../escape", "..-escape"),
        ("a..b", "a..b"),
    ],
)
def test_sanitize_name_keeps_usable_names(name: str, expected: str) -> None:
    assert sanitize_name(name) == expected


@pytest.mark.parametrize("name", [".", "..", "...", "", "   "])
def test_sanitize_name_rejects_names_that_are_no_name(name: str) -> None:
    """`.` and `..` are directories: as a path component they leave the caller's directory."""
    assert sanitize_name(name) == "target"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://host/repo.git", "repo"),
        ("git@host:repo.git", "repo"),
        ("https://host/a/..", "target"),
        ("git@host:..", "target"),
    ],
)
def test_derive_repo_base_name_never_returns_a_parent_directory(url: str, expected: str) -> None:
    assert derive_repo_base_name(url) == expected

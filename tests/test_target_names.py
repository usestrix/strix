"""Names derived from user targets must stay usable as one path component."""

import pytest

from strix.interface.utils import (
    assign_workspace_subdirs,
    derive_repo_base_name,
    sanitize_name,
)


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


def test_workspace_subdirs_stay_unique_when_a_base_name_already_carries_a_counter() -> None:
    """`repo`, `repo`, `repo-2` must not give two targets the same directory."""
    targets = [
        {"type": "repository", "details": {"target_repo": "https://host/a/repo"}},
        {"type": "repository", "details": {"target_repo": "https://host/b/repo"}},
        {"type": "repository", "details": {"target_repo": "https://host/c/repo-2"}},
    ]

    assign_workspace_subdirs(targets)

    subdirs = [target["details"]["workspace_subdir"] for target in targets]
    assert subdirs == ["repo", "repo-2", "repo-2-2"]
    assert len(set(subdirs)) == len(subdirs)


def test_workspace_subdirs_keep_the_plain_counter_for_repeated_names() -> None:
    targets = [
        {"type": "repository", "details": {"target_repo": "https://host/a/app"}},
        {"type": "repository", "details": {"target_repo": "https://host/b/app"}},
    ]

    assign_workspace_subdirs(targets)

    assert [target["details"]["workspace_subdir"] for target in targets] == ["app", "app-2"]


def test_a_repository_never_takes_the_spec_directory_name() -> None:
    """stage_api_specs() mounts specs at `api-specs`; a repository of that name would share it."""
    targets = [{"type": "repository", "details": {"target_repo": "https://host/a/api-specs"}}]

    assign_workspace_subdirs(targets)

    assert targets[0]["details"]["workspace_subdir"] == "api-specs-2"

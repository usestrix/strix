"""Names derived from user targets must stay usable as one path component."""

import argparse

import pytest

from strix.core.inputs import build_root_task, build_scan_targets
from strix.interface.scan_setup import attach_workspace_mount
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


def test_a_workspace_mount_does_not_take_a_target_directory(tmp_path) -> None:
    """`--workspace-mount ./app` next to a repository called `app` must not share its subdir."""
    mount = tmp_path / "app"
    mount.mkdir()
    args = argparse.Namespace(
        workspace_mount=str(mount),
        workspace_subdir=None,
        local_sources=[{"source_path": "/clone", "workspace_subdir": "app"}],
    )

    attach_workspace_mount(args)

    assert args.workspace_subdir == "app-2"
    assert args.local_sources[-1]["workspace_subdir"] == "app-2"


def test_three_same_named_targets_render_three_workspace_paths(tmp_path) -> None:
    """The task the agent reads must give each checkout its own path, not just a unique name."""
    clones = []
    for name in ("one", "two", "three"):
        directory = tmp_path / name
        directory.mkdir()
        clones.append(str(directory))

    targets = [
        {
            "type": "repository",
            "original": url,
            "details": {"target_repo": url, "cloned_repo_path": clone},
        }
        for url, clone in zip(
            ("https://host/a/repo", "https://host/b/repo", "https://host/c/repo-2"),
            clones,
            strict=True,
        )
    ]
    assign_workspace_subdirs(targets)
    config = {"targets": targets, "scan_mode": "quick"}

    rendered = build_root_task(config)
    canonical = build_scan_targets(config)

    expected = ["/workspace/repo", "/workspace/repo-2", "/workspace/repo-2-2"]
    assert canonical == expected
    for path in expected:
        assert f"available at: {path}" in rendered

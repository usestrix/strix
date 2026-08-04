"""Tests for how local sources reach the sandbox: bind mounts or manifest upload."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agents.sandbox.entries import LocalDir

from strix.runtime.backends import (
    _BACKENDS,
    _BIND_MOUNT_BACKENDS,
    backend_supports_bind_mounts,
    register_backend,
)
from strix.runtime.session_manager import build_bind_mounts, build_manifest_entries


if TYPE_CHECKING:
    from pathlib import Path


def _source(subdir: str, path: str, *, protect_metadata: bool = False) -> dict[str, Any]:
    return {"source_path": path, "workspace_subdir": subdir, "protect_metadata": protect_metadata}


def test_source_becomes_writable_bind_mount(tmp_path: Path) -> None:
    assert build_bind_mounts([_source("repo", str(tmp_path))]) == [
        {
            "source": str(tmp_path.resolve()),
            "target": "/workspace/repo",
            "read_only": False,
        }
    ]


def test_git_dir_is_remounted_read_only_when_protected(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()

    mounts = build_bind_mounts([_source("repo", str(tmp_path), protect_metadata=True)])

    assert mounts == [
        {"source": str(tmp_path.resolve()), "target": "/workspace/repo", "read_only": False},
        {
            "source": str((tmp_path / ".git").resolve()),
            "target": "/workspace/repo/.git",
            "read_only": True,
        },
    ]


def test_agent_instruction_dirs_are_protected_too(tmp_path: Path) -> None:
    (tmp_path / ".agents").mkdir()
    (tmp_path / ".codex").mkdir()

    mounts = build_bind_mounts([_source("repo", str(tmp_path), protect_metadata=True)])

    assert [(m["target"], m["read_only"]) for m in mounts] == [
        ("/workspace/repo", False),
        ("/workspace/repo/.agents", True),
        ("/workspace/repo/.codex", True),
    ]


def test_worktree_git_pointer_file_is_protected(tmp_path: Path) -> None:
    gitdir = tmp_path / "nested" / "gitdir"
    gitdir.mkdir(parents=True)
    (tmp_path / ".git").write_text(f"gitdir: {gitdir}\n", encoding="utf-8")

    mounts = build_bind_mounts([_source("repo", str(tmp_path), protect_metadata=True)])

    assert [(m["target"], m["read_only"]) for m in mounts] == [
        ("/workspace/repo", False),
        ("/workspace/repo/.git", True),
        ("/workspace/repo/nested/gitdir", True),
    ]


def test_git_pointer_to_a_missing_gitdir_is_not_mounted(tmp_path: Path) -> None:
    (tmp_path / ".git").write_text(f"gitdir: {tmp_path / 'gone'}\n", encoding="utf-8")

    mounts = build_bind_mounts([_source("repo", str(tmp_path), protect_metadata=True)])

    assert [m["target"] for m in mounts] == ["/workspace/repo", "/workspace/repo/.git"]


def test_git_pointer_outside_the_tree_needs_no_nested_mount(tmp_path: Path) -> None:
    tree = tmp_path / "worktree"
    tree.mkdir()
    (tree / ".git").write_text(f"gitdir: {tmp_path / 'main' / '.git'}\n", encoding="utf-8")

    mounts = build_bind_mounts([_source("repo", str(tree), protect_metadata=True)])

    assert [m["target"] for m in mounts] == ["/workspace/repo", "/workspace/repo/.git"]


def test_metadata_symlinked_outside_the_tree_is_not_mounted(tmp_path: Path) -> None:
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    tree = tmp_path / "repo"
    tree.mkdir()
    (tree / ".git").symlink_to(outside, target_is_directory=True)

    mounts = build_bind_mounts([_source("repo", str(tree), protect_metadata=True)])

    assert [m["target"] for m in mounts] == ["/workspace/repo"]


def test_no_git_guard_without_a_git_dir(tmp_path: Path) -> None:
    mounts = build_bind_mounts([_source("repo", str(tmp_path), protect_metadata=True)])
    assert [m["target"] for m in mounts] == ["/workspace/repo"]


def test_clone_keeps_its_git_writable(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    mounts = build_bind_mounts([_source("clone", str(tmp_path), protect_metadata=False)])
    assert [m["target"] for m in mounts] == ["/workspace/clone"]


def test_multiple_sources_each_get_a_mount(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()

    mounts = build_bind_mounts([_source("first", str(first)), _source("second", str(second))])

    assert [m["target"] for m in mounts] == ["/workspace/first", "/workspace/second"]
    assert all(m["read_only"] is False for m in mounts)


def test_incomplete_sources_are_skipped() -> None:
    assert (
        build_bind_mounts(
            [
                {"source_path": "", "workspace_subdir": "x"},
                {"source_path": "/p", "workspace_subdir": ""},
            ]
        )
        == []
    )


def test_manifest_entries_upload_sources_for_backends_without_bind_mounts(
    tmp_path: Path,
) -> None:
    entries = build_manifest_entries([_source("repo", str(tmp_path), protect_metadata=True)])

    assert set(entries) == {"repo"}
    entry = entries["repo"]
    assert isinstance(entry, LocalDir)
    assert entry.src == tmp_path.resolve()


def test_manifest_entries_skip_incomplete_sources() -> None:
    assert (
        build_manifest_entries(
            [
                {"source_path": "", "workspace_subdir": "x"},
                {"source_path": "/p", "workspace_subdir": ""},
            ]
        )
        == {}
    )


def test_only_bind_mount_capable_backends_are_registered_as_such() -> None:
    assert backend_supports_bind_mounts("docker")
    assert not backend_supports_bind_mounts("e2b")

    async def _remote_backend(**_kwargs: Any) -> tuple[Any, Any]:
        return object(), object()

    try:
        register_backend("e2b", _remote_backend)
        assert not backend_supports_bind_mounts("e2b")
        register_backend("e2b", _remote_backend, supports_bind_mounts=True)
        assert backend_supports_bind_mounts("e2b")
    finally:
        _BACKENDS.pop("e2b", None)
        _BIND_MOUNT_BACKENDS.discard("e2b")

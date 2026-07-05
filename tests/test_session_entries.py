"""Tests for local-source handling in session_manager.

Covers splitting copied vs bind-mounted sources (``split_local_sources``) and
the in-memory tar builder (``_build_source_tar``) that replaces the SDK's
per-file ``LocalDir`` copy.
"""

from __future__ import annotations

import io
import os
import tarfile
from typing import TYPE_CHECKING, Any

import pytest

from strix.runtime.session_manager import _build_source_tar, split_local_sources


if TYPE_CHECKING:
    from pathlib import Path


_HAS_SYMLINK = hasattr(os, "symlink")


def _source(subdir: str, path: str, *, mount: bool = False) -> dict[str, Any]:
    return {"source_path": path, "workspace_subdir": subdir, "mount": mount}


def _tar_names(tar_bytes: bytes) -> set[str]:
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r") as tar:
        return set(tar.getnames())


def test_copied_source_is_returned_for_import(tmp_path: Path) -> None:
    copied, bind_mounts = split_local_sources([_source("repo", str(tmp_path))])

    assert bind_mounts == []
    assert copied == [{"source_path": str(tmp_path.resolve()), "workspace_subdir": "repo"}]


def test_mounted_source_becomes_bind_mount(tmp_path: Path) -> None:
    copied, bind_mounts = split_local_sources([_source("repo", str(tmp_path), mount=True)])

    assert copied == []
    assert bind_mounts == [
        {
            "source": str(tmp_path.resolve()),
            "target": "/workspace/repo",
            "read_only": True,
        }
    ]


def test_mixed_sources_split_correctly(tmp_path: Path) -> None:
    copied_dir = tmp_path / "copied"
    mounted_dir = tmp_path / "mounted"
    copied_dir.mkdir()
    mounted_dir.mkdir()

    copied, bind_mounts = split_local_sources(
        [
            _source("copied", str(copied_dir)),
            _source("mounted", str(mounted_dir), mount=True),
        ]
    )

    assert [c["workspace_subdir"] for c in copied] == ["copied"]
    assert [m["target"] for m in bind_mounts] == ["/workspace/mounted"]


def test_incomplete_sources_are_skipped() -> None:
    copied, bind_mounts = split_local_sources(
        [
            {"source_path": "", "workspace_subdir": "x"},
            {"source_path": "/p", "workspace_subdir": ""},
        ]
    )
    assert copied == []
    assert bind_mounts == []


def test_workspace_subdir_slashes_are_stripped(tmp_path: Path) -> None:
    copied, _ = split_local_sources([_source("/repo/", str(tmp_path))])
    assert copied[0]["workspace_subdir"] == "repo"


def test_tar_packs_files_under_arc_prefix(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("a")
    nested = tmp_path / "sub"
    nested.mkdir()
    (nested / "b.txt").write_text("b")

    tar_bytes, added, skipped = _build_source_tar(tmp_path, "repo")

    assert added == 2
    assert skipped == 0
    assert _tar_names(tar_bytes) == {"repo/a.txt", "repo/sub/b.txt"}


def test_tar_preserves_dotfiles_and_git(tmp_path: Path) -> None:
    # .git and other dotfiles must survive so source-aware / git-diff analysis
    # keeps working — unlike a naive "skip hidden" copy.
    (tmp_path / ".env").write_text("SECRET=1")
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "HEAD").write_text("ref: refs/heads/main")

    tar_bytes, added, _ = _build_source_tar(tmp_path, "repo")

    assert added == 2
    assert _tar_names(tar_bytes) == {"repo/.env", "repo/.git/HEAD"}


@pytest.mark.skipif(not _HAS_SYMLINK, reason="requires symlink support")
def test_tar_skips_file_symlinks(tmp_path: Path) -> None:
    (tmp_path / "real.txt").write_text("real")
    (tmp_path / "link.txt").symlink_to(tmp_path / "real.txt")

    tar_bytes, added, skipped = _build_source_tar(tmp_path, "repo")

    assert added == 1
    assert skipped == 1
    assert _tar_names(tar_bytes) == {"repo/real.txt"}


@pytest.mark.skipif(not _HAS_SYMLINK, reason="requires symlink support")
def test_tar_skips_dir_symlinks_without_descending(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret")

    src = tmp_path / "src"
    src.mkdir()
    (src / "keep.txt").write_text("keep")
    (src / "escape").symlink_to(outside)

    tar_bytes, added, skipped = _build_source_tar(src, "repo")

    # The symlinked directory is not followed, so nothing under ``outside``
    # leaks into the tar.
    assert added == 1
    assert skipped == 1
    assert _tar_names(tar_bytes) == {"repo/keep.txt"}


def test_tar_empty_dir_produces_no_files(tmp_path: Path) -> None:
    tar_bytes, added, skipped = _build_source_tar(tmp_path, "repo")
    assert added == 0
    assert skipped == 0
    assert _tar_names(tar_bytes) == set()

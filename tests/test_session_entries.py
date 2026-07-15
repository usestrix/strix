"""Tests for local-source handling in session_manager.

Covers splitting copied vs bind-mounted sources (``split_local_sources``) and
the on-disk tar builder (``_build_source_tar``) that replaces the SDK's
per-file ``LocalDir`` copy.
"""

from __future__ import annotations

import io
import os
import tarfile
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import pytest

from strix.runtime.session_manager import _build_source_tar, split_local_sources


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


_HAS_SYMLINK = hasattr(os, "symlink")


def _source(subdir: str, path: str, *, mount: bool = False) -> dict[str, Any]:
    return {"source_path": path, "workspace_subdir": subdir, "mount": mount}


@contextmanager
def _built_tar(src_root: Path, arc_prefix: str) -> Iterator[tuple[bytes, int, int]]:
    tar_path, added, skipped = _build_source_tar(src_root, arc_prefix)
    try:
        yield tar_path.read_bytes(), added, skipped
    finally:
        tar_path.unlink(missing_ok=True)


def _tar_names(tar_bytes: bytes) -> set[str]:
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r") as tar:
        return set(tar.getnames())


def _tar_file_names(tar_bytes: bytes) -> set[str]:
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r") as tar:
        return {m.name for m in tar.getmembers() if m.isfile()}


def _tar_dir_names(tar_bytes: bytes) -> set[str]:
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r") as tar:
        return {m.name for m in tar.getmembers() if m.isdir()}


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
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    nested = tmp_path / "sub"
    nested.mkdir()
    (nested / "b.txt").write_text("b", encoding="utf-8")

    with _built_tar(tmp_path, "repo") as (tar_bytes, added, skipped):
        assert added == 2
        assert skipped == 0
        assert _tar_file_names(tar_bytes) == {"repo/a.txt", "repo/sub/b.txt"}
        assert {"repo", "repo/sub"} <= _tar_dir_names(tar_bytes)


def test_tar_preserves_dotfiles_and_git(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("SECRET=1", encoding="utf-8")
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "HEAD").write_text("ref: refs/heads/main", encoding="utf-8")

    with _built_tar(tmp_path, "repo") as (tar_bytes, added, _):
        assert added == 2
        assert _tar_file_names(tar_bytes) == {"repo/.env", "repo/.git/HEAD"}


@pytest.mark.skipif(not _HAS_SYMLINK, reason="requires symlink support")
def test_tar_skips_file_symlinks(tmp_path: Path) -> None:
    (tmp_path / "real.txt").write_text("real", encoding="utf-8")
    try:
        (tmp_path / "link.txt").symlink_to(tmp_path / "real.txt")
    except OSError:
        pytest.skip("symlink creation requires elevated privileges on this platform")

    with _built_tar(tmp_path, "repo") as (tar_bytes, added, skipped):
        assert added == 1
        assert skipped == 1
        assert _tar_file_names(tar_bytes) == {"repo/real.txt"}


@pytest.mark.skipif(not _HAS_SYMLINK, reason="requires symlink support")
def test_tar_skips_dir_symlinks_without_descending(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret", encoding="utf-8")

    src = tmp_path / "src"
    src.mkdir()
    (src / "keep.txt").write_text("keep", encoding="utf-8")
    try:
        (src / "escape").symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation requires elevated privileges on this platform")

    with _built_tar(src, "repo") as (tar_bytes, added, skipped):
        assert added == 1
        assert skipped == 1
        assert _tar_file_names(tar_bytes) == {"repo/keep.txt"}
        assert "repo/escape" not in _tar_names(tar_bytes)


def test_tar_preserves_empty_dirs(tmp_path: Path) -> None:
    (tmp_path / "empty").mkdir()
    (tmp_path / "keep.txt").write_text("k", encoding="utf-8")

    with _built_tar(tmp_path, "repo") as (tar_bytes, added, skipped):
        assert added == 1
        assert skipped == 0
        assert _tar_file_names(tar_bytes) == {"repo/keep.txt"}
        assert {"repo", "repo/empty"} <= _tar_dir_names(tar_bytes)


def test_tar_empty_root_still_packs_prefix(tmp_path: Path) -> None:
    with _built_tar(tmp_path, "repo") as (tar_bytes, added, skipped):
        assert added == 0
        assert skipped == 0
        assert _tar_file_names(tar_bytes) == set()
        assert _tar_dir_names(tar_bytes) == {"repo"}


def test_unsafe_workspace_subdir_is_skipped(tmp_path: Path) -> None:
    copied, bind_mounts = split_local_sources(
        [
            _source("../escape", str(tmp_path)),
            _source("ok/../../escape", str(tmp_path)),
        ]
    )
    assert copied == []
    assert bind_mounts == []


def test_unsafe_workspace_subdir_skipped_for_mount(tmp_path: Path) -> None:
    copied, bind_mounts = split_local_sources([_source("../escape", str(tmp_path), mount=True)])
    assert copied == []
    assert bind_mounts == []


def test_tar_raises_on_unreadable_directory(tmp_path: Path) -> None:
    """Unreadable subtrees must fail import, not silently disappear."""
    nested = tmp_path / "secret"
    nested.mkdir()
    (nested / "x.txt").write_text("hidden", encoding="utf-8")

    real_walk = os.walk

    def _walk_boom(
        top: str | os.PathLike[str],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        onerror = kwargs.get("onerror")
        # First yield root so walk has started, then simulate listdir failure
        # on the nested dir by invoking onerror like os.walk would.
        yield from real_walk(top, *args, **kwargs)
        if onerror is not None:
            onerror(PermissionError(13, "Permission denied", str(nested)))

    with (
        patch("strix.runtime.session_manager.os.walk", side_effect=_walk_boom),
        pytest.raises(PermissionError, match="Permission denied"),
    ):
        _build_source_tar(tmp_path, "repo")

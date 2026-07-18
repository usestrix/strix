"""Tests for symlink-safe LocalDir staging."""

from __future__ import annotations

from typing import TYPE_CHECKING

from strix.runtime.local_dir_staging import stage_symlink_safe_dir, tree_has_symlink


if TYPE_CHECKING:
    from pathlib import Path


def _make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "pkg").mkdir(parents=True)
    (repo / "pkg" / "mod.py").write_text("x = 1\n")
    (repo / "README.md").write_text("readme\n")
    return repo


def test_tree_without_symlinks_used_as_is(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)

    upload_path, staged = stage_symlink_safe_dir(repo)

    assert staged is None
    assert upload_path == repo.resolve()
    assert not tree_has_symlink(repo)


def test_in_tree_file_symlink_is_dereferenced(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    (repo / "link.py").symlink_to(repo / "pkg" / "mod.py")

    upload_path, staged = stage_symlink_safe_dir(repo)

    assert staged is not None
    assert upload_path == staged
    assert not (staged / "link.py").is_symlink()
    assert (staged / "link.py").read_text() == "x = 1\n"
    assert (staged / "pkg" / "mod.py").read_text() == "x = 1\n"
    assert not tree_has_symlink(staged)


def test_in_tree_relative_dir_symlink_is_dereferenced(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    (repo / "pkg_alias").symlink_to("pkg")

    _upload, staged = stage_symlink_safe_dir(repo)

    assert staged is not None
    assert (staged / "pkg_alias" / "mod.py").read_text() == "x = 1\n"
    assert not tree_has_symlink(staged)


def test_out_of_tree_symlink_is_dropped(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("secret\n")
    (repo / "escape.txt").symlink_to(outside)
    (repo / "abs_escape").symlink_to("/etc")

    _upload, staged = stage_symlink_safe_dir(repo)

    assert staged is not None
    assert not (staged / "escape.txt").exists()
    assert not (staged / "abs_escape").exists()
    assert (staged / "README.md").exists()


def test_dangling_symlink_is_dropped(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    (repo / "dangling").symlink_to(repo / "does-not-exist")

    _upload, staged = stage_symlink_safe_dir(repo)

    assert staged is not None
    assert not (staged / "dangling").exists()
    assert not (staged / "dangling").is_symlink()


def test_cyclic_symlink_terminates(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    (repo / "self").symlink_to(repo)
    (repo / "pkg" / "up").symlink_to("..")

    _upload, staged = stage_symlink_safe_dir(repo)

    assert staged is not None
    assert (staged / "README.md").exists()
    assert not tree_has_symlink(staged)


def test_nested_symlinks_inside_linked_dir(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    shared = repo / "shared"
    shared.mkdir()
    (shared / "conf.json").write_text("{}\n")
    (shared / "escape").symlink_to("/etc/passwd")
    (repo / "pkg" / "shared_link").symlink_to(shared)

    _upload, staged = stage_symlink_safe_dir(repo)

    assert staged is not None
    assert (staged / "pkg" / "shared_link" / "conf.json").read_text() == "{}\n"
    assert not (staged / "pkg" / "shared_link" / "escape").exists()
    assert not (staged / "shared" / "escape").exists()

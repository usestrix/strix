"""Tests for local-source collection and mount policy in interface.utils."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from strix.interface.utils import (
    check_mountable_dir,
    collect_local_sources,
    dedupe_local_targets,
    infer_target_type,
    read_target_list_file,
)


def _local_target(target_path: str) -> dict[str, Any]:
    return {
        "type": "local_code",
        "details": {"target_path": target_path, "workspace_subdir": "repo"},
        "original": target_path,
    }


def test_collect_local_sources_protects_the_users_own_git() -> None:
    sources = collect_local_sources([_local_target("/code")])
    assert sources == [
        {"source_path": "/code", "workspace_subdir": "repo", "protect_metadata": True}
    ]


def test_collect_local_sources_leaves_a_clone_writable() -> None:
    repo = {
        "type": "repository",
        "details": {"cloned_repo_path": "/clone", "workspace_subdir": "clone"},
    }
    sources = collect_local_sources([repo])
    assert sources == [
        {"source_path": "/clone", "workspace_subdir": "clone", "protect_metadata": False}
    ]


def test_check_mountable_dir_accepts_a_project_dir(tmp_path: Path) -> None:
    check_mountable_dir(tmp_path)


def test_check_mountable_dir_rejects_missing_path(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not an existing directory"):
        check_mountable_dir(tmp_path / "nope")


def test_check_mountable_dir_rejects_filesystem_root() -> None:
    with pytest.raises(ValueError, match="Refusing to mount"):
        check_mountable_dir(Path("/"))


def test_check_mountable_dir_rejects_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: home))

    with pytest.raises(ValueError, match="Refusing to mount"):
        check_mountable_dir(home)


def test_check_mountable_dir_rejects_system_root() -> None:
    etc = Path("/etc")
    if not etc.is_dir():
        pytest.skip("no /etc on this platform")
    with pytest.raises(ValueError, match="Refusing to mount"):
        check_mountable_dir(etc)


def test_check_mountable_dir_rejects_the_shared_home_root() -> None:
    home_root = Path("/home")
    if not home_root.is_dir():
        pytest.skip("no /home on this platform")
    with pytest.raises(ValueError, match="Refusing to mount"):
        check_mountable_dir(home_root)


def test_check_mountable_dir_matches_forbidden_names_case_insensitively(tmp_path: Path) -> None:
    ssh_dir = tmp_path / ".SSH"
    ssh_dir.mkdir()

    with pytest.raises(ValueError, match="holds credentials"):
        check_mountable_dir(ssh_dir)


def test_check_mountable_dir_rejects_credential_dirs(tmp_path: Path) -> None:
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()

    with pytest.raises(ValueError, match="holds credentials"):
        check_mountable_dir(ssh_dir)


def test_check_mountable_dir_rejects_credential_subdirs(tmp_path: Path) -> None:
    keys = tmp_path / ".ssh" / "keys"
    keys.mkdir(parents=True)

    with pytest.raises(ValueError, match="holds credentials"):
        check_mountable_dir(keys)


def test_check_mountable_dir_rejects_system_subdirs() -> None:
    system_subdir = next((p for p in (Path("/etc/ssl"), Path("/usr/bin")) if p.is_dir()), None)
    if system_subdir is None:
        pytest.skip("no system subdirectory on this platform")
    with pytest.raises(ValueError, match="Refusing to mount"):
        check_mountable_dir(system_subdir)


def test_check_mountable_dir_accepts_a_project_under_the_home_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "home" / "dev" / "project"
    project.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: tmp_path / "home" / "dev"))

    check_mountable_dir(project)


def test_infer_target_type_applies_the_mount_policy() -> None:
    with pytest.raises(ValueError, match="Refusing to mount"):
        infer_target_type("/etc")


def test_read_target_list_file_strips_blank_lines(tmp_path: Path) -> None:
    target_list = tmp_path / "targets.txt"
    target_list.write_text(
        "\n https://test1.com/ \n\nhttp://test2.com:5789/\n  \n",
        encoding="utf-8",
    )

    assert read_target_list_file(str(target_list)) == [
        "https://test1.com/",
        "http://test2.com:5789/",
    ]


def test_read_target_list_file_ignores_comment_lines(tmp_path: Path) -> None:
    target_list = tmp_path / "targets.txt"
    target_list.write_text(
        "# production targets\nhttps://test1.com/\n  # staging targets\nhttp://test2.com:5789/\n",
        encoding="utf-8",
    )

    assert read_target_list_file(str(target_list)) == [
        "https://test1.com/",
        "http://test2.com:5789/",
    ]


def test_read_target_list_file_rejects_empty_file(tmp_path: Path) -> None:
    target_list = tmp_path / "targets.txt"
    target_list.write_text(" \n# no targets yet\n\n", encoding="utf-8")

    with pytest.raises(ValueError, match="is empty"):
        read_target_list_file(str(target_list))


def test_read_target_list_file_rejects_missing_path(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not an existing file"):
        read_target_list_file(str(tmp_path / "missing.txt"))


def test_read_target_list_file_rejects_non_utf8_file(tmp_path: Path) -> None:
    target_list = tmp_path / "targets.txt"
    target_list.write_bytes(b"https://test1.com/\xff\n")

    with pytest.raises(ValueError, match="must be valid UTF-8 text"):
        read_target_list_file(str(target_list))


@pytest.mark.parametrize("empty", ["", "   "])
def test_read_target_list_file_rejects_empty_path(empty: str) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        read_target_list_file(empty)


def test_dedupe_keeps_distinct_targets_in_order() -> None:
    targets = [
        _local_target("/a"),
        {"type": "web_application", "details": {"target_url": "https://x"}},
        _local_target("/b"),
    ]
    assert dedupe_local_targets(targets) == targets


def test_dedupe_collapses_the_same_path() -> None:
    assert dedupe_local_targets([_local_target("/repo"), _local_target("/repo")]) == [
        _local_target("/repo")
    ]

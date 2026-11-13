"""Tests for clone_repository, infer_target_type, and sanitization in strix.interface.utils."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest

from strix.interface.utils import (
    assign_workspace_subdirs,
    clone_repository,
    derive_repo_base_name,
    infer_target_type,
    sanitize_name,
)


if TYPE_CHECKING:
    from pathlib import Path


def test_clone_repository_includes_double_dash_separator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/git" if cmd == "git" else None)

    mock_run = MagicMock()
    with patch("subprocess.run", mock_run):
        res = clone_repository("https://github.com/example/test-repo.git", "run_123")

    expected_path = tmp_path / "strix_repos" / "run_123" / "test-repo"
    assert res == str(expected_path.resolve())
    mock_run.assert_called_once_with(
        [
            "/usr/bin/git",
            "clone",
            "--",
            "https://github.com/example/test-repo.git",
            str(expected_path),
        ],
        capture_output=True,
        text=True,
        check=True,
    )


def test_clone_repository_rejects_leading_dash_url() -> None:
    with pytest.raises(ValueError, match="Repository URL cannot start with a dash"):
        clone_repository("-u/upload-pack.git", "run_123")

    with pytest.raises(ValueError, match="Repository URL cannot start with a dash"):
        clone_repository("--upload-pack=touch /tmp/pwn", "run_123")


def test_clone_repository_rejects_invalid_dest_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/git" if cmd == "git" else None)

    with pytest.raises(ValueError, match="Invalid repository destination name"):
        clone_repository("https://example.com/repo.git", "run_123", dest_name="..")

    with pytest.raises(ValueError, match="Invalid repository destination name"):
        clone_repository("https://example.com/repo.git", "run_123", dest_name=".")

    with pytest.raises(ValueError, match="Invalid repository destination name"):
        clone_repository("https://example.com/repo.git", "run_123", dest_name="-dashed")

    with pytest.raises(ValueError, match="Invalid repository destination name"):
        clone_repository("https://example.com/repo.git", "run_123", dest_name="sub/dir")


def test_infer_target_type_rejects_leading_dash() -> None:
    with pytest.raises(ValueError, match="Targets cannot start with a dash"):
        infer_target_type("-u/upload-pack.git")

    with pytest.raises(ValueError, match="Targets cannot start with a dash"):
        infer_target_type("--target-flag")


def test_sanitize_name_strips_leading_dots_and_dashes() -> None:
    assert sanitize_name("..") == "target"
    assert sanitize_name(".") == "target"
    assert sanitize_name("-dashed") == "dashed"
    assert sanitize_name(".hidden") == "hidden"
    assert sanitize_name("normal_repo-1") == "normal_repo-1"


def test_derive_repo_base_name_handles_dot_git() -> None:
    assert derive_repo_base_name("..git") == "target"
    assert derive_repo_base_name("https://github.com/foo/bar.git") == "bar"
    assert derive_repo_base_name("git@github.com:foo/bar.git") == "bar"


def test_clone_repository_rejects_symlink_pointing_outside_temp_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/git" if cmd == "git" else None)

    outside_dir = tmp_path / "sensitive_outside_directory"
    outside_dir.mkdir(parents=True)
    canary_file = outside_dir / "canary.txt"
    canary_file.write_text("critical data", encoding="utf-8")

    run_temp_dir = tmp_path / "strix_repos" / "run_123"
    run_temp_dir.mkdir(parents=True)
    symlink_dest = run_temp_dir / "external_symlink"
    symlink_dest.symlink_to(outside_dir)

    mock_run = MagicMock()
    with (
        patch("subprocess.run", mock_run),
        pytest.raises(ValueError, match="Invalid clone path outside temporary directory"),
    ):
        clone_repository(
            "https://example.com/repo.git",
            "run_123",
            dest_name="external_symlink",
        )

    # Verify external directory and canary were not touched by shutil.rmtree
    assert outside_dir.exists()
    assert canary_file.exists()
    assert canary_file.read_text(encoding="utf-8") == "critical data"
    mock_run.assert_not_called()


def test_assign_workspace_subdirs_avoids_collisions_with_generated_suffixes() -> None:
    targets_info: list[dict[str, Any]] = [
        {"type": "repository", "details": {"target_repo": "https://example.com/foo.git"}},
        {"type": "repository", "details": {"target_repo": "https://example.com/.foo.git"}},
        {"type": "repository", "details": {"target_repo": "https://example.com/foo-2.git"}},
    ]
    assign_workspace_subdirs(targets_info)
    subdirs = [t["details"]["workspace_subdir"] for t in targets_info]
    assert len(subdirs) == len(set(subdirs)), f"Collisions found: {subdirs}"
    assert subdirs == ["foo", "foo-2", "foo-2-2"]

    # Also verify repeated names increment cleanly
    repeated_targets: list[dict[str, Any]] = [
        {"type": "repository", "details": {"target_repo": "https://example.com/bar.git"}},
        {"type": "repository", "details": {"target_repo": "https://example.com/bar.git"}},
        {"type": "repository", "details": {"target_repo": "https://example.com/bar.git"}},
    ]
    assign_workspace_subdirs(repeated_targets)
    repeated_subdirs = [t["details"]["workspace_subdir"] for t in repeated_targets]
    assert repeated_subdirs == ["bar", "bar-2", "bar-3"]

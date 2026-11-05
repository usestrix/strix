"""Automatic diff-scope must compare complete Git branch names."""

from __future__ import annotations

import shutil
import subprocess
from typing import TYPE_CHECKING

import pytest

from strix.interface.utils import resolve_diff_scope_context


if TYPE_CHECKING:
    from pathlib import Path


def _git(repo: Path, *args: str) -> str:
    executable = shutil.which("git")
    assert executable is not None
    return subprocess.run(  # noqa: S603 - only synthetic test arguments are passed to Git.
        [executable, "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _commit(repo: Path) -> None:
    _git(repo, "add", ".")
    _git(
        repo,
        "-c",
        "user.name=Regression Test",
        "-c",
        "user.email=test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-m",
        "Add synthetic source",
    )


def _default_branch_repo(repo: Path, branch: str) -> list[dict[str, str]]:
    _git(repo, "init", "-b", branch)
    (repo / "app.py").write_text('print("synthetic")\n', encoding="utf-8")
    _commit(repo)
    remote_ref = f"refs/remotes/origin/{branch}"
    _git(repo, "update-ref", remote_ref, "HEAD")
    _git(repo, "symbolic-ref", "refs/remotes/origin/HEAD", remote_ref)
    return [{"source_path": str(repo), "workspace_subdir": "app"}]


@pytest.mark.parametrize("branch", ["main", "release/stable", "release/lts/stable"])
def test_auto_scope_stays_inactive_on_the_default_branch(tmp_path: Path, branch: str) -> None:
    sources = _default_branch_repo(tmp_path, branch)

    result = resolve_diff_scope_context(
        sources, scope_mode="auto", diff_base=None, non_interactive=True, env={"CI": "true"}
    )

    assert result.active is False
    assert result.metadata == {"active": False, "mode": "auto"}


@pytest.mark.parametrize("branch", ["main", "release/stable"])
def test_auto_scope_still_activates_on_feature_branches(tmp_path: Path, branch: str) -> None:
    sources = _default_branch_repo(tmp_path, branch)
    _git(tmp_path, "switch", "-c", "feature/auth-fix")
    (tmp_path / "auth.py").write_text('print("changed")\n', encoding="utf-8")
    _commit(tmp_path)

    result = resolve_diff_scope_context(
        sources, scope_mode="auto", diff_base=None, non_interactive=True, env={"CI": "true"}
    )

    assert result.active is True
    assert result.metadata["total_analyzable_files"] == 1
    assert result.metadata["repos"][0]["analyzable_files"] == ["auth.py"]


def test_branch_sharing_the_default_branch_suffix_is_still_a_feature_branch(tmp_path: Path) -> None:
    sources = _default_branch_repo(tmp_path, "release/stable")
    _git(tmp_path, "switch", "-c", "stable")
    (tmp_path / "auth.py").write_text('print("changed")\n', encoding="utf-8")
    _commit(tmp_path)

    result = resolve_diff_scope_context(
        sources, scope_mode="auto", diff_base=None, non_interactive=True, env={"CI": "true"}
    )

    assert result.active is True
    assert result.metadata["total_analyzable_files"] == 1

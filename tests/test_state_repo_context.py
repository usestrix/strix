"""Tests for SARIF repository-context derivation in strix.report.state."""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

from strix.report.state import ReportState, _parse_repo_full_name


if TYPE_CHECKING:
    from pathlib import Path


def test_parse_repo_full_name_handles_common_forms() -> None:
    assert _parse_repo_full_name("https://github.com/acme/widget") == "acme/widget"
    assert _parse_repo_full_name("https://github.com/acme/widget.git") == "acme/widget"
    assert _parse_repo_full_name("git@github.com:acme/widget.git") == "acme/widget"
    assert _parse_repo_full_name("acme/widget") == "acme/widget"
    assert _parse_repo_full_name("") is None
    assert _parse_repo_full_name("nothost") is None


def test_repository_context_none_for_non_repository_targets() -> None:
    state = ReportState(run_name="t")
    state.run_record["targets_info"] = [
        {"type": "web_application", "details": {"target_url": "https://example.com"}}
    ]
    assert state._sarif_repository_context() is None


def test_repository_context_uri_only_without_clone() -> None:
    state = ReportState(run_name="t")
    state.run_record["targets_info"] = [
        {"type": "repository", "details": {"target_repo": "https://github.com/acme/widget"}}
    ]
    ctx = state._sarif_repository_context()
    assert ctx == {
        "repositoryUri": "https://github.com/acme/widget",
        "repositoryFullName": "acme/widget",
    }


def test_repository_context_none_for_multiple_repository_targets() -> None:
    state = ReportState(run_name="t")
    state.run_record["targets_info"] = [
        {"type": "repository", "details": {"target_repo": "https://github.com/acme/widget"}},
        {"type": "repository", "details": {"target_repo": "https://github.com/acme/api"}},
    ]
    assert state._sarif_repository_context() is None


def test_repository_context_derives_commit_and_branch_from_clone(tmp_path: Path) -> None:
    repo = tmp_path / "widget"
    repo.mkdir()

    def _git(*args: str) -> None:
        subprocess.run(  # noqa: S603
            ["git", "-C", str(repo), *args],  # noqa: S607
            check=True,
            capture_output=True,
        )

    _git("init", "-b", "main")
    _git("config", "user.email", "t@example.com")
    _git("config", "user.name", "Test")
    (repo / "README.md").write_text("hi", encoding="utf-8")
    _git("add", "README.md")
    _git("commit", "-m", "init")

    head = subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), "rev-parse", "HEAD"],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    state = ReportState(run_name="t")
    state.run_record["targets_info"] = [
        {
            "type": "repository",
            "details": {
                "target_repo": "https://github.com/acme/widget",
                "cloned_repo_path": str(repo),
            },
        }
    ]
    ctx = state._sarif_repository_context()
    assert ctx is not None
    assert ctx["repositoryUri"] == "https://github.com/acme/widget"
    assert ctx["repositoryFullName"] == "acme/widget"
    assert ctx["commitSha"] == head
    assert ctx["branch"] == "main"
    assert ctx["ref"] == "refs/heads/main"

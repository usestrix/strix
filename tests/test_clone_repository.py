"""Tests for clone_repository in strix.interface.utils."""

from __future__ import annotations

import argparse
import subprocess
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest

from strix.interface.scan_setup import prepare_run
from strix.interface.utils import (
    DEFAULT_GIT_CLONE_TIMEOUT_SECONDS,
    clone_repository,
)


if TYPE_CHECKING:
    from pathlib import Path


def test_clone_repository_default_settings_timeout(
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
        ["/usr/bin/git", "clone", "https://github.com/example/test-repo.git", str(expected_path)],
        capture_output=True,
        text=True,
        check=True,
        timeout=DEFAULT_GIT_CLONE_TIMEOUT_SECONDS,
    )


def test_clone_repository_env_var_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/git" if cmd == "git" else None)
    monkeypatch.setattr(
        "strix.interface.utils.load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(git_clone_timeout=600)),
    )

    mock_run = MagicMock()
    with patch("subprocess.run", mock_run):
        res = clone_repository("https://github.com/example/test-repo.git", "run_123")

    expected_path = tmp_path / "strix_repos" / "run_123" / "test-repo"
    assert res == str(expected_path.resolve())
    mock_run.assert_called_once_with(
        ["/usr/bin/git", "clone", "https://github.com/example/test-repo.git", str(expected_path)],
        capture_output=True,
        text=True,
        check=True,
        timeout=600.0,
    )


def test_clone_repository_disabled_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/git" if cmd == "git" else None)

    mock_run = MagicMock()
    with patch("subprocess.run", mock_run):
        res = clone_repository("https://github.com/example/test-repo.git", "run_123", timeout=0)

    expected_path = tmp_path / "strix_repos" / "run_123" / "test-repo"
    assert res == str(expected_path.resolve())
    mock_run.assert_called_once_with(
        ["/usr/bin/git", "clone", "https://github.com/example/test-repo.git", str(expected_path)],
        capture_output=True,
        text=True,
        check=True,
        timeout=None,
    )


def test_clone_repository_custom_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/git" if cmd == "git" else None)

    mock_run = MagicMock()
    with patch("subprocess.run", mock_run):
        res = clone_repository(
            "https://github.com/example/test-repo.git",
            "run_123",
            dest_name="custom_dest",
            timeout=45.0,
        )

    expected_path = tmp_path / "strix_repos" / "run_123" / "custom_dest"
    assert res == str(expected_path.resolve())
    mock_run.assert_called_once_with(
        ["/usr/bin/git", "clone", "https://github.com/example/test-repo.git", str(expected_path)],
        capture_output=True,
        text=True,
        check=True,
        timeout=45.0,
    )


def test_clone_repository_timeout_expired(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/git" if cmd == "git" else None)

    def _mock_timeout(*_args: object, **_kwargs: object) -> None:
        clone_dir = tmp_path / "strix_repos" / "run_123" / "slow-repo"
        clone_dir.mkdir(parents=True, exist_ok=True)
        (clone_dir / "partial_file.txt").write_text("partial", encoding="utf-8")
        raise subprocess.TimeoutExpired(cmd="git clone", timeout=30.0)

    with (
        patch("subprocess.run", side_effect=_mock_timeout),
        pytest.raises(
            ValueError,
            match=r"Cloning repository .* timed out after 30s.*--git-clone-timeout",
        ),
    ):
        clone_repository(
            "https://github.com/example/slow-repo.git",
            "run_123",
            timeout=30.0,
        )

    # Check partial clone dir is cleaned up on timeout
    clone_dir = tmp_path / "strix_repos" / "run_123" / "slow-repo"
    assert not clone_dir.exists()


def test_clone_repository_called_process_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/git" if cmd == "git" else None)

    with (
        patch(
            "subprocess.run",
            side_effect=subprocess.CalledProcessError(
                returncode=128, cmd="git clone", stderr="fatal: repository not found"
            ),
        ),
        pytest.raises(ValueError, match=r"fatal: repository not found"),
    ):
        clone_repository("https://github.com/example/missing.git", "run_123")


def test_clone_repository_git_not_found(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr("shutil.which", lambda _cmd: None)

    with pytest.raises(FileNotFoundError, match="Git executable not found"):
        clone_repository("https://github.com/example/repo.git", "run_123")


def test_prepare_run_passes_git_clone_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    target_info: dict[str, Any] = {
        "type": "repository",
        "details": {"target_repo": "https://github.com/example/repo.git"},
    }
    args = argparse.Namespace(
        resume=None,
        targets_info=[target_info],
        run_name=None,
        git_clone_timeout=450,
        scope_mode="auto",
        diff_base=None,
        non_interactive=True,
        instruction=None,
    )

    mock_clone = MagicMock(return_value="/cloned/path")
    monkeypatch.setattr("strix.interface.scan_setup.clone_repository", mock_clone)
    monkeypatch.setattr("strix.interface.scan_setup.collect_local_sources", lambda _t: [])
    monkeypatch.setattr("strix.interface.scan_setup.stage_api_specs", lambda _t, _r: [])
    monkeypatch.setattr(
        "strix.interface.scan_setup.resolve_diff_scope_context",
        lambda **_kwargs: SimpleNamespace(metadata={"active": False}, instruction_block=None),
    )
    monkeypatch.setattr("strix.interface.scan_setup.attach_workspace_mount", lambda _a: None)
    monkeypatch.setattr("strix.interface.scan_setup._persist_run_record", lambda _a: None)

    prepare_run(args)

    mock_clone.assert_called_once_with(
        "https://github.com/example/repo.git", args.run_name, None, timeout=450
    )
    assert target_info["details"]["cloned_repo_path"] == "/cloned/path"

"""STRIX_MOUNT_READONLY binds local targets read-only.

For review/localization scans the agent must inspect, not modify, the code under
review. A read-only mount makes write/patch/delete physically impossible, so an
agent can't wipe or "fix" the target instead of reporting on it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from strix.interface.utils import collect_local_sources


if TYPE_CHECKING:
    import pytest


def _local_code() -> list[dict]:
    return [{"type": "local_code", "details": {"target_path": "/work/x", "workspace_subdir": "x"}}]


def _repo() -> list[dict]:
    details = {"cloned_repo_path": "/work/r", "workspace_subdir": "r"}
    return [{"type": "repository", "details": details}]


def test_default_is_writable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_MOUNT_READONLY", raising=False)
    assert collect_local_sources(_local_code())[0]["read_only"] is False
    assert collect_local_sources(_repo())[0]["read_only"] is False


def test_env_forces_read_only(monkeypatch: pytest.MonkeyPatch) -> None:
    for val in ("1", "true", "yes", "on"):
        monkeypatch.setenv("STRIX_MOUNT_READONLY", val)
        assert collect_local_sources(_local_code())[0]["read_only"] is True, val
        assert collect_local_sources(_repo())[0]["read_only"] is True, val


def test_off_values_stay_writable(monkeypatch: pytest.MonkeyPatch) -> None:
    for val in ("", "0", "false", "no"):
        monkeypatch.setenv("STRIX_MOUNT_READONLY", val)
        assert collect_local_sources(_local_code())[0]["read_only"] is False, val


def test_per_target_read_only_still_honored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_MOUNT_READONLY", raising=False)
    ti = [{"type": "local_code", "details": {"target_path": "/work/x", "read_only": True}}]
    assert collect_local_sources(ti)[0]["read_only"] is True

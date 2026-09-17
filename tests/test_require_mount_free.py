"""STRIX_REQUIRE_MOUNT_FREE: local sources reach the sandbox without a host bind mount.

With the flag set, ``create_or_reuse`` must hand the docker backend an empty
``bind_mounts`` list and upload sources as ``LocalDir`` / ``File`` manifest
entries instead, and must refuse to start if a bind mount would still be used.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from agents.sandbox.entries import File, LocalDir

from strix.config import loader
from strix.core.inputs import build_root_task
from strix.runtime import backends, session_manager


if TYPE_CHECKING:
    from pathlib import Path


class _BackendReachedError(Exception):
    """Raised by the stub backend so the test stops before the Caido bootstrap."""


@pytest.fixture
def backend_calls(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Swap the docker backend for a stub that records what it was handed."""
    calls: list[dict[str, Any]] = []

    async def _stub(**kwargs: Any) -> tuple[Any, Any]:
        calls.append(kwargs)
        raise _BackendReachedError

    monkeypatch.setitem(backends._BACKENDS, "docker", _stub)
    monkeypatch.delenv("STRIX_RUNTIME_BACKEND", raising=False)
    monkeypatch.setattr(loader, "_cached", None)
    return calls


def _set_flag(monkeypatch: pytest.MonkeyPatch, value: str | None) -> None:
    if value is None:
        monkeypatch.delenv("STRIX_REQUIRE_MOUNT_FREE", raising=False)
    else:
        monkeypatch.setenv("STRIX_REQUIRE_MOUNT_FREE", value)
    monkeypatch.setattr(loader, "_cached", None)


async def _create(tmp_path: Path, scan_id: str) -> None:
    with pytest.raises(_BackendReachedError):
        await session_manager.create_or_reuse(
            scan_id,
            image="strix-sandbox:test",
            local_sources=[
                {
                    "workspace_subdir": "repo",
                    "source_path": str(tmp_path),
                    "protect_metadata": True,
                }
            ],
            extra_files=[{"workspace_path": "/workspace/notes.txt", "content": "hi"}],
        )


@pytest.mark.asyncio
async def test_docker_gets_no_bind_mounts_when_mount_free_is_required(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backend_calls: list[dict[str, Any]]
) -> None:
    (tmp_path / ".git").mkdir()
    _set_flag(monkeypatch, "true")

    await _create(tmp_path, "scan-mount-free")

    (call,) = backend_calls
    assert call["bind_mounts"] == []
    entries = call["manifest"].entries
    assert isinstance(entries["repo"], LocalDir)
    assert entries["repo"].src == tmp_path.resolve()
    assert isinstance(entries["notes.txt"], File)


@pytest.mark.asyncio
async def test_docker_still_bind_mounts_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backend_calls: list[dict[str, Any]]
) -> None:
    _set_flag(monkeypatch, None)

    await _create(tmp_path, "scan-default-transport")

    (call,) = backend_calls
    assert call["manifest"].entries == {}
    sources = {mount["source"] for mount in call["bind_mounts"]}
    assert str(tmp_path.resolve()) in sources


def test_a_bind_mount_is_refused_when_mount_free_is_required(tmp_path: Path) -> None:
    session_manager._refuse_bind_mounts([])

    leaked = [{"source": str(tmp_path), "target": "/workspace/repo", "read_only": False}]
    with pytest.raises(RuntimeError, match="STRIX_REQUIRE_MOUNT_FREE"):
        session_manager._refuse_bind_mounts(leaked)


def test_agent_is_told_the_directory_is_a_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    scan_config = {
        "targets": [
            {
                "type": "local_code",
                "details": {"target_path": "/src/app", "workspace_subdir": "app"},
            }
        ]
    }

    _set_flag(monkeypatch, "true")
    mount_free = build_root_task(scan_config)
    _set_flag(monkeypatch, None)
    default = build_root_task(scan_config)

    assert "snapshot" in mount_free
    assert "mounted live" not in mount_free
    assert "mounted live and writable" in default

"""Unit tests for tar-based local source import (no live Docker required)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from strix.runtime import session_manager


class _FakeExecResult:
    def __init__(self, exit_code: int = 0, output: bytes = b"") -> None:
        self.exit_code = exit_code
        self.output = output


class _FakeContainer:
    def __init__(
        self,
        *,
        put_ok: bool = True,
        chown_exit: int = 0,
        config_user: str = "pentester",
        pentester_exists: bool = True,
    ) -> None:
        self.put_ok = put_ok
        self.chown_exit = chown_exit
        self.pentester_exists = pentester_exists
        self.attrs = {"Config": {"User": config_user}}
        self.put_calls: list[tuple[str, bytes]] = []
        self.exec_calls: list[list[str]] = []

    def put_archive(self, path: str, data: Any) -> bool:
        payload = data.read() if hasattr(data, "read") else data
        self.put_calls.append((path, payload))
        return self.put_ok

    def exec_run(self, cmd: list[str], user: str = "root") -> _FakeExecResult:  # noqa: ARG002
        self.exec_calls.append(list(cmd))
        if cmd and cmd[0] == "chown":
            return _FakeExecResult(self.chown_exit, b"chown failed" if self.chown_exit else b"")
        # Probe: id -u pentester ...
        joined = " ".join(cmd)
        if "id -u pentester" in joined:
            if self.pentester_exists:
                return _FakeExecResult(0, b"pentester")
            return _FakeExecResult(1, b"")
        return _FakeExecResult(0, b"")


def _session_with(container: Any) -> SimpleNamespace:
    return SimpleNamespace(_inner=SimpleNamespace(_container=container))


@pytest.mark.asyncio
async def test_import_local_sources_put_archive_and_chown(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("hello", encoding="utf-8")
    container = _FakeContainer()
    session = _session_with(container)

    await session_manager._import_local_sources(
        session,
        [{"source_path": str(tmp_path), "workspace_subdir": "repo"}],
    )

    assert len(container.put_calls) == 1
    path, payload = container.put_calls[0]
    assert path == "/workspace"
    assert payload  # non-empty tar
    assert any(cmd[0] == "mkdir" for cmd in container.exec_calls)
    chown_cmds = [cmd for cmd in container.exec_calls if cmd[0] == "chown"]
    assert chown_cmds == [
        ["chown", "-R", "pentester:pentester", "/workspace/repo"],
    ]


@pytest.mark.asyncio
async def test_import_local_sources_raises_on_put_failure(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("hello", encoding="utf-8")
    container = _FakeContainer(put_ok=False)
    session = _session_with(container)

    with pytest.raises(RuntimeError, match="put_archive failed"):
        await session_manager._import_local_sources(
            session,
            [{"source_path": str(tmp_path), "workspace_subdir": "repo"}],
        )


@pytest.mark.asyncio
async def test_import_continues_when_chown_fails(tmp_path: Path) -> None:
    """Custom images / missing users must not abort import after put_archive."""
    (tmp_path / "a.txt").write_text("hello", encoding="utf-8")
    container = _FakeContainer(chown_exit=1)
    session = _session_with(container)

    await session_manager._import_local_sources(
        session,
        [{"source_path": str(tmp_path), "workspace_subdir": "repo"}],
    )

    assert len(container.put_calls) == 1
    assert any(cmd[0] == "chown" for cmd in container.exec_calls)


@pytest.mark.asyncio
async def test_import_uses_config_user_for_chown(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("hello", encoding="utf-8")
    container = _FakeContainer(config_user="agent", pentester_exists=False)
    session = _session_with(container)

    await session_manager._import_local_sources(
        session,
        [{"source_path": str(tmp_path), "workspace_subdir": "repo"}],
    )

    chown_cmds = [cmd for cmd in container.exec_calls if cmd[0] == "chown"]
    assert chown_cmds == [["chown", "-R", "agent:agent", "/workspace/repo"]]


@pytest.mark.asyncio
async def test_import_skips_chown_when_no_owner(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("hello", encoding="utf-8")
    container = _FakeContainer(config_user="", pentester_exists=False)
    session = _session_with(container)

    await session_manager._import_local_sources(
        session,
        [{"source_path": str(tmp_path), "workspace_subdir": "repo"}],
    )

    assert len(container.put_calls) == 1
    assert not any(cmd[0] == "chown" for cmd in container.exec_calls)


@pytest.mark.asyncio
async def test_import_skips_non_directory(tmp_path: Path) -> None:
    file_path = tmp_path / "file.txt"
    file_path.write_text("x", encoding="utf-8")
    container = _FakeContainer()
    session = _session_with(container)

    await session_manager._import_local_sources(
        session,
        [{"source_path": str(file_path), "workspace_subdir": "repo"}],
    )

    assert container.put_calls == []


@pytest.mark.asyncio
async def test_create_or_reuse_tears_down_on_import_failure() -> None:
    client = MagicMock()
    client.delete = AsyncMock()
    session = MagicMock()

    async def _backend(**_kwargs: Any) -> tuple[Any, Any]:
        return client, session

    with (
        patch("strix.runtime.session_manager.load_settings") as settings,
        patch("strix.runtime.session_manager.get_backend", return_value=_backend),
        patch(
            "strix.runtime.session_manager._import_local_sources",
            new_callable=AsyncMock,
            side_effect=RuntimeError("put failed"),
        ),
    ):
        settings.return_value.runtime.backend = "docker"
        with pytest.raises(RuntimeError, match="put failed"):
            await session_manager.create_or_reuse(
                "scan-leak-test",
                image="test-image",
                local_sources=[
                    {"source_path": str(Path.cwd() / "missing-src"), "workspace_subdir": "repo"}
                ],
            )

    client.delete.assert_awaited_once_with(session)
    assert "scan-leak-test" not in session_manager._SESSION_CACHE


def test_container_of_missing_raises() -> None:
    with pytest.raises(RuntimeError, match="could not locate docker container"):
        session_manager._container_of(SimpleNamespace())


def test_container_of_reads_inner() -> None:
    container = MagicMock(name="container")
    session = _session_with(container)
    assert session_manager._container_of(session) is container


def test_build_source_tar_uses_temp_file_not_bytes(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("hello", encoding="utf-8")
    tar_path, added, skipped = session_manager._build_source_tar(tmp_path, "repo")
    try:
        assert tar_path.is_file()
        assert added == 1
        assert skipped == 0
        assert tar_path.stat().st_size > 0
    finally:
        tar_path.unlink(missing_ok=True)

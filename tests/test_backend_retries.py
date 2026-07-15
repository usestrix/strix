"""Tests for transient sandbox start retries."""

from __future__ import annotations

import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from agents.sandbox.errors import (
    LocalDirReadError,
    WorkspaceArchiveWriteError,
    WorkspaceStartError,
)

from strix.runtime import session_manager
from strix.runtime.backends import start_session_with_retry


class _FakeSession:
    def __init__(self, failures: list[BaseException]) -> None:
        self._failures = iter(failures)

    async def start(self) -> None:
        try:
            raise next(self._failures)
        except StopIteration:
            return

    async def resolve_exposed_port(self, _port: int) -> SimpleNamespace:
        return SimpleNamespace(tls=False, host="127.0.0.1", port=48080)


class _FakeClient:
    def __init__(self, *, delete_error: BaseException | None = None) -> None:
        self.created = 0
        self.deleted: list[_FakeSession] = []
        self.delete_error = delete_error

    async def create(self) -> _FakeSession:
        self.created += 1
        failures: list[BaseException] = []
        if self.created == 1:
            failures = [
                WorkspaceStartError(
                    path=Path("/workspace"),
                    cause=WorkspaceArchiveWriteError(
                        path=Path("/workspace"),
                        cause=TimeoutError("transient transport timeout"),
                    ),
                )
            ]
        return _FakeSession(failures)

    async def delete(self, session: _FakeSession) -> None:
        self.deleted.append(session)
        if self.delete_error is not None:
            raise self.delete_error


async def test_transient_workspace_failure_retries_and_tears_down(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient()
    sleeps: list[float] = []

    async def record_sleep(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr("strix.runtime.backends.asyncio.sleep", record_sleep)

    session = await start_session_with_retry(client, client.create, attempts=3)

    assert isinstance(session, _FakeSession)
    assert client.created == 2
    assert len(client.deleted) == 1
    assert sleeps == [2.0]


async def test_non_transient_workspace_failure_does_not_retry() -> None:
    client = _FakeClient()
    session = _FakeSession([LocalDirReadError(src=Path("/workspace/repo"))])

    async def create_session() -> _FakeSession:
        client.created += 1
        return session

    with pytest.raises(LocalDirReadError):
        await start_session_with_retry(client, create_session, attempts=3)

    assert client.created == 1
    assert client.deleted == [session]


async def test_teardown_failure_raises_original_error_without_retry() -> None:
    start_error = WorkspaceStartError(
        path=Path("/workspace"),
        cause=TimeoutError("transient transport timeout"),
    )
    teardown_error = RuntimeError("teardown failed")
    client = _FakeClient(delete_error=teardown_error)
    session = _FakeSession([start_error])

    async def create_session() -> _FakeSession:
        client.created += 1
        return session

    with pytest.raises(WorkspaceStartError) as caught:
        await start_session_with_retry(client, create_session, attempts=3)

    assert caught.value is start_error
    assert caught.value.__cause__ is teardown_error
    assert client.created == 1
    assert client.deleted == [session]


async def test_each_transient_attempt_is_torn_down(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient()
    client.created = 0
    sessions: list[_FakeSession] = []
    sleeps: list[float] = []

    async def record_sleep(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr("strix.runtime.backends.asyncio.sleep", record_sleep)

    async def create_session() -> _FakeSession:
        client.created += 1
        failures: list[BaseException] = []
        if client.created < 3:
            failures = [
                WorkspaceStartError(
                    path=Path("/workspace"),
                    cause=TimeoutError("transient transport timeout"),
                )
            ]
        session = _FakeSession(failures)
        sessions.append(session)
        return session

    result = await start_session_with_retry(client, create_session, attempts=3)

    assert result is sessions[2]
    assert client.deleted == sessions[:2]
    assert sleeps == [2.0, 4.0]


async def test_staged_dirs_survive_retries_and_cleanup_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "real.txt").write_text("content")
    (repo / "link.txt").symlink_to(repo / "real.txt")

    client = _FakeClient()
    observed_paths: list[Path] = []
    sleeps: list[float] = []
    original_rmtree = shutil.rmtree  # pyright: ignore[reportDeprecated]
    removed_paths: list[Path] = []

    async def record_sleep(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr("strix.runtime.backends.asyncio.sleep", record_sleep)

    def record_rmtree(path: str | Path, **kwargs: Any) -> None:
        removed_paths.append(Path(path))
        original_rmtree(path, **kwargs)  # pyright: ignore[reportDeprecated]

    monkeypatch.setattr("strix.runtime.session_manager.shutil.rmtree", record_rmtree)
    monkeypatch.setattr(
        session_manager,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(backend="fake")),
    )
    monkeypatch.setattr(session_manager, "bootstrap_caido", _bootstrap_caido)

    async def fake_backend(**kwargs: Any) -> tuple[_FakeClient, _FakeSession]:
        staged_path = kwargs["manifest"].entries["repo"].src

        async def create_session() -> _FakeSession:
            observed_paths.append(Path(staged_path))
            return await client.create()

        session = await start_session_with_retry(client, create_session, attempts=3)
        return client, session

    def fake_get_backend(_name: str) -> Any:
        return fake_backend

    monkeypatch.setattr(session_manager, "get_backend", fake_get_backend)

    try:
        await session_manager.create_or_reuse(
            "retry-test",
            image="test-image",
            local_sources=[
                {
                    "source_path": str(repo),
                    "workspace_subdir": "repo",
                }
            ],
        )
    finally:
        await session_manager.cleanup("retry-test")

    assert len(observed_paths) == 2
    assert observed_paths[0] == observed_paths[1]
    assert observed_paths[0] in removed_paths
    assert not observed_paths[0].exists()


async def _bootstrap_caido(*_args: Any, **_kwargs: Any) -> object:
    return object()

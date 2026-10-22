from __future__ import annotations

import asyncio
import io
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from agents.run_config import SandboxRunConfig
from agents.sandbox import SandboxAgent
from agents.sandbox.capabilities import Filesystem, Shell
from agents.sandbox.runtime_session_manager import SandboxRuntimeSessionManager

from strix.runtime import session_manager
from strix.runtime.backends import _BACKENDS, _BIND_MOUNT_BACKENDS, register_backend
from strix.runtime.deferred_session import DeferredSandboxClient, DeferredSandboxSession


if TYPE_CHECKING:
    from collections.abc import Iterator


@dataclass
class _RuntimeSettings:
    backend: str


@dataclass
class _Settings:
    runtime: _RuntimeSettings


@dataclass
class _Endpoint:
    host: str = "127.0.0.1"
    port: int = 8080
    tls: bool = False


@dataclass
class _ExecResult:
    exit_code: int = 0
    stdout: bytes = b""
    stderr: bytes = b""

    def ok(self) -> bool:
        return self.exit_code == 0


class _State:
    def __init__(self) -> None:
        self.manifest: Any = None
        self.session_id = "00000000-0000-4000-8000-000000000001"

    def model_copy(self, *, update: dict[str, Any]) -> _State:
        copy = _State()
        copy.manifest = update.get("manifest", self.manifest)
        return copy


class _Session:
    def __init__(self) -> None:
        self.state = _State()
        self.execs: list[tuple[str, ...]] = []
        self.writes: list[tuple[Path, bytes]] = []
        self.limits: list[Any] = []

    def _set_concurrency_limits(self, limits: Any) -> None:
        self.limits.append(limits)

    def _set_archive_limits(self, limits: Any) -> None:
        self.limits.append(limits)

    async def running(self) -> bool:
        return True

    async def resolve_exposed_port(self, _port: int) -> _Endpoint:
        return _Endpoint()

    async def exec(self, *argv: str, timeout: float | None = None, **_kw: Any) -> _ExecResult:
        del timeout
        self.execs.append(argv)
        return _ExecResult()

    async def write(self, path: Path, data: io.IOBase, **_kw: Any) -> None:
        self.writes.append((path, data.read()))


class _Client:
    def __init__(self) -> None:
        self.deleted: list[Any] = []

    async def delete(self, session: Any) -> None:
        self.deleted.append(session)


async def _no_caido(*_args: Any, **_kwargs: Any) -> None:
    return None


class _Backend:
    def __init__(self, *, fail: bool = False) -> None:
        self.gate = asyncio.Event()
        self.calls = 0
        self.fail = fail
        self.client = _Client()
        self.session = _Session()

    async def __call__(self, **_kwargs: Any) -> tuple[Any, Any]:
        self.calls += 1
        await self.gate.wait()
        if self.fail:
            raise RuntimeError("bring-up exploded")
        return self.client, self.session


@pytest.fixture
def backend(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest) -> Iterator[_Backend]:
    name = f"deferred-{request.node.name}"
    fake = _Backend(fail="fail" in request.node.name)
    register_backend(name, fake, supports_bind_mounts=True)
    monkeypatch.setattr(session_manager, "bootstrap_caido", _no_caido)
    monkeypatch.setattr(
        session_manager, "load_settings", lambda: _Settings(runtime=_RuntimeSettings(backend=name))
    )
    yield fake
    _BACKENDS.pop(name, None)
    _BIND_MOUNT_BACKENDS.discard(name)


async def _settle() -> None:
    for _ in range(10):
        await asyncio.sleep(0)


async def _create(scan_id: str, **kwargs: Any) -> dict[str, Any]:
    return await session_manager.create_or_reuse(
        scan_id, image="img", local_sources=[], defer=True, **kwargs
    )


@pytest.mark.asyncio
async def test_deferred_bundle_returns_before_the_backend_finishes(backend: _Backend) -> None:
    scan_id = "deferred-returns"
    try:
        bundle = await asyncio.wait_for(_create(scan_id), timeout=1)
        session = bundle["session"]
        assert isinstance(session, DeferredSandboxSession)
        assert isinstance(bundle["client"], DeferredSandboxClient)
        assert session.pending
        await _settle()
        assert backend.calls == 1
        assert await session.running()
        assert session.state.manifest.environment.value["PYTHONUNBUFFERED"] == "1"
        again = await session_manager.create_or_reuse(scan_id, image="img", local_sources=[])
        assert again is bundle
        assert backend.calls == 1
    finally:
        await session_manager.cleanup(scan_id)


@pytest.mark.asyncio
async def test_first_io_resolves_the_sandbox_then_delegates(backend: _Backend) -> None:
    scan_id = "deferred-io"
    try:
        bundle = await _create(scan_id)
        session = bundle["session"]
        session._set_concurrency_limits("limits")
        exec_task = asyncio.create_task(session.exec("echo", "hi"))
        await asyncio.sleep(0.05)
        assert not exec_task.done()
        backend.gate.set()
        result = await asyncio.wait_for(exec_task, timeout=1)
        assert result.ok()
        assert backend.session.execs == [("echo", "hi")]
        assert not session.pending
        assert backend.session.limits == ["limits"]
        assert backend.session.state.manifest is session.state.manifest
        await session.write(Path("/workspace/x"), io.BytesIO(b"data"))
        assert backend.session.writes == [(Path("/workspace/x"), b"data")]
    finally:
        await session_manager.cleanup(scan_id)
    assert backend.client.deleted == [backend.session]


@pytest.mark.asyncio
async def test_failed_bring_up_surfaces_on_first_io(backend: _Backend) -> None:
    scan_id = "deferred-fail"
    try:
        bundle = await _create(scan_id)
        session = bundle["session"]
        backend.gate.set()
        with pytest.raises(RuntimeError, match="bring-up exploded"):
            await asyncio.wait_for(session.exec("true"), timeout=1)
        assert not await session.running()
        with pytest.raises(RuntimeError, match="bring-up exploded"):
            await bundle["caido_client"].get()
    finally:
        await session_manager.cleanup(scan_id)
    assert backend.client.deleted == []


@pytest.mark.asyncio
async def test_cleanup_while_pending_cancels_the_bring_up(backend: _Backend) -> None:
    scan_id = "deferred-cancel"
    bundle = await _create(scan_id)
    session = bundle["session"]
    await asyncio.wait_for(session_manager.cleanup(scan_id), timeout=1)
    assert session.bring_up.cancelled()
    assert backend.client.deleted == []
    assert session_manager._SESSION_CACHE.get(scan_id) is None
    backend.gate.set()
    await _settle()
    assert backend.client.deleted == [backend.session]


@pytest.mark.asyncio
async def test_cleanup_while_pending_ignores_a_failed_late_bring_up(backend: _Backend) -> None:
    scan_id = "deferred-cancel-fail"
    await _create(scan_id)
    await asyncio.wait_for(session_manager.cleanup(scan_id), timeout=1)
    backend.gate.set()
    await _settle()
    assert backend.client.deleted == []


@pytest.mark.asyncio
async def test_extra_files_are_staged_inside_the_deferred_bring_up(backend: _Backend) -> None:
    scan_id = "deferred-extra"
    try:
        bundle = await _create(
            scan_id,
            extra_files=[{"workspace_path": "/workspace/.strix/notes.md", "content": "hi"}],
        )
        assert backend.session.writes == []
        backend.gate.set()
        await asyncio.wait_for(bundle["session"].resolve(), timeout=1)
        assert len(backend.session.writes) == 1
        assert backend.session.execs
    finally:
        await session_manager.cleanup(scan_id)


@pytest.mark.asyncio
async def test_awaitable_extra_files_do_not_delay_the_backend_call(backend: _Backend) -> None:
    scan_id = "deferred-extra-awaitable"
    files: asyncio.Future[list[dict[str, Any]] | None] = asyncio.get_running_loop().create_future()
    try:
        bundle = await _create(scan_id, extra_files=files)
        backend.gate.set()
        await _settle()
        assert backend.calls == 1
        assert backend.session.writes == []
        files.set_result([{"workspace_path": "/workspace/.strix/notes.md", "content": "hi"}])
        await asyncio.wait_for(bundle["session"].resolve(), timeout=1)
        assert len(backend.session.writes) == 1
    finally:
        await session_manager.cleanup(scan_id)


@pytest.mark.asyncio
async def test_awaitable_extra_files_resolving_to_none_stage_nothing(backend: _Backend) -> None:
    scan_id = "deferred-extra-none"

    async def _nothing() -> list[dict[str, Any]] | None:
        return None

    try:
        bundle = await _create(scan_id, extra_files=_nothing())
        backend.gate.set()
        await asyncio.wait_for(bundle["session"].resolve(), timeout=1)
        assert backend.session.writes == []
    finally:
        await session_manager.cleanup(scan_id)


@pytest.mark.asyncio
async def test_default_path_still_blocks_until_the_sandbox_is_up(backend: _Backend) -> None:
    scan_id = "deferred-off"
    backend.gate.set()
    try:
        bundle = await session_manager.create_or_reuse(scan_id, image="img", local_sources=[])
        assert bundle["session"] is backend.session
        assert bundle["client"] is backend.client
    finally:
        await session_manager.cleanup(scan_id)
    assert backend.client.deleted == [backend.session]


@pytest.mark.asyncio
async def test_sdk_session_prep_does_not_wait_for_the_bring_up(backend: _Backend) -> None:
    scan_id = "deferred-sdk-prep"
    try:
        bundle = await _create(scan_id)
        agent = SandboxAgent(
            name="root", instructions="x", tools=[], capabilities=[Filesystem(), Shell()]
        )
        manager = SandboxRuntimeSessionManager(
            starting_agent=agent,
            sandbox_config=SandboxRunConfig(client=bundle["client"], session=bundle["session"]),
            run_state=None,
        )
        session = await asyncio.wait_for(
            manager.ensure_session(
                agent=agent, capabilities=list(agent.capabilities), is_resumed_state=False
            ),
            timeout=1,
        )
        assert session is bundle["session"]
        assert session.pending
        backend.gate.set()
        await asyncio.wait_for(session.resolve(), timeout=1)
        assert not session.pending
    finally:
        await session_manager.cleanup(scan_id)

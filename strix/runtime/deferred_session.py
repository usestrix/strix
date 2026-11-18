from __future__ import annotations

import asyncio
import contextlib
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agents.sandbox.session.manager import Instrumentation
from agents.sandbox.session.sandbox_session import SandboxSession
from agents.sandbox.session.sandbox_session_state import SandboxSessionState
from agents.sandbox.snapshot import NoopSnapshot


if TYPE_CHECKING:
    import io
    from collections.abc import Sequence

    from agents.sandbox.entries import BaseEntry
    from agents.sandbox.manifest import Manifest
    from agents.sandbox.materialization import MaterializedFile
    from agents.sandbox.session.base_sandbox_session import BaseSandboxSession
    from agents.sandbox.types import ExecResult, ExposedPortEndpoint, User


logger = logging.getLogger(__name__)


class _PendingSessionState(SandboxSessionState):
    type: str = "pending"


class DeferredSandboxSession(SandboxSession):
    def __init__(
        self,
        bring_up: asyncio.Task[tuple[Any, BaseSandboxSession]],
        *,
        manifest: Manifest,
        exposed_ports: tuple[int, ...] = (),
    ) -> None:
        self._bring_up = bring_up
        self._pending_state: SandboxSessionState = _PendingSessionState(
            snapshot=NoopSnapshot(id="pending"),
            manifest=manifest,
            exposed_ports=exposed_ports,
        )
        self._pending_limits: Any = None
        self._pending_archive_limits: Any = None
        self._resolved: BaseSandboxSession | None = None
        self._client: Any = None
        self._instrumentation: Instrumentation = Instrumentation()
        self._seq = 0

    @property
    def pending(self) -> bool:
        return self._resolved is None

    @property
    def bring_up(self) -> asyncio.Task[tuple[Any, BaseSandboxSession]]:
        return self._bring_up

    async def resolve(self) -> BaseSandboxSession:
        if self._resolved is not None:
            return self._resolved
        client, session = await asyncio.shield(self._bring_up)
        self._adopt(client, session)
        return session

    def _adopt(self, client: Any, session: BaseSandboxSession) -> None:
        if self._resolved is not None:
            return
        self._client = client
        self._resolved = session
        self._inner = session
        if self._pending_limits is not None:
            session._set_concurrency_limits(self._pending_limits)
        if self._pending_archive_limits is not None:
            session._set_archive_limits(self._pending_archive_limits)
        if self._pending_state.manifest != session.state.manifest:
            session.state = session.state.model_copy(
                update={"manifest": self._pending_state.manifest}
            )

    @property
    def client(self) -> Any:
        return self._client

    @property
    def state(self) -> SandboxSessionState:
        if self._resolved is None:
            return self._pending_state
        return self._resolved.state

    @state.setter
    def state(self, value: SandboxSessionState) -> None:
        if self._resolved is None:
            self._pending_state = value
        else:
            self._resolved.state = value

    def _set_concurrency_limits(self, limits: Any) -> None:
        if self._resolved is None:
            self._pending_limits = limits
        else:
            self._resolved._set_concurrency_limits(limits)

    def _set_archive_limits(self, limits: Any) -> None:
        if self._resolved is None:
            self._pending_archive_limits = limits
        else:
            self._resolved._set_archive_limits(limits)

    def _manifest_base_dir(self) -> Path:
        if self._resolved is None:
            return Path.cwd()
        return self._resolved._manifest_base_dir()

    def normalize_path(self, path: Path | str, *, for_write: bool = False) -> Path:
        if self._resolved is None:
            return Path(path)
        return self._resolved.normalize_path(path, for_write=for_write)

    def register_persist_workspace_skip_path(self, path: Path | str) -> Path:
        if self._resolved is None:
            return Path(path)
        return self._resolved.register_persist_workspace_skip_path(path)

    def supports_pty(self) -> bool:
        return self._resolved.supports_pty() if self._resolved is not None else False

    async def running(self) -> bool:
        if self._resolved is None:
            if not self._bring_up.done():
                return True
            return not self._bring_up.cancelled() and self._bring_up.exception() is None
        return await self._resolved.running()

    async def start(self) -> None:
        if self._resolved is None:
            return
        await self._resolved.start()

    async def stop(self) -> None:
        if self._resolved is None:
            return
        await self._resolved.stop()

    async def shutdown(self) -> None:
        if self._resolved is None:
            return
        await self._resolved.shutdown()

    async def aclose(self) -> None:
        if self._resolved is None:
            return
        await self._resolved.aclose()

    async def _validate_manifest_application(self, *, only_ephemeral: bool = False) -> None:
        session = await self.resolve()
        await session._validate_manifest_application(only_ephemeral=only_ephemeral)

    async def apply_manifest(self, *, only_ephemeral: bool = False) -> Any:
        session = await self.resolve()
        return await session.apply_manifest(only_ephemeral=only_ephemeral)

    async def _apply_entry_batch(
        self,
        entries: Sequence[tuple[Path, BaseEntry]],
        *,
        base_dir: Path,
    ) -> list[MaterializedFile]:
        del base_dir
        session = await self.resolve()
        return await session._apply_entry_batch(entries, base_dir=session._manifest_base_dir())

    async def exec(self, *command: str | Path, **kwargs: Any) -> ExecResult:
        await self.resolve()
        return await super().exec(*command, **kwargs)

    async def ls(self, *args: Any, **kwargs: Any) -> Any:
        await self.resolve()
        return await super().ls(*args, **kwargs)

    async def rm(self, *args: Any, **kwargs: Any) -> Any:
        await self.resolve()
        return await super().rm(*args, **kwargs)

    async def mkdir(self, *args: Any, **kwargs: Any) -> Any:
        await self.resolve()
        return await super().mkdir(*args, **kwargs)

    async def read(self, path: Path, *, user: str | User | None = None) -> io.IOBase:
        await self.resolve()
        return await super().read(path, user=user)

    async def write(self, *args: Any, **kwargs: Any) -> Any:
        await self.resolve()
        return await super().write(*args, **kwargs)

    async def resolve_exposed_port(self, port: int) -> ExposedPortEndpoint:
        await self.resolve()
        return await super().resolve_exposed_port(port)

    async def _resolve_exposed_port(self, port: int) -> ExposedPortEndpoint:
        session = await self.resolve()
        return await session._resolve_exposed_port(port)

    async def pty_exec_start(self, *args: Any, **kwargs: Any) -> Any:
        await self.resolve()
        return await super().pty_exec_start(*args, **kwargs)

    async def pty_write_stdin(self, *args: Any, **kwargs: Any) -> Any:
        await self.resolve()
        return await super().pty_write_stdin(*args, **kwargs)

    async def pty_terminate_all(self) -> None:
        if self._resolved is None:
            return
        await super().pty_terminate_all()

    async def persist_workspace(self) -> io.IOBase:
        await self.resolve()
        return await super().persist_workspace()

    async def hydrate_workspace(self, data: io.IOBase) -> None:
        await self.resolve()
        await super().hydrate_workspace(data)

    async def teardown(self) -> None:
        if self._resolved is None:
            self._bring_up.cancel()
            with contextlib.suppress(BaseException):
                client, session = await self._bring_up
                self._adopt(client, session)
        if self._resolved is None:
            return
        await self._client.delete(self._resolved)


class DeferredSandboxClient:
    def __init__(self, session: DeferredSandboxSession) -> None:
        self._session = session

    def __getattr__(self, name: str) -> Any:
        client = self._session.client
        if client is None:
            raise AttributeError(f"sandbox client unavailable before bring-up finishes ({name})")
        return getattr(client, name)

    async def delete(self, session: Any) -> None:
        if isinstance(session, DeferredSandboxSession):
            await session.teardown()
            return
        real = await self._session.resolve()
        await self._session.client.delete(real if session is self._session else session)

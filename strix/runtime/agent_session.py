"""Per-agent process ownership within a shared sandbox (not a security boundary)."""

from __future__ import annotations

import copy
import uuid
from typing import TYPE_CHECKING, Any

from agents.sandbox.session import BaseSandboxSession


if TYPE_CHECKING:
    from pathlib import Path


class AgentSandboxSession(BaseSandboxSession):
    def __init__(self, parent: BaseSandboxSession, root: str, task_id: str) -> None:
        while isinstance(parent, AgentSandboxSession):
            parent = parent.parent
        self.parent: BaseSandboxSession = parent
        self.state = copy.deepcopy(parent.state)
        self.state.manifest.root = root
        self.state.manifest.entries = {}
        self.state.session_id = uuid.uuid5(parent.state.session_id, task_id)
        self.task_id = task_id
        self.processes: set[int] = set()

    async def stop_process(self, pid: int) -> Any:
        if pid <= 1:
            raise ValueError("A positive process ID greater than 1 is required")
        return await self.parent.exec(
            "python",
            "-c",
            _STOP_OWN_PROCESSES,
            self.task_id,
            str(pid),
            shell=False,
            timeout=15,
        )

    def _command(self, command: tuple[Any, ...]) -> list[str]:
        return [
            "env",
            f"STRIX_AGENT_TASK={self.task_id}",
            "sh",
            "-c",
            'cd -- "$1" || exit; shift; exec "$@"',
            "sh",
            self.state.manifest.root,
            *map(str, command),
        ]

    async def _exec_internal(self, *command: Any, timeout: float | None = None) -> Any:
        return await self.parent.exec(
            *self._command(command),
            shell=False,
            timeout=min(timeout or 600, 600),
        )

    def supports_pty(self) -> bool:
        return self.parent.supports_pty()

    async def pty_exec_start(self, *command: Any, **kwargs: Any) -> Any:
        # Intentional native sandbox shell, never host execution.
        prepared = self._prepare_exec_command(  # nosec B604
            *command,
            shell=kwargs.pop("shell", True),
            user=kwargs.pop("user", None),
        )
        kwargs["timeout"] = min(kwargs.get("timeout") or 600, 600)
        update = await self.parent.pty_exec_start(
            *self._command(tuple(prepared)),
            shell=False,
            **kwargs,
        )
        if update.process_id is not None:
            self.processes.add(update.process_id)
        return update

    async def pty_write_stdin(self, *, session_id: int, **kwargs: Any) -> Any:
        if session_id not in self.processes:
            raise ValueError("That process belongs to another agent")
        return await self.parent.pty_write_stdin(session_id=session_id, **kwargs)

    async def read(self, path: Path, **kwargs: Any) -> Any:
        return await self.parent.read(self.normalize_path(path), **kwargs)

    async def write(self, path: Path, data: Any, **kwargs: Any) -> None:
        await self.parent.write(self.normalize_path(path, for_write=True), data, **kwargs)

    async def running(self) -> bool:
        return await self.parent.running()

    async def hydrate_workspace(self, _data: Any) -> None:
        raise RuntimeError("A borrowed worktree cannot restore the scan workspace")

    async def persist_workspace(self) -> Any:
        raise RuntimeError("The scan owns workspace persistence")

    async def stop(self) -> None:
        await self.pty_terminate_all()

    async def shutdown(self) -> None:
        await self.pty_terminate_all()

    async def pty_terminate_all(self) -> None:
        # Background services inherit this task marker too. Never call the
        # parent session's terminate_all(), which would kill assessment tools.
        await self.parent.exec(
            "python",
            "-c",
            _STOP_OWN_PROCESSES,
            self.task_id,
            shell=False,
            timeout=15,
        )
        self.processes.clear()


_STOP_OWN_PROCESSES = r"""
import os, pathlib, signal, sys, time
marker = b"STRIX_AGENT_TASK=" + sys.argv[1].encode()
requested = int(sys.argv[2]) if len(sys.argv) > 2 else None
def owned():
    found = []
    for path in pathlib.Path("/proc").glob("[0-9]*/environ"):
        try:
            if marker in path.read_bytes().split(b"\0"):
                found.append(int(path.parent.name))
        except (OSError, ValueError):
            pass
    return found
if requested is not None and requested not in owned():
    sys.exit("Process is absent or belongs to another agent; nothing was stopped")
for sig in (signal.SIGTERM, signal.SIGKILL):
    for pid in owned():
        if requested is not None and pid != requested:
            continue
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            pass
    if sig == signal.SIGTERM:
        time.sleep(0.2)
"""

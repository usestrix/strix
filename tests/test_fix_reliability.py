"""Local transport for native SDK tools, plus patch-export boundary tests."""

from __future__ import annotations

import asyncio
import io
import json
import os
import sys
import tarfile
from pathlib import Path
from typing import Any

import pytest
from agents.sandbox.manifest import Manifest
from agents.sandbox.session import BaseSandboxSession
from agents.sandbox.session.sandbox_session_state import SandboxSessionState
from agents.sandbox.snapshot import NoopSnapshot
from agents.sandbox.types import ExecResult

from strix.fix import runtime as fix_runtime
from strix.fix.workspace import apply_checkpoint, source_archive
from tests.test_fix_runtime import _git, _workspace


class LocalSandbox(BaseSandboxSession):
    """Only the transport is local; agents use actual SDK filesystem/shell tools."""

    def __init__(self, root: Path) -> None:
        root.mkdir(parents=True, exist_ok=True)
        self.state = SandboxSessionState(
            type="test", snapshot=NoopSnapshot(id="test"), manifest=Manifest(root=str(root))
        )

    async def exec(self, *args: Any, **kwargs: Any) -> ExecResult:
        shell = kwargs.get("shell", False)
        if shell:
            command = [*(shell if isinstance(shell, list) else ["bash", "-lc"]), str(args[0])]
        else:
            command = [
                sys.executable if str(a) in {"python", "/usr/bin/python3"} else str(a) for a in args
            ]
        process = await asyncio.create_subprocess_exec(
            *command,
            cwd=self.state.manifest.root,
            env={**os.environ, "PATH": str(Path(sys.executable).parent) + ":" + os.environ["PATH"]},
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), kwargs.get("timeout", 60)
            )
        except TimeoutError:
            process.kill()
            await process.wait()
            raise
        return ExecResult(stdout=stdout, stderr=stderr, exit_code=process.returncode)

    async def _exec_internal(self, *command: Any, **kwargs: Any) -> ExecResult:
        return await self.exec(*command, **kwargs)

    async def write(self, path: Path, data: Any, **_kwargs: Any) -> None:
        path = Path(self.normalize_path(path))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.read())

    async def read(self, path: Path, **_kwargs: Any) -> io.BytesIO:
        return io.BytesIO(Path(self.normalize_path(path)).read_bytes())

    async def running(self) -> bool:
        return True

    async def persist_workspace(self) -> io.IOBase:
        raise NotImplementedError

    async def hydrate_workspace(self, data: io.IOBase) -> None:
        raise NotImplementedError


def environment(workspace: Path, tmp_path: Path) -> fix_runtime._RuntimeEnvironment:
    root = tmp_path / "execution" / "source"
    return fix_runtime._RuntimeEnvironment(
        workspace,
        sandbox_session=LocalSandbox(root.parent),
        network_allowed=True,
        sandbox_workspace=str(root),
    )


def existing_suite(workspace: Path) -> str:
    (workspace / ".gitignore").write_text(".venv/\n__pycache__/\n")
    (workspace / "tests").mkdir()
    (workspace / "tests/test_existing.py").write_text(
        "import unittest\nfrom app import result\nclass Existing(unittest.TestCase):\n"
        "    def test_type(self): self.assertIsInstance(result(),str)\n"
    )
    _git(workspace, "add", ".")
    _git(
        workspace,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@local",
        "commit",
        "-qm",
        "existing tests",
    )
    return _git(workspace, "rev-parse", "HEAD")


@pytest.mark.asyncio
async def test_checkpoint_handles_rename_deletion_and_agent_commit(tmp_path: Path) -> None:
    workspace, _ = _workspace(tmp_path)
    env = environment(workspace, tmp_path)
    await env.initialize()
    await env.session.exec(
        *[
            "sh",
            "-c",
            f"cd {env.sandbox_workspace} && mv app.py renamed.py && git add -A && "
            "git -c user.name=Test -c user.email=test@local commit -qm rename",
        ],
        shell=False,
    )
    await env.checkpoint()
    assert not (workspace / "app.py").exists()
    assert (workspace / "renamed.py").exists()
    assert "unsafe" in _git(workspace, "show", "HEAD:app.py")


def test_checkpoint_rejects_escaping_paths_before_mutating_mirror(tmp_path: Path) -> None:
    workspace, _ = _workspace(tmp_path)
    content = io.BytesIO()
    with tarfile.open(fileobj=content, mode="w") as archive:
        body = json.dumps([{"path": "../escape", "delete": True}]).encode()
        info = tarfile.TarInfo("manifest.json")
        info.size = len(body)
        archive.addfile(info, io.BytesIO(body))
    with pytest.raises(ValueError, match="Unsafe"):
        apply_checkpoint(workspace, content.getvalue())
    assert "unsafe" in (workspace / "app.py").read_text()


def test_initial_source_snapshot_ignores_export_rules(tmp_path: Path) -> None:
    workspace, _ = _workspace(tmp_path)
    (workspace / ".gitattributes").write_text("app.py export-ignore\n")
    _git(workspace, "add", ".")
    _git(
        workspace,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@local",
        "commit",
        "-qm",
        "attributes",
    )
    with tarfile.open(fileobj=io.BytesIO(source_archive(workspace))) as archive:
        assert "app.py" in archive.getnames()

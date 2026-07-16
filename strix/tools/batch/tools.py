"""``batch_view_files`` / ``batch_terminal_execute`` — sandbox-side concurrency.

v1 sets ``parallel_tool_calls=False`` (the SDK issues one tool call per turn), so
an agent that needs to read 20 files or run 10 independent commands pays a full
model round-trip each. These tools let it fan out in a SINGLE call: the reads /
execs run concurrently inside the sandbox (bounded), and the combined results
come back in one tool response — the wall-clock win on the recon-heavy phase of
a scan.

Concurrency is bounded (a semaphore) so a large batch can't exhaust the sandbox.
Each item is isolated: one failing read/exec returns its own error entry, never
aborts the batch. Order is preserved (results[i] corresponds to inputs[i]).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)

_MAX_CONCURRENCY = 8          # bounded fan-out — don't swamp the sandbox
_MAX_ITEMS = 50               # cap batch size (a 200-file batch is a smell)
_DEFAULT_TIMEOUT = 60


def _session(ctx: RunContextWrapper) -> Any:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    return inner.get("sandbox_session")


async def _gather_bounded(coros: list[Any]) -> list[Any]:
    sem = asyncio.Semaphore(_MAX_CONCURRENCY)

    async def _run(coro: Any) -> Any:
        async with sem:
            return await coro

    return await asyncio.gather(*(_run(c) for c in coros), return_exceptions=True)


async def _view_files_impl(session: Any, paths: list[str]) -> dict[str, Any]:
    """Core of batch_view_files — session-injected so it's directly testable."""
    if session is None:
        return {"success": False, "error": "no sandbox session in context"}
    if not paths:
        return {"success": True, "results": []}
    if len(paths) > _MAX_ITEMS:
        return {"success": False,
                "error": f"batch too large ({len(paths)} > {_MAX_ITEMS}); split it"}

    async def _read(path: str) -> dict[str, Any]:
        rel = path.lstrip("/")
        target = rel if rel.startswith("workspace/") else f"workspace/{rel}"
        result = await session.exec("cat", f"/{target}", timeout=_DEFAULT_TIMEOUT)
        if getattr(result, "exit_code", 1) != 0:
            return {"path": path, "error": (getattr(result, "stderr", "") or
                                            "read failed").strip()[:200]}
        content = result.stdout or ""
        truncated = len(content) > 100_000
        return {"path": path, "content": content[:100_000], "truncated": truncated}

    settled = await _gather_bounded([_read(p) for p in paths])
    results = [
        r if isinstance(r, dict)
        else {"path": paths[i], "error": f"{type(r).__name__}: {r}"}
        for i, r in enumerate(settled)
    ]
    return {"success": True, "results": results}


@function_tool(timeout=180, strict_mode=False)
async def batch_view_files(
    ctx: RunContextWrapper,
    paths: list[str],
) -> dict[str, Any]:
    """Read multiple files from the target in one call (concurrent, bounded).

    Prefer this over N single reads when mapping a codebase — one tool call, one
    model round-trip. Each result carries the path, content (or an error), and a
    truncation flag; order matches ``paths``.

    Args:
        paths: repo-relative file paths to read (max 50).
    """
    return await _view_files_impl(_session(ctx), paths)


async def _exec_impl(session: Any, commands: list[str]) -> dict[str, Any]:
    """Core of batch_terminal_execute — session-injected so it's directly testable."""
    if session is None:
        return {"success": False, "error": "no sandbox session in context"}
    if not commands:
        return {"success": True, "results": []}
    if len(commands) > _MAX_ITEMS:
        return {"success": False,
                "error": f"batch too large ({len(commands)} > {_MAX_ITEMS}); split it"}

    async def _run(cmd: str) -> dict[str, Any]:
        result = await session.exec("sh", "-c", cmd, timeout=_DEFAULT_TIMEOUT)
        return {
            "command": cmd,
            "exit_code": getattr(result, "exit_code", None),
            "stdout": (result.stdout or "")[:50_000],
            "stderr": (getattr(result, "stderr", "") or "")[:10_000],
        }

    settled = await _gather_bounded([_run(c) for c in commands])
    results = [
        r if isinstance(r, dict)
        else {"command": commands[i], "error": f"{type(r).__name__}: {r}"}
        for i, r in enumerate(settled)
    ]
    return {"success": True, "results": results}


@function_tool(timeout=300, strict_mode=False)
async def batch_terminal_execute(
    ctx: RunContextWrapper,
    commands: list[str],
) -> dict[str, Any]:
    """Run multiple INDEPENDENT shell commands in the sandbox in one call
    (concurrent, bounded). Use only for commands with no ordering dependency
    between them (parallel greps, per-service probes, etc.) — order of
    completion is not guaranteed, but results[i] maps to commands[i].

    Args:
        commands: shell command strings to run (max 50).
    """
    return await _exec_impl(_session(ctx), commands)

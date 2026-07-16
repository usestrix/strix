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
import os
from pathlib import PurePosixPath
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)

_MAX_CONCURRENCY = 8          # bounded fan-out — don't swamp the sandbox
_MAX_ITEMS = 50               # cap batch size (a 200-file batch is a smell)

# Per-item timeouts are bounded so a full, valid batch cannot exceed the
# enclosing @function_tool deadline (below) and get cancelled before returning
# its per-item results. Worst case is ceil(_MAX_ITEMS / _MAX_CONCURRENCY) waves
# of per-item timeouts: ceil(50/8) = 7. So keep 7 * per_item < tool deadline:
#   view: 7 * 20s = 140s < 180s ;  exec: 7 * 40s = 280s < 300s.
_VIEW_ITEM_TIMEOUT = 20
_EXEC_ITEM_TIMEOUT = 40
_VIEW_TOOL_TIMEOUT = 180
_EXEC_TOOL_TIMEOUT = 300


def _session(ctx: RunContextWrapper) -> Any:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    return inner.get("sandbox_session")


def _safe_workspace_path(path: str) -> str | None:
    """Resolve a caller path to an absolute /workspace path, or None if it would
    escape the workspace root.

    The path is passed to ``cat`` verbatim, so a ``..`` hop (e.g.
    ``workspace/../../etc/passwd``) would read container files outside the
    target. Normalise and require the result to stay under ``/workspace``.
    """
    rel = path.lstrip("/")
    rel = rel[len("workspace/") :] if rel.startswith("workspace/") else rel
    # PurePosixPath: sandbox paths are always posix regardless of host OS.
    normalized = PurePosixPath("/workspace") / rel
    resolved = PurePosixPath(os.path.normpath(str(normalized)))
    if resolved != PurePosixPath("/workspace") and PurePosixPath(
        "/workspace"
    ) not in resolved.parents:
        return None
    return str(resolved)


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
        safe = _safe_workspace_path(path)
        if safe is None:
            return {"path": path, "error": "path escapes /workspace (rejected)"}
        result = await session.exec("cat", safe, timeout=_VIEW_ITEM_TIMEOUT)
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


@function_tool(timeout=_VIEW_TOOL_TIMEOUT, strict_mode=False)
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
        result = await session.exec("sh", "-c", cmd, timeout=_EXEC_ITEM_TIMEOUT)
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


@function_tool(timeout=_EXEC_TOOL_TIMEOUT, strict_mode=False)
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

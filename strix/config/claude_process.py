"""Subprocess transport for the Claude Code backend.

One ``claude -p`` invocation per Strix turn (the SDK model is stateless — Strix
resends the full conversation each turn, so a warm pipe would carry nothing).
A module-level semaphore bounds how many ``claude`` processes run at once, so a
wide multi-agent graph doesn't fork an unbounded number of heavyweight CLIs.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
from typing import Any, cast

from strix.config import claude_bridge, claude_code


logger = logging.getLogger(__name__)

_DEFAULT_MAX_PROCS = 8
_KILL_GRACE_S = 5.0

_BASE_ARGS = (
    "-p",
    "--output-format",
    "stream-json",
    "--verbose",
    "--tools",
    "",
    "--setting-sources",
    "",
    "--strict-mcp-config",
    "--disable-slash-commands",
    "--no-session-persistence",
)


def _max_procs() -> int:
    raw = os.environ.get("STRIX_CLAUDE_CODE_MAX_PROCS")
    if raw:
        try:
            value = int(raw)
        except ValueError:
            value = _DEFAULT_MAX_PROCS
        else:
            return max(1, value)
    return _DEFAULT_MAX_PROCS


# Holder rather than module globals so rebinding needs no `global` statement.
_sem_state: dict[str, object] = {"semaphore": None, "size": None}


def _get_semaphore() -> asyncio.Semaphore:
    size = _max_procs()
    semaphore = _sem_state["semaphore"]
    if not isinstance(semaphore, asyncio.Semaphore) or _sem_state["size"] != size:
        semaphore = asyncio.Semaphore(size)
        _sem_state["semaphore"] = semaphore
        _sem_state["size"] = size
    return semaphore


def _build_argv(slug: str, extra_args: list[str]) -> list[str]:
    binary = claude_code.binary_path()
    if binary is None:
        raise claude_code.ClaudeCodeError(
            "STRIX_LLM=claude-code/... needs the Claude Code CLI on PATH. "
            "Install it, then run `claude /login`."
        )
    schema = json.dumps(claude_bridge.RESULT_SCHEMA, separators=(",", ":"))
    return [
        binary,
        *_BASE_ARGS,
        "--model",
        slug,
        "--json-schema",
        schema,
        *extra_args,
    ]


async def run_turn(slug: str, prompt: str, *, extra_args: list[str] | None = None) -> str:
    """Run one ``claude -p`` turn and return its terminal ``result`` line, unparsed.

    Raises :class:`claude_code.ClaudeCodeError` on a non-zero exit or a stream
    with no result line; the caller decodes the JSON via ``claude_bridge``.
    """
    argv = _build_argv(slug, extra_args or [])
    async with _get_semaphore():
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await proc.communicate(prompt.encode("utf-8"))
        except BaseException:
            await _terminate(proc)
            raise

    if proc.returncode != 0:
        tail = _tail(stderr)
        raise claude_code.ClaudeCodeError(f"claude -p exited with code {proc.returncode}: {tail}")

    result_line = _extract_result_line(stdout.decode("utf-8", errors="replace"))
    if result_line is None:
        tail = _tail(stderr)
        raise claude_code.ClaudeCodeError(f"claude -p produced no result line (stderr: {tail})")
    return result_line


def _extract_result_line(stdout: str) -> str | None:
    """Return the last stream-json line whose parsed ``type`` is ``result``."""
    found: str | None = None
    for raw in stdout.splitlines():
        text = raw.strip()
        if not text.startswith("{"):
            continue
        try:
            event = json.loads(text)
        except ValueError:
            continue
        if isinstance(event, dict) and cast("dict[str, Any]", event).get("type") == "result":
            found = text
    return found


def _tail(stderr: bytes, *, limit: int = 400) -> str:
    text = stderr.decode("utf-8", errors="replace").strip()
    return text[-limit:] if text else "(no stderr)"


async def _terminate(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        return
    try:
        proc.terminate()
    except ProcessLookupError:
        return
    try:
        await asyncio.wait_for(proc.wait(), timeout=_KILL_GRACE_S)
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        with contextlib.suppress(ProcessLookupError):
            await proc.wait()

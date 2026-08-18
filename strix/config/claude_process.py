"""Subprocess transport for the Claude Code backend.

One ``claude -p`` invocation per Strix turn (the SDK model is stateless, Strix
resends the full conversation each turn, so a warm pipe would carry nothing).

The turn is a plain request/response (write the prompt, read all output), so it
runs as a **blocking** ``subprocess.run`` inside ``asyncio.to_thread``. That is
deliberate: on Windows Strix forces a ``SelectorEventLoop``, which cannot spawn
subprocesses (``asyncio.create_subprocess_exec`` raises a bare
``NotImplementedError`` there), so the async-subprocess API is unusable. A
threaded blocking call works under any event-loop policy on every platform.

A module-level semaphore bounds how many ``claude`` processes run at once so a
wide multi-agent graph doesn't fork an unbounded number of heavyweight CLIs.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess  # we invoke a trusted, user-installed CLI, never a shell
import weakref
from typing import Any

from strix.config import claude_bridge, claude_code


logger = logging.getLogger(__name__)

_DEFAULT_MAX_PROCS = 8
# A single agent turn can involve real model latency; bound it generously so a
# genuinely hung subprocess still cannot wedge the run forever.
_DEFAULT_TURN_TIMEOUT_S = 900

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
            return _DEFAULT_MAX_PROCS
        return max(1, value)
    return _DEFAULT_MAX_PROCS


def _turn_timeout() -> float:
    raw = os.environ.get("STRIX_CLAUDE_CODE_TIMEOUT")
    if raw:
        try:
            value = float(raw)
        except ValueError:
            return _DEFAULT_TURN_TIMEOUT_S
        return value if value > 0 else _DEFAULT_TURN_TIMEOUT_S
    return _DEFAULT_TURN_TIMEOUT_S


# One semaphore per event loop. An asyncio.Semaphore binds to the loop it is
# first awaited on, so a single cached instance shared between the warm-up loop
# (`asyncio.run(warm_up_llm())`) and the separate scan loop would fail once it
# had waiters on both. Keyed by loop and auto-dropped when the loop is collected.
_sems: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, tuple[asyncio.Semaphore, int]] = (
    weakref.WeakKeyDictionary()
)


def _get_semaphore() -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    size = _max_procs()
    cached = _sems.get(loop)
    if cached is None or cached[1] != size:
        semaphore = asyncio.Semaphore(size)
        _sems[loop] = (semaphore, size)
        return semaphore
    return cached[0]


def _build_argv(slug: str, extra_args: list[str]) -> list[str]:
    binary = claude_code.binary_path()
    if binary is None:
        raise claude_code.ClaudeCodeError(
            "STRIX_LLM=claude-code/... needs the Claude Code CLI on PATH. "
            "Install it, then run `claude /login`."
        )
    schema = json.dumps(claude_bridge.RESULT_SCHEMA, separators=(",", ":"))
    return [binary, *_BASE_ARGS, "--model", slug, "--json-schema", schema, *extra_args]


def _run_blocking(argv: list[str], prompt: str, timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603  # trusted binary, fixed argv, no shell
        argv,
        input=prompt,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


async def run_turn(
    slug: str, prompt: str, *, extra_args: list[str] | None = None
) -> dict[str, Any]:
    """Run one ``claude -p`` turn and return its terminal ``result`` event.

    Raises :class:`claude_code.ClaudeCodeError` on a non-zero exit, a timeout, or
    a stream with no result event; the caller decodes it via ``claude_bridge``.
    """
    argv = _build_argv(slug, extra_args or [])
    timeout = _turn_timeout()
    async with _get_semaphore():
        try:
            completed = await asyncio.to_thread(_run_blocking, argv, prompt, timeout)
        except subprocess.TimeoutExpired as exc:
            raise claude_code.ClaudeCodeError(f"claude -p timed out after {timeout:.0f}s") from exc
        except OSError as exc:
            raise claude_code.ClaudeCodeError(f"could not launch claude -p: {exc}") from exc

    # A result event, if present, is authoritative even on a non-zero exit: the
    # CLI reports API errors (429/overload) in its api_error_status, and the model
    # layer decodes that into a retryable ClaudeStreamError. So try to parse it
    # first; only fall back to a generic error when there is no result event.
    try:
        return claude_bridge.parse_transcript(completed.stdout.splitlines())
    except claude_bridge.ClaudeStreamError as exc:
        if completed.returncode != 0:
            raise claude_code.ClaudeCodeError(
                f"claude -p exited with code {completed.returncode}: {_tail(completed.stderr)}"
            ) from exc
        raise claude_code.ClaudeCodeError(
            f"claude -p produced no result event (stderr: {_tail(completed.stderr)})"
        ) from exc


def _tail(stderr: str, *, limit: int = 400) -> str:
    text = stderr.strip()
    return text[-limit:] if text else "(no stderr)"

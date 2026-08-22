"""Subprocess transport for the Claude Code backend.

One ``claude -p`` invocation per Strix turn (the SDK model is stateless, Strix
resends the full conversation each turn, so a warm pipe would carry nothing).

The turn is a plain request/response (write the prompt, read all output), so it
runs as a **blocking** ``Popen.communicate`` inside ``asyncio.to_thread``. That
is deliberate: on Windows Strix forces a ``SelectorEventLoop``, which cannot
spawn subprocesses (``asyncio.create_subprocess_exec`` raises a bare
``NotImplementedError`` there), so the async-subprocess API is unusable. A
threaded blocking call works under any event-loop policy on every platform.

``Popen`` rather than ``subprocess.run`` because a thread cannot be cancelled:
holding the handle is the only way an abandoned turn can stop the child instead
of leaking it past the semaphore slot it already gave back.

A module-level semaphore bounds how many ``claude`` processes run at once so a
wide multi-agent graph doesn't fork an unbounded number of heavyweight CLIs.
"""

from __future__ import annotations

import asyncio
import contextlib
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


def _spawn(argv: list[str]) -> subprocess.Popen[str]:
    return subprocess.Popen(  # noqa: S603  # trusted binary, fixed argv, no shell
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _kill_if_running(process: subprocess.Popen[str]) -> None:
    """Kill the child unless it has already exited."""
    if process.poll() is not None:
        return
    with contextlib.suppress(OSError):
        process.kill()


def _communicate(
    process: subprocess.Popen[str], prompt: str, timeout: float
) -> subprocess.CompletedProcess[str]:
    """Feed the prompt in, read the streams out, and wait. Blocking; runs on a thread."""
    try:
        stdout, stderr = process.communicate(prompt, timeout=timeout)
    except subprocess.TimeoutExpired:
        # Popen.communicate() leaves the child running on timeout, unlike
        # subprocess.run(); reap it here so the timeout is not itself a leak.
        _kill_if_running(process)
        process.communicate()
        raise
    return subprocess.CompletedProcess(
        args=process.args, returncode=process.wait(), stdout=stdout, stderr=stderr
    )


async def _execute(
    argv: list[str], prompt: str, timeout: float
) -> subprocess.CompletedProcess[str]:
    """Run one bounded ``claude -p`` process, never leaving the child behind.

    Raises :class:`claude_code.ClaudeCodeError` if the process cannot be launched,
    times out, or fails mid-turn.
    """
    async with _get_semaphore():
        try:
            process = _spawn(argv)
        except OSError as exc:
            raise claude_code.ClaudeCodeError(f"could not launch claude -p: {exc}") from exc
        try:
            return await asyncio.to_thread(_communicate, process, prompt, timeout)
        except subprocess.TimeoutExpired as exc:
            raise claude_code.ClaudeCodeError(f"claude -p timed out after {timeout:.0f}s") from exc
        except OSError as exc:  # the child is already running, so this is a pipe failure
            raise claude_code.ClaudeCodeError(f"claude -p failed mid-turn: {exc}") from exc
        finally:
            # asyncio.to_thread cannot be cancelled: the worker thread runs to
            # completion whatever happens out here. On an outer timeout, a budget
            # stop, or a wind-down, this coroutine unwinds and releases its
            # semaphore slot at once, so without this kill the abandoned `claude`
            # keeps running for the rest of the turn timeout, still spending
            # subscription quota, and real concurrency can exceed
            # STRIX_CLAUDE_CODE_MAX_PROCS exactly when turns are being abandoned.
            # Killing it also lets the stranded worker thread finish.
            _kill_if_running(process)


def _decode_transcript(completed: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    """Pull the terminal ``result`` event out of a finished turn's stdout.

    A result event is authoritative even on a non-zero exit: the CLI reports API
    errors (429/overload) in its ``api_error_status``, and the model layer decodes
    that into a retryable ``ClaudeStreamError``. So parse first, and fall back to a
    generic error only when there is no result event to read.
    """
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


async def run_turn(
    slug: str, prompt: str, *, extra_args: list[str] | None = None
) -> dict[str, Any]:
    """Run one ``claude -p`` turn and return its terminal ``result`` event.

    Raises :class:`claude_code.ClaudeCodeError` on a non-zero exit, a timeout, or
    a stream with no result event; the caller decodes it via ``claude_bridge``.
    """
    argv = _build_argv(slug, extra_args or [])
    completed = await _execute(argv, prompt, _turn_timeout())
    return _decode_transcript(completed)


def _tail(stderr: str, *, limit: int = 400) -> str:
    text = stderr.strip()
    return text[-limit:] if text else "(no stderr)"

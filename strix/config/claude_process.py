"""Subprocess transport for the Claude Code backend.

One ``claude -p`` invocation per Strix turn (the SDK model is stateless, Strix
resends the full conversation each turn, so a warm pipe would carry nothing).

The turn is a plain request/response (write one message, read all output), so it
runs as a **blocking** ``Popen.communicate`` on a worker thread. That is
deliberate: on Windows Strix forces a ``SelectorEventLoop``, which cannot spawn
subprocesses (``asyncio.create_subprocess_exec`` raises a bare
``NotImplementedError`` there), so the async-subprocess API is unusable. A
threaded blocking call works under any event-loop policy on every platform. The
pool is this module's own, not asyncio's default, so a wide graph of turns
cannot starve every other threaded call in Strix.

``Popen`` rather than ``subprocess.run`` because a thread cannot be cancelled:
holding the handle is the only way an abandoned turn can stop the child instead
of leaking it past the semaphore slot it already gave back.

A module-level semaphore bounds how many ``claude`` processes run at once so a
wide multi-agent graph doesn't fork an unbounded number of heavyweight CLIs.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import json
import logging
import math
import os
import shutil
import subprocess  # we invoke a trusted, user-installed CLI, never a shell
import sys
import weakref
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from strix.config import claude_bridge, claude_code


logger = logging.getLogger(__name__)

_DEFAULT_MAX_PROCS = 8
# A single agent turn can involve real model latency; bound it generously so a
# genuinely hung subprocess still cannot wedge the run forever.
_DEFAULT_TURN_TIMEOUT_S = 900
# Reaping a killed child is a pipe read, so it gets its own small bound.
_KILL_TIMEOUT_S = 10
# taskkill either reaps the tree at once or not at all. This runs inline on the
# event loop, deliberately: the semaphore slot must not be released while the
# child is still alive, which is the leak the kill exists to prevent. Kept short
# so the worst case is a brief pause, not a stalled loop.
_TASKKILL_TIMEOUT_S = 3

_BASE_ARGS = (
    "-p",
    # stream-json in, so one turn can carry image content blocks beside its
    # prose; stream-json out, so the terminal result event carries the
    # structured output, the usage block and the cost.
    "--input-format",
    "stream-json",
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


def _usable_timeout(value: float | None) -> float | None:
    """``value`` when it is a positive, finite number of seconds, else None.

    ``float("inf")`` passes a bare ``> 0`` test but reaches
    ``Popen.communicate(timeout=...)`` as an OverflowError, killing every turn
    with an error that classifies as nothing at all.
    """
    if value is None or not math.isfinite(value) or value <= 0:
        return None
    return value


def _env_timeout() -> float | None:
    raw = os.environ.get("STRIX_CLAUDE_CODE_TIMEOUT")
    if not raw:
        return None
    try:
        return _usable_timeout(float(raw))
    except ValueError:
        return None


def _turn_timeout(requested: float | None = None) -> float:
    """Seconds to allow one turn.

    ``STRIX_CLAUDE_CODE_TIMEOUT`` wins, being this backend's own knob. Otherwise
    the caller's request timeout (``LLM_TIMEOUT``, which every other route
    honours) applies, and the generous default only backstops a turn nobody
    bounded. Without the caller's value a hung turn would burn the full default
    and then be retried, so one stuck turn could hold a run for over an hour.
    """
    return _env_timeout() or _usable_timeout(requested) or _DEFAULT_TURN_TIMEOUT_S


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


# The turn blocks a whole thread for its duration, so it gets its own pool rather
# than asyncio's default executor. That default is sized min(32, cpu_count + 4),
# which on a 2-core host is six workers against a default of eight concurrent
# turns: the transport would fill it and stall every other asyncio.to_thread in
# Strix (the notes, coverage, threat-model and reporting tools, and the TUI
# sidecar's process wait) behind a model call. Sized to the same bound as the
# semaphore, so a slot always has a thread waiting for it.
_executors: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, tuple[ThreadPoolExecutor, int]] = (
    weakref.WeakKeyDictionary()
)


def _get_executor(loop: asyncio.AbstractEventLoop) -> ThreadPoolExecutor:
    size = _max_procs()
    cached = _executors.get(loop)
    if cached is not None and cached[1] == size:
        return cached[0]
    if cached is not None:
        # Never wait: a resize must not block on turns still in flight, and the
        # old pool retires itself once they finish.
        cached[0].shutdown(wait=False)
    executor = ThreadPoolExecutor(max_workers=size, thread_name_prefix="strix-claude-code")
    _executors[loop] = (executor, size)
    return executor


def _build_argv(slug: str, extra_args: list[str], *, structured: bool = True) -> list[str]:
    binary = claude_code.binary_path()
    if binary is None:
        raise claude_code.ClaudeCodeError(
            "STRIX_LLM=claude-code/... needs the Claude Code CLI on PATH. "
            "Install it, then run `claude /login`.",
            retryable=False,
        )
    argv = [binary, *_BASE_ARGS, "--model", slug]
    if structured:
        # Only agent turns speak the {text, tool_calls} envelope. Forcing the
        # schema on a one-shot completion would bury the caller's answer inside it.
        schema = json.dumps(claude_bridge.RESULT_SCHEMA, separators=(",", ":"))
        argv += ["--json-schema", schema]
    return [*argv, *extra_args]


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


def _kill_windows_tree(pid: int) -> None:
    """Kill ``pid`` and its descendants on Windows.

    An npm install puts a ``claude.cmd`` shim on PATH, so the handle we hold is
    ``cmd.exe`` and killing it leaves the node grandchild alive, still holding
    the pipes and still spending quota; the reaping ``communicate()`` then waits
    on a pipe nobody will close. ``taskkill /T`` takes the whole tree.
    """
    taskkill = shutil.which("taskkill")
    if taskkill is None:  # pragma: no cover - present on every supported Windows
        return
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        subprocess.run(  # noqa: S603  # fixed argv, no shell
            [taskkill, "/F", "/T", "/PID", str(pid)],
            capture_output=True,
            check=False,
            timeout=_TASKKILL_TIMEOUT_S,
        )


def _kill_if_running(process: subprocess.Popen[str]) -> None:
    """Kill the child unless it has already exited."""
    if process.poll() is not None:
        return
    if sys.platform == "win32":
        _kill_windows_tree(process.pid)
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
        # Bounded, because the reaping read is itself a wait on the pipes.
        _kill_if_running(process)
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.communicate(timeout=_KILL_TIMEOUT_S)
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
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                _get_executor(loop), functools.partial(_communicate, process, prompt, timeout)
            )
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
        # split("\n"), not splitlines(): the latter also breaks on U+2028,
        # U+2029 and U+0085, which a model's own prose puts inside the JSON
        # result line, cutting it in two so no line parses as the result event.
        return claude_bridge.parse_transcript(completed.stdout.split("\n"))
    except claude_bridge.ClaudeStreamError as exc:
        if completed.returncode != 0:
            raise claude_code.ClaudeCodeError(
                f"claude -p exited with code {completed.returncode}: {_tail(completed.stderr)}"
            ) from exc
        raise claude_code.ClaudeCodeError(
            f"claude -p produced no result event (stderr: {_tail(completed.stderr)})"
        ) from exc


def _encode_message(message: dict[str, Any]) -> str:
    """The single ``stream-json`` line written to the child's stdin.

    ASCII-escaped deliberately. The CLI reads stdin a line at a time, and
    ``ensure_ascii=False`` would pass U+2028, U+2029 and U+0085 through as
    literals; a reader that treats those as line breaks, as several do, would
    see one message arrive as four unparseable fragments. A pentest turn carries
    captured page text and payloads, so those characters are not hypothetical.
    This is the same hazard the transcript decoder guards on the way back.
    """
    return json.dumps(message, separators=(",", ":")) + "\n"


async def run_turn(
    slug: str,
    message: dict[str, Any],
    *,
    extra_args: list[str] | None = None,
    structured: bool = True,
    timeout: float | None = None,
) -> dict[str, Any]:
    """Run one ``claude -p`` turn and return its terminal ``result`` event.

    ``message`` is the ``stream-json`` user message ``claude_bridge`` built.
    ``timeout`` is the caller's request timeout, applied unless
    ``STRIX_CLAUDE_CODE_TIMEOUT`` overrides it.
    ``structured`` selects the reply contract: agent turns force the
    ``{text, tool_calls}`` schema, one-shot completions return the model's own
    answer verbatim.

    Raises :class:`claude_code.ClaudeCodeError` on a non-zero exit, a timeout, or
    a stream with no result event; the caller decodes it via ``claude_bridge``.
    """
    argv = _build_argv(slug, extra_args or [], structured=structured)
    completed = await _execute(argv, _encode_message(message), _turn_timeout(timeout))
    return _decode_transcript(completed)


def _tail(stderr: str, *, limit: int = 400) -> str:
    text = stderr.strip()
    return text[-limit:] if text else "(no stderr)"

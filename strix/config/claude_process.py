"""Subprocess transport for the Claude Code backend.

One ``claude -p`` invocation per Strix turn (the SDK model is stateless — Strix
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
from typing import Any, cast

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


async def run_turn(slug: str, prompt: str, *, extra_args: list[str] | None = None) -> str:
    """Run one ``claude -p`` turn and return its terminal ``result`` line, unparsed.

    Raises :class:`claude_code.ClaudeCodeError` on a non-zero exit, a timeout, or
    a stream with no result line; the caller decodes the JSON via ``claude_bridge``.
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

    if completed.returncode != 0:
        raise claude_code.ClaudeCodeError(
            f"claude -p exited with code {completed.returncode}: {_tail(completed.stderr)}"
        )

    result_line = _extract_result_line(completed.stdout)
    if result_line is None:
        raise claude_code.ClaudeCodeError(
            f"claude -p produced no result line (stderr: {_tail(completed.stderr)})"
        )
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


def _tail(stderr: str, *, limit: int = 400) -> str:
    text = stderr.strip()
    return text[-limit:] if text else "(no stderr)"

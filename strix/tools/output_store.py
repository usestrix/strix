"""Bound oversized tool results before they enter agent history.

A single verbose tool result (a recursive ``find``, a noisy scanner, a full
page dump) can otherwise pin the whole conversation near the model's context
limit for the rest of the scan. Oversized results are spilled into the agent's
own sandbox at ``/workspace/.strix/tool-output/<id>.txt``; what the agent sees
is a head + tail slice plus the path, which it reads back on demand with its
normal file tools (``exec_command`` etc.) — so truncated detail is bounded in
history but never lost.

The spill writer is injected by the runner via :func:`configure_spill_writer`
once the sandbox session exists.
"""

from __future__ import annotations

import logging
import uuid
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


logger = logging.getLogger(__name__)

_TRUNCATION_NOTICE = "[... {lines} lines ({bytes} bytes) truncated ...]"
_WORKSPACE_SPILL_NOTICE = (
    "[... {lines} lines ({bytes} bytes) truncated — full output saved to {path} "
    "in the sandbox; read it with exec_command (e.g. `sed -n`, `grep`, `cat`) ...]"
)

# Where the workspace writer stores spilled output inside the sandbox. Fixed
# so a notice's byte size is known before the id is minted (see _head_tail).
WORKSPACE_SPILL_DIR = "/workspace/.strix/tool-output"

# A representative longest workspace path, used only to reserve notice bytes.
_SAMPLE_WORKSPACE_PATH = f"{WORKSPACE_SPILL_DIR}/{'0' * 32}.txt"

if TYPE_CHECKING:
    SpillWriter = Callable[[str, str], Awaitable[str | None]]

# Single-key holder so the writer can be swapped per scan without a
# module-level ``global`` rebind.
_spill: dict[str, SpillWriter] = {}


def configure_spill_writer(writer: SpillWriter | None) -> None:
    """Install (or clear) the sandbox-workspace spill writer.

    ``writer(output_id, text)`` persists ``text`` inside the sandbox and returns
    the path the agent can read, or ``None`` if the write failed.
    """
    if writer is None:
        _spill.pop("writer", None)
    else:
        _spill["writer"] = writer


def _byte_len(text: str) -> int:
    return len(text.encode("utf-8"))


def _take_prefix(text: str, max_bytes: int) -> str:
    budget = 0
    out: list[str] = []
    for char in text:
        size = len(char.encode("utf-8"))
        if budget + size > max_bytes:
            break
        out.append(char)
        budget += size
    return "".join(out)


def _take_suffix(text: str, max_bytes: int) -> str:
    budget = 0
    out: list[str] = []
    for char in reversed(text):
        size = len(char.encode("utf-8"))
        if budget + size > max_bytes:
            break
        out.append(char)
        budget += size
    out.reverse()
    return "".join(out)


def _head_tail(
    text: str,
    max_lines: int,
    max_bytes: int,
    *,
    notice_templates: tuple[str, ...] = (_TRUNCATION_NOTICE,),
) -> tuple[str, str, int, int] | None:
    """Head/tail slices plus dropped line/byte counts, or ``None`` if small.

    ``max_bytes`` bounds the *entire* joined result, so the notice and its two
    blank-line separators are reserved out of the byte budget before slicing —
    otherwise ``head + tail`` alone could already consume the whole budget and
    the appended metadata would push the persisted value over ``max_bytes``.
    The largest of ``notice_templates`` is reserved so the preview fits whichever
    notice the caller ends up using (workspace path or plain). ``max_bytes`` must
    be large enough to hold the notice itself (guaranteed by the
    ``tool_output_max_bytes`` config floor).
    """
    lines = text.split("\n")
    total_bytes = _byte_len(text)
    if len(lines) <= max_lines and total_bytes <= max_bytes:
        return None

    # Upper-bound the notice size using the largest possible counts (and a
    # full-length path); the real notice is never longer. ``+ 4`` covers the
    # two ``\n\n`` separators added by ``_join``.
    notice_overhead = (
        max(
            _byte_len(
                template.format(
                    lines=len(lines),
                    bytes=total_bytes,
                    path=_SAMPLE_WORKSPACE_PATH,
                )
            )
            for template in notice_templates
        )
        + 4
    )
    byte_budget = max(2, max_bytes - notice_overhead)

    head_lines = max(1, max_lines // 2)
    tail_lines = max_lines - head_lines
    head = "\n".join(lines[:head_lines])
    tail = "\n".join(lines[len(lines) - tail_lines :]) if tail_lines > 0 else ""

    # Enforce the byte budget even when the line count alone was fine.
    half_bytes = max(1, byte_budget // 2)
    if _byte_len(head) > half_bytes:
        head = _take_prefix(head, half_bytes)
    if tail and _byte_len(tail) > half_bytes:
        tail = _take_suffix(tail, half_bytes)

    # Count kept lines from the final slices: the byte pass above may have
    # dropped whole lines from head/tail, so deriving this from the original
    # head_lines/tail_lines would undercount what was actually removed.
    kept_lines = len(head.split("\n")) + (len(tail.split("\n")) if tail else 0)
    dropped_lines = max(0, len(lines) - kept_lines)
    dropped_bytes = max(0, total_bytes - _byte_len(head) - _byte_len(tail))
    return head, tail, dropped_lines, dropped_bytes


def _join(head: str, tail: str, notice: str) -> str:
    return f"{head}\n\n{notice}\n\n{tail}" if tail else f"{head}\n\n{notice}"


def bound_text(text: str, *, max_lines: int, max_bytes: int) -> str:
    """Return ``text`` unchanged when small, else a head+tail preview.

    Truncation happens on whichever limit is hit first (line count or UTF-8
    byte size). The removed middle is replaced with a notice recording how
    many lines and bytes were dropped so the agent knows output was elided.
    Nothing is persisted; use :func:`bound_and_store` to keep the full output.
    """
    parts = _head_tail(text, max_lines, max_bytes)
    if parts is None:
        return text
    head, tail, dropped_lines, dropped_bytes = parts
    return _join(head, tail, _TRUNCATION_NOTICE.format(lines=dropped_lines, bytes=dropped_bytes))


async def bound_and_store(text: str, *, max_lines: int, max_bytes: int) -> str:
    """Like :func:`bound_text`, but spill the full output into the sandbox.

    Writes the complete output to ``/workspace/.strix/tool-output/<id>.txt`` via
    the configured sandbox writer and points the agent at that path so it reads
    the elided detail with its own file tools. If no writer is configured or the
    write fails, degrades to a plain head+tail preview (nothing persisted).
    """
    parts = _head_tail(
        text,
        max_lines,
        max_bytes,
        notice_templates=(_WORKSPACE_SPILL_NOTICE, _TRUNCATION_NOTICE),
    )
    if parts is None:
        return text
    head, tail, dropped_lines, dropped_bytes = parts

    writer = _spill.get("writer")
    if writer is not None:
        path = await writer(uuid.uuid4().hex, text)
        if path is not None:
            notice = _WORKSPACE_SPILL_NOTICE.format(
                lines=dropped_lines, bytes=dropped_bytes, path=path
            )
            return _join(head, tail, notice)

    return _join(head, tail, _TRUNCATION_NOTICE.format(lines=dropped_lines, bytes=dropped_bytes))

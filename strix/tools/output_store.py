"""Bound oversized tool results before they enter agent history.

Oversized results are spilled into the sandbox at
``/workspace/.strix/tool-output/<id>.txt``; the agent sees a head + tail slice
plus the path and reads the rest back with its own file tools. The spill writer
is injected by the runner via :func:`configure_spill_writer`.
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

WORKSPACE_SPILL_DIR = "/workspace/.strix/tool-output"

# Longest possible workspace path, used only to reserve notice bytes.
_SAMPLE_WORKSPACE_PATH = f"{WORKSPACE_SPILL_DIR}/{'0' * 32}.txt"

if TYPE_CHECKING:
    SpillWriter = Callable[[str, str], Awaitable[str | None]]

_spill: dict[str, SpillWriter] = {}


def configure_spill_writer(writer: SpillWriter | None) -> None:
    """Install (or clear) the sandbox-workspace spill writer."""
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

    ``max_bytes`` bounds the entire joined result; the largest of
    ``notice_templates`` (plus separators) is reserved before slicing.
    """
    lines = text.split("\n")
    total_bytes = _byte_len(text)
    if len(lines) <= max_lines and total_bytes <= max_bytes:
        return None

    # Reserve using the largest counts/path; ``+ 4`` covers the two "\n\n".
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

    half_bytes = max(1, byte_budget // 2)
    if _byte_len(head) > half_bytes:
        head = _take_prefix(head, half_bytes)
    if tail and _byte_len(tail) > half_bytes:
        tail = _take_suffix(tail, half_bytes)

    # Count from the final slices; the byte pass may have dropped whole lines.
    kept_lines = len(head.split("\n")) + (len(tail.split("\n")) if tail else 0)
    dropped_lines = max(0, len(lines) - kept_lines)
    dropped_bytes = max(0, total_bytes - _byte_len(head) - _byte_len(tail))
    return head, tail, dropped_lines, dropped_bytes


def _join(head: str, tail: str, notice: str) -> str:
    return f"{head}\n\n{notice}\n\n{tail}" if tail else f"{head}\n\n{notice}"


def bound_text(text: str, *, max_lines: int, max_bytes: int) -> str:
    """Return ``text`` unchanged when small, else a head+tail preview.

    Nothing is persisted; use :func:`bound_and_store` to keep the full output.
    """
    parts = _head_tail(text, max_lines, max_bytes)
    if parts is None:
        return text
    head, tail, dropped_lines, dropped_bytes = parts
    return _join(head, tail, _TRUNCATION_NOTICE.format(lines=dropped_lines, bytes=dropped_bytes))


async def bound_and_store(text: str, *, max_lines: int, max_bytes: int) -> str:
    """Like :func:`bound_text`, but spill the full output into the sandbox and
    point the agent at its path. Degrades to a plain preview if the spill fails.
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

"""Bound oversized tool results before they enter agent history.

A single verbose tool result (a recursive ``find``, a noisy scanner, a full
page dump) can otherwise pin the whole conversation near the model's context
limit for the rest of the scan. Oversized results are spilled to a per-scan
store on disk; what the agent sees is a head + tail slice plus an id it can
pass to ``read_tool_output`` to page through the full content on demand — so
truncated detail is bounded in history but never lost.
"""

from __future__ import annotations

import itertools
import logging
import re
import uuid
from pathlib import Path


logger = logging.getLogger(__name__)

_TRUNCATION_NOTICE = "[... {lines} lines ({bytes} bytes) truncated ...]"
_SPILL_NOTICE = (
    "[... {lines} lines ({bytes} bytes) truncated — full output saved as "
    'output_id="{output_id}"; read it with read_tool_output(output_id="{output_id}") ...]'
)

_OUTPUT_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_DEFAULT_STORE_DIR = Path.home() / ".strix" / "tool-output"

# Ceilings for a single retrieval page, so a page of very long lines can't
# itself overflow history. Applied without spilling (no new output_id), or
# paging would loop forever.
_PAGE_MAX_LINES = 2_000
_PAGE_MAX_BYTES = 50 * 1024

# Single-key holder so the configured path can be swapped per scan without a
# module-level ``global`` rebind.
_config: dict[str, Path] = {}


def configure_output_store(directory: Path) -> None:
    """Point the tool-output store at ``directory`` (created on demand)."""
    _config["dir"] = directory


def _active_store_dir() -> Path:
    directory = _config.get("dir", _DEFAULT_STORE_DIR)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


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
    text: str, max_lines: int, max_bytes: int, *, notice_template: str = _TRUNCATION_NOTICE
) -> tuple[str, str, int, int] | None:
    """Head/tail slices plus dropped line/byte counts, or ``None`` if small.

    ``max_bytes`` bounds the *entire* joined result, so the notice and its two
    blank-line separators are reserved out of the byte budget before slicing —
    otherwise ``head + tail`` alone could already consume the whole budget and
    the appended metadata would push the persisted value over ``max_bytes``.
    ``max_bytes`` must be large enough to hold the notice itself (guaranteed by
    the ``tool_output_max_bytes`` config floor).
    """
    lines = text.split("\n")
    total_bytes = _byte_len(text)
    if len(lines) <= max_lines and total_bytes <= max_bytes:
        return None

    # Upper-bound the notice size using the largest possible counts (and a
    # full-length id); the real notice is never longer. ``+ 4`` covers the two
    # ``\n\n`` separators added by ``_join``.
    notice_overhead = (
        _byte_len(notice_template.format(lines=len(lines), bytes=total_bytes, output_id="0" * 32))
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


def store_full_output(text: str) -> str | None:
    """Persist ``text`` and return its output id, or ``None`` if writing fails."""
    output_id = uuid.uuid4().hex
    try:
        (_active_store_dir() / f"{output_id}.txt").write_text(text, encoding="utf-8")
    except OSError:
        logger.exception("failed to persist oversized tool output")
        return None
    return output_id


def bound_and_store(text: str, *, max_lines: int, max_bytes: int) -> str:
    """Like :func:`bound_text`, but spill the full output and reference its id.

    When truncation happens the complete output is written to the store and the
    preview's notice tells the agent the ``output_id`` to pass to
    ``read_tool_output``. Falls back to a plain preview if the spill fails.
    """
    # Reserve for the (longer) spill notice so the preview honours max_bytes
    # whether or not the spill succeeds.
    parts = _head_tail(text, max_lines, max_bytes, notice_template=_SPILL_NOTICE)
    if parts is None:
        return text
    head, tail, dropped_lines, dropped_bytes = parts
    output_id = store_full_output(text)
    notice = (
        _SPILL_NOTICE.format(lines=dropped_lines, bytes=dropped_bytes, output_id=output_id)
        if output_id is not None
        else _TRUNCATION_NOTICE.format(lines=dropped_lines, bytes=dropped_bytes)
    )
    return _join(head, tail, notice)


def read_stored_output(output_id: str, *, offset: int = 0, limit: int = 2_000) -> str:
    """Return up to ``limit`` lines of a stored output starting at ``offset``.

    ``output_id`` must be a token previously returned in a truncation notice;
    it is validated to prevent path traversal.
    """
    if not _OUTPUT_ID_RE.match(output_id):
        return f"Invalid output_id: {output_id!r}"
    path = _active_store_dir() / f"{output_id}.txt"
    if not path.is_file():
        return f"No stored output for output_id={output_id!r} (it may have expired)."

    start = max(0, offset)
    count = min(max(1, limit), _PAGE_MAX_LINES)
    with path.open(encoding="utf-8") as handle:
        # Stream to the window instead of materialising the whole file per page.
        for _ in itertools.islice(handle, start):
            pass
        window = [line.rstrip("\n") for line in itertools.islice(handle, count)]
        remaining = sum(1 for _ in handle)

    # Bound the page's byte size with a plain notice (never a spill id) so a
    # page of very long lines stays within history without re-triggering spill.
    shown = bound_text("\n".join(window), max_lines=_PAGE_MAX_LINES, max_bytes=_PAGE_MAX_BYTES)
    if remaining > 0:
        shown += f"\n\n[... {remaining} more lines; call read_tool_output(output_id="
        shown += f'"{output_id}", offset={start + len(window)}) to continue ...]'
    return shown

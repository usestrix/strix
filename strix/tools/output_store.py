"""Bound oversized tool results before they enter agent history.

A single verbose tool result (a recursive ``find``, a noisy scanner, a full
page dump) can otherwise pin the whole conversation near the model's context
limit for the rest of the scan. Oversized results are spilled to a per-scan
store on disk; what the agent sees is a head + tail slice plus an id it can
pass to ``read_tool_output`` to page through the full content on demand — so
truncated detail is bounded in history but never lost.
"""

from __future__ import annotations

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

# Byte ceiling for a single retrieval page so retrieval itself can never
# overflow history — even for one very long line. Retrieval pages by byte
# offset (not by line) precisely so an oversized line is split across pages
# instead of returned whole.
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


def _trim_incomplete_utf8_head(chunk: bytes) -> bytes:
    """Drop leading continuation bytes so a chunk starting mid-character decodes cleanly.

    A caller-supplied ``offset`` can land inside a multi-byte character; its
    orphaned continuation bytes (0b10xxxxxx) belong to a character whose lead
    byte is before ``offset``, so we skip forward to the next character start
    instead of emitting replacement characters.
    """
    index = 0
    while index < len(chunk) and chunk[index] & 0xC0 == 0x80:
        index += 1
    return chunk[index:]


def _trim_incomplete_utf8_tail(chunk: bytes) -> bytes:
    """Drop a trailing partial UTF-8 sequence so ``chunk`` decodes cleanly.

    A fixed byte window can land in the middle of a multi-byte character; the
    incomplete tail bytes are dropped here and re-read on the next page (the
    caller advances the offset by the *kept* length), so nothing is lost.
    """
    # A UTF-8 char is 1-4 bytes; scan back over continuation bytes (0b10xxxxxx)
    # to the last lead byte, then keep it only if the whole char is present.
    index = len(chunk) - 1
    steps = 0
    while index >= 0 and chunk[index] & 0xC0 == 0x80 and steps < 3:
        index -= 1
        steps += 1
    if index < 0:
        return chunk
    lead = chunk[index]
    if lead & 0x80 == 0x00:
        expected = 1
    elif lead & 0xE0 == 0xC0:
        expected = 2
    elif lead & 0xF0 == 0xE0:
        expected = 3
    elif lead & 0xF8 == 0xF0:
        expected = 4
    else:
        return chunk  # invalid lead byte; leave for errors="replace" to handle
    if len(chunk) - index < expected:
        return chunk[:index]
    return chunk


def read_stored_output(output_id: str, *, offset: int = 0, limit: int = _PAGE_MAX_BYTES) -> str:
    """Return a bounded byte-window of a stored output starting at byte ``offset``.

    ``output_id`` must be a token previously returned in a truncation notice; it
    is validated to prevent path traversal. The page is bounded by a UTF-8 byte
    budget (``limit``, capped at ``_PAGE_MAX_BYTES``) so it can never overflow
    history — even a single very long line is split across pages rather than
    returned whole. Paging forward with the printed ``offset`` hint reconstructs
    the full output byte-for-byte.
    """
    if not _OUTPUT_ID_RE.match(output_id):
        return f"Invalid output_id: {output_id!r}"
    path = _active_store_dir() / f"{output_id}.txt"
    if not path.is_file():
        return f"No stored output for output_id={output_id!r} (it may have expired)."

    start = max(0, offset)
    size = path.stat().st_size
    if start >= size:
        return ""
    # Floor at 4 bytes (the max UTF-8 char length) so a page always makes
    # progress past a single multi-byte character.
    budget = min(max(4, limit), _PAGE_MAX_BYTES)
    with path.open("rb") as handle:
        handle.seek(start)
        chunk = handle.read(budget)

    has_more = start + len(chunk) < size
    if has_more:
        chunk = _trim_incomplete_utf8_tail(chunk)
    next_offset = start + len(chunk)
    # Drop a partial leading character when an arbitrary offset lands mid-char.
    # This never removes content: the previous page's tail-trim guarantees a
    # forward-paged offset starts on a boundary, so this only affects an
    # explicit caller-chosen offset (whose partial char began on an earlier page).
    if start > 0:
        chunk = _trim_incomplete_utf8_head(chunk)
    shown = chunk.decode("utf-8", errors="replace")
    if has_more:
        shown += (
            "\n\n[... more; call read_tool_output("
            f'output_id="{output_id}", offset={next_offset}) to continue ...]'
        )
    return shown

"""Bound oversized tool results before they enter agent history.

A single verbose tool result (a recursive ``find``, a noisy scanner, a full
page dump) can otherwise pin the whole conversation near the model's context
limit for the rest of the scan. Oversized results are spilled to durable
storage; what the agent sees is a head + tail slice plus a pointer to the full
content it can retrieve on demand — so truncated detail is bounded in history
but never lost.

Two spill backends exist:

* **Sandbox workspace (preferred):** the full output is written into the
  agent's own sandbox at ``/workspace/.strix/tool-output/<id>.txt`` and the
  agent reads it back with its normal file tools (``exec_command`` etc.). A
  writer is injected by the runner via :func:`configure_spill_writer` once the
  sandbox session exists.
* **Host-side store (fallback):** when no sandbox writer is configured (unit
  tests, chat mode), the output is kept host-side and retrieved through the
  ``read_tool_output`` tool.
"""

from __future__ import annotations

import logging
import re
import uuid
from pathlib import Path
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


logger = logging.getLogger(__name__)

_TRUNCATION_NOTICE = "[... {lines} lines ({bytes} bytes) truncated ...]"
_SPILL_NOTICE = (
    "[... {lines} lines ({bytes} bytes) truncated — full output saved as "
    'output_id="{output_id}"; read it with read_tool_output(output_id="{output_id}") ...]'
)
_WORKSPACE_SPILL_NOTICE = (
    "[... {lines} lines ({bytes} bytes) truncated — full output saved to {path} "
    "in the sandbox; read it with exec_command (e.g. `sed -n`, `grep`, `cat`) ...]"
)

# Where the workspace writer stores spilled output inside the sandbox. Fixed
# so a notice's byte size is known before the id is minted (see _head_tail).
WORKSPACE_SPILL_DIR = "/workspace/.strix/tool-output"

_OUTPUT_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_DEFAULT_STORE_DIR = Path.home() / ".strix" / "tool-output"

# A representative longest workspace path, used only to reserve notice bytes.
_SAMPLE_WORKSPACE_PATH = f"{WORKSPACE_SPILL_DIR}/{'0' * 32}.txt"

# Byte ceiling for a single retrieval page so retrieval itself can never
# overflow history — even for one very long line. Retrieval pages by byte
# offset (not by line) precisely so an oversized line is split across pages
# instead of returned whole.
_PAGE_MAX_BYTES = 50 * 1024

# Appended to a non-final page so the agent can request the next one. Its bytes
# are reserved out of the page budget so a full page plus this hint still fits
# ``_PAGE_MAX_BYTES``.
_CONTINUATION_HINT = (
    "\n\n[... more; call read_tool_output("
    'output_id="{output_id}", offset={offset}) to continue ...]'
)

# Single-key holders so configuration can be swapped per scan without a
# module-level ``global`` rebind.
_config: dict[str, Path] = {}

if TYPE_CHECKING:
    SpillWriter = Callable[[str, str], Awaitable[str | None]]

_spill: dict[str, SpillWriter] = {}


def configure_output_store(directory: Path) -> None:
    """Point the host-side (fallback) tool-output store at ``directory``."""
    _config["dir"] = directory


def configure_spill_writer(writer: SpillWriter | None) -> None:
    """Install (or clear) the sandbox-workspace spill writer.

    ``writer(output_id, text)`` persists ``text`` inside the sandbox and returns
    the path the agent can read, or ``None`` if the write failed (so the caller
    falls back to the host-side store).
    """
    if writer is None:
        _spill.pop("writer", None)
    else:
        _spill["writer"] = writer


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
    notice the caller ends up using (workspace path, host id, or plain).
    ``max_bytes`` must be large enough to hold the notice itself (guaranteed by
    the ``tool_output_max_bytes`` config floor).
    """
    lines = text.split("\n")
    total_bytes = _byte_len(text)
    if len(lines) <= max_lines and total_bytes <= max_bytes:
        return None

    # Upper-bound the notice size using the largest possible counts (and a
    # full-length id/path); the real notice is never longer. ``+ 4`` covers the
    # two ``\n\n`` separators added by ``_join``.
    notice_overhead = (
        max(
            _byte_len(
                template.format(
                    lines=len(lines),
                    bytes=total_bytes,
                    output_id="0" * 32,
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


def store_full_output(text: str, *, output_id: str | None = None) -> str | None:
    """Persist ``text`` host-side and return its output id, or ``None`` on error."""
    output_id = output_id or uuid.uuid4().hex
    try:
        (_active_store_dir() / f"{output_id}.txt").write_text(text, encoding="utf-8")
    except OSError:
        logger.exception("failed to persist oversized tool output")
        return None
    return output_id


async def bound_and_store(
    text: str,
    *,
    max_lines: int,
    max_bytes: int,
    allow_workspace_spill: bool = False,
) -> str:
    """Like :func:`bound_text`, but spill the full output and point at it.

    When ``allow_workspace_spill`` is set (only for sandbox-origin tools whose
    output already lived inside the sandbox), prefers the sandbox-workspace
    writer so the agent reads the file with its own tools. Orchestrator-side
    tool output must never be written into the hostile sandbox, so it always
    uses the host-side store + ``read_tool_output`` fallback. The fallback is
    also used when no writer is configured or the workspace write fails.
    """
    parts = _head_tail(
        text,
        max_lines,
        max_bytes,
        notice_templates=(_WORKSPACE_SPILL_NOTICE, _SPILL_NOTICE, _TRUNCATION_NOTICE),
    )
    if parts is None:
        return text
    head, tail, dropped_lines, dropped_bytes = parts
    output_id = uuid.uuid4().hex

    writer = _spill.get("writer") if allow_workspace_spill else None
    if writer is not None:
        path = await writer(output_id, text)
        if path is not None:
            notice = _WORKSPACE_SPILL_NOTICE.format(
                lines=dropped_lines, bytes=dropped_bytes, path=path
            )
            return _join(head, tail, notice)

    stored = store_full_output(text, output_id=output_id)
    notice = (
        _SPILL_NOTICE.format(lines=dropped_lines, bytes=dropped_bytes, output_id=stored)
        if stored is not None
        else _TRUNCATION_NOTICE.format(lines=dropped_lines, bytes=dropped_bytes)
    )
    return _join(head, tail, notice)


def _boundary_offset(path: Path, offset: int) -> int:
    """Advance ``offset`` past a partial leading character to the next boundary.

    A caller-supplied offset can land inside a multi-byte character; its orphaned
    continuation bytes (0b10xxxxxx) belong to a character whose lead byte is
    earlier, so we skip forward to the next character start. This keeps the page
    on a real boundary (no replacement characters) and guarantees each page makes
    forward progress. A UTF-8 char is at most 4 bytes, so at most 3 continuation
    bytes are ever skipped. Forward-paged offsets already sit on a boundary, so
    this only affects an explicit caller-chosen offset.
    """
    with path.open("rb") as handle:
        handle.seek(offset)
        lead = handle.read(3)
    skip = 0
    while skip < len(lead) and lead[skip] & 0xC0 == 0x80:
        skip += 1
    return offset + skip


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
    is validated to prevent path traversal. The *complete* response — content
    plus any continuation hint — is bounded by a UTF-8 byte budget (``limit``,
    capped at ``_PAGE_MAX_BYTES``) so it can never overflow history; even a
    single very long line is split across pages rather than returned whole.
    Paging forward with the printed ``offset`` hint reconstructs the full output
    byte-for-byte.
    """
    if not _OUTPUT_ID_RE.match(output_id):
        return f"Invalid output_id: {output_id!r}"
    path = _active_store_dir() / f"{output_id}.txt"
    if not path.is_file():
        return f"No stored output for output_id={output_id!r} (it may have expired)."

    size = path.stat().st_size
    start = _boundary_offset(path, max(0, offset)) if offset > 0 else 0
    if start >= size:
        return ""

    effective = min(max(4, limit), _PAGE_MAX_BYTES)
    # A final page carries no continuation hint, so the whole remaining output
    # can use the budget and any limit is honoured exactly.
    if size - start <= effective:
        with path.open("rb") as handle:
            handle.seek(start)
            return handle.read().decode("utf-8", errors="replace")

    # A non-final page's complete response is content + a continuation hint, and
    # the whole thing must fit ``effective``. next_offset can never exceed the
    # file size, so formatting with ``size`` is an exact upper bound on the hint.
    # A page needs at least one char (4 bytes) of content to make progress, so a
    # limit too small to hold that plus the hint is rejected rather than silently
    # exceeded.
    hint_reserve = len(_CONTINUATION_HINT.format(output_id=output_id, offset=size))
    content_budget = effective - hint_reserve
    if content_budget < 4:
        return (
            f"limit={limit} is too small to page this output; "
            f"request at least {hint_reserve + 4} bytes."
        )
    with path.open("rb") as handle:
        handle.seek(start)
        chunk = _trim_incomplete_utf8_tail(handle.read(content_budget))
    next_offset = start + len(chunk)
    return chunk.decode("utf-8", errors="replace") + _CONTINUATION_HINT.format(
        output_id=output_id, offset=next_offset
    )

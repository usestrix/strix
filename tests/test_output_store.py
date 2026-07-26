"""Tests for per-tool-output bounding and the durable spill store."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from strix.tools.output_store import (
    _PAGE_MAX_BYTES,
    bound_and_store,
    bound_text,
    configure_output_store,
    read_stored_output,
)


if TYPE_CHECKING:
    from pathlib import Path


def test_small_output_passes_through_unchanged() -> None:
    text = "line 1\nline 2\nline 3"
    assert bound_text(text, max_lines=100, max_bytes=10_000) == text


def test_line_limit_keeps_head_and_tail() -> None:
    text = "\n".join(str(i) for i in range(1000))
    bounded = bound_text(text, max_lines=10, max_bytes=1_000_000)

    assert bounded.startswith("0\n1\n2\n3\n4")
    assert bounded.rstrip().endswith("999")
    assert "truncated" in bounded
    assert len(bounded.splitlines()) < 30


def test_byte_limit_enforced_on_single_long_line() -> None:
    text = "x" * 100_000
    bounded = bound_text(text, max_lines=2_000, max_bytes=1_000)

    assert "truncated" in bounded
    assert len(bounded.encode("utf-8")) <= 1_000


def test_spill_preview_honours_byte_budget(tmp_path: Path) -> None:
    # bound_and_store's notice is longer (it carries the output_id), so the
    # preview must reserve for the spill notice to stay within max_bytes.
    configure_output_store(tmp_path)
    text = "\n".join("x" * 500 for _ in range(200))
    bounded = bound_and_store(text, max_lines=2_000, max_bytes=2_000)

    assert "output_id=" in bounded
    assert len(bounded.encode("utf-8")) <= 2_000


def test_multibyte_characters_not_split() -> None:
    text = "😀" * 50_000
    bounded = bound_text(text, max_lines=2_000, max_bytes=1_000)

    # Must remain valid UTF-8 (no mid-character cut).
    assert bounded == bounded.encode("utf-8").decode("utf-8")
    assert "truncated" in bounded


def test_notice_reports_dropped_counts() -> None:
    text = "\n".join("y" * 10 for _ in range(500))
    bounded = bound_text(text, max_lines=10, max_bytes=1_000_000)

    assert "lines" in bounded
    assert "bytes" in bounded


def test_dropped_line_count_accounts_for_byte_trimming() -> None:
    # Tight byte budget drops whole lines from head/tail; the notice must count them.
    text = "\n".join(f"line-{i}" for i in range(200))
    bounded = bound_text(text, max_lines=20, max_bytes=40)

    match = re.search(r"\[\.\.\. (\d+) lines", bounded)
    assert match is not None, bounded
    dropped = int(match.group(1))
    kept = [ln for ln in bounded.splitlines() if ln and "truncated" not in ln]
    assert dropped == 200 - len(kept)
    assert dropped > 200 - 20


def test_bound_and_store_small_output_not_spilled(tmp_path: Path) -> None:
    configure_output_store(tmp_path)
    text = "just a few lines\nsecond line"
    assert bound_and_store(text, max_lines=100, max_bytes=10_000) == text
    assert list(tmp_path.iterdir()) == []


def test_bound_and_store_spills_full_output_and_is_retrievable(tmp_path: Path) -> None:
    configure_output_store(tmp_path)
    text = "\n".join(f"secret-line-{i}" for i in range(1000))

    bounded = bound_and_store(text, max_lines=10, max_bytes=1_000_000)

    match = re.search(r'output_id="([0-9a-f]{32})"', bounded)
    assert match is not None, bounded
    output_id = match.group(1)

    # The full, untruncated output round-trips through the store.
    full = read_stored_output(output_id, offset=0, limit=1_000_000)
    assert full.splitlines() == text.splitlines()
    # A buried line elided from the preview is retrievable.
    assert "secret-line-500" not in bounded
    assert "secret-line-500" in full


def test_read_stored_output_paginates(tmp_path: Path) -> None:
    configure_output_store(tmp_path)
    text = "\n".join(str(i) for i in range(100))
    output_id = re.search(
        r'output_id="([0-9a-f]{32})"',
        bound_and_store(text, max_lines=4, max_bytes=1_000_000),
    )
    assert output_id is not None
    page = read_stored_output(output_id.group(1), offset=0, limit=10)
    assert page.startswith("0\n1")
    assert "more;" in page
    assert "offset=10" in page


def test_read_stored_output_page_including_hint_stays_within_ceiling(tmp_path: Path) -> None:
    # A full non-final page plus its continuation hint must not exceed the page
    # ceiling — retrieval bypasses the general result-bounding wrapper.
    configure_output_store(tmp_path)
    text = "x" * (_PAGE_MAX_BYTES * 3)
    output_id = re.search(
        r'output_id="([0-9a-f]{32})"',
        bound_and_store(text, max_lines=4, max_bytes=1_000),
    )
    assert output_id is not None
    page = read_stored_output(output_id.group(1), offset=0, limit=_PAGE_MAX_BYTES)
    assert "more;" in page  # a hint was appended (non-final page)
    assert len(page.encode("utf-8")) <= _PAGE_MAX_BYTES


def test_read_stored_output_pages_long_lines_losslessly(tmp_path: Path) -> None:
    # A single line far larger than the page budget must be split across pages
    # (never returned whole), and paging forward must reconstruct the output
    # byte-for-byte without ever minting a fresh spill id.
    configure_output_store(tmp_path)
    text = "\n".join(f"{i}-" + "z" * 5_000 for i in range(50))
    output_id = re.search(
        r'output_id="([0-9a-f]{32})"',
        bound_and_store(text, max_lines=4, max_bytes=1_000),
    )
    assert output_id is not None
    oid = output_id.group(1)

    collected = ""
    offset = 0
    for _ in range(500):  # guard against a paging loop
        page = read_stored_output(oid, offset=offset, limit=2_000)
        body, _sep, hint = page.partition("\n\n[... more;")
        # Every page honours the byte budget, even inside one oversized line.
        assert len(body.encode("utf-8")) <= 2_000
        assert re.findall(r'output_id="([0-9a-f]{32})"', body) in ([], [oid])
        collected += body
        if not hint:
            break
        match = re.search(r"offset=(\d+)", hint)
        assert match is not None
        offset = int(match.group(1))

    assert collected == text


def test_read_stored_output_pages_multibyte_without_corruption(tmp_path: Path) -> None:
    # A byte window can split a 4-byte char; paging must never emit a broken
    # (replacement) character and must still reconstruct the text exactly.
    configure_output_store(tmp_path)
    text = "😀" * 20_000
    output_id = re.search(
        r'output_id="([0-9a-f]{32})"',
        bound_and_store(text, max_lines=4, max_bytes=1_000),
    )
    assert output_id is not None
    oid = output_id.group(1)

    collected = ""
    offset = 0
    for _ in range(500):  # guard against a paging loop
        page = read_stored_output(oid, offset=offset, limit=1_002)  # not a multiple of 4
        body, _sep, hint = page.partition("\n\n[... more;")
        assert "\ufffd" not in body
        assert len(body.encode("utf-8")) <= 1_002
        collected += body
        if not hint:
            break
        match = re.search(r"offset=(\d+)", hint)
        assert match is not None
        offset = int(match.group(1))

    assert collected == text


def test_read_stored_output_offset_inside_char_returns_valid_utf8(tmp_path: Path) -> None:
    # An arbitrary caller-chosen offset that lands inside a 4-byte char must skip
    # the partial leading char rather than emit a replacement character.
    configure_output_store(tmp_path)
    text = "😀" * 100
    output_id = re.search(
        r'output_id="([0-9a-f]{32})"',
        bound_and_store(text, max_lines=4, max_bytes=200),
    )
    assert output_id is not None
    oid = output_id.group(1)

    # Byte 1 is inside the first emoji (each 😀 is 4 bytes).
    page = read_stored_output(oid, offset=1, limit=1_000)
    body = page.partition("\n\n[... more;")[0]
    assert "\ufffd" not in body
    assert body == body.encode("utf-8").decode("utf-8")
    # The partial leading char is skipped; content resumes at the next boundary.
    assert body.startswith("😀")


def test_read_stored_output_rejects_traversal(tmp_path: Path) -> None:
    configure_output_store(tmp_path)
    assert "Invalid output_id" in read_stored_output("../../etc/passwd")


def test_read_stored_output_missing_id(tmp_path: Path) -> None:
    configure_output_store(tmp_path)
    assert "No stored output" in read_stored_output("0" * 32)

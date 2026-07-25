"""Tests for per-tool-output bounding and the durable spill store."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from strix.tools import output_store as _output_store
from strix.tools.output_store import (
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
    full = read_stored_output(output_id, offset=0, limit=10_000)
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
    assert "more lines" in page
    assert "offset=10" in page


def test_read_stored_output_pages_long_lines_losslessly(tmp_path: Path) -> None:
    # A page of very long lines is bounded by returning *fewer whole lines*,
    # never by dropping content, so paging forward reconstructs everything and
    # never mints a fresh spill id.
    configure_output_store(tmp_path)
    lines = [f"{i}-" + "z" * 5_000 for i in range(50)]
    output_id = re.search(
        r'output_id="([0-9a-f]{32})"',
        bound_and_store("\n".join(lines), max_lines=4, max_bytes=1_000),
    )
    assert output_id is not None
    oid = output_id.group(1)

    collected: list[str] = []
    offset = 0
    for _ in range(200):  # guard against a paging loop
        page = read_stored_output(oid, offset=offset, limit=2_000)
        body, _sep, hint = page.partition("\n\n[... more lines;")
        assert len(body.encode("utf-8")) <= _output_store._PAGE_MAX_BYTES
        assert re.findall(r'output_id="([0-9a-f]{32})"', body) in ([], [oid])
        collected.extend(body.split("\n"))
        if not hint:
            break
        match = re.search(r"offset=(\d+)", hint)
        assert match is not None
        offset = int(match.group(1))

    assert collected == lines


def test_read_stored_output_rejects_traversal(tmp_path: Path) -> None:
    configure_output_store(tmp_path)
    assert "Invalid output_id" in read_stored_output("../../etc/passwd")


def test_read_stored_output_missing_id(tmp_path: Path) -> None:
    configure_output_store(tmp_path)
    assert "No stored output" in read_stored_output("0" * 32)

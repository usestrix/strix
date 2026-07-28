"""Tests for per-tool-output bounding and sandbox-workspace spill."""

from __future__ import annotations

import re

import pytest

from strix.tools.output_store import (
    WORKSPACE_SPILL_DIR,
    bound_and_store,
    bound_text,
    configure_spill_writer,
)


@pytest.fixture(autouse=True)
def _clear_spill_writer() -> None:
    configure_spill_writer(None)


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


async def test_bound_and_store_small_output_not_spilled() -> None:
    written: dict[str, str] = {}

    async def writer(output_id: str, text: str) -> str | None:
        written[output_id] = text
        return f"{WORKSPACE_SPILL_DIR}/{output_id}.txt"

    configure_spill_writer(writer)
    text = "just a few lines\nsecond line"
    assert await bound_and_store(text, max_lines=100, max_bytes=10_000) == text
    assert written == {}


async def test_bound_and_store_spills_full_output_to_workspace() -> None:
    written: dict[str, str] = {}

    async def writer(output_id: str, text: str) -> str | None:
        written[output_id] = text
        return f"{WORKSPACE_SPILL_DIR}/{output_id}.txt"

    configure_spill_writer(writer)
    text = "\n".join(f"secret-line-{i}" for i in range(1000))
    bounded = await bound_and_store(text, max_lines=10, max_bytes=1_000_000)

    assert WORKSPACE_SPILL_DIR in bounded
    assert "exec_command" in bounded
    assert "read_tool_output" not in bounded
    assert len(bounded.encode("utf-8")) <= 1_000_000
    assert list(written.values()) == [text]
    stored = next(iter(written.values()))
    assert stored.splitlines() == text.splitlines()
    # A buried line elided from the preview is still present in the spilled file.
    assert "secret-line-500" not in bounded
    assert "secret-line-500" in stored


async def test_workspace_notice_carries_the_returned_path() -> None:
    async def writer(output_id: str, _text: str) -> str | None:
        return f"{WORKSPACE_SPILL_DIR}/{output_id}.txt"

    configure_spill_writer(writer)
    text = "\n".join(f"line-{i}" for i in range(1000))
    bounded = await bound_and_store(text, max_lines=10, max_bytes=1_000_000)

    match = re.search(rf"{re.escape(WORKSPACE_SPILL_DIR)}/([0-9a-f]{{32}})\.txt", bounded)
    assert match is not None, bounded


async def test_no_writer_degrades_to_plain_preview() -> None:
    text = "\n".join(f"line-{i}" for i in range(1000))
    bounded = await bound_and_store(text, max_lines=10, max_bytes=1_000_000)

    assert "truncated" in bounded
    assert WORKSPACE_SPILL_DIR not in bounded
    assert "read_tool_output" not in bounded
    assert len(bounded.encode("utf-8")) <= 1_000_000


async def test_writer_failure_degrades_to_plain_preview() -> None:
    async def failing_writer(_output_id: str, _text: str) -> str | None:
        return None

    configure_spill_writer(failing_writer)
    text = "\n".join(f"line-{i}" for i in range(1000))
    bounded = await bound_and_store(text, max_lines=10, max_bytes=1_000_000)

    assert "truncated" in bounded
    assert WORKSPACE_SPILL_DIR not in bounded
    assert len(bounded.encode("utf-8")) <= 1_000_000


async def test_workspace_preview_honours_byte_budget() -> None:
    # The workspace notice is longer than a plain notice; the preview reserves for it.
    async def writer(output_id: str, _text: str) -> str | None:
        return f"{WORKSPACE_SPILL_DIR}/{output_id}.txt"

    configure_spill_writer(writer)
    text = "\n".join("x" * 500 for _ in range(200))
    bounded = await bound_and_store(text, max_lines=2_000, max_bytes=2_000)

    assert WORKSPACE_SPILL_DIR in bounded
    assert len(bounded.encode("utf-8")) <= 2_000

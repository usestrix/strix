"""Tests for strix/core/mapreduce_output.py — MapReduce LLM compression."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

from strix.config import load_settings
from strix.core.mapreduce_output import (
    CHUNK_SIZE_LINES,
    CHUNK_SIZE_RECORDS,
    _consolidate,
    _split,
    _summarise,
    compress_exec_result,
    compress_large_output,
)


if TYPE_CHECKING:
    import pytest


# ---------------------------------------------------------------------------
# _split
# ---------------------------------------------------------------------------


def test_split_json_array_into_multiple_chunks() -> None:
    """250 records at CHUNK_SIZE_RECORDS=100 → 3 chunks, each valid JSON."""
    records = [{"id": i} for i in range(250)]
    chunks = _split(json.dumps(records))
    assert len(chunks) == 3
    for chunk in chunks:
        assert isinstance(json.loads(chunk), list)


def test_split_json_respects_record_boundaries() -> None:
    """No record is split across chunk boundaries."""
    records = [{"id": i, "data": "x" * 10} for i in range(CHUNK_SIZE_RECORDS + 1)]
    chunks = _split(json.dumps(records))
    assert len(chunks) == 2
    first = json.loads(chunks[0])
    assert len(first) == CHUNK_SIZE_RECORDS


def test_split_plain_text_into_chunks() -> None:
    """1200 lines at CHUNK_SIZE_LINES=500 → 3 chunks."""
    text = "\n".join(f"line {i}" for i in range(1200))
    chunks = _split(text)
    assert len(chunks) == 3


def test_split_invalid_json_falls_back_to_line_split() -> None:
    """'[not valid json' triggers line-based split."""
    text = "\n".join("[not json" for _ in range(CHUNK_SIZE_LINES + 1))
    chunks = _split(text)
    assert len(chunks) == 2


def test_split_single_chunk_not_split() -> None:
    """50 records → 1 chunk (≤ CHUNK_SIZE_RECORDS)."""
    records = [{"id": i} for i in range(50)]
    chunks = _split(json.dumps(records))
    assert len(chunks) == 1


def test_split_empty_string_returns_one_chunk() -> None:
    chunks = _split("")
    assert len(chunks) == 1


def test_split_empty_json_array_returns_one_chunk() -> None:
    """An empty JSON array [] must return [output], not an empty list."""
    chunks = _split("[]")
    assert len(chunks) == 1


def test_split_whitespace_only_returns_one_chunk() -> None:
    """Whitespace-only input falls through to line split with one chunk."""
    chunks = _split("   ")
    assert len(chunks) == 1


# ---------------------------------------------------------------------------
# _consolidate
# ---------------------------------------------------------------------------


def test_consolidate_produces_header() -> None:
    result = _consolidate(["a", "b"], total_chars=1000, total_chunks=2)
    assert "MapReduce compression" in result
    assert "1,000 chars" in result


def test_consolidate_numbers_chunks() -> None:
    result = _consolidate(["summary0", "summary1"], total_chars=500, total_chunks=2)
    assert "[Chunk 1/2]" in result
    assert "[Chunk 2/2]" in result
    assert "summary0" in result
    assert "summary1" in result


# ---------------------------------------------------------------------------
# _summarise
# ---------------------------------------------------------------------------


async def test_summarise_returns_llm_content() -> None:
    mock_resp = MagicMock()
    mock_resp.choices[0].message.content = "3 SQL injection findings"
    with patch(
        "strix.core.mapreduce_output.litellm.acompletion", new_callable=AsyncMock
    ) as mock_ac:
        mock_ac.return_value = mock_resp
        result = await _summarise('["finding"]', "claude-sonnet-4-6", "SQL injection scan")
    assert result == "3 SQL injection findings"


async def test_summarise_returns_placeholder_on_exception() -> None:
    with patch(
        "strix.core.mapreduce_output.litellm.acompletion", new_callable=AsyncMock
    ) as mock_ac:
        mock_ac.side_effect = RuntimeError("API error")
        result = await _summarise("chunk_data", "model", "hint")
    assert "[summarisation failed" in result
    assert "chunk_data"[:100] in result


async def test_summarise_returns_placeholder_on_timeout() -> None:
    with patch(
        "strix.core.mapreduce_output.litellm.acompletion", new_callable=AsyncMock
    ) as mock_ac:
        mock_ac.side_effect = TimeoutError()
        result = await _summarise("chunk_data", "model", "hint")
    assert "[summarisation failed" in result


# ---------------------------------------------------------------------------
# compress_large_output
# ---------------------------------------------------------------------------


async def test_compress_single_chunk_returns_output_unchanged() -> None:
    """≤ CHUNK_SIZE_RECORDS records → 1 chunk → returned unchanged, no LLM call.

    The caller (factory._wrap_exec_command) owns the post-compression backstop
    for the single-oversized-chunk case; compress_large_output itself is a no-op.
    """
    records = [{"id": i} for i in range(50)]
    output = json.dumps(records)
    with patch(
        "strix.core.mapreduce_output.litellm.acompletion", new_callable=AsyncMock
    ) as mock_ac:
        result = await compress_large_output(output, model="model", task_hint="hint")
    mock_ac.assert_not_called()
    assert result == output


async def test_compress_multi_chunk_consolidates_summaries() -> None:
    """250 records → 3 chunks → 3 LLM calls → consolidated output."""
    records = [{"id": i} for i in range(250)]
    output = json.dumps(records)
    mock_resp = MagicMock()
    mock_resp.choices[0].message.content = "summary"
    with patch(
        "strix.core.mapreduce_output.litellm.acompletion", new_callable=AsyncMock
    ) as mock_ac:
        mock_ac.return_value = mock_resp
        result = await compress_large_output(output, model="model", task_hint="hint")
    assert mock_ac.call_count == 3
    assert "MapReduce compression" in result
    assert "summary" in result


async def test_compress_partial_failure_returns_partial_result() -> None:
    """If one chunk fails, its placeholder appears alongside successful summaries."""
    records = [{"id": i} for i in range(250)]
    output = json.dumps(records)
    good_resp = MagicMock()
    good_resp.choices[0].message.content = "good summary"

    call_count = 0

    async def side_effect(*_args: object, **_kwargs: object) -> MagicMock:
        nonlocal call_count
        call_count += 1
        if call_count == 2:
            raise RuntimeError("chunk 2 failed")
        return good_resp

    with patch("strix.core.mapreduce_output.litellm.acompletion", side_effect=side_effect):
        result = await compress_large_output(output, model="model", task_hint="hint")

    assert "good summary" in result
    assert "[summarisation failed" in result


async def test_compress_consolidated_too_large_is_truncated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If consolidated result exceeds threshold, it is hard-truncated with a warning."""
    records = [{"id": i} for i in range(250)]
    output = json.dumps(records)
    mock_resp = MagicMock()
    mock_resp.choices[0].message.content = "x" * 300  # 3 summaries x 300 chars = 900+ chars

    settings = load_settings()
    monkeypatch.setattr(settings.runtime, "max_tool_output_chars", 100)

    with (
        patch("strix.core.mapreduce_output.load_settings", return_value=settings),
        patch("strix.core.mapreduce_output.litellm.acompletion", new_callable=AsyncMock) as mock_ac,
    ):
        mock_ac.return_value = mock_resp
        result = await compress_large_output(output, model="model", task_hint="hint")

    assert len(result) <= 100 + len("\n[consolidated summary still too large — truncated]")
    assert "truncated" in result


# ---------------------------------------------------------------------------
# compress_exec_result (SDK header handling)
# ---------------------------------------------------------------------------


async def test_compress_exec_result_preserves_sdk_header() -> None:
    """SDK header up to '\\nOutput:\\n' is returned verbatim."""
    records = [{"id": i} for i in range(250)]
    sdk_output = (
        "Chunk ID: abc123\nWall time: 1.23s\nProcess exited with code 0\nOutput:\n"
        + json.dumps(records)
    )
    mock_resp = MagicMock()
    mock_resp.choices[0].message.content = "summary"
    with patch(
        "strix.core.mapreduce_output.litellm.acompletion", new_callable=AsyncMock
    ) as mock_ac:
        mock_ac.return_value = mock_resp
        result = await compress_exec_result(sdk_output, model="model", task_hint="hint")
    assert result.startswith("Chunk ID: abc123")
    assert "MapReduce compression" in result


async def test_compress_exec_result_no_separator_passes_through() -> None:
    """Without SDK separator, entire string is passed to compress_large_output."""
    records = [{"id": i} for i in range(250)]
    output = json.dumps(records)
    mock_resp = MagicMock()
    mock_resp.choices[0].message.content = "summary"
    with patch(
        "strix.core.mapreduce_output.litellm.acompletion", new_callable=AsyncMock
    ) as mock_ac:
        mock_ac.return_value = mock_resp
        result = await compress_exec_result(output, model="model", task_hint="hint")
    assert "MapReduce compression" in result

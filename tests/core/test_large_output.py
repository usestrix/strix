"""Tests for strix/core/large_output.py — structure-aware output truncation."""

from __future__ import annotations

import json

from strix.core.large_output import truncate_exec_result, truncate_tool_output


def test_small_output_is_unchanged() -> None:
    """Output below threshold must be returned verbatim."""
    output = "hello world\n" * 10
    assert truncate_tool_output(output, threshold=65536) == output


def test_plain_text_is_truncated_with_header() -> None:
    """Plain text over threshold keeps first lines and prepends a summary header."""
    line = "x" * 200 + "\n"
    output = line * 500  # 100_500 chars
    result = truncate_tool_output(output, threshold=65536)

    assert len(result) <= 65536 + 200  # header may push slightly over
    assert "[truncated" in result
    assert "500 lines" in result


def test_json_array_is_truncated_to_valid_json() -> None:
    """A large JSON array must be trimmed to first N records, still valid JSON."""
    records = [{"id": i, "data": "x" * 200} for i in range(500)]
    output = json.dumps(records)
    result = truncate_tool_output(output, threshold=65536)

    assert "[truncated" in result
    # The JSON portion after the header must be parseable.
    json_part = result[result.index("[") :].split("\n", 1)[-1].strip()
    parsed = json.loads(json_part)
    assert isinstance(parsed, list)
    assert len(parsed) < 500


def test_invalid_json_falls_back_to_text_truncation() -> None:
    """Output that looks like JSON but is invalid falls back to plain-text truncation."""
    line = "[not valid json " + "x" * 100
    output = (line + "\n") * 700  # ~81,900 chars across 700 lines
    result = truncate_tool_output(output, threshold=65536)

    assert "[truncated" in result
    assert "700 lines" in result
    assert len(result) < len(output)


def test_threshold_zero_disables_truncation() -> None:
    """threshold=0 means no truncation (disabled)."""
    output = "x" * 200_000
    assert truncate_tool_output(output, threshold=0) == output


def test_plain_text_single_long_line_is_capped() -> None:
    """A single line longer than the threshold must be capped at threshold chars."""
    output = "x" * 200_000
    result = truncate_tool_output(output, threshold=65536)
    assert "[truncated" in result
    assert len(result) <= 65536 + 200  # generous header allowance


def test_json_truncation_respects_threshold_for_large_records() -> None:
    """When 50 large records exceed the threshold, fewer records must be kept."""
    records = [{"id": i, "data": "x" * 2000} for i in range(500)]
    output = json.dumps(records)
    result = truncate_tool_output(output, threshold=65536)
    assert "[truncated" in result
    assert "records" in result
    assert len(result) <= 65536 + 300  # header is modest; total must fit


def test_truncate_exec_result_detects_json_in_sdk_wrapped_output() -> None:
    """JSON content after the SDK's 'Output:' marker must use JSON-aware truncation."""
    records = [{"id": i, "data": "x" * 200} for i in range(500)]
    sdk_output = (
        "Chunk ID: abc123\nWall time: 1.234s\nProcess exited with code 0\nOutput:\n"
        + json.dumps(records)
    )
    result = truncate_exec_result(sdk_output, threshold=65536)
    assert "Chunk ID" in result  # SDK header preserved
    assert "records" in result  # JSON path used (not plain-text path)
    assert "[truncated" in result

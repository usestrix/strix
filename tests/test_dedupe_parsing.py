"""Unit tests for :func:`strix.report.dedupe._parse_dedupe_response`."""

from __future__ import annotations

import json

import pytest

from strix.report.dedupe import _parse_dedupe_response


def test_plain_json_round_trip() -> None:
    content = json.dumps(
        {
            "is_duplicate": True,
            "duplicate_id": "vuln-1",
            "confidence": 0.75,
            "reason": "same endpoint",
        }
    )

    result = _parse_dedupe_response(content)

    assert result == {
        "is_duplicate": True,
        "duplicate_id": "vuln-1",
        "confidence": 0.75,
        "reason": "same endpoint",
    }


def test_json_fenced_block_is_unwrapped() -> None:
    payload = {"is_duplicate": False, "duplicate_id": "", "confidence": 0.1, "reason": "n/a"}
    content = f"```json\n{json.dumps(payload)}\n```"

    result = _parse_dedupe_response(content)

    assert result["is_duplicate"] is False
    assert result["confidence"] == 0.1
    assert result["reason"] == "n/a"


def test_no_json_object_raises_value_error() -> None:
    with pytest.raises(ValueError, match="No JSON object found"):
        _parse_dedupe_response("there is no json here")


def test_duplicate_id_truncated_to_64_chars() -> None:
    long_id = "a" * 200
    content = json.dumps({"is_duplicate": True, "duplicate_id": long_id, "confidence": 1.0})

    result = _parse_dedupe_response(content)

    assert result["duplicate_id"] == "a" * 64
    assert len(result["duplicate_id"]) == 64


def test_non_numeric_or_null_confidence_defaults_to_zero() -> None:
    non_numeric = _parse_dedupe_response(json.dumps({"is_duplicate": False, "confidence": "high"}))
    null_confidence = _parse_dedupe_response(
        json.dumps({"is_duplicate": False, "confidence": None})
    )

    assert non_numeric["confidence"] == 0.0
    assert null_confidence["confidence"] == 0.0

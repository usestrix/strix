"""Tests for the _parse_credentials helper in main.py."""

from __future__ import annotations

import argparse
import json

import pytest

from strix.interface.main import _parse_credentials


def _parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser()


def test_no_credentials_returns_empty_dict():
    result = _parse_credentials(None, None, _parser())
    assert result == {}


def test_inline_single_pair():
    result = _parse_credentials("PASSWORD=secret", None, _parser())
    assert result == {"PASSWORD": "secret"}


def test_inline_multiple_pairs():
    result = _parse_credentials("USER=admin,PASS=s3cr3t", None, _parser())
    assert result == {"USER": "admin", "PASS": "s3cr3t"}


def test_inline_value_with_equals_sign():
    """Values that contain '=' should be preserved after the first '='."""
    result = _parse_credentials("TOKEN=abc=def", None, _parser())
    assert result == {"TOKEN": "abc=def"}


def test_credentials_file(tmp_path):
    creds = {"API_KEY": "abc123", "TOKEN": "xyz789"}
    f = tmp_path / "creds.json"
    f.write_text(json.dumps(creds))
    result = _parse_credentials(None, str(f), _parser())
    assert result == creds


def test_credentials_file_overridden_by_inline(tmp_path):
    """Inline values override file values for the same key."""
    f = tmp_path / "creds.json"
    f.write_text(json.dumps({"USER": "file_user", "PASS": "file_pass"}))
    result = _parse_credentials("PASS=override", str(f), _parser())
    assert result == {"USER": "file_user", "PASS": "override"}


def test_missing_file_raises_system_exit():
    with pytest.raises(SystemExit):
        _parse_credentials(None, "/nonexistent/creds.json", _parser())


def test_invalid_json_raises_system_exit(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not json {{{")
    with pytest.raises(SystemExit):
        _parse_credentials(None, str(bad), _parser())


def test_non_object_json_raises_system_exit(tmp_path):
    bad = tmp_path / "list.json"
    bad.write_text(json.dumps(["a", "b"]))
    with pytest.raises(SystemExit):
        _parse_credentials(None, str(bad), _parser())


def test_invalid_inline_format_raises_system_exit():
    with pytest.raises(SystemExit):
        _parse_credentials("NOEQUALS", None, _parser())


def test_empty_key_raises_system_exit():
    with pytest.raises(SystemExit):
        _parse_credentials("=value", None, _parser())


def test_non_string_json_values_raise_system_exit(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"KEY": {"nested": "object"}}))
    with pytest.raises(SystemExit):
        _parse_credentials(None, str(bad), _parser())


def test_invalid_key_characters_raise_system_exit():
    with pytest.raises(SystemExit):
        _parse_credentials("MY-API-KEY=value", None, _parser())


def test_key_with_dot_raises_system_exit():
    with pytest.raises(SystemExit):
        _parse_credentials("API.KEY=value", None, _parser())

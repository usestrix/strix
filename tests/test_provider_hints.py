"""Tests for the provider import-error hint helper in interface/main.py."""

from __future__ import annotations

from strix.interface.main import _provider_import_hint


def test_bedrock_boto3_hint() -> None:
    exc = ModuleNotFoundError("No module named 'boto3'")
    hint = _provider_import_hint(exc, "bedrock/anthropic.claude-4-5-sonnet")
    assert hint is not None
    assert 'pipx install "strix-agent[' in hint
    assert "bedrock" in hint


def test_vertex_google_hint() -> None:
    exc = ImportError("No module named 'google'")
    hint = _provider_import_hint(exc, "vertex_ai/gemini-3-pro-preview")
    assert hint is not None
    assert 'pipx install "strix-agent[' in hint
    assert "vertex" in hint


def test_non_import_error_returns_none() -> None:
    assert _provider_import_hint(ConnectionError("boom"), "bedrock/whatever") is None


def test_unrelated_provider_returns_none() -> None:
    exc = ImportError("No module named 'something'")
    assert _provider_import_hint(exc, "openai/gpt-4") is None

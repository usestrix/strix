"""Tests for the provider import-error hint helper in interface/main.py."""

from __future__ import annotations

from strix.interface.main import _provider_import_hint


VERTEX_MODEL = "vertex_ai/gemini-3-pro-preview"
BEDROCK_MODEL = "bedrock/anthropic.claude-4-5-sonnet"
VERTEX_EXTRA_NAME = "vertex"
BEDROCK_EXTRA_NAME = "bedrock"
INSTALL_EXTRA_COMMAND_FRAGMENT = 'pipx install "strix-agent['
WRAPPED_VERTEX_GOOGLE_ERROR = "litellm.APIConnectionError: No module named 'google'"
WRAPPED_BEDROCK_BOTO3_ERROR = "litellm.APIConnectionError: No module named 'boto3'"


def test_bedrock_boto3_hint() -> None:
    exc = ModuleNotFoundError("No module named 'boto3'")
    hint = _provider_import_hint(exc, BEDROCK_MODEL)
    assert hint is not None
    assert INSTALL_EXTRA_COMMAND_FRAGMENT in hint
    assert BEDROCK_EXTRA_NAME in hint


def test_vertex_google_hint() -> None:
    exc = ImportError("No module named 'google'")
    hint = _provider_import_hint(exc, VERTEX_MODEL)
    assert hint is not None
    assert INSTALL_EXTRA_COMMAND_FRAGMENT in hint
    assert VERTEX_EXTRA_NAME in hint


def test_vertex_google_hint_for_litellm_wrapped_connection_error() -> None:
    exc = ConnectionError(WRAPPED_VERTEX_GOOGLE_ERROR)
    hint = _provider_import_hint(exc, VERTEX_MODEL)
    assert hint is not None
    assert INSTALL_EXTRA_COMMAND_FRAGMENT in hint
    assert VERTEX_EXTRA_NAME in hint


def test_bedrock_boto3_hint_for_litellm_wrapped_connection_error() -> None:
    exc = ConnectionError(WRAPPED_BEDROCK_BOTO3_ERROR)
    hint = _provider_import_hint(exc, BEDROCK_MODEL)
    assert hint is not None
    assert INSTALL_EXTRA_COMMAND_FRAGMENT in hint
    assert BEDROCK_EXTRA_NAME in hint


def test_vertex_google_submodule_hint() -> None:
    exc = ModuleNotFoundError("No module named 'google.auth'")
    hint = _provider_import_hint(exc, VERTEX_MODEL)
    assert hint is not None
    assert INSTALL_EXTRA_COMMAND_FRAGMENT in hint
    assert VERTEX_EXTRA_NAME in hint


def test_vertex_google_hint_for_deeply_chained_error() -> None:
    root = ModuleNotFoundError("No module named 'google.auth'")
    middle = RuntimeError("provider init failed")
    middle.__cause__ = root
    exc = ConnectionError("litellm.APIConnectionError: request failed")
    exc.__cause__ = middle
    hint = _provider_import_hint(exc, VERTEX_MODEL)
    assert hint is not None
    assert VERTEX_EXTRA_NAME in hint


def test_non_import_error_returns_none() -> None:
    assert _provider_import_hint(ConnectionError("boom"), "bedrock/whatever") is None


def test_unrelated_provider_returns_none() -> None:
    exc = ImportError("No module named 'something'")
    assert _provider_import_hint(exc, "openai/gpt-4") is None

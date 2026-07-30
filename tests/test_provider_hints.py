"""Tests for the provider import-error hint helper in interface/main.py."""

from __future__ import annotations

import importlib
from typing import Any

import pytest

from strix.config import (
    ProviderAuthState,
    clear_provider_credentials_invalid,
    provider_auth_status,
)
from strix.config.settings import Settings
from strix.interface.main import (
    ProviderCredentialRejectedError,
    _provider_import_hint,
    preflight_model_connection,
)


VERTEX_MODEL = "vertex_ai/gemini-3-pro-preview"
BEDROCK_MODEL = "bedrock/anthropic.claude-4-5-sonnet"
VERTEX_EXTRA_NAME = "vertex"
BEDROCK_EXTRA_NAME = "bedrock"
INSTALL_EXTRA_COMMAND_FRAGMENT = 'pipx install "strix-agent['
WRAPPED_VERTEX_GOOGLE_ERROR = "litellm.APIConnectionError: No module named 'google'"
WRAPPED_BEDROCK_BOTO3_ERROR = "litellm.APIConnectionError: No module named 'boto3'"
main_module = importlib.import_module("strix.interface.main")


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


@pytest.mark.asyncio
async def test_preflight_turns_rejected_key_into_actionable_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class RejectingModel:
        async def get_response(self, **_kwargs: Any) -> None:
            raise RuntimeError("HTTP 401 Unauthorized")

    class Provider:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        def get_model(self, _model: str) -> RejectingModel:
            return RejectingModel()

    clear_provider_credentials_invalid("anthropic")
    monkeypatch.setattr(main_module, "StrixProvider", Provider)
    monkeypatch.setattr(main_module, "configure_sdk_model_defaults", lambda _settings: None)

    with pytest.raises(
        ProviderCredentialRejectedError,
        match=r"authentication failed.*was rejected",
    ) as error:
        await preflight_model_connection(
            "anthropic/claude",
            settings=Settings(llm={"model": "anthropic/claude", "timeout": 1}),
        )

    assert error.value.provider == "anthropic"
    assert error.value.credential_role == "primary"
    assert provider_auth_status("anthropic").state is ProviderAuthState.INVALID
    clear_provider_credentials_invalid("anthropic")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [
        TimeoutError("connection timed out"),
        RuntimeError("429 rate limit exceeded"),
        RuntimeError("403 model access denied"),
    ],
)
async def test_preflight_does_not_classify_ordinary_connection_errors_as_rejected_keys(
    monkeypatch: pytest.MonkeyPatch,
    error: BaseException,
) -> None:
    class FailingModel:
        async def get_response(self, **_kwargs: Any) -> None:
            raise error

    class Provider:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        def get_model(self, _model: str) -> FailingModel:
            return FailingModel()

    clear_provider_credentials_invalid("anthropic")
    monkeypatch.setattr(main_module, "StrixProvider", Provider)
    monkeypatch.setattr(main_module, "configure_sdk_model_defaults", lambda _settings: None)

    with pytest.raises(type(error), match=str(error)):
        await preflight_model_connection(
            "anthropic/claude",
            settings=Settings(llm={"model": "anthropic/claude", "timeout": 1}),
        )

    assert provider_auth_status("anthropic").state is not ProviderAuthState.INVALID

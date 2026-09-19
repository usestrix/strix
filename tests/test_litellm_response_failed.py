"""Tests for LiteLLM Responses API failed stream events."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest
from litellm.exceptions import APIError
from litellm.responses.streaming_iterator import BaseResponsesAPIStreamingIterator

from strix.config.models import _configure_litellm_compatibility


FAILED_EVENT_TYPE = "response.failed"
FAILED_MESSAGE = "Insufficient credits"
FAILED_CODE = "billing_hard_limit_reached"
FAILED_MODEL = "openai/gpt-5"
FAILED_PROVIDER = "openai"


class _ProviderConfig:
    def transform_streaming_response(self, **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(
            type=FAILED_EVENT_TYPE,
            response=SimpleNamespace(
                error=SimpleNamespace(message=FAILED_MESSAGE, code=FAILED_CODE)
            ),
        )


def _make_iterator() -> Any:
    iterator: Any = BaseResponsesAPIStreamingIterator.__new__(BaseResponsesAPIStreamingIterator)
    iterator.responses_api_provider_config = _ProviderConfig()
    iterator.logging_obj = SimpleNamespace()
    iterator.model = FAILED_MODEL
    iterator.custom_llm_provider = FAILED_PROVIDER
    iterator.litellm_metadata = None
    iterator.completed_response = None
    iterator._handle_logging_failed_response = lambda: None
    iterator._handle_logging_completed_response = lambda: None
    return iterator


def test_response_failed_stream_event_is_raised() -> None:
    _configure_litellm_compatibility()
    iterator = _make_iterator()
    payload = json.dumps({"type": FAILED_EVENT_TYPE, "response": {"error": {}}})

    with pytest.raises(APIError) as exc_info:
        iterator._process_chunk(payload)

    error_text = str(exc_info.value)
    assert FAILED_MESSAGE in error_text
    assert FAILED_CODE in error_text

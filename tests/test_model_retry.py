"""The SDK model retry is off: the turn loop is the only retry layer."""

from __future__ import annotations

from strix.config.models import DEFAULT_MODEL_RETRY


def test_sdk_model_retry_is_disabled() -> None:
    assert DEFAULT_MODEL_RETRY.max_retries == 0

"""Tests for provider-reported LLM cost capture."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import litellm

from strix.config.models import _configure_litellm_compatibility
from strix.report.state import litellm_cost_callback


def test_streaming_logging_stays_enabled_for_cost_callback() -> None:
    with (
        patch.object(litellm, "disable_streaming_logging", new=True),
        patch("strix.config.models._register_litellm_cost_callback") as register,
    ):
        _configure_litellm_compatibility()
        assert litellm.disable_streaming_logging is False
        register.assert_called_once_with()


def test_cost_callback_reads_openrouter_stream_usage_cost() -> None:
    report_state = MagicMock()
    response = SimpleNamespace(
        usage=SimpleNamespace(cost=1.2345),
        _hidden_params={},
    )

    with patch("strix.report.state.get_global_report_state", return_value=report_state):
        litellm_cost_callback({"response_cost": None}, response)

    report_state.record_observed_llm_cost.assert_called_once_with(1.2345)


def test_cost_callback_reads_usage_cost_from_mapping_response() -> None:
    report_state = MagicMock()
    response = {"usage": {"cost": 0.125}}

    with patch("strix.report.state.get_global_report_state", return_value=report_state):
        litellm_cost_callback({}, response)

    report_state.record_observed_llm_cost.assert_called_once_with(0.125)

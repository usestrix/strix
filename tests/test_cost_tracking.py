"""Tests for provider-reported LLM cost capture."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import litellm
import pytest

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


def test_cost_callback_reads_byok_upstream_inference_cost() -> None:
    report_state = MagicMock()
    response = SimpleNamespace(
        usage=SimpleNamespace(
            cost=0,
            is_byok=True,
            cost_details=SimpleNamespace(upstream_inference_cost=6.75e-06),
        ),
        _hidden_params={},
    )

    with patch("strix.report.state.get_global_report_state", return_value=report_state):
        litellm_cost_callback({"response_cost": None}, response)

    report_state.record_observed_llm_cost.assert_called_once_with(6.75e-06)


def test_cost_callback_sums_usage_cost_and_upstream_inference_cost() -> None:
    report_state = MagicMock()
    response = {
        "usage": {
            "cost": 0.01,
            "is_byok": True,
            "cost_details": {"upstream_inference_cost": 0.2},
        }
    }

    with patch("strix.report.state.get_global_report_state", return_value=report_state):
        litellm_cost_callback({}, response)

    report_state.record_observed_llm_cost.assert_called_once_with(pytest.approx(0.21))


def test_cost_callback_ignores_upstream_cost_for_non_byok_responses() -> None:
    report_state = MagicMock()
    response = {
        "usage": {
            "cost": 0.05,
            "is_byok": False,
            "cost_details": {"upstream_inference_cost": 0.04},
        }
    }

    with patch("strix.report.state.get_global_report_state", return_value=report_state):
        litellm_cost_callback({}, response)

    report_state.record_observed_llm_cost.assert_called_once_with(0.05)


def test_cost_callback_estimates_cost_with_provider_prefixed_model() -> None:
    report_state = MagicMock()
    response = {"usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}
    kwargs = {
        "response_cost": None,
        "model": "anthropic/claude-sonnet-4.5",
        "litellm_params": {"custom_llm_provider": "openrouter"},
    }

    def fake_completion_cost(**kwargs: object) -> float:
        if kwargs["model"] == "openrouter/anthropic/claude-sonnet-4.5":
            return 0.5
        raise ValueError(kwargs["model"])

    with (
        patch("strix.report.state.get_global_report_state", return_value=report_state),
        patch("litellm.completion_cost", side_effect=fake_completion_cost),
    ):
        litellm_cost_callback(kwargs, response)

    report_state.record_observed_llm_cost.assert_called_once_with(0.5)


def test_cost_callback_estimates_cost_with_bare_model_fallback() -> None:
    report_state = MagicMock()
    response = {"usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}
    kwargs = {
        "response_cost": None,
        "model": "openai/gpt-4o-mini",
        "litellm_params": {"custom_llm_provider": "openrouter"},
    }

    def fake_completion_cost(**kwargs: object) -> float:
        if kwargs["model"] == "gpt-4o-mini":
            return 0.025
        raise ValueError(kwargs["model"])

    with (
        patch("strix.report.state.get_global_report_state", return_value=report_state),
        patch("litellm.completion_cost", side_effect=fake_completion_cost),
    ):
        litellm_cost_callback(kwargs, response)

    report_state.record_observed_llm_cost.assert_called_once_with(0.025)


def test_cost_callback_records_nothing_when_no_cost_available() -> None:
    report_state = MagicMock()
    response = {"usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}

    with (
        patch("strix.report.state.get_global_report_state", return_value=report_state),
        patch("litellm.completion_cost", side_effect=ValueError("unknown model")),
    ):
        litellm_cost_callback({"response_cost": None, "model": "x/y"}, response)

    report_state.record_observed_llm_cost.assert_not_called()
